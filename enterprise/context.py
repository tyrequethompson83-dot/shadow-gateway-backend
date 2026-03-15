import uuid
from dataclasses import dataclass
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app_config import is_dev
from auth_rate_limit import client_ip_from_request
from auth_mode import (
    extract_bearer_token,
    is_public_path,
    jwt_enabled,
    parse_access_token,
)
from .db_enterprise import (
    ensure_user,
    get_default_tenant_id,
    get_role,
    get_user_by_username,
    write_audit_log,
)
from product_auth import (
    create_membership,
    ensure_product_auth_schema,
    get_membership_role,
    get_user_by_email,
    has_membership,
    is_token_revoked,
)


@dataclass
class RequestContext:
    tenant_id: int
    user_id: Optional[int]
    external_user: Optional[str]
    role: str
    request_id: str
    auth_mode: str
    token_jti: Optional[str] = None
    token_exp: Optional[int] = None


class EnterpriseContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
        request.state.ctx = None
        request.state.user = None
        request.state.tenant = None

        try:
            ensure_product_auth_schema()
        except Exception:
            pass

        x_user_header = request.headers.get("X-User")
        path = str(request.url.path)
        if x_user_header and not is_dev():
            return JSONResponse(
                status_code=400,
                content={"detail": "X-User header auth is disabled outside dev"},
                headers={"X-Request-Id": request_id},
            )

        token = extract_bearer_token(request.headers.get("Authorization"))
        token_mode = bool(token)

        if token_mode:
            try:
                claims = parse_access_token(token or "")
                token_jti = str(claims.get("jti") or "").strip()
                if token_jti and is_token_revoked(token_jti):
                    raise ValueError("token revoked")
                username = str(claims.get("sub") or "").strip()
                if not username:
                    raise ValueError("missing subject")
                user = get_user_by_username(username) or get_user_by_email(username)
                if not user or int(user.get("is_active", 0) or 0) != 1:
                    raise ValueError("invalid user")
                tenant_header = request.headers.get("X-Tenant-Id")
                tenant_id = int(claims.get("tenant_id") or get_default_tenant_id())
                if tenant_header and tenant_header.isdigit() and int(tenant_header) != tenant_id:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "X-Tenant-Id does not match token tenant"},
                        headers={"X-Request-Id": request_id},
                    )
                user_id = int(user["id"])
                if not has_membership(user_id=user_id, tenant_id=tenant_id) and not is_public_path(path):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Tenant membership required"},
                        headers={"X-Request-Id": request_id},
                    )
                role = get_membership_role(user_id=user_id, tenant_id=tenant_id) or get_role(tenant_id, user_id)
                if role == "admin":
                    role = "platform_admin"
                external_user = str(user.get("email") or user.get("username") or user.get("external_id") or username)
                request.state.ctx = RequestContext(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    external_user=external_user,
                    role=role,
                    request_id=request_id,
                    auth_mode="jwt",
                    token_jti=token_jti or None,
                    token_exp=int(claims.get("exp")) if claims.get("exp") is not None else None,
                )
            except Exception:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Invalid token"},
                    headers={"X-Request-Id": request_id},
                )
        elif jwt_enabled():
            if not is_public_path(path):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authentication required"},
                    headers={"X-Request-Id": request_id},
                )
        else:
            if not is_dev():
                if not is_public_path(path):
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Authentication required"},
                        headers={"X-Request-Id": request_id},
                    )
                response = await call_next(request)
                response.headers["X-Request-Id"] = request_id
                return response
            external_user = request.headers.get("X-User")
            tenant_header = request.headers.get("X-Tenant-Id")
            tenant_id = int(tenant_header) if tenant_header and tenant_header.isdigit() else get_default_tenant_id()
            user_id = ensure_user(external_user)
            if user_id and not has_membership(user_id=user_id, tenant_id=tenant_id):
                try:
                    create_membership(tenant_id=tenant_id, user_id=int(user_id), role="user")
                except Exception:
                    pass
            role = get_role(tenant_id, user_id)
            if role == "admin":
                role = "platform_admin"
            request.state.ctx = RequestContext(
                tenant_id=tenant_id,
                user_id=user_id,
                external_user=external_user,
                role=role,
                request_id=request_id,
                auth_mode="header",
            )

        ctx = getattr(request.state, "ctx", None)
        if ctx:
            request.state.user = {
                "id": ctx.user_id,
                "external_user": ctx.external_user,
                "role": ctx.role,
                "auth_mode": ctx.auth_mode,
            }
            request.state.tenant = {"id": ctx.tenant_id}

        response = await call_next(request)

        ctx = getattr(request.state, "ctx", None)
        if ctx:
            try:
                write_audit_log(
                    tenant_id=ctx.tenant_id,
                    user_id=ctx.user_id,
                    action="http.request",
                    metadata={
                        "method": request.method,
                        "path": str(request.url.path),
                        "status": response.status_code,
                        "auth_mode": ctx.auth_mode,
                    },
                    ip=client_ip_from_request(request),
                    user_agent=request.headers.get("User-Agent"),
                    request_id=request_id,
                )
            except Exception:
                pass

        response.headers["X-Request-Id"] = request_id
        return response
