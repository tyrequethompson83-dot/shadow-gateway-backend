from fastapi import Depends, HTTPException, Request
import os

ENTERPRISE_MODE = os.getenv("ENTERPRISE_MODE", "true").lower() == "true"
# Enforce RBAC by default for admin routes now (flip to false to disable)
ENFORCE_RBAC = os.getenv("ENFORCE_RBAC", "true").lower() == "true"

ROLE_ORDER = {"user": 1, "employee": 1, "auditor": 2, "tenant_admin": 2, "admin": 3, "platform_admin": 4}

def require_role(min_role: str):
    async def _dep(request: Request):
        ctx = getattr(request.state, "ctx", None)
        if not ctx:
            return  # if middleware not installed yet, don't break anything

        has = ROLE_ORDER.get(ctx.role, 0)
        need = ROLE_ORDER.get(min_role, 999)

        if has < need:
            # Log-only if not enforcing yet
            if ENTERPRISE_MODE and ENFORCE_RBAC:
                raise HTTPException(status_code=403, detail="Forbidden")
        return
    return Depends(_dep)


def require_platform_admin():
    async def _dep(request: Request):
        ctx = getattr(request.state, "ctx", None)
        if not ctx:
            return
        role = str(getattr(ctx, "role", "") or "")
        if role != "platform_admin":
            if ENTERPRISE_MODE and ENFORCE_RBAC:
                raise HTTPException(status_code=403, detail="Platform admin access required")
        return

    return Depends(_dep)
