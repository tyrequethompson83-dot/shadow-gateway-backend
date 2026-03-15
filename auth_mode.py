import os
from typing import Any, Dict, Optional

from security_utils import decode_jwt, issue_jwt


AUTH_MODE_HEADER = "header"
AUTH_MODE_JWT = "jwt"


PUBLIC_PATHS = {
    "/health",
    "/onboarding/status",
    "/onboarding/bootstrap",
    "/auth/login",
    "/auth/signup/company",
    "/auth/signup/individual",
    "/auth/signup/invite",
    "/docs",
    "/openapi.json",
    "/redoc",
}


def auth_mode() -> str:
    mode = (os.getenv("AUTH_MODE", AUTH_MODE_HEADER) or AUTH_MODE_HEADER).strip().lower()
    return AUTH_MODE_JWT if mode == AUTH_MODE_JWT else AUTH_MODE_HEADER


def jwt_enabled() -> bool:
    return auth_mode() == AUTH_MODE_JWT


def is_public_path(path: str) -> bool:
    value = (path or "").strip()
    if value in PUBLIC_PATHS:
        return True
    return value.startswith("/docs") or value.startswith("/redoc")


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    raw = (auth_header or "").strip()
    if not raw:
        return None
    if not raw.lower().startswith("bearer "):
        return None
    token = raw[7:].strip()
    return token or None


def make_access_token(*, user_id: int, username: str, tenant_id: int, role: str) -> str:
    return issue_jwt(
        {
            "sub": username,
            "user_id": int(user_id),
            "tenant_id": int(tenant_id),
            "role": str(role),
        }
    )


def parse_access_token(token: str) -> Dict[str, Any]:
    return decode_jwt(token)
