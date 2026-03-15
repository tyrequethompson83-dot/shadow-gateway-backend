import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .db_enterprise import (
    get_default_tenant_id,
    get_tenant_limits,
    get_tenant_usage_daily,
    increment_tenant_usage_daily,
    write_audit_log,
)


def _env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        return int(raw)
    except Exception:
        return int(default)


ENABLE_TENANT_LIMITS = os.getenv("ENABLE_TENANT_LIMITS", "true").lower() == "true"
TENANT_RPM_DEFAULT = max(1, _env_int("TENANT_RPM_DEFAULT", 60))
TENANT_RPD_DEFAULT = max(1, _env_int("TENANT_RPD_DEFAULT", 2000))
TENANT_MAX_TOKENS_DEFAULT = max(0, _env_int("TENANT_MAX_TOKENS_DEFAULT", 200000))
_BUCKET_LOCK = threading.Lock()
_MINUTE_BUCKETS: Dict[tuple[int, str], Deque[float]] = {}


def _current_utc_day() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _seconds_until_next_utc_day() -> int:
    now = datetime.now(timezone.utc)
    next_day = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((next_day - now).total_seconds()))


def _prune_window(window: Deque[float], now_ts: float) -> None:
    while window and (now_ts - float(window[0])) >= 60.0:
        window.popleft()


def _allow_rpm(
    tenant_id: int,
    rpm_limit: int,
    *,
    now_ts: Optional[float] = None,
    scope: str = "global",
) -> bool:
    current = time.time() if now_ts is None else float(now_ts)
    with _BUCKET_LOCK:
        key = (int(tenant_id), str(scope))
        window = _MINUTE_BUCKETS.get(key)
        if window is None:
            window = deque()
            _MINUTE_BUCKETS[key] = window

        _prune_window(window, current)
        if len(window) >= int(rpm_limit):
            return False
        window.append(current)
        return True


def _rpm_retry_after_seconds(
    tenant_id: int,
    *,
    now_ts: Optional[float] = None,
    scope: str = "global",
) -> int:
    current = time.time() if now_ts is None else float(now_ts)
    with _BUCKET_LOCK:
        window = _MINUTE_BUCKETS.get((int(tenant_id), str(scope)))
        if not window:
            return 1
        _prune_window(window, current)
        if not window:
            return 1
        oldest = float(window[0])
        remaining = 60.0 - (current - oldest)
        return max(1, int(remaining) if remaining.is_integer() else int(remaining) + 1)


def estimate_prompt_tokens(prompt: str) -> int:
    text = str(prompt or "").strip()
    if not text:
        return 0
    return max(0, len(text.split()))


def _resolved_limits(tenant_id: int) -> Dict[str, Any]:
    limits: Dict[str, Any] = {
        "enabled": True,
        "rpm_limit": TENANT_RPM_DEFAULT,
        "daily_requests_limit": TENANT_RPD_DEFAULT,
        "daily_token_limit": TENANT_MAX_TOKENS_DEFAULT,
    }
    try:
        persisted = get_tenant_limits(tenant_id)
    except Exception:
        return limits

    limits["enabled"] = bool(persisted.get("enabled", True))
    limits["rpm_limit"] = max(1, int(persisted.get("rpm_limit") or TENANT_RPM_DEFAULT))
    limits["daily_requests_limit"] = max(
        1, int(persisted.get("daily_requests_limit") or TENANT_RPD_DEFAULT)
    )
    return limits


def check_tenant_chat_limits(tenant_id: int) -> Optional[Dict[str, Any]]:
    if not ENABLE_TENANT_LIMITS:
        return None

    limits = _resolved_limits(tenant_id)
    if not limits.get("enabled", True):
        return None

    rpm_limit = int(limits["rpm_limit"])
    if not _allow_rpm(tenant_id=tenant_id, rpm_limit=rpm_limit, scope="chat"):
        return {
            "message": "Tenant limit exceeded",
            "limit": "rpm",
            "retry_after_seconds": _rpm_retry_after_seconds(tenant_id, scope="chat"),
        }

    try:
        usage = get_tenant_usage_daily(tenant_id=tenant_id, day=_current_utc_day())
    except Exception:
        return None
    daily_limit = int(limits["daily_requests_limit"])
    if int(usage.get("request_count", 0)) >= daily_limit:
        return {
            "message": "Tenant limit exceeded",
            "limit": "rpd",
            "retry_after_seconds": _seconds_until_next_utc_day(),
        }

    token_limit = int(limits["daily_token_limit"])
    if token_limit > 0 and int(usage.get("token_count", 0)) >= token_limit:
        return {
            "message": "Tenant limit exceeded",
            "limit": "rpd",
            "retry_after_seconds": _seconds_until_next_utc_day(),
        }

    return None


def record_tenant_chat_usage(
    tenant_id: int,
    *,
    blocked: bool,
    token_delta: int,
    risk_delta: int = 0,
    request_delta: int = 1,
) -> None:
    if not ENABLE_TENANT_LIMITS:
        return
    try:
        increment_tenant_usage_daily(
            tenant_id=tenant_id,
            blocked=blocked,
            risk_delta=int(risk_delta),
            token_delta=max(0, int(token_delta)),
            request_delta=max(0, int(request_delta)),
            day=_current_utc_day(),
        )
    except Exception:
        pass


def reset_rate_limit_state() -> None:
    """Test helper to clear in-memory rolling windows."""
    with _BUCKET_LOCK:
        _MINUTE_BUCKETS.clear()


class TenantLimitsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not ENABLE_TENANT_LIMITS:
            return await call_next(request)

        if str(request.url.path) == "/chat":
            return await call_next(request)

        ctx = getattr(request.state, "ctx", None)
        if ctx and getattr(ctx, "tenant_id", None) is not None:
            tenant_id = int(ctx.tenant_id)
            user_id = ctx.user_id
            request_id = ctx.request_id
        else:
            tenant_header = request.headers.get("X-Tenant-Id")
            tenant_id = int(tenant_header) if tenant_header and tenant_header.isdigit() else int(get_default_tenant_id())
            user_id = None
            request_id = request.headers.get("X-Request-Id")

        try:
            limits = get_tenant_limits(tenant_id)
        except Exception:
            return await call_next(request)

        if limits.get("enabled", True):
            rpm_limit = int(limits["rpm_limit"])
            if not _allow_rpm(tenant_id=tenant_id, rpm_limit=rpm_limit):
                increment_tenant_usage_daily(tenant_id=tenant_id, blocked=True, risk_delta=0, day=_current_utc_day())
                try:
                    write_audit_log(
                        tenant_id=tenant_id,
                        user_id=user_id,
                        action="ratelimit.blocked",
                        target_type="request",
                        target_id=request_id,
                        metadata={"rpm_limit": rpm_limit, "path": str(request.url.path)},
                        ip=request.client.host if request.client else None,
                        user_agent=request.headers.get("User-Agent"),
                        request_id=request_id,
                    )
                except Exception:
                    pass
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded",
                        "reason": "rpm_limit",
                        "tenant_id": tenant_id,
                        "rpm_limit": rpm_limit,
                    },
                )

            usage = get_tenant_usage_daily(tenant_id=tenant_id, day=_current_utc_day())
            daily_limit = int(limits["daily_requests_limit"])
            if int(usage.get("request_count", 0)) >= daily_limit:
                increment_tenant_usage_daily(tenant_id=tenant_id, blocked=True, risk_delta=0, day=_current_utc_day())
                try:
                    write_audit_log(
                        tenant_id=tenant_id,
                        user_id=user_id,
                        action="quota.blocked",
                        target_type="request",
                        target_id=request_id,
                        metadata={"daily_requests_limit": daily_limit, "path": str(request.url.path)},
                        ip=request.client.host if request.client else None,
                        user_agent=request.headers.get("User-Agent"),
                        request_id=request_id,
                    )
                except Exception:
                    pass
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Daily quota exceeded",
                        "reason": "daily_requests_limit",
                        "tenant_id": tenant_id,
                        "daily_requests_limit": daily_limit,
                    },
                )

        response = await call_next(request)

        try:
            risk_delta = int(getattr(request.state, "risk_score", 0) or 0)
        except Exception:
            risk_delta = 0
        blocked = response.status_code == 429
        try:
            increment_tenant_usage_daily(
                tenant_id=tenant_id,
                blocked=blocked,
                risk_delta=risk_delta,
                token_delta=0,
                request_delta=1,
                day=_current_utc_day(),
            )
        except Exception:
            pass
        return response
