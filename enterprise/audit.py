from fastapi import Request
from typing import Optional, Dict, Any

from .db_enterprise import write_audit_log


def audit(
    request: Request,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    ctx = getattr(request.state, "ctx", None)
    if not ctx:
        return

    write_audit_log(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        metadata=metadata or {},
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
        request_id=ctx.request_id,
    )
