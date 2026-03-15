import os
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

from enterprise.audit import audit as audit_event
from enterprise.db_enterprise import (
    create_auth_user,
    create_job,
    create_policy_rule,
    create_tenant,
    delete_policy_rule,
    get_job,
    get_tenant_limits,
    get_tenant_provider_config,
    get_tenant_usage_daily,
    get_user_by_external_id,
    list_policy_rules,
    list_audit_logs,
    list_jobs,
    list_memberships,
    list_tenants,
    list_users,
    ensure_user,
    set_user_password,
    update_policy_rule,
    upsert_membership,
    upsert_tenant_limits,
    verify_audit_chain,
)
from enterprise.rbac import require_platform_admin, require_role
from policy_engine import invalidate_policy_cache
from provider_layer import ProviderCallError
from scrubber import scrub_prompt
from tenant_llm import build_tenant_provider

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[require_platform_admin()])


@router.get("/whoami", dependencies=[require_role("auditor")])
async def whoami(request: Request):
    ctx = request.state.ctx
    return {
        "tenant_id": ctx.tenant_id,
        "role": ctx.role,
        "external_user": ctx.external_user,
        "user_id": ctx.user_id,
        "request_id": ctx.request_id,
    }


@router.get("/audit", dependencies=[require_role("auditor")])
async def audit_logs(request: Request, limit: int = 100, offset: int = 0):
    ctx = request.state.ctx
    logs = list_audit_logs(ctx.tenant_id, limit=limit, offset=offset)
    return {"tenant_id": ctx.tenant_id, "count": len(logs), "items": logs}


@router.get("/audit/verify", dependencies=[require_role("auditor")])
async def audit_verify(request: Request, limit: int = 500):
    ctx = request.state.ctx
    result = verify_audit_chain(ctx.tenant_id, limit=limit)
    return result


@router.post("/grant-role", dependencies=[require_role("admin")])
async def grant_role(request: Request, external_user: str, role: str):
    ctx = request.state.ctx
    user_id = ensure_user(external_user)
    if not user_id:
        raise HTTPException(status_code=400, detail="Missing external_user")

    try:
        upsert_membership(ctx.tenant_id, user_id, role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(
        request,
        "policy.updated",
        target_type="membership",
        target_id=str(user_id),
        metadata={"external_user": external_user, "role": role},
    )
    user = get_user_by_external_id(external_user)
    return {"ok": True, "tenant_id": ctx.tenant_id, "user": user, "role": role}


@router.get("/users", dependencies=[require_role("admin")])
async def users_list(limit: int = 200):
    items = list_users(limit=limit)
    return {"count": len(items), "items": items}


@router.post("/users", dependencies=[require_role("admin")])
async def users_create(
    request: Request,
    username: str,
    password: str,
    display_name: Optional[str] = None,
    role: str = "user",
):
    ctx = request.state.ctx
    try:
        item = create_auth_user(username=username, password=password, display_name=display_name)
        upsert_membership(ctx.tenant_id, int(item["id"]), role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(
        request,
        "user.created",
        target_type="user",
        target_id=str(item["id"]),
        metadata={"username": item["username"], "role": role},
    )
    return {"ok": True, "tenant_id": int(ctx.tenant_id), "item": item, "role": role}


@router.post("/users/{user_id}/password", dependencies=[require_role("admin")])
async def users_reset_password(request: Request, user_id: int, new_password: str):
    try:
        item = set_user_password(user_id=int(user_id), new_password=new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(
        request,
        "user.password.reset",
        target_type="user",
        target_id=str(user_id),
        metadata={"username": item.get("username")},
    )
    return {"ok": True, "item": item}


@router.get("/memberships", dependencies=[require_role("auditor")])
async def memberships(request: Request):
    ctx = request.state.ctx
    rows = list_memberships(ctx.tenant_id)
    return {"tenant_id": ctx.tenant_id, "count": len(rows), "items": rows}


@router.get("/tenants", dependencies=[require_role("auditor")])
async def tenants():
    items = list_tenants()
    return {"count": len(items), "items": items}


@router.post("/tenants", dependencies=[require_role("admin")])
async def create_tenant_endpoint(request: Request, name: str):
    tenant_id = create_tenant(name)
    audit_event(
        request,
        "tenant.created",
        target_type="tenant",
        target_id=str(tenant_id),
        metadata={"name": name},
    )
    return {"ok": True, "tenant_id": tenant_id, "name": name}


@router.get("/limits", dependencies=[require_role("auditor")])
async def get_limits(request: Request):
    ctx = request.state.ctx
    return get_tenant_limits(ctx.tenant_id)


@router.get("/usage", dependencies=[require_role("auditor")])
async def get_usage(request: Request, day: Optional[str] = None):
    ctx = request.state.ctx
    limits = get_tenant_limits(ctx.tenant_id)
    usage = get_tenant_usage_daily(ctx.tenant_id, day=day)
    remaining_daily = max(0, int(limits["daily_requests_limit"]) - int(usage.get("request_count", 0)))
    return {
        "tenant_id": int(ctx.tenant_id),
        "day": usage.get("day"),
        "usage": usage,
        "limits": limits,
        "remaining_daily_requests": remaining_daily,
    }


@router.get("/provider", dependencies=[require_role("auditor")])
async def get_provider_config(request: Request):
    ctx = request.state.ctx
    return get_tenant_provider_config(ctx.tenant_id)


@router.post("/provider", dependencies=[require_role("admin")])
async def set_provider_config(
    request: Request,
    provider: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
):
    raise HTTPException(
        status_code=403,
        detail="Provider key updates are restricted to tenant_admin via /tenant/keys",
    )


@router.get("/policies", dependencies=[require_role("auditor")])
async def get_policies(request: Request):
    ctx = request.state.ctx
    items = list_policy_rules(ctx.tenant_id)
    return {"tenant_id": int(ctx.tenant_id), "count": len(items), "items": items}


@router.post("/policies", dependencies=[require_role("admin")])
async def create_policy(
    request: Request,
    rule_type: str,
    match: str,
    action: str,
    enabled: bool = True,
):
    ctx = request.state.ctx
    try:
        item = create_policy_rule(
            tenant_id=ctx.tenant_id,
            rule_type=rule_type,
            match=match,
            action=action,
            enabled=enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    invalidate_policy_cache(ctx.tenant_id)
    audit_event(
        request,
        "policy.rule.created",
        target_type="policy",
        target_id=str(item["id"]),
        metadata={"rule_type": item["rule_type"], "match": item["match"], "action": item["action"]},
    )
    return {"ok": True, "item": item}


@router.post("/policies/{rule_id}", dependencies=[require_role("admin")])
async def patch_policy(
    request: Request,
    rule_id: int,
    rule_type: Optional[str] = None,
    match: Optional[str] = None,
    action: Optional[str] = None,
    enabled: Optional[bool] = None,
):
    ctx = request.state.ctx
    try:
        item = update_policy_rule(
            tenant_id=ctx.tenant_id,
            rule_id=rule_id,
            rule_type=rule_type,
            match=match,
            action=action,
            enabled=enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    invalidate_policy_cache(ctx.tenant_id)
    audit_event(
        request,
        "policy.rule.updated",
        target_type="policy",
        target_id=str(item["id"]),
        metadata={"rule_type": item["rule_type"], "match": item["match"], "action": item["action"], "enabled": item["enabled"]},
    )
    return {"ok": True, "item": item}


@router.delete("/policies/{rule_id}", dependencies=[require_role("admin")])
async def remove_policy(request: Request, rule_id: int):
    ctx = request.state.ctx
    deleted = delete_policy_rule(tenant_id=ctx.tenant_id, rule_id=rule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")
    invalidate_policy_cache(ctx.tenant_id)
    audit_event(
        request,
        "policy.rule.deleted",
        target_type="policy",
        target_id=str(rule_id),
        metadata={},
    )
    return {"ok": True, "deleted": int(rule_id)}


@router.post("/policies/preview", dependencies=[require_role("admin")])
async def preview_policy_redaction(prompt: str):
    scrubbed = scrub_prompt(prompt or "")
    return {
        "ok": True,
        "cleaned_prompt": scrubbed["cleaned_prompt"],
        "detections": scrubbed["detections"],
        "placeholders_count": len(scrubbed["placeholders"]),
    }


@router.get("/llm-smoke", dependencies=[require_role("auditor")])
async def llm_smoke(request: Request, prompt: str = "ping"):
    ctx = request.state.ctx
    smoke_prompt = (prompt or "").strip() or "ping"
    provider_cfg = get_tenant_provider_config(ctx.tenant_id)

    try:
        provider_client = build_tenant_provider(
            ctx.tenant_id,
            default_gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    started = time.perf_counter()
    try:
        result = await provider_client.generate_text(smoke_prompt)
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": True,
            "tenant_id": int(ctx.tenant_id),
            "provider": result.provider,
            "model": result.model,
            "provider_source": provider_cfg["source"],
            "has_api_key": provider_cfg["has_api_key"],
            "api_key_tail": provider_cfg["api_key_tail"],
            "latency_ms": latency_ms,
            "status_code": 200,
            "message": "ok",
            "retry_info": result.retry_info,
        }
    except ProviderCallError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return {
            "ok": False,
            "tenant_id": int(ctx.tenant_id),
            "provider": exc.provider,
            "model": exc.model,
            "provider_source": provider_cfg["source"],
            "has_api_key": provider_cfg["has_api_key"],
            "api_key_tail": provider_cfg["api_key_tail"],
            "latency_ms": latency_ms,
            "status_code": exc.status_code,
            "message": exc.message,
            "retry_info": exc.retry_info,
        }


@router.post("/limits", dependencies=[require_role("admin")])
async def update_limits(
    request: Request,
    daily_requests_limit: Optional[int] = None,
    rpm_limit: Optional[int] = None,
    enabled: Optional[bool] = None,
):
    ctx = request.state.ctx
    try:
        updated = upsert_tenant_limits(
            tenant_id=ctx.tenant_id,
            daily_requests_limit=daily_requests_limit,
            rpm_limit=rpm_limit,
            enabled=enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(
        request,
        "tenant.limits.updated",
        target_type="tenant",
        target_id=str(ctx.tenant_id),
        metadata=updated,
    )
    return updated


@router.post("/exports", dependencies=[require_role("auditor")])
async def queue_export(request: Request):
    ctx = request.state.ctx
    job_id = create_job(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        job_type="export_report",
        input_payload={"tenant_id": ctx.tenant_id},
    )
    audit_event(
        request,
        "report.export.queued",
        target_type="job",
        target_id=job_id,
        metadata={"tenant_id": ctx.tenant_id},
    )
    return {"ok": True, "tenant_id": ctx.tenant_id, "job_id": job_id, "status": "queued"}


@router.post("/exports/compliance", dependencies=[require_role("auditor")])
async def queue_compliance_export(request: Request):
    ctx = request.state.ctx
    job_id = create_job(
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        job_type="compliance_report",
        input_payload={"tenant_id": ctx.tenant_id},
    )
    audit_event(
        request,
        "compliance.export.queued",
        target_type="job",
        target_id=job_id,
        metadata={"tenant_id": ctx.tenant_id},
    )
    return {"ok": True, "tenant_id": ctx.tenant_id, "job_id": job_id, "status": "queued"}


@router.get("/jobs", dependencies=[require_role("auditor")])
async def get_jobs(request: Request, limit: int = 50):
    ctx = request.state.ctx
    items = list_jobs(ctx.tenant_id, limit=limit)
    return {"tenant_id": int(ctx.tenant_id), "count": len(items), "items": items}


@router.get("/jobs/{job_id}", dependencies=[require_role("auditor")])
async def get_job_status(request: Request, job_id: str):
    ctx = request.state.ctx
    job = get_job(job_id)
    if not job or int(job["tenant_id"]) != int(ctx.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    return {"ok": True, "item": job}


@router.get("/exports/{job_id}/download", dependencies=[require_role("auditor")])
async def download_export(request: Request, job_id: str):
    ctx = request.state.ctx
    job = get_job(job_id)
    if not job or int(job["tenant_id"]) != int(ctx.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("type") not in {"export_report", "compliance_report"}:
        raise HTTPException(status_code=400, detail="Unsupported job type")
    if job.get("status") != "done":
        raise HTTPException(status_code=409, detail=f"Job not done (status={job.get('status')})")

    output_path = job.get("output_path")
    if not output_path or not os.path.exists(output_path):
        raise HTTPException(status_code=404, detail="Output file not found")
    media_type = "application/octet-stream"
    filename = os.path.basename(output_path)
    if str(output_path).lower().endswith(".pdf"):
        media_type = "application/pdf"
    elif str(output_path).lower().endswith(".zip"):
        media_type = "application/zip"
    elif str(output_path).lower().endswith(".csv"):
        media_type = "text/csv"
    elif str(output_path).lower().endswith(".json"):
        media_type = "application/json"
    return FileResponse(
        output_path,
        filename=filename,
        media_type=media_type,
    )
