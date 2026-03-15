# main.py
import os
import json
import logging
import math
import uuid
from datetime import datetime
from typing import Optional, Any, Dict, List, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv
load_dotenv(override=False)
# Load .env BEFORE importing modules that read env vars at import time.

from app_config import cors_allowed_origins, is_prod
from auth_rate_limit import client_ip_from_request, enforce_rate_limit_or_429
from scrubber import scrub_prompt, rehydrate
from risk import count_entities, compute_risk_score
from db import (
    get_compliance_snapshot,
    get_entity_totals,
    get_recent_requests,
    get_risk_trend,
    get_summary,
    init_db,
    insert_request,
)
from auth_mode import auth_mode, extract_bearer_token, make_access_token, parse_access_token
from file_extraction import FileValidationError, TextExtractionError
from file_scan_service import (
    UploadRequestError,
    read_upload_from_request,
    scan_text_with_policy,
    validate_and_extract_text,
)
from enterprise.db_enterprise import (
    bootstrap_first_run,
    delete_tenant_key,
    get_tenant_limits,
    get_tenant_provider_config,
    get_tenant_tavily_key,
    get_tenant_usage_daily,
    list_tenant_keys,
    get_user_by_external_id,
    has_any_admin_membership,
    get_tenant_policy_settings,
    set_user_password,
    upsert_tenant_policy_settings,
    upsert_tenant_provider_config,
    upsert_tenant_key,
    write_audit_log as enterprise_write_audit_log,
    get_default_tenant_id,
    ensure_user,
)
from enterprise.context import EnterpriseContextMiddleware, RequestContext
from enterprise.limits import (
    TenantLimitsMiddleware,
    check_tenant_chat_limits,
    estimate_prompt_tokens,
    record_tenant_chat_usage,
)
from enterprise.jobs import start_job_worker
from enterprise.db_enterprise import ensure_enterprise_schema as enterprise_ensure_schema
from product_auth import (
    LoginError,
    PRODUCT_ADMIN_ROLE,
    authenticate_login,
    create_company_signup,
    create_individual_signup,
    create_invite,
    ensure_product_auth_schema,
    get_membership_role,
    list_tenant_members,
    get_user_profile,
    has_membership,
    is_personal_tenant,
    revoke_token_jti,
    signup_with_invite,
)
from routes.admin import router as admin_router
from gemini_client import build_gemini_client_from_env
from injection_detector import detect_prompt_injection
from metrics_store import METRICS
from provider_layer import (
    ProviderCallError,
    ProviderCallResult,
    OpenAIProvider,
    AnthropicProvider,
    GeminiProvider,
)
from security_utils import redact_secrets, validate_runtime_security
from tenant_policy import evaluate_tenant_policy
from tenant_llm import build_tenant_provider, provider_health_snapshot
from tools.tool_router import execute_tool_call
from tools.web_search import WebSearchError, WEB_SEARCH_TOOL

app = FastAPI(title="Shadow AI Gateway (MVP + Risk + DB)")

# Enterprise middleware (non-breaking defaults)
app.add_middleware(TenantLimitsMiddleware)
app.add_middleware(EnterpriseContextMiddleware)


def _dev_safe_cors_origins() -> List[str]:
    origins = list(cors_allowed_origins())
    is_loopback_only = all(
        ("localhost" in str(origin).lower()) or ("127.0.0.1" in str(origin))
        for origin in origins
    ) if origins else False

    if (not is_prod()) or is_loopback_only:
        for origin in ("http://localhost:3000", "http://127.0.0.1:3000"):
            if origin not in origins:
                origins.append(origin)
    return origins


# Keep CORS as the outermost middleware so preflight OPTIONS is handled before auth/rate-limit middleware.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://shadow-gateway-frontend.pages.dev", "https://app.shadowaigateway.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "X-Tenant-Id", "X-User", "X-Request-Id"],
)
app.include_router(admin_router)

# -------------------------
# Config
# -------------------------
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
GEMINI_CLIENT = build_gemini_client_from_env()
LOG_DIR = os.getenv("LOG_DIR", "logs").strip()
AUTH_LOG = logging.getLogger("shadow.auth")
CHAT_LOG = logging.getLogger("shadow.chat")
AUTH_LOGIN_RATE_LIMIT = int(os.getenv("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", "5"))
AUTH_SIGNUP_RATE_LIMIT = int(os.getenv("AUTH_SIGNUP_RATE_LIMIT_PER_MINUTE", "3"))
FILE_SCAN_MAX_BYTES = max(1024, int(os.getenv("FILE_SCAN_MAX_BYTES", str(5 * 1024 * 1024))))
FILE_SCAN_MAX_FORM_BYTES = max(FILE_SCAN_MAX_BYTES + 1024, int(os.getenv("FILE_SCAN_MAX_FORM_BYTES", str(FILE_SCAN_MAX_BYTES + 256 * 1024))))
PLACEHOLDER_TOKEN_GUARD_INSTRUCTION = "Do not modify placeholder tokens like [PERSON_1], [EMAIL_1], etc."
CHAT_LOG_PREVIEW_LIMIT = 4000


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.getenv(name, "") or "").strip().lower()
    if not raw:
        return bool(default)
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return bool(default)


RESTORE_REDACTED_VALUES = _env_bool("RESTORE_REDACTED_VALUES", _env_bool("restore_redacted_values", True))


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


def _log_auth_event(request: Request, event: str, **fields: Any) -> None:
    payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "event": event,
        "ip": client_ip_from_request(request),
        **fields,
    }
    AUTH_LOG.info(json.dumps(redact_secrets(payload), ensure_ascii=True, sort_keys=True))


def _preview_for_log(value: Any, limit: int = CHAT_LOG_PREVIEW_LIMIT) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value if len(value) <= limit else f"{value[:limit]}...<truncated>"
    try:
        text = json.dumps(value, ensure_ascii=True, default=str, sort_keys=True)
    except Exception:
        text = str(value)
    return text if len(text) <= limit else f"{text[:limit]}...<truncated>"


def _log_chat_event(event: str, **fields: Any) -> None:
    payload = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "event": event,
        **fields,
    }
    CHAT_LOG.info(json.dumps(redact_secrets(payload), ensure_ascii=True, default=str, sort_keys=True))


def _limit_login_attempts(request: Request) -> None:
    enforce_rate_limit_or_429(
        request,
        bucket="auth.login",
        limit=AUTH_LOGIN_RATE_LIMIT,
        window_seconds=60,
        error_message="Too many login attempts from this IP. Try again in one minute.",
    )


def _limit_signup_attempts(request: Request) -> None:
    enforce_rate_limit_or_429(
        request,
        bucket="auth.signup",
        limit=AUTH_SIGNUP_RATE_LIMIT,
        window_seconds=60,
        error_message="Too many signup attempts from this IP. Try again in one minute.",
    )


class ChatIn(BaseModel):
    prompt: str
    purpose: Optional[str] = None
    rehydrate_response: bool = False  # legacy flag (server restoration is config-driven)


class ChatOut(BaseModel):
    request_id: str
    provider: str
    model: str
    cleaned_prompt: str
    detections: List[Dict[str, Any]]
    entity_counts: Dict[str, int]
    risk_categories: Dict[str, int]
    risk_score: float
    risk_level: str
    redactions_applied: int
    severity: str
    decision: str
    decision_reasons: List[str]
    show_sanitized_prompt_admin: bool = True
    assistant_response: str
    redaction_metadata: Dict[str, Any]
    ai_response_clean: str
    ai_response_rehydrated: Optional[str] = None
    message: str
    sources: List[Dict[str, Any]] = Field(default_factory=list)


class OnboardingBootstrapIn(BaseModel):
    tenant_name: str
    admin_external_user: str
    admin_password: Optional[str] = None
    provider: str = "gemini"
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None


class TenantMembershipOut(BaseModel):
    tenant_id: int
    tenant_name: str
    role: str
    is_personal: bool = False


class AuthOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: int
    role: str
    memberships: List[TenantMembershipOut]


class SignupCompanyIn(BaseModel):
    company_name: str
    admin_email: str
    password: str


class SignupIndividualIn(BaseModel):
    name_or_label: Optional[str] = None
    email: str
    password: str


class SignupInviteIn(BaseModel):
    token: str
    email: str
    password: str


class LoginIn(BaseModel):
    email: Optional[str] = None
    username: Optional[str] = None
    password: str
    tenant_id: Optional[int] = None


class InviteEmployeeIn(BaseModel):
    email: Optional[str] = None
    role: str = "employee"
    expires_hours: int = 72
    max_uses: Optional[int] = None


class TenantKeyIn(BaseModel):
    provider: str
    api_key: str
    model: Optional[str] = None
    base_url: Optional[str] = None


class MeOut(BaseModel):
    user_id: int
    email: str
    tenant_id: int
    role: str
    is_personal: bool = False
    memberships: List[TenantMembershipOut]


class TenantPolicyOut(BaseModel):
    tenant_id: int
    pii_action: str
    financial_action: str
    secrets_action: str
    health_action: str
    ip_action: str
    block_threshold: str
    store_original_prompt: bool
    show_sanitized_prompt_admin: bool
    created_at: str
    updated_at: str


class TenantPolicyIn(BaseModel):
    pii_action: Optional[str] = None
    financial_action: Optional[str] = None
    secrets_action: Optional[str] = None
    health_action: Optional[str] = None
    ip_action: Optional[str] = None
    block_threshold: Optional[str] = None
    store_original_prompt: Optional[bool] = None
    show_sanitized_prompt_admin: Optional[bool] = None


class TenantUsageSummaryOut(BaseModel):
    tenant_id: int
    daily_requests_limit: int
    rpm_limit: int
    today_request_count: int
    today_token_count: int
    daily_requests_remaining: int
    daily_percent_used: float


class FileScanOut(BaseModel):
    request_id: str
    filename: str
    content_type: str
    file_type: str
    size_bytes: int
    extracted_text: str
    redacted_text: str
    entities: List[Dict[str, Any]]
    entity_counts: Dict[str, int]
    risk_categories: Dict[str, int]
    findings_count: int
    risk_score: float
    risk_level: str
    severity: str
    decision: str
    blocked: bool
    allowed: bool
    decision_reasons: List[str]
    injection_detected: bool = False


class TenantActivityItemOut(BaseModel):
    id: str
    ts: str
    user: str
    purpose: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    decision: str
    risk_level: Optional[str] = None
    severity: Optional[str] = None
    risk_score: float = 0.0
    detections_count: int = 0
    injection_detected: bool = False
    entity_counts: Dict[str, int]
    risk_categories: Dict[str, int]


class TenantActivityOut(BaseModel):
    tenant_id: int
    count: int
    items: List[TenantActivityItemOut]


class TenantAnalyticsOut(BaseModel):
    tenant_id: int
    summary: Dict[str, Any]
    usage: Dict[str, Any]
    risk_trend: List[Dict[str, Any]]
    entity_totals: Dict[str, int]
    compliance: Dict[str, Any]


def write_file_audit(event: Dict[str, Any]) -> None:
    """Local JSONL audit (non-enterprise). Enterprise audit goes to enterprise_write_audit_log."""
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, "audit.jsonl")
    with open(path, "a", encoding="utf-8") as f:
        safe_event = redact_secrets(event)
        f.write(json.dumps(safe_event, ensure_ascii=False) + "\n")


def _retry_after_seconds(retry_info: Any) -> Optional[int]:
    if not isinstance(retry_info, dict):
        return None
    raw = retry_info.get("retry_after_seconds")
    try:
        seconds = float(raw)
    except Exception:
        return None
    if seconds <= 0:
        return None
    return max(1, int(math.ceil(seconds)))


def _parse_counts_json(raw: Any) -> Dict[str, int]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        out: Dict[str, int] = {}
        for key, value in raw.items():
            try:
                out[str(key)] = int(value or 0)
            except Exception:
                out[str(key)] = 0
        return out
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except Exception:
            return {}
        if not isinstance(parsed, dict):
            return {}
        out = {}
        for key, value in parsed.items():
            try:
                out[str(key)] = int(value or 0)
            except Exception:
                out[str(key)] = 0
        return out
    return {}


def _token_subject(user: Dict[str, Any]) -> str:
    return str(user.get("email") or user.get("username") or user.get("external_id") or user.get("id"))


def _build_auth_response(user: Dict[str, Any], tenant_id: int, role: str, memberships: List[Dict[str, Any]]) -> AuthOut:
    try:
        token = make_access_token(
            user_id=int(user["id"]),
            username=_token_subject(user),
            tenant_id=int(tenant_id),
            role=str(role),
        )
    except ValueError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return AuthOut(
        access_token=token,
        tenant_id=int(tenant_id),
        role=str(role),
        memberships=[
            TenantMembershipOut(
                tenant_id=int(m["tenant_id"]),
                tenant_name=str(m.get("tenant_name") or f"Tenant {int(m['tenant_id'])}"),
                role=str(m.get("role") or "employee"),
                is_personal=bool(int(m.get("is_personal") or 0)),
            )
            for m in memberships
        ],
    )


def require_tenant_member(request: Request) -> RequestContext:
    ctx = getattr(request.state, "ctx", None)
    if not ctx or not getattr(ctx, "user_id", None):
        raise HTTPException(status_code=401, detail="Authentication required")
    if not has_membership(user_id=int(ctx.user_id), tenant_id=int(ctx.tenant_id)):
        raise HTTPException(status_code=403, detail="Tenant membership required")
    request.state.user = {
        "id": int(ctx.user_id),
        "external_user": str(ctx.external_user or ""),
        "role": str(ctx.role),
    }
    request.state.tenant = {"id": int(ctx.tenant_id)}
    return ctx


def require_tenant_admin(ctx: RequestContext = Depends(require_tenant_member)) -> RequestContext:
    role = str(ctx.role or "")
    if role != PRODUCT_ADMIN_ROLE:
        raise HTTPException(status_code=403, detail="Tenant admin access required")
    return ctx


def require_company_tenant_admin(ctx: RequestContext = Depends(require_tenant_admin)) -> RequestContext:
    if is_personal_tenant(int(ctx.tenant_id)):
        raise HTTPException(status_code=403, detail="Forbidden for personal tenants")
    return ctx


def _tenant_usage_summary(tenant_id: int) -> Dict[str, Any]:
    limits = get_tenant_limits(int(tenant_id))
    usage = get_tenant_usage_daily(int(tenant_id))

    daily_requests_limit = max(1, int(limits.get("daily_requests_limit") or 1))
    rpm_limit = max(1, int(limits.get("rpm_limit") or 1))
    today_request_count = max(0, int(usage.get("request_count") or 0))
    today_token_count = max(0, int(usage.get("token_count") or 0))
    daily_requests_remaining = max(0, daily_requests_limit - today_request_count)
    daily_percent_used = min(100.0, round((today_request_count / float(daily_requests_limit)) * 100.0, 2))

    return {
        "tenant_id": int(tenant_id),
        "daily_requests_limit": daily_requests_limit,
        "rpm_limit": rpm_limit,
        "today_request_count": today_request_count,
        "today_token_count": today_token_count,
        "daily_requests_remaining": daily_requests_remaining,
        "daily_percent_used": daily_percent_used,
    }


async def call_model(clean_prompt: str, tenant_id: int) -> ProviderCallResult:
    try:
        provider_client = build_tenant_provider(
            tenant_id=tenant_id,
            default_gemini_client=GEMINI_CLIENT,
            default_gemini_api_key=GEMINI_API_KEY,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await provider_client.generate_text(clean_prompt)


async def call_model_with_tools(clean_prompt: str, tenant_id: int) -> Tuple[ProviderCallResult, List[Dict[str, Any]]]:
    tavily_key = get_tenant_tavily_key(int(tenant_id)).get("api_key")
    try:
        provider_client = build_tenant_provider(
            tenant_id=tenant_id,
            default_gemini_client=GEMINI_CLIENT,
            default_gemini_api_key=GEMINI_API_KEY,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    tools = [WEB_SEARCH_TOOL]

    if isinstance(provider_client, GeminiProvider):
        try:
            _log_chat_event(
                "chat.tool.called",
                provider=provider_client.provider_name,
                tool="google_search",
                arguments=None,
            )
            result = await provider_client.generate_text(clean_prompt, google_search=True)
        except ProviderCallError:
            raise
        return result, []

    if isinstance(provider_client, OpenAIProvider):
        return await _execute_openai_tool_flow(provider_client, clean_prompt, tools, tavily_key)

    if isinstance(provider_client, AnthropicProvider):
        return await _execute_anthropic_tool_flow(provider_client, clean_prompt, tools, tavily_key)

    result = await provider_client.generate_text(clean_prompt)
    return result, []


def _collect_sources(result: Any) -> List[Dict[str, Any]]:
    if not isinstance(result, list):
        return []
    sources: List[Dict[str, Any]] = []
    for item in result:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        sources.append(
            {
                "title": str(item.get("title") or "").strip() or url,
                "url": url,
                "content": str(item.get("content") or "").strip(),
            }
        )
    return sources


async def _execute_openai_tool_flow(
    provider_client: OpenAIProvider,
    prompt: str,
    tools: List[Dict[str, Any]],
    tavily_api_key: Optional[str],
) -> Tuple[ProviderCallResult, List[Dict[str, Any]]]:
    messages: List[Dict[str, Any]] = [{"role": "user", "content": prompt}]
    sources: List[Dict[str, Any]] = []

    try:
        initial = await provider_client._client.chat_with_tools(messages, tools)
    except OpenAIClientError as exc:
        raise ProviderCallError(
            provider=provider_client.provider_name,
            model=provider_client.model,
            status_code=exc.status_code,
            message=exc.message,
            retry_info=exc.retry_info,
            raw_error_json=exc.raw_error_json,
        )

    total_latency = int(initial.latency_ms)
    retry_info = dict(initial.retry_info)
    text = initial.text or ""

    if initial.tool_calls:
        assistant_msg = {
            "role": "assistant",
            "content": text or "",
            "tool_calls": initial.tool_calls,
        }
        messages.append(assistant_msg)

        tool_messages: List[Dict[str, Any]] = []
        for tc in initial.tool_calls:
            func = tc.get("function") if isinstance(tc, dict) else None
            name = str(func.get("name") or "") if isinstance(func, dict) else ""
            raw_args = func.get("arguments") if isinstance(func, dict) else "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else {}
            except Exception:
                args = {}
            _log_chat_event(
                "chat.tool.called",
                provider=provider_client.provider_name,
                tool=name,
                arguments=_preview_for_log(args),
            )
            try:
                result = await execute_tool_call(name, args, tavily_api_key=tavily_api_key)
            except WebSearchError as exc:
                raise HTTPException(status_code=502, detail={"message": str(exc)})
            sources.extend(_collect_sources(result))
            tool_messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id") if isinstance(tc, dict) else "",
                    "content": json.dumps({"results": result}, ensure_ascii=True),
                }
            )

        messages.extend(tool_messages)

        try:
            final = await provider_client._client.chat_with_tools(messages, tools)
        except OpenAIClientError as exc:
            raise ProviderCallError(
                provider=provider_client.provider_name,
                model=provider_client.model,
                status_code=exc.status_code,
                message=exc.message,
                retry_info=exc.retry_info,
                raw_error_json=exc.raw_error_json,
            )
        total_latency += int(final.latency_ms)
        retry_info = dict(final.retry_info)
        text = final.text or text

    result = ProviderCallResult(
        text=text,
        provider=provider_client.provider_name,
        model=provider_client.model,
        latency_ms=total_latency,
        retry_info=retry_info,
    )
    return result, sources


async def _execute_anthropic_tool_flow(
    provider_client: AnthropicProvider,
    prompt: str,
    tools: List[Dict[str, Any]],
    tavily_api_key: Optional[str],
) -> Tuple[ProviderCallResult, List[Dict[str, Any]]]:
    messages: List[Dict[str, Any]] = [{"role": "user", "content": [{"type": "text", "text": prompt}]}]
    sources: List[Dict[str, Any]] = []

    try:
        initial = await provider_client._client.chat_with_tools(messages, tools)
    except AnthropicClientError as exc:
        raise ProviderCallError(
            provider=provider_client.provider_name,
            model=provider_client.model,
            status_code=exc.status_code,
            message=exc.message,
            retry_info=exc.retry_info,
            raw_error_json=exc.raw_error_json,
        )

    total_latency = int(initial.latency_ms)
    retry_info = dict(initial.retry_info)
    text = initial.text or ""

    if initial.tool_calls:
        assistant_content: List[Dict[str, Any]] = []
        if initial.text:
            assistant_content.append({"type": "text", "text": initial.text})
        for tc in initial.tool_calls:
            if isinstance(tc, dict):
                assistant_content.append(tc)
        messages.append({"role": "assistant", "content": assistant_content})

        for tc in initial.tool_calls:
            if not isinstance(tc, dict):
                continue
            name = str(tc.get("name") or "")
            args = tc.get("input") if isinstance(tc.get("input"), dict) else {}
            _log_chat_event(
                "chat.tool.called",
                provider=provider_client.provider_name,
                tool=name,
                arguments=_preview_for_log(args),
            )
            try:
                result = await execute_tool_call(name, args, tavily_api_key=tavily_api_key)
            except WebSearchError as exc:
                raise HTTPException(status_code=502, detail={"message": str(exc)})
            sources.extend(_collect_sources(result))
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": tc.get("id"),
                            "content": json.dumps({"results": result}, ensure_ascii=True),
                        }
                    ],
                }
            )

        try:
            final = await provider_client._client.chat_with_tools(messages, tools)
        except AnthropicClientError as exc:
            raise ProviderCallError(
                provider=provider_client.provider_name,
                model=provider_client.model,
                status_code=exc.status_code,
                message=exc.message,
                retry_info=exc.retry_info,
                raw_error_json=exc.raw_error_json,
            )
        total_latency += int(final.latency_ms)
        retry_info = dict(final.retry_info)
        text = final.text or text

    result = ProviderCallResult(
        text=text,
        provider=provider_client.provider_name,
        model=provider_client.model,
        latency_ms=total_latency,
        retry_info=retry_info,
    )
    return result, sources


def _with_placeholder_guard_instruction(cleaned_prompt: str) -> str:
    prompt = str(cleaned_prompt or "").strip()
    if not prompt:
        return PLACEHOLDER_TOKEN_GUARD_INSTRUCTION
    return f"{PLACEHOLDER_TOKEN_GUARD_INSTRUCTION}\n\n{prompt}"


@app.on_event("startup")
def _startup():
    validate_runtime_security()

    # Ensure DB exists as soon as server starts
    init_db()

    # Ensure enterprise tables (additive only)
    try:
        enterprise_ensure_schema()
    except Exception:
        # don't crash startup if enterprise schema creation fails
        pass
    try:
        ensure_product_auth_schema()
    except Exception:
        pass

    # Start background worker (if your jobs module checks env flags, great; otherwise this is "best effort")
    try:
        start_job_worker()
    except Exception:
        pass


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = str(getattr(request.state, "request_id", "") or uuid.uuid4())
    _log_chat_event(
        "request.unhandled_exception",
        request_id=request_id,
        path=str(request.url.path),
        method=str(request.method),
        prompt_text=_preview_for_log(getattr(request.state, "chat_prompt_text", None)),
        provider_prompt=_preview_for_log(getattr(request.state, "chat_provider_prompt", None)),
        exception_type=type(exc).__name__,
        exception_message=str(exc),
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": {
                "message": "Internal server error",
                "request_id": request_id,
            }
        },
    )


@app.post("/chat", response_model=ChatOut)
async def chat(
    request: Request,
    payload: ChatIn,
    x_user: Optional[str] = Header(default=None),
    ctx: RequestContext = Depends(require_tenant_member),
):
    if not payload.prompt or not payload.prompt.strip():
        raise HTTPException(status_code=400, detail="prompt is required")

    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    request.state.chat_prompt_text = payload.prompt
    user = str(ctx.external_user or x_user or "unknown")
    tenant_id = int(ctx.tenant_id)
    prompt_tokens = estimate_prompt_tokens(payload.prompt)
    _log_chat_event(
        "chat.request.received",
        request_id=request_id,
        tenant_id=tenant_id,
        user=user,
        purpose=payload.purpose,
        prompt_text=_preview_for_log(payload.prompt),
    )

    limit_hit = check_tenant_chat_limits(tenant_id=tenant_id)
    if limit_hit:
        record_tenant_chat_usage(tenant_id=tenant_id, blocked=True, token_delta=0, risk_delta=0, request_delta=1)
        raise HTTPException(status_code=429, detail=limit_hit)

    provider_status = provider_health_snapshot(tenant_id)
    provider_name = str(provider_status["provider"])
    model_name = str(provider_status["model"])

    scrubbed = scrub_prompt(payload.prompt)
    cleaned_prompt = scrubbed["cleaned_prompt"]
    token_map = scrubbed["placeholders"]
    detections = scrubbed["detections"]

    injection = detect_prompt_injection(payload.prompt)
    entity_counts = count_entities(detections)
    risk_pack = compute_risk_score(entity_counts, injection_detected=injection.detected)
    tenant_policy = get_tenant_policy_settings(tenant_id)
    policy_eval = evaluate_tenant_policy(
        tenant_policy=tenant_policy,
        risk_level=str(risk_pack.get("risk_level", "LOW")),
        risk_score=float(risk_pack.get("risk_score", 0.0)),
        entity_counts=entity_counts,
        category_counts=risk_pack.get("risk_categories") or {},
        cleaned_prompt=cleaned_prompt,
        redactions_applied=len(token_map),
        injection_detected=bool(injection.detected),
    )
    decision = str(policy_eval["decision"]).upper()
    decision_reasons = [str(x) for x in policy_eval.get("reasons", [])]
    cleaned_prompt_to_send = str(policy_eval.get("cleaned_prompt") or cleaned_prompt)
    provider_prompt = _with_placeholder_guard_instruction(cleaned_prompt_to_send)
    request.state.chat_provider_prompt = provider_prompt
    show_sanitized_prompt_admin = bool(tenant_policy.get("show_sanitized_prompt_admin", True))
    store_original_prompt = bool(tenant_policy.get("store_original_prompt", True))
    prompt_original_preview = (payload.prompt or "")[:200] if store_original_prompt else ""
    prompt_sent_to_ai_preview = cleaned_prompt_to_send[:200]
    request.state.risk_score = int(risk_pack.get("risk_score", 0))
    _log_chat_event(
        "chat.provider.request.prepared",
        request_id=request_id,
        tenant_id=tenant_id,
        provider=provider_name,
        model=model_name,
        decision=decision,
        cleaned_prompt=_preview_for_log(cleaned_prompt_to_send),
        provider_prompt=_preview_for_log(provider_prompt),
    )

    if injection.detected:
        try:
            enterprise_write_audit_log(
                tenant_id=tenant_id,
                user_id=ensure_user(user) if user else None,
                action="prompt.injection.detected",
                target_type="request",
                target_id=request_id,
                metadata={
                    "category": injection.category,
                    "severity": injection.severity,
                    "matches": injection.matches,
                },
            )
        except Exception:
            pass

    if decision == "BLOCK":
        _log_chat_event(
            "chat.request.blocked",
            request_id=request_id,
            tenant_id=tenant_id,
            provider=provider_name,
            model=model_name,
            decision=decision,
            risk_level=str(risk_pack.get("risk_level", "LOW")),
            risk_score=float(risk_pack.get("risk_score", 0.0)),
            reasons=decision_reasons,
        )
        write_file_audit(
            {
                "ts": datetime.utcnow().isoformat() + "Z",
                "request_id": request_id,
                "tenant_id": tenant_id,
                "user": user,
                "purpose": payload.purpose,
                "model": model_name,
                "provider": provider_name,
                "decision": "BLOCK",
                "risk_score": risk_pack["risk_score"],
                "risk_level": risk_pack["risk_level"],
                "severity": risk_pack.get("severity"),
                "risk_categories": risk_pack.get("risk_categories"),
                "injection_detected": bool(injection.detected),
                "entity_counts": entity_counts,
                "prompt_original_preview": prompt_original_preview,
                "prompt_sent_to_ai_preview": prompt_sent_to_ai_preview,
                "cleaned_prompt_preview": prompt_sent_to_ai_preview,
                "reasons": decision_reasons,
            }
        )
        insert_request(
            {
                "id": request_id,
                "ts": datetime.utcnow().isoformat() + "Z",
                "user": user,
                "purpose": payload.purpose,
                "model": model_name,
                "provider": provider_name,
                "prompt_original_preview": prompt_original_preview,
                "prompt_sent_to_ai_preview": prompt_sent_to_ai_preview,
                "cleaned_prompt_preview": prompt_sent_to_ai_preview,
                "detections_count": len(detections),
                "entity_counts_json": json.dumps(entity_counts),
                "risk_categories_json": json.dumps(risk_pack.get("risk_categories") or {}),
                "risk_score": risk_pack["risk_score"],
                "risk_level": risk_pack["risk_level"],
                "severity": risk_pack.get("severity"),
                "decision": "BLOCK",
                "injection_detected": int(bool(injection.detected)),
            },
            tenant_id=tenant_id,
        )

        try:
            enterprise_write_audit_log(
                tenant_id=tenant_id,
                user_id=ensure_user(user) if user else None,
                action="entity.blocked",
                target_type="request",
                target_id=request_id,
                metadata={"reason": decision_reasons, "risk_score": risk_pack["risk_score"]},
            )
        except Exception:
            pass

        METRICS.inc_request(tenant_id=tenant_id, action="BLOCK", provider=provider_name)
        if injection.detected:
            METRICS.inc_redaction("PROMPT_INJECTION")
        for category, count in (risk_pack.get("risk_categories") or {}).items():
            if int(count) > 0:
                METRICS.inc_redaction(category, delta=int(count))

        record_tenant_chat_usage(
            tenant_id=tenant_id,
            blocked=True,
            token_delta=prompt_tokens,
            risk_delta=int(risk_pack.get("risk_score", 0) or 0),
            request_delta=1,
        )

        raise HTTPException(
            status_code=403,
            detail={
                "request_id": request_id,
                "provider": provider_name,
                "model": model_name,
                "decision": "BLOCK",
                "cleaned_prompt": cleaned_prompt_to_send,
                "message": "Request blocked by tenant policy.",
                "risk_score": risk_pack["risk_score"],
                "risk_level": risk_pack["risk_level"],
                "redactions_applied": len(token_map),
                "risk_categories": risk_pack.get("risk_categories") or {},
                "entity_counts": entity_counts,
                "reasons": decision_reasons,
                "show_sanitized_prompt_admin": show_sanitized_prompt_admin,
            },
        )

    tool_sources: List[Dict[str, Any]] = []
    try:
        provider_result, tool_sources = await call_model_with_tools(provider_prompt, tenant_id=tenant_id)
    except ProviderCallError as exc:
        METRICS.inc_upstream_error(provider=exc.provider, status=exc.status_code)
        METRICS.inc_request(tenant_id=tenant_id, action=decision, provider=exc.provider)
        detail = exc.to_dict()
        detail["request_id"] = request_id
        detail["decision"] = decision
        detail["risk_level"] = str(risk_pack.get("risk_level", "LOW"))
        detail["risk_score"] = float(risk_pack.get("risk_score", 0.0))
        detail["redactions_applied"] = len(token_map)
        detail["entity_counts"] = entity_counts
        detail["risk_categories"] = risk_pack.get("risk_categories") or {}
        detail["cleaned_prompt"] = cleaned_prompt_to_send
        detail["show_sanitized_prompt_admin"] = show_sanitized_prompt_admin
        retry_after_seconds = _retry_after_seconds(detail.get("retry_info"))
        if retry_after_seconds is not None:
            detail["retry_after_seconds"] = retry_after_seconds
        if isinstance(exc.raw_error_json, dict) and "error" in exc.raw_error_json:
            detail["error"] = exc.raw_error_json["error"]
        _log_chat_event(
            "chat.provider.error",
            request_id=request_id,
            tenant_id=tenant_id,
            provider=exc.provider,
            model=exc.model,
            status_code=int(exc.status_code),
            detail=_preview_for_log(detail),
        )

        write_file_audit(
            {
                "ts": datetime.utcnow().isoformat() + "Z",
                "request_id": request_id,
                "tenant_id": tenant_id,
                "user": user,
                "purpose": payload.purpose,
                "provider": exc.provider,
                "model": exc.model,
                "decision": decision,
                "prompt_original_preview": prompt_original_preview,
                "prompt_sent_to_ai_preview": prompt_sent_to_ai_preview,
                "upstream_error": detail,
            }
        )
        try:
            enterprise_write_audit_log(
                tenant_id=tenant_id,
                user_id=ensure_user(user) if user else None,
                action="provider.error",
                target_type="request",
                target_id=request_id,
                metadata=detail,
            )
        except Exception:
            pass

        http_status = 503 if exc.provider == "none" and int(exc.status_code) == 503 else 502
        raise HTTPException(status_code=http_status, detail=detail)

    ai_response_clean = provider_result.text
    model_name = provider_result.model
    provider_name = provider_result.provider
    METRICS.observe_latency_ms(provider=provider_name, latency_ms=provider_result.latency_ms)
    _log_chat_event(
        "chat.provider.success",
        request_id=request_id,
        tenant_id=tenant_id,
        provider=provider_name,
        model=model_name,
        latency_ms=int(provider_result.latency_ms),
        response_text=_preview_for_log(ai_response_clean),
    )

    ai_response_rehydrated = None
    assistant_response = ai_response_clean
    if RESTORE_REDACTED_VALUES and token_map:
        ai_response_rehydrated = rehydrate(ai_response_clean, token_map)
        assistant_response = ai_response_rehydrated

    write_file_audit(
        {
            "ts": datetime.utcnow().isoformat() + "Z",
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user": user,
            "purpose": payload.purpose,
            "model": model_name,
            "provider": provider_name,
            "decision": decision,
            "risk_score": risk_pack["risk_score"],
            "risk_level": risk_pack["risk_level"],
            "severity": risk_pack.get("severity"),
            "risk_categories": risk_pack.get("risk_categories"),
            "injection_detected": bool(injection.detected),
            "detections_count": len(detections),
            "entity_counts": entity_counts,
            "prompt_original_preview": prompt_original_preview,
            "prompt_sent_to_ai_preview": prompt_sent_to_ai_preview,
            "cleaned_prompt_preview": prompt_sent_to_ai_preview,
        }
    )

    insert_request(
        {
            "id": request_id,
            "ts": datetime.utcnow().isoformat() + "Z",
            "user": user,
            "purpose": payload.purpose,
            "model": model_name,
            "provider": provider_name,
            "prompt_original_preview": prompt_original_preview,
            "prompt_sent_to_ai_preview": prompt_sent_to_ai_preview,
            "cleaned_prompt_preview": prompt_sent_to_ai_preview,
            "detections_count": len(detections),
            "entity_counts_json": json.dumps(entity_counts),
            "risk_categories_json": json.dumps(risk_pack.get("risk_categories") or {}),
            "risk_score": risk_pack["risk_score"],
            "risk_level": risk_pack["risk_level"],
            "severity": risk_pack.get("severity"),
            "decision": decision,
            "injection_detected": int(bool(injection.detected)),
        },
        tenant_id=tenant_id,
    )

    METRICS.inc_request(tenant_id=tenant_id, action=decision, provider=provider_name)
    if decision in {"REDACT", "BLOCK"}:
        if injection.detected:
            METRICS.inc_redaction("PROMPT_INJECTION")
        for category, count in (risk_pack.get("risk_categories") or {}).items():
            if int(count) > 0:
                METRICS.inc_redaction(category, delta=int(count))

    record_tenant_chat_usage(
        tenant_id=tenant_id,
        blocked=False,
        token_delta=prompt_tokens,
        risk_delta=int(risk_pack.get("risk_score", 0) or 0),
        request_delta=1,
    )

    return ChatOut(
        request_id=request_id,
        provider=provider_name,
        model=model_name,
        cleaned_prompt=cleaned_prompt_to_send,
        detections=detections,
        entity_counts=entity_counts,
        risk_categories=risk_pack.get("risk_categories") or {},
        risk_score=float(risk_pack["risk_score"]),
        risk_level=str(risk_pack["risk_level"]),
        redactions_applied=len(token_map),
        severity=str(risk_pack.get("severity", "Low")),
        decision=decision,
        decision_reasons=decision_reasons,
        show_sanitized_prompt_admin=show_sanitized_prompt_admin,
        assistant_response=assistant_response,
        redaction_metadata={
            "request_id": request_id,
            "decision": decision,
            "risk_score": float(risk_pack["risk_score"]),
            "risk_level": str(risk_pack["risk_level"]),
            "severity": str(risk_pack.get("severity", "Low")),
            "redactions_applied": len(token_map),
            "risk_categories": risk_pack.get("risk_categories") or {},
            "entity_counts": entity_counts,
            "cleaned_prompt": cleaned_prompt_to_send,
            "decision_reasons": decision_reasons,
            "show_sanitized_prompt_admin": show_sanitized_prompt_admin,
            "provider": provider_name,
            "model": model_name,
        },
        ai_response_clean=ai_response_clean,
        ai_response_rehydrated=ai_response_rehydrated,
        message=assistant_response,
        sources=tool_sources,
    )


@app.post("/files/scan", response_model=FileScanOut)
async def files_scan(
    request: Request,
    ctx: RequestContext = Depends(require_tenant_member),
):
    request_id = str(uuid.uuid4())
    tenant_id = int(ctx.tenant_id)
    actor = str(ctx.external_user or "unknown")
    user_id = int(ctx.user_id) if ctx.user_id is not None else None

    try:
        upload, form_fields, file_bytes = await read_upload_from_request(
            request,
            max_file_bytes=FILE_SCAN_MAX_BYTES,
            max_form_bytes=FILE_SCAN_MAX_FORM_BYTES,
        )
    except UploadRequestError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)

    filename = str(upload.filename or "").strip() or "upload.bin"
    content_type = str(upload.content_type or "application/octet-stream")
    scan_purpose = str((form_fields or {}).get("purpose") or "").strip()[:120]

    try:
        file_info, extracted_text = validate_and_extract_text(
            filename=filename,
            content_type=content_type,
            file_bytes=file_bytes,
        )
    except FileValidationError as exc:
        detail = {
            "request_id": request_id,
            "filename": filename,
            "content_type": content_type,
            "message": str(exc),
        }
        try:
            enterprise_write_audit_log(
                tenant_id=tenant_id,
                user_id=user_id,
                action="file.scan.failed",
                target_type="file",
                target_id=request_id,
                metadata={
                    "filename": filename,
                    "content_type": content_type,
                    "error": "validation_failed",
                    "message": str(exc),
                },
            )
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=detail)
    except TextExtractionError as exc:
        detail = {
            "request_id": request_id,
            "filename": filename,
            "content_type": content_type,
            "message": str(exc),
        }
        try:
            enterprise_write_audit_log(
                tenant_id=tenant_id,
                user_id=user_id,
                action="file.scan.failed",
                target_type="file",
                target_id=request_id,
                metadata={
                    "filename": filename,
                    "content_type": content_type,
                    "error": "extraction_failed",
                    "message": str(exc),
                },
            )
        except Exception:
            pass
        raise HTTPException(status_code=422, detail=detail)
    finally:
        try:
            await upload.close()
        except Exception:
            pass

    tenant_policy = get_tenant_policy_settings(tenant_id)
    scan = scan_text_with_policy(text=extracted_text, tenant_policy=tenant_policy)
    request.state.risk_score = int(scan.get("risk_score", 0) or 0)

    metadata = {
        "filename": file_info.filename,
        "file_type": file_info.extension,
        "content_type": file_info.content_type,
        "size_bytes": int(len(file_bytes)),
        "findings_count": int(scan.get("findings_count") or 0),
        "risk_score": float(scan.get("risk_score") or 0.0),
        "risk_level": str(scan.get("risk_level") or "LOW"),
        "decision": str(scan.get("decision") or "ALLOW"),
        "blocked": bool(scan.get("blocked")),
    }
    if scan_purpose:
        metadata["purpose"] = scan_purpose
    try:
        enterprise_write_audit_log(
            tenant_id=tenant_id,
            user_id=user_id,
            action="file.scan.completed",
            target_type="file",
            target_id=request_id,
            metadata=metadata,
            ip=client_ip_from_request(request),
            user_agent=request.headers.get("User-Agent"),
            request_id=request_id,
        )
    except Exception:
        pass

    write_file_audit(
        {
            "ts": datetime.utcnow().isoformat() + "Z",
            "request_id": request_id,
            "tenant_id": tenant_id,
            "user": actor,
            "action": "file.scan.completed",
            **metadata,
        }
    )

    return FileScanOut(
        request_id=request_id,
        filename=file_info.filename,
        content_type=file_info.content_type,
        file_type=file_info.extension,
        size_bytes=int(len(file_bytes)),
        extracted_text=str(scan.get("extracted_text") or ""),
        redacted_text=str(scan.get("redacted_text") or ""),
        entities=[dict(item) for item in (scan.get("entities") or [])],
        entity_counts={str(k): int(v) for k, v in (scan.get("entity_counts") or {}).items()},
        risk_categories={str(k): int(v) for k, v in (scan.get("risk_categories") or {}).items()},
        findings_count=int(scan.get("findings_count") or 0),
        risk_score=float(scan.get("risk_score") or 0.0),
        risk_level=str(scan.get("risk_level") or "LOW"),
        severity=str(scan.get("severity") or "Low"),
        decision=str(scan.get("decision") or "ALLOW"),
        blocked=bool(scan.get("blocked")),
        allowed=bool(scan.get("allowed")),
        decision_reasons=[str(item) for item in (scan.get("decision_reasons") or [])],
        injection_detected=bool(scan.get("injection_detected")),
    )


@app.get("/health")
def health(request: Request):
    if is_prod():
        return {
            "ok": True,
            "auth_mode": auth_mode(),
        }
    ctx = getattr(request.state, "ctx", None)
    tenant_id = int(ctx.tenant_id) if ctx and getattr(ctx, "tenant_id", None) is not None else int(get_default_tenant_id())
    provider = provider_health_snapshot(tenant_id)
    return {
        "ok": True,
        "tenant_id": int(tenant_id),
        "provider": provider["provider"],
        "model": provider["model"],
        "provider_source": provider["source"],
        "has_key": provider["has_key"],
        "api_key_tail": provider["api_key_tail"],
        "auth_mode": auth_mode(),
    }


@app.get("/metrics", response_class=PlainTextResponse)
def metrics():
    return METRICS.render_prometheus()


@app.get("/summary")
def summary(request: Request, ctx: RequestContext = Depends(require_tenant_member)):
    """Quick endpoint to confirm DB logging works"""
    return get_summary(tenant_id=int(ctx.tenant_id))


@app.get("/tenant/activity", response_model=TenantActivityOut)
def tenant_activity(
    limit: int = 100,
    ctx: RequestContext = Depends(require_tenant_member),
):
    safe_limit = max(1, min(int(limit), 500))
    rows = get_recent_requests(tenant_id=int(ctx.tenant_id), limit=safe_limit)
    items: List[TenantActivityItemOut] = []
    for row in rows:
        try:
            risk_score = float(row.get("risk_score") or 0.0)
        except Exception:
            risk_score = 0.0
        items.append(
            TenantActivityItemOut(
                id=str(row.get("id") or ""),
                ts=str(row.get("ts") or ""),
                user=str(row.get("user") or ""),
                purpose=(str(row.get("purpose")) if row.get("purpose") is not None else None),
                provider=(str(row.get("provider")) if row.get("provider") is not None else None),
                model=(str(row.get("model")) if row.get("model") is not None else None),
                decision=str(row.get("decision") or "ALLOW"),
                risk_level=(str(row.get("risk_level")) if row.get("risk_level") is not None else None),
                severity=(str(row.get("severity")) if row.get("severity") is not None else None),
                risk_score=risk_score,
                detections_count=int(row.get("detections_count") or 0),
                injection_detected=bool(int(row.get("injection_detected") or 0)),
                entity_counts=_parse_counts_json(row.get("entity_counts_json")),
                risk_categories=_parse_counts_json(row.get("risk_categories_json")),
            )
        )
    return TenantActivityOut(
        tenant_id=int(ctx.tenant_id),
        count=len(items),
        items=items,
    )


@app.get("/tenant/analytics", response_model=TenantAnalyticsOut)
def tenant_analytics(
    days: int = 14,
    ctx: RequestContext = Depends(require_tenant_member),
):
    tenant_id = int(ctx.tenant_id)
    safe_days = max(1, min(int(days), 90))
    return TenantAnalyticsOut(
        tenant_id=tenant_id,
        summary=get_summary(tenant_id=tenant_id),
        usage=_tenant_usage_summary(tenant_id),
        risk_trend=get_risk_trend(tenant_id=tenant_id, days=safe_days),
        entity_totals=get_entity_totals(tenant_id=tenant_id),
        compliance=get_compliance_snapshot(tenant_id=tenant_id),
    )


@app.post("/auth/signup/company", response_model=AuthOut)
def auth_signup_company(payload: SignupCompanyIn, _request: Request, _rl: None = Depends(_limit_signup_attempts)):
    try:
        created = create_company_signup(
            company_name=payload.company_name,
            admin_email=payload.admin_email,
            password=payload.password,
        )
    except ValueError as exc:
        detail = str(exc)
        status = 409 if "exists" in detail.lower() else 400
        raise HTTPException(status_code=status, detail=detail)

    return _build_auth_response(
        user=created["user"],
        tenant_id=int(created["tenant_id"]),
        role=str(created["role"]),
        memberships=list(created["memberships"]),
    )


@app.post("/auth/signup/individual", response_model=AuthOut)
def auth_signup_individual(payload: SignupIndividualIn, _request: Request, _rl: None = Depends(_limit_signup_attempts)):
    try:
        created = create_individual_signup(
            email=payload.email,
            password=payload.password,
            name_or_label=payload.name_or_label,
        )
    except ValueError as exc:
        detail = str(exc)
        status = 409 if "exists" in detail.lower() else 400
        raise HTTPException(status_code=status, detail=detail)

    return _build_auth_response(
        user=created["user"],
        tenant_id=int(created["tenant_id"]),
        role=str(created["role"]),
        memberships=list(created["memberships"]),
    )


@app.post("/auth/signup/invite", response_model=AuthOut)
def auth_signup_invite(payload: SignupInviteIn):
    try:
        created = signup_with_invite(
            token=payload.token,
            email=payload.email,
            password=payload.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return _build_auth_response(
        user=created["user"],
        tenant_id=int(created["tenant_id"]),
        role=str(created["role"]),
        memberships=list(created["memberships"]),
    )


@app.post("/auth/login", response_model=AuthOut)
def auth_login(payload: LoginIn, request: Request, _rl: None = Depends(_limit_login_attempts)):
    identifier = (payload.email or payload.username or "").strip()
    if not identifier:
        raise HTTPException(status_code=400, detail="email is required")
    try:
        login = authenticate_login(
            email=identifier,
            password=payload.password,
            tenant_id=payload.tenant_id,
            ip_address=client_ip_from_request(request),
        )
    except LoginError as exc:
        detail = str(exc)
        _log_auth_event(
            request,
            "auth.login.lockout" if exc.code == "account_locked" else "auth.login.failure",
            email=identifier.lower(),
            reason=exc.code,
        )
        status = 423 if exc.code == "account_locked" else 401
        raise HTTPException(status_code=status, detail=detail)
    except ValueError as exc:
        detail = str(exc)
        status = 400
        raise HTTPException(status_code=status, detail=detail)

    _log_auth_event(
        request,
        "auth.login.success",
        email=identifier.lower(),
        user_id=int(login["user"]["id"]),
        tenant_id=int(login["tenant_id"]),
    )
    return _build_auth_response(
        user=login["user"],
        tenant_id=int(login["tenant_id"]),
        role=str(login["role"]),
        memberships=list(login["memberships"]),
    )


@app.post("/auth/logout")
def auth_logout(request: Request, ctx: RequestContext = Depends(require_tenant_member)):
    token = extract_bearer_token(request.headers.get("Authorization"))
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token required")

    try:
        claims = parse_access_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    jti = str(claims.get("jti") or "").strip()
    exp = claims.get("exp")
    if not jti or exp is None:
        raise HTTPException(status_code=400, detail="Token missing jti/exp")

    try:
        revoke_token_jti(
            jti=jti,
            user_id=int(ctx.user_id) if ctx.user_id is not None else None,
            tenant_id=int(ctx.tenant_id) if ctx.tenant_id is not None else None,
            expires_at=int(exp),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _log_auth_event(
        request,
        "auth.logout.success",
        user_id=int(ctx.user_id) if ctx.user_id is not None else None,
        tenant_id=int(ctx.tenant_id),
    )
    return {"ok": True}


@app.get("/me", response_model=MeOut)
def me(ctx: RequestContext = Depends(require_tenant_member)):
    try:
        profile = get_user_profile(int(ctx.user_id))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    role = get_membership_role(user_id=int(ctx.user_id), tenant_id=int(ctx.tenant_id))
    if not role:
        raise HTTPException(status_code=403, detail="Tenant membership required")
    email = str(profile.get("email") or "")
    if not email:
        raise HTTPException(status_code=400, detail="User email is missing")

    memberships = [
        TenantMembershipOut(
            tenant_id=int(m["tenant_id"]),
            tenant_name=str(m.get("tenant_name") or f"Tenant {int(m['tenant_id'])}"),
            role=str(m.get("role") or "employee"),
            is_personal=bool(int(m.get("is_personal") or 0)),
        )
        for m in profile.get("memberships", [])
    ]
    current_is_personal = is_personal_tenant(int(ctx.tenant_id))
    return MeOut(
        user_id=int(profile["id"]),
        email=email,
        tenant_id=int(ctx.tenant_id),
        role=str(role),
        is_personal=current_is_personal,
        memberships=memberships,
    )


@app.post("/tenant/admin/invite")
def tenant_admin_invite(payload: InviteEmployeeIn, ctx: RequestContext = Depends(require_company_tenant_admin)):
    try:
        invite = create_invite(
            tenant_id=int(ctx.tenant_id),
            role=payload.role,
            email=payload.email,
            expires_hours=payload.expires_hours,
            max_uses=payload.max_uses,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, **invite}


@app.get("/tenant/admin/members")
def tenant_admin_members(ctx: RequestContext = Depends(require_company_tenant_admin)):
    items = list_tenant_members(int(ctx.tenant_id))
    return {"tenant_id": int(ctx.tenant_id), "count": len(items), "items": items}


@app.get("/tenant/admin/usage-summary", response_model=TenantUsageSummaryOut)
def tenant_admin_usage_summary(ctx: RequestContext = Depends(require_company_tenant_admin)):
    return TenantUsageSummaryOut(**_tenant_usage_summary(int(ctx.tenant_id)))


@app.get("/tenant/admin/policy", response_model=TenantPolicyOut)
def tenant_admin_policy_get(ctx: RequestContext = Depends(require_company_tenant_admin)):
    return TenantPolicyOut(**get_tenant_policy_settings(int(ctx.tenant_id)))


@app.put("/tenant/admin/policy", response_model=TenantPolicyOut)
def tenant_admin_policy_put(payload: TenantPolicyIn, ctx: RequestContext = Depends(require_company_tenant_admin)):
    try:
        updated = upsert_tenant_policy_settings(
            int(ctx.tenant_id),
            pii_action=payload.pii_action,
            financial_action=payload.financial_action,
            secrets_action=payload.secrets_action,
            health_action=payload.health_action,
            ip_action=payload.ip_action,
            block_threshold=payload.block_threshold,
            store_original_prompt=payload.store_original_prompt,
            show_sanitized_prompt_admin=payload.show_sanitized_prompt_admin,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    try:
        enterprise_write_audit_log(
            tenant_id=int(ctx.tenant_id),
            user_id=int(ctx.user_id) if ctx.user_id is not None else None,
            action="tenant.policy.updated",
            target_type="tenant_policy_settings",
            target_id=str(ctx.tenant_id),
            metadata=updated,
        )
    except Exception:
        pass
    return TenantPolicyOut(**updated)


@app.get("/tenant/keys")
def tenant_keys_get(ctx: RequestContext = Depends(require_tenant_admin)):
    items = list_tenant_keys(int(ctx.tenant_id))
    return {"tenant_id": int(ctx.tenant_id), "items": items}


@app.get("/tenant/provider")
def tenant_provider_get(ctx: RequestContext = Depends(require_tenant_admin)):
    cfg = get_tenant_provider_config(int(ctx.tenant_id))
    return {
        "tenant_id": int(ctx.tenant_id),
        "provider": str(cfg.get("provider") or "none"),
        "model": str(cfg.get("model") or ""),
        "base_url": cfg.get("base_url"),
        "source": str(cfg.get("source") or "none"),
        "has_api_key": bool(cfg.get("has_api_key")),
        "api_key_tail": cfg.get("api_key_tail"),
    }


@app.put("/tenant/keys")
def tenant_keys_set(payload: TenantKeyIn, ctx: RequestContext = Depends(require_tenant_admin)):
    provider_name = str(payload.provider or "").strip().lower()
    try:
        if provider_name == "tavily":
            upsert_tenant_key(tenant_id=int(ctx.tenant_id), provider="tavily", api_key_plain=payload.api_key)
        else:
            upsert_tenant_provider_config(
                tenant_id=int(ctx.tenant_id),
                provider=payload.provider,
                model=payload.model,
                api_key=payload.api_key,
                base_url=payload.base_url,
            )
        items = list_tenant_keys(int(ctx.tenant_id))
        updated = next((item for item in items if str(item.get("provider") or "") == provider_name), None)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "tenant_id": int(ctx.tenant_id), "item": updated}


@app.delete("/tenant/keys/{provider}")
def tenant_keys_delete(provider: str, ctx: RequestContext = Depends(require_tenant_admin)):
    try:
        deleted = delete_tenant_key(
            tenant_id=int(ctx.tenant_id),
            provider=provider,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"ok": True, "tenant_id": int(ctx.tenant_id), "deleted": bool(deleted)}


@app.get("/onboarding/status")
def onboarding_status():
    return {
        "ok": True,
        "needs_onboarding": not has_any_admin_membership(),
    }


@app.post("/onboarding/bootstrap")
def onboarding_bootstrap(payload: OnboardingBootstrapIn):
    provider = (payload.provider or "").strip().lower() or "gemini"
    if provider == "gemini":
        key = (payload.api_key or "").strip() or os.getenv("GEMINI_API_KEY", "").strip()
        if not key:
            raise HTTPException(status_code=400, detail="api_key is required when provider=gemini")
    try:
        result = bootstrap_first_run(
            tenant_name=payload.tenant_name,
            admin_external_user=payload.admin_external_user,
            provider=provider,
            model=payload.model,
            api_key=payload.api_key,
            base_url=payload.base_url,
        )
    except ValueError as exc:
        detail = str(exc)
        status = 409 if "already completed" in detail.lower() else 400
        raise HTTPException(status_code=status, detail=detail)
    if payload.admin_password:
        user = get_user_by_external_id(payload.admin_external_user)
        if user:
            try:
                set_user_password(int(user["id"]), payload.admin_password)
            except Exception:
                pass
    return result
