import os
from typing import Any, Dict, List, Optional

import httpx
import streamlit as st
from db import init_db
from enterprise.db_enterprise import ensure_enterprise_schema
from risk_dashboard_ui import render_risk_dashboard


API_BASE_URL = (
    os.getenv("API_BASE_URL")
    or os.getenv("SHADOW_API_BASE_URL")
    or "http://127.0.0.1:8080"
).rstrip("/")
APP_BASE_URL = (os.getenv("APP_BASE_URL") or "http://localhost:8501").rstrip("/")
APP_ENV = (os.getenv("APP_ENV") or "dev").strip().lower()
PROVIDER_CHOICES = ("gemini", "openai", "groq", "anthropic")
POLICY_ACTION_CHOICES = ("allow", "redact", "block")
BLOCK_THRESHOLD_CHOICES = ("high", "critical")
FILE_SCAN_EXTENSIONS = ("txt", "md", "csv", "json", "pdf", "docx")
ATTACHMENT_TEXT_MAX_CHARS = 14000
CHAT_SECURITY_ADMIN_ROLES = {"tenant_admin", "platform_admin"}


class ApiRequestError(RuntimeError):
    def __init__(self, status_code: int, detail: Any):
        self.status_code = int(status_code)
        self.detail = detail
        super().__init__(f"{self.status_code}: {detail}")


@st.cache_resource
def _bootstrap_local_data() -> bool:
    init_db()
    ensure_enterprise_schema()
    return True


def _init_state() -> None:
    st.session_state.setdefault("token", "")
    st.session_state.setdefault("tenant_id", None)
    st.session_state.setdefault("role", "")
    st.session_state.setdefault("is_personal", False)
    st.session_state.setdefault("email", "")
    st.session_state.setdefault("memberships", [])
    st.session_state.setdefault("view", "login")
    st.session_state.setdefault("messages", [])
    st.session_state.setdefault("invite_result", None)
    st.session_state.setdefault("page", "Login")
    st.session_state.setdefault("invite_token", "")
    st.session_state.setdefault("invite_expanded", False)
    st.session_state.setdefault("invite_link", "")
    st.session_state.setdefault("last_join_token", "")
    st.session_state.setdefault("tenant_admin_section", "Team Admin")


def _to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on"}


def _active_tenant_is_personal(tenant_id: Optional[int], memberships: Any) -> Optional[bool]:
    if not isinstance(memberships, list):
        return None
    target_tenant_id: Optional[int] = None
    try:
        if tenant_id is not None:
            target_tenant_id = int(tenant_id)
    except Exception:
        target_tenant_id = None
    for item in memberships:
        if not isinstance(item, dict):
            continue
        try:
            item_tenant_id = int(item.get("tenant_id") or 0)
        except Exception:
            continue
        if target_tenant_id is None or item_tenant_id == target_tenant_id:
            return _to_bool(item.get("is_personal"))
    return None


def _resolve_is_personal_from_payload(payload: Dict[str, Any], tenant_id: Optional[int], fallback: bool = False) -> bool:
    if "is_personal" in payload:
        return _to_bool(payload.get("is_personal"))
    memberships = payload.get("memberships")
    derived = _active_tenant_is_personal(tenant_id, memberships)
    if derived is None:
        return bool(fallback)
    return bool(derived)


def _default_view_for_user(role: str, is_personal: bool) -> str:
    if is_personal:
        return "chat"
    return "chat" if role == "employee" else "tenant_admin"


def _nav_options_for_user(role: str, is_personal: bool) -> List[str]:
    if is_personal:
        return ["Chat", "Settings"]
    if role == "employee":
        return ["Chat", "Settings"]
    return ["Tenant Admin", "Chat", "Settings"]


def _resolve_auth_context() -> tuple[int, str, bool]:
    fallback_tenant_id = st.session_state.get("tenant_id")
    fallback_role = str(st.session_state.get("role") or "")
    fallback_is_personal = _to_bool(st.session_state.get("is_personal"))
    try:
        me = _get("/me", auth=True)
        tenant_id = int(me.get("tenant_id") or 0)
        role = str(me.get("role") or fallback_role)
        memberships = me.get("memberships") or []
        is_personal = _resolve_is_personal_from_payload(me, tenant_id, fallback=fallback_is_personal)
        st.session_state["tenant_id"] = tenant_id
        st.session_state["role"] = role
        st.session_state["is_personal"] = is_personal
        st.session_state["memberships"] = memberships if isinstance(memberships, list) else []
    except Exception as exc:
        if fallback_tenant_id is None or int(fallback_tenant_id) <= 0 or not fallback_role:
            st.error(f"Failed to load session context: {exc}")
            st.stop()
        tenant_id = int(fallback_tenant_id)
        role = fallback_role
        is_personal = fallback_is_personal
    if tenant_id <= 0:
        st.error("Forbidden")
        st.stop()
    return tenant_id, role, is_personal


def _query_param_value(name: str) -> str:
    value: Any = ""
    try:
        params = st.query_params
        value = params.get(name, "")
    except Exception:
        getter = getattr(st, "experimental_get_query_params", None)
        if callable(getter):
            params = getter()
            value = params.get(name, [""])
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "").strip()


def _sync_invite_from_query_params() -> None:
    join_token = _query_param_value("join")
    if not join_token:
        return
    if join_token == str(st.session_state.get("last_join_token") or ""):
        return
    st.session_state["last_join_token"] = join_token
    st.session_state["page"] = "Signup"
    st.session_state["invite_token"] = join_token
    st.session_state["invite_expanded"] = True


def _auth_headers() -> Dict[str, str]:
    headers = {"Authorization": f"Bearer {st.session_state['token']}"}
    tenant_id = st.session_state.get("tenant_id")
    if tenant_id is not None:
        headers["X-Tenant-Id"] = str(int(tenant_id))
    return headers


def _post(path: str, payload: Dict[str, Any], auth: bool = False) -> Dict[str, Any]:
    url = f"{API_BASE_URL}{path}"
    headers = _auth_headers() if auth else {}
    with httpx.Client(timeout=30, http2=False) as client:
        response = client.post(url, headers=headers, json=payload)
    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        raise ApiRequestError(response.status_code, detail)
    if not response.content:
        return {}
    return response.json()


def _post_multipart(
    path: str,
    *,
    data: Optional[Dict[str, Any]] = None,
    files: Optional[Dict[str, Any]] = None,
    auth: bool = False,
) -> Dict[str, Any]:
    url = f"{API_BASE_URL}{path}"
    headers = _auth_headers() if auth else {}
    with httpx.Client(timeout=60, http2=False) as client:
        response = client.post(url, headers=headers, data=data or {}, files=files or {})
    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        raise ApiRequestError(response.status_code, detail)
    if not response.content:
        return {}
    return response.json()


def _get(path: str, auth: bool = False) -> Dict[str, Any]:
    url = f"{API_BASE_URL}{path}"
    headers = _auth_headers() if auth else {}
    with httpx.Client(timeout=30, http2=False) as client:
        response = client.get(url, headers=headers)
    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        raise RuntimeError(f"{response.status_code}: {detail}")
    if not response.content:
        return {}
    return response.json()


def _put(path: str, payload: Dict[str, Any], auth: bool = False) -> Dict[str, Any]:
    url = f"{API_BASE_URL}{path}"
    headers = _auth_headers() if auth else {}
    with httpx.Client(timeout=30, http2=False) as client:
        response = client.put(url, headers=headers, json=payload)
    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        raise RuntimeError(f"{response.status_code}: {detail}")
    if not response.content:
        return {}
    return response.json()


def _delete(path: str, auth: bool = False) -> Dict[str, Any]:
    url = f"{API_BASE_URL}{path}"
    headers = _auth_headers() if auth else {}
    with httpx.Client(timeout=30, http2=False) as client:
        response = client.delete(url, headers=headers)
    if response.status_code >= 400:
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        raise RuntimeError(f"{response.status_code}: {detail}")
    if not response.content:
        return {}
    return response.json()


def _friendly_invite_error(exc: Exception) -> str:
    text = str(exc or "")
    lowered = text.lower()
    if "already used" in lowered:
        return "Invite link already used"
    if "max uses reached" in lowered:
        return "Invite link max uses reached"
    return f"Invite signup failed: {text}"


def _store_auth(auth: Dict[str, Any]) -> None:
    st.session_state["token"] = str(auth.get("access_token") or "")
    st.session_state["tenant_id"] = int(auth.get("tenant_id") or 0)
    st.session_state["role"] = str(auth.get("role") or "")
    memberships = auth.get("memberships") or []
    st.session_state["memberships"] = memberships if isinstance(memberships, list) else []
    st.session_state["is_personal"] = _resolve_is_personal_from_payload(
        auth,
        st.session_state["tenant_id"],
        fallback=False,
    )
    st.session_state["messages"] = []


def _logout() -> None:
    st.session_state["token"] = ""
    st.session_state["tenant_id"] = None
    st.session_state["role"] = ""
    st.session_state["is_personal"] = False
    st.session_state["email"] = ""
    st.session_state["memberships"] = []
    st.session_state["messages"] = []
    st.session_state["view"] = "login"


def _render_signup() -> None:
    st.subheader("Create Account")
    account_kind = st.radio("Signup Type", options=["Company", "Individual"], horizontal=True)

    if account_kind == "Company":
        with st.form("signup_company_form"):
            company_name = st.text_input("Company Name", value="")
            admin_email = st.text_input("Admin Email", value="")
            password = st.text_input("Password", value="", type="password")
            submitted = st.form_submit_button("Create Company Account")
        if submitted:
            try:
                auth = _post(
                    "/auth/signup/company",
                    {
                        "company_name": company_name,
                        "admin_email": admin_email,
                        "password": password,
                    },
                    auth=False,
                )
                _store_auth(auth)
                st.session_state["email"] = admin_email.strip().lower()
                st.session_state["view"] = _default_view_for_user(
                    str(st.session_state.get("role") or ""),
                    _to_bool(st.session_state.get("is_personal")),
                )
                st.rerun()
            except Exception as exc:
                st.error(f"Signup failed: {exc}")
    else:
        with st.form("signup_individual_form"):
            label = st.text_input("Personal Label (optional)", value="")
            email = st.text_input("Email", value="")
            password = st.text_input("Password", value="", type="password")
            submitted = st.form_submit_button("Create Personal Account")
        if submitted:
            try:
                auth = _post(
                    "/auth/signup/individual",
                    {
                        "name_or_label": label or None,
                        "email": email,
                        "password": password,
                    },
                    auth=False,
                )
                _store_auth(auth)
                st.session_state["email"] = email.strip().lower()
                st.session_state["view"] = _default_view_for_user(
                    str(st.session_state.get("role") or ""),
                    _to_bool(st.session_state.get("is_personal")),
                )
                st.rerun()
            except Exception as exc:
                st.error(f"Signup failed: {exc}")

    expand_invite = bool(st.session_state.get("invite_expanded"))
    with st.expander("Join an Existing Company via Invite Token", expanded=expand_invite):
        with st.form("signup_invite_form"):
            invite_token = st.text_input("Invite Token", key="invite_token")
            invite_email = st.text_input("Work Email", value="")
            invite_password = st.text_input("Password", value="", type="password")
            submit_invite = st.form_submit_button("Join Company")
        if submit_invite:
            try:
                auth = _post(
                    "/auth/signup/invite",
                    {
                        "token": invite_token,
                        "email": invite_email,
                        "password": invite_password,
                    },
                    auth=False,
                )
                _store_auth(auth)
                st.session_state["email"] = invite_email.strip().lower()
                st.session_state["view"] = _default_view_for_user(
                    str(st.session_state.get("role") or ""),
                    _to_bool(st.session_state.get("is_personal")),
                )
                st.rerun()
            except Exception as exc:
                st.error(_friendly_invite_error(exc))
    if expand_invite:
        st.session_state["invite_expanded"] = False


def _render_login() -> None:
    st.subheader("Login")
    with st.form("login_form"):
        email = st.text_input("Email", value=st.session_state.get("email", ""))
        password = st.text_input("Password", value="", type="password")
        tenant_hint = st.text_input("Tenant ID (optional)", value="")
        submitted = st.form_submit_button("Login")
    if submitted:
        payload: Dict[str, Any] = {"email": email, "password": password}
        if tenant_hint.strip():
            try:
                payload["tenant_id"] = int(tenant_hint.strip())
            except Exception:
                st.error("Tenant ID must be a number.")
                return
        try:
            auth = _post("/auth/login", payload, auth=False)
            _store_auth(auth)
            st.session_state["email"] = email.strip().lower()
            st.session_state["view"] = _default_view_for_user(
                str(st.session_state.get("role") or ""),
                _to_bool(st.session_state.get("is_personal")),
            )
            st.rerun()
        except Exception as exc:
            st.error(f"Login failed: {exc}")


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _is_security_admin_role(role: str) -> bool:
    return str(role or "").strip().lower() in CHAT_SECURITY_ADMIN_ROLES


def _message_was_protected(item: Dict[str, Any]) -> bool:
    decision = str(item.get("decision") or "").strip().upper()
    if decision in {"REDACT", "BLOCK"}:
        return True
    return _to_int(item.get("redactions_applied"), 0) > 0


def _choice_index(options: tuple[str, ...], value: Any, default: int = 0) -> int:
    candidate = str(value or "").strip().lower()
    try:
        return options.index(candidate)
    except ValueError:
        return int(default)


def _extract_retry_after_seconds(detail_payload: Any) -> Optional[int]:
    if not isinstance(detail_payload, dict):
        return None
    top_level = detail_payload.get("retry_after_seconds")
    if top_level is not None:
        return max(1, _to_int(top_level, 1))
    retry_info = detail_payload.get("retry_info")
    if isinstance(retry_info, dict):
        nested = retry_info.get("retry_after_seconds")
        if nested is not None:
            return max(1, _to_int(nested, 1))
    return None


def _provider_429_warning_text(retry_after_seconds: Optional[int]) -> str:
    wait_hint = f"~{int(retry_after_seconds)} seconds" if retry_after_seconds is not None else "~60 seconds"
    return (
        "AI provider quota/rate limit reached for this tenant. "
        f"Please retry in {wait_hint} or ask admin to update billing/limits."
    )


def _trace_summary(item: Dict[str, Any]) -> str:
    is_error = bool(item.get("is_error"))
    decision = str(item.get("decision") or ("ERROR" if is_error else "ALLOW")).strip().upper()
    risk_level = str(item.get("risk_level") or "UNKNOWN").strip().upper()
    redactions = _to_int(item.get("redactions_applied"), 0)
    provider = str(item.get("provider") or "").strip().lower()
    model = str(item.get("model") or "").strip()
    provider_model = f"{provider}:{model}" if provider and model else (provider or "none")

    if is_error:
        badge = "[ERR]"
    elif decision == "BLOCK":
        badge = "[BLOCK]"
    elif decision == "REDACT":
        badge = "[REDACT]"
    else:
        badge = "[OK]"
    return f"{badge} {risk_level} | {decision} | Redactions: {redactions} | {provider_model}"


def _entity_labels(item: Dict[str, Any]) -> List[str]:
    entity_counts = item.get("entity_counts")
    if not isinstance(entity_counts, dict):
        return []
    labels: List[str] = []
    for key, value in sorted(entity_counts.items(), key=lambda kv: str(kv[0])):
        if _to_int(value, 0) <= 0:
            continue
        labels.append(str(key).replace("_", " ").title())
    return labels


def _render_governance_trace(item: Dict[str, Any], viewer_role: str) -> None:
    is_admin_viewer = _is_security_admin_role(viewer_role)
    if not is_admin_viewer:
        if _message_was_protected(item):
            st.caption("Sensitive data was protected.")
        return

    request_id = str(item.get("request_id") or "").strip() or "n/a"
    decision = str(item.get("decision") or ("ERROR" if bool(item.get("is_error")) else "ALLOW")).strip().upper()
    risk_level = str(item.get("risk_level") or "UNKNOWN").strip().upper()
    risk_score = _to_float(item.get("risk_score"), 0.0)
    redactions = _to_int(item.get("redactions_applied"), 0)
    entity_labels = _entity_labels(item)
    entity_text = ", ".join(entity_labels) if entity_labels else "None"

    st.markdown("**Security Report**")
    st.write(f"Decision: `{decision}`")
    st.write(f"Risk Level: `{risk_level}`")
    st.write(f"Risk Score: `{risk_score:.2f}`")
    st.write(f"Redactions Applied: `{redactions}`")
    st.write(f"Entities: `{entity_text}`")
    st.caption(_trace_summary(item))
    st.caption(f"Request ID: `{request_id}`")

    cleaned_prompt = str(item.get("cleaned_prompt") or "")
    show_sanitized = bool(item.get("show_sanitized_prompt_admin", True))
    if bool(item.get("is_error")) and cleaned_prompt:
        st.caption("Sanitized Prompt Sent To Provider")
        st.code(cleaned_prompt, language="text")
    elif is_admin_viewer and show_sanitized and cleaned_prompt:
        st.caption("Sanitized Prompt Sent To Provider")
        st.code(cleaned_prompt, language="text")
    elif is_admin_viewer and cleaned_prompt and not show_sanitized:
        st.caption("Sanitized prompt hidden by tenant policy.")

    if bool(item.get("is_error")):
        detail = item.get("error_detail")
        if isinstance(detail, dict):
            st.write("Provider Error:")
            st.json(detail)
        elif detail is not None:
            st.write(f"Provider Error: {detail}")


def _render_assistant_message(item: Dict[str, Any], viewer_role: str) -> None:
    if bool(item.get("is_error")):
        if bool(item.get("is_warning")):
            st.warning(str(item.get("content") or "Request failed"))
        else:
            st.error(str(item.get("content") or "Request failed"))
    else:
        content = str(item.get("content") or "").strip()
        st.markdown("**AI Response**")
        st.markdown(content or "_No assistant text returned._")
    _render_governance_trace(item, viewer_role=viewer_role)


def _format_file_size(size_bytes: int) -> str:
    value = float(max(0, int(size_bytes)))
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024.0 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024.0
    return f"{int(size_bytes)} B"


def _inject_chat_composer_styles() -> None:
    st.markdown(
        """
        <style>
        [data-testid="stChatInput"] {
            padding-bottom: 0.35rem;
        }
        [data-testid="stChatInput"] > div {
            border: 1px solid #dbe2ea;
            border-radius: 28px;
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
            background: #ffffff;
        }
        [data-testid="stChatInput"] textarea {
            font-size: 0.98rem;
        }
        [data-testid="stChatInput"] button[aria-label*="Upload"],
        [data-testid="stChatInput"] button[aria-label*="upload"],
        [data-testid="stChatInput"] button[aria-label*="Attach"],
        [data-testid="stChatInput"] button[aria-label*="attach"],
        [data-testid="stChatInput"] button[aria-label*="File"],
        [data-testid="stChatInput"] button[aria-label*="file"] {
            width: 2rem;
            min-width: 2rem;
            height: 2rem;
            min-height: 2rem;
            border-radius: 999px;
            border: 1px solid #cbd5e1;
            background: #f8fafc;
            color: transparent;
            position: relative;
        }
        [data-testid="stChatInput"] button[aria-label*="Upload"] svg,
        [data-testid="stChatInput"] button[aria-label*="upload"] svg,
        [data-testid="stChatInput"] button[aria-label*="Attach"] svg,
        [data-testid="stChatInput"] button[aria-label*="attach"] svg,
        [data-testid="stChatInput"] button[aria-label*="File"] svg,
        [data-testid="stChatInput"] button[aria-label*="file"] svg {
            opacity: 0;
        }
        [data-testid="stChatInput"] button[aria-label*="Upload"]::after,
        [data-testid="stChatInput"] button[aria-label*="upload"]::after,
        [data-testid="stChatInput"] button[aria-label*="Attach"]::after,
        [data-testid="stChatInput"] button[aria-label*="attach"]::after,
        [data-testid="stChatInput"] button[aria-label*="File"]::after,
        [data-testid="stChatInput"] button[aria-label*="file"]::after {
            content: "+";
            color: #0f172a;
            font-size: 1.25rem;
            font-weight: 600;
            line-height: 1;
            position: absolute;
            top: 48%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        [data-testid="stChatInput"] button[aria-label*="Send"],
        [data-testid="stChatInput"] button[aria-label*="send"] {
            width: 2rem;
            min-width: 2rem;
            height: 2rem;
            min-height: 2rem;
            border-radius: 999px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _extract_error_message(detail: Any) -> str:
    payload = detail.get("detail") if isinstance(detail, dict) and "detail" in detail else detail
    if isinstance(payload, dict):
        return str(payload.get("message") or payload.get("detail") or payload)
    return str(payload)


def _render_user_message(item: Dict[str, Any]) -> None:
    content = str(item.get("content") or "").strip()
    attachments = item.get("attachments")
    if content:
        st.markdown(content)
    elif isinstance(attachments, list) and attachments:
        st.markdown("_Attachment sent_")
    else:
        st.markdown("")

    if isinstance(attachments, list) and attachments:
        labels: List[str] = []
        for entry in attachments:
            if isinstance(entry, dict):
                name = str(entry.get("name") or "attachment")
                size_bytes = _to_int(entry.get("size_bytes"), 0)
                if size_bytes > 0:
                    labels.append(f"`{name}` ({_format_file_size(size_bytes)})")
                else:
                    labels.append(f"`{name}`")
            else:
                labels.append(f"`{str(entry)}`")
        st.caption("Attachment: " + "  ".join(labels))


def _render_chat_history(messages: List[Dict[str, Any]], viewer_role: str) -> None:
    for item in messages:
        role = str(item.get("role") or "assistant")
        with st.chat_message(role):
            if role != "assistant":
                _render_user_message(item)
                continue
            _render_assistant_message(item, viewer_role=viewer_role)


def _parse_chat_submission(submission: Any) -> tuple[str, Optional[Any]]:
    if submission is None:
        return "", None
    if isinstance(submission, str):
        return submission.strip(), None
    prompt = str(getattr(submission, "text", "") or "").strip()
    files = getattr(submission, "files", None)
    first_file: Optional[Any] = files[0] if isinstance(files, list) and files else None
    return prompt, first_file


def _clip_text_for_prompt(text: str, limit: int = ATTACHMENT_TEXT_MAX_CHARS) -> str:
    raw = str(text or "")
    max_chars = max(500, int(limit))
    if len(raw) <= max_chars:
        return raw
    return f"{raw[:max_chars]}\n\n[Attachment text truncated by {len(raw) - max_chars} chars]"


def _build_prompt_with_attachment(prompt: str, attachment_name: str, scan_result: Dict[str, Any]) -> str:
    user_prompt = str(prompt or "").strip() or "Please analyze the attached file and provide a concise response."
    filename = str(attachment_name or scan_result.get("filename") or "attachment")
    decision = str(scan_result.get("decision") or "ALLOW").upper()
    risk_level = str(scan_result.get("risk_level") or "LOW").upper()
    extracted = str(scan_result.get("redacted_text") or scan_result.get("extracted_text") or "").strip()
    clipped_text = _clip_text_for_prompt(extracted)
    if not clipped_text:
        clipped_text = "No extractable text was found in the attachment."
    return (
        f"{user_prompt}\n\n"
        f"[Attachment Context]\n"
        f"Filename: {filename}\n"
        f"Decision: {decision}\n"
        f"Risk Level: {risk_level}\n\n"
        f"{clipped_text}"
    )


def _build_scan_error_assistant_message(message: str, detail: Any) -> Dict[str, Any]:
    return {
        "role": "assistant",
        "content": f"Attachment processing failed: {message}",
        "provider": "file_scan",
        "model": "",
        "request_id": "",
        "decision": "ERROR",
        "risk_level": "UNKNOWN",
        "risk_score": 0.0,
        "redactions_applied": 0,
        "risk_categories": {},
        "entity_counts": {},
        "cleaned_prompt": "",
        "show_sanitized_prompt_admin": True,
        "is_error": True,
        "error_detail": detail,
    }


def _build_scan_blocked_assistant_message(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    reasons = scan_result.get("decision_reasons")
    reason_text = "; ".join(str(item) for item in reasons) if isinstance(reasons, list) and reasons else ""
    message = "Attachment was blocked by tenant policy and was not sent to the model."
    if reason_text:
        message = f"{message} Reasons: {reason_text}"
    return {
        "role": "assistant",
        "content": message,
        "provider": "file_scan",
        "model": "",
        "request_id": str(scan_result.get("request_id") or ""),
        "decision": str(scan_result.get("decision") or "BLOCK"),
        "risk_level": str(scan_result.get("risk_level") or "UNKNOWN"),
        "risk_score": _to_float(scan_result.get("risk_score"), 0.0),
        "redactions_applied": 0,
        "risk_categories": scan_result.get("risk_categories") if isinstance(scan_result.get("risk_categories"), dict) else {},
        "entity_counts": scan_result.get("entity_counts") if isinstance(scan_result.get("entity_counts"), dict) else {},
        "cleaned_prompt": "",
        "show_sanitized_prompt_admin": True,
        "is_error": True,
        "is_warning": True,
        "error_detail": scan_result,
    }


def _scan_attachment_for_chat(uploaded_file: Any) -> Dict[str, Any]:
    file_bytes = uploaded_file.getvalue()
    content_type = str(getattr(uploaded_file, "type", "") or "application/octet-stream")
    return _post_multipart(
        "/files/scan",
        data={"purpose": "streamlit_chat_attachment"},
        files={"file": (uploaded_file.name, file_bytes, content_type)},
        auth=True,
    )


def _request_assistant_message(prompt: str) -> Dict[str, Any]:
    try:
        result = _post(
            "/chat",
            {"prompt": prompt, "purpose": "Product chat", "rehydrate_response": False},
            auth=True,
        )
        metadata = result.get("redaction_metadata") if isinstance(result.get("redaction_metadata"), dict) else {}
        answer = str(result.get("assistant_response") or result.get("ai_response_clean") or "")
        provider = str(result.get("provider") or "").strip().lower()
        model = str(result.get("model") or "").strip()
        return {
            "role": "assistant",
            "content": answer,
            "provider": provider,
            "model": model,
            "request_id": str(metadata.get("request_id") or result.get("request_id") or ""),
            "decision": str(metadata.get("decision") or result.get("decision") or "ALLOW"),
            "risk_level": str(metadata.get("risk_level") or result.get("risk_level") or "LOW"),
            "risk_score": _to_float(metadata.get("risk_score", result.get("risk_score")), 0.0),
            "redactions_applied": _to_int(metadata.get("redactions_applied", result.get("redactions_applied")), 0),
            "risk_categories": (
                metadata.get("risk_categories")
                if isinstance(metadata.get("risk_categories"), dict)
                else result.get("risk_categories")
                if isinstance(result.get("risk_categories"), dict)
                else {}
            ),
            "entity_counts": (
                metadata.get("entity_counts")
                if isinstance(metadata.get("entity_counts"), dict)
                else result.get("entity_counts")
                if isinstance(result.get("entity_counts"), dict)
                else {}
            ),
            "cleaned_prompt": str(metadata.get("cleaned_prompt") or result.get("cleaned_prompt") or ""),
            "show_sanitized_prompt_admin": bool(
                metadata.get(
                    "show_sanitized_prompt_admin",
                    result.get("show_sanitized_prompt_admin", True),
                )
            ),
            "is_error": False,
        }
    except ApiRequestError as exc:
        detail_payload: Any = exc.detail
        if isinstance(detail_payload, dict) and "detail" in detail_payload:
            detail_payload = detail_payload["detail"]

        provider = ""
        model = ""
        request_id = ""
        decision = "ERROR"
        risk_level = "UNKNOWN"
        risk_score = 0.0
        redactions_applied = 0
        risk_categories: Dict[str, Any] = {}
        entity_counts: Dict[str, Any] = {}
        cleaned_prompt = ""
        show_sanitized_prompt_admin = True
        status_code = int(exc.status_code)
        message = "Request failed"
        retry_after_seconds: Optional[int] = None
        if isinstance(detail_payload, dict):
            provider = str(detail_payload.get("provider") or "").strip().lower()
            model = str(detail_payload.get("model") or "").strip()
            request_id = str(detail_payload.get("request_id") or "")
            decision = str(detail_payload.get("decision") or decision)
            risk_level = str(detail_payload.get("risk_level") or risk_level)
            risk_score = _to_float(detail_payload.get("risk_score"), risk_score)
            redactions_applied = _to_int(detail_payload.get("redactions_applied"), redactions_applied)
            if isinstance(detail_payload.get("risk_categories"), dict):
                risk_categories = dict(detail_payload.get("risk_categories") or {})
            if isinstance(detail_payload.get("entity_counts"), dict):
                entity_counts = dict(detail_payload.get("entity_counts") or {})
            cleaned_prompt = str(detail_payload.get("cleaned_prompt") or "")
            show_sanitized_prompt_admin = bool(detail_payload.get("show_sanitized_prompt_admin", True))
            try:
                status_code = int(detail_payload.get("status_code") or status_code)
            except Exception:
                pass
            retry_after_seconds = _extract_retry_after_seconds(detail_payload)
            message = str(detail_payload.get("message") or message)
        elif detail_payload is not None:
            message = str(detail_payload)

        provider_label = provider or "upstream"
        is_no_key_error = provider == "none" and status_code == 503
        is_upstream_429 = provider in PROVIDER_CHOICES and status_code == 429
        return {
            "role": "assistant",
            "content": (
                "No AI provider key configured. Add a key in Settings > Provider."
                if is_no_key_error
                else _provider_429_warning_text(retry_after_seconds)
                if is_upstream_429
                else f"{provider_label} HTTP {status_code}: {message}"
            ),
            "provider": provider,
            "model": model,
            "request_id": request_id,
            "decision": decision,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "redactions_applied": redactions_applied,
            "risk_categories": risk_categories,
            "entity_counts": entity_counts,
            "cleaned_prompt": cleaned_prompt,
            "show_sanitized_prompt_admin": show_sanitized_prompt_admin,
            "is_error": True,
            "is_warning": (is_no_key_error or is_upstream_429),
            "error_detail": detail_payload,
        }
    except Exception as exc:
        return {
            "role": "assistant",
            "content": f"Request failed: {exc}",
            "provider": "",
            "model": "",
            "request_id": "",
            "decision": "ERROR",
            "risk_level": "UNKNOWN",
            "risk_score": 0.0,
            "redactions_applied": 0,
            "risk_categories": {},
            "entity_counts": {},
            "cleaned_prompt": "",
            "show_sanitized_prompt_admin": True,
            "is_error": True,
            "error_detail": str(exc),
        }


def _render_chat() -> None:
    st.subheader("Team Chat")
    _inject_chat_composer_styles()
    messages: List[Dict[str, Any]] = st.session_state.get("messages", [])
    viewer_role = str(st.session_state.get("role") or "")
    _render_chat_history(messages, viewer_role=viewer_role)

    submission = st.chat_input(
        "Message Shadow Gateway Product App",
        accept_file=True,
        file_type=list(FILE_SCAN_EXTENSIONS),
        key="chat_composer",
    )
    prompt, attachment = _parse_chat_submission(submission)
    if not prompt and attachment is None:
        return

    user_message: Dict[str, Any] = {
        "role": "user",
        "content": prompt or "Sent an attachment.",
    }
    if attachment is not None:
        user_message["attachments"] = [
            {
                "name": str(getattr(attachment, "name", "attachment")),
                "size_bytes": _to_int(getattr(attachment, "size", 0), 0),
            }
        ]
    messages.append(user_message)
    st.session_state["messages"] = messages
    with st.chat_message("user"):
        _render_user_message(user_message)

    prompt_to_send = prompt
    if attachment is not None:
        try:
            scan_result = _scan_attachment_for_chat(attachment)
        except ApiRequestError as exc:
            assistant_message = _build_scan_error_assistant_message(
                _extract_error_message(exc.detail),
                exc.detail,
            )
            messages.append(assistant_message)
            st.session_state["messages"] = messages
            with st.chat_message("assistant"):
                _render_assistant_message(assistant_message, viewer_role=viewer_role)
            return
        except Exception as exc:
            assistant_message = _build_scan_error_assistant_message(str(exc), str(exc))
            messages.append(assistant_message)
            st.session_state["messages"] = messages
            with st.chat_message("assistant"):
                _render_assistant_message(assistant_message, viewer_role=viewer_role)
            return

        if bool(scan_result.get("blocked")):
            assistant_message = _build_scan_blocked_assistant_message(scan_result)
            messages.append(assistant_message)
            st.session_state["messages"] = messages
            with st.chat_message("assistant"):
                _render_assistant_message(assistant_message, viewer_role=viewer_role)
            return

        prompt_to_send = _build_prompt_with_attachment(
            prompt=prompt,
            attachment_name=str(getattr(attachment, "name", "")),
            scan_result=scan_result,
        )

    assistant_message = _request_assistant_message(prompt_to_send)
    messages.append(assistant_message)
    st.session_state["messages"] = messages
    with st.chat_message("assistant"):
        _render_assistant_message(assistant_message, viewer_role=viewer_role)


def _render_provider_keys(form_key_prefix: str = "tenant_admin") -> None:
    key_rows: List[Dict[str, Any]] = []
    try:
        keys_payload = _get("/tenant/keys", auth=True)
        raw_items = keys_payload.get("items") if isinstance(keys_payload, dict) else []
        for item in raw_items or []:
            if not isinstance(item, dict):
                continue
            provider_name = str(item.get("provider") or "").strip().lower()
            if provider_name not in PROVIDER_CHOICES:
                continue
            has_key = bool(item.get("has_key"))
            key_rows.append(
                {
                    "Provider": provider_name,
                    "Status": "Set" if has_key else "Not set",
                    "Tail": str(item.get("api_key_tail") or ""),
                    "Updated": str(item.get("updated_at") or ""),
                    "_has_key": has_key,
                }
            )
    except Exception as exc:
        st.error(f"Failed to load provider keys: {exc}")

    if key_rows:
        table_rows = [
            {
                "Provider": row["Provider"],
                "Status": row["Status"],
                "Tail": row["Tail"],
                "Updated": row["Updated"],
            }
            for row in key_rows
        ]
        st.table(table_rows)
    else:
        st.info("No provider keys found.")

    try:
        active_cfg = _get("/tenant/provider", auth=True)
        active_provider = str(active_cfg.get("provider") or "none")
        active_model = str(active_cfg.get("model") or "")
        active_base_url = str(active_cfg.get("base_url") or "").strip()
        with st.container(border=True):
            st.caption("Active Provider Configuration (read-only)")
            st.write(f"Provider: `{active_provider}`")
            st.write(f"Active Model: `{active_model or 'n/a'}`")
            if active_base_url:
                st.write(f"Base URL: `{active_base_url}`")
    except Exception as exc:
        st.caption(f"Active provider details unavailable: {exc}")

    with st.form(f"{form_key_prefix}_provider_key_form"):
        provider = st.selectbox(
            "Provider",
            list(PROVIDER_CHOICES),
            index=0,
            key=f"{form_key_prefix}_provider_select",
        )
        api_key = st.text_input(
            "API Key",
            value="",
            type="password",
            key=f"{form_key_prefix}_provider_api_key",
        )
        submit_key = st.form_submit_button("Save Provider Key")
    if submit_key:
        try:
            _put(
                "/tenant/keys",
                {"provider": provider, "api_key": api_key},
                auth=True,
            )
            st.success("Provider key saved.")
            st.rerun()
        except Exception as exc:
            st.error(f"Key save failed: {exc}")

    st.caption("Delete key (requires confirmation):")
    for row in key_rows:
        provider_name = row["Provider"]
        if not row["_has_key"]:
            continue
        confirm_key = f"{form_key_prefix}_confirm_delete_{provider_name}"
        st.checkbox(f"Confirm delete {provider_name}", key=confirm_key)
        if st.button(f"Delete {provider_name} key", key=f"{form_key_prefix}_delete_key_{provider_name}"):
            if not bool(st.session_state.get(confirm_key)):
                st.warning(f"Please confirm deletion for {provider_name}.")
                continue
            try:
                _delete(f"/tenant/keys/{provider_name}", auth=True)
                st.success(f"Deleted key for {provider_name}.")
                st.session_state[confirm_key] = False
                st.rerun()
            except Exception as exc:
                st.error(f"Delete failed for {provider_name}: {exc}")


def _render_usage_limits_card() -> None:
    st.subheader("Usage & Limits")
    try:
        summary = _get("/tenant/admin/usage-summary", auth=True)
    except Exception as exc:
        st.error(f"Failed to load usage summary: {exc}")
        return

    daily_requests_limit = _to_int(summary.get("daily_requests_limit"), 0)
    rpm_limit = _to_int(summary.get("rpm_limit"), 0)
    today_request_count = _to_int(summary.get("today_request_count"), 0)
    today_token_count = _to_int(summary.get("today_token_count"), 0)
    daily_requests_remaining = _to_int(summary.get("daily_requests_remaining"), 0)
    daily_percent_used = _to_float(summary.get("daily_percent_used"), 0.0)

    with st.container(border=True):
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Daily Request Limit", str(daily_requests_limit))
        m2.metric("RPM Limit", str(rpm_limit))
        m3.metric("Today Requests", str(today_request_count))
        m4.metric("Today Tokens", str(today_token_count))
        st.caption(
            f"Used today: {daily_percent_used:.2f}% | Remaining requests today: {daily_requests_remaining}"
        )
        st.progress(max(0.0, min(1.0, daily_percent_used / 100.0)))


def _render_workspace_switcher(memberships: Any) -> None:
    if not isinstance(memberships, list) or not memberships:
        return
    options = {f"{m['tenant_id']} - {m['tenant_name']} ({m['role']})": m for m in memberships}
    selected = st.selectbox("Switch Active Tenant", list(options.keys()))
    selected_item = options[selected]
    if int(selected_item["tenant_id"]) != int(st.session_state.get("tenant_id") or 0):
        if st.button("Use Selected Tenant"):
            st.session_state["tenant_id"] = int(selected_item["tenant_id"])
            st.session_state["role"] = str(selected_item["role"])
            selected_is_personal = _to_bool(selected_item.get("is_personal"))
            st.session_state["is_personal"] = selected_is_personal
            st.session_state["view"] = _default_view_for_user(
                str(selected_item["role"]),
                selected_is_personal,
            )
            st.success("Tenant switched.")
            st.rerun()


def _render_workspace_admin_controls() -> None:
    with st.form("invite_form"):
        invite_email = st.text_input("Employee Email (optional)", value="")
        invite_role = st.selectbox("Role", ["employee", "tenant_admin"], index=0)
        invite_type = st.selectbox("Invite Type", ["Single-use", "Multi-use"], index=0)
        invite_hours = st.number_input("Invite Expires In (hours)", min_value=1, value=72, step=1)
        max_uses: Optional[int] = None
        if invite_type == "Multi-use":
            max_uses = int(st.number_input("Max uses", min_value=2, value=10, step=1))
        submit_invite = st.form_submit_button("Invite Employee")
    if submit_invite:
        try:
            created = _post(
                "/tenant/admin/invite",
                {
                    "email": invite_email or None,
                    "role": invite_role,
                    "expires_hours": int(invite_hours),
                    "max_uses": max_uses,
                },
                auth=True,
            )
            st.session_state["invite_result"] = created
            st.session_state["invite_link"] = ""
            st.success("Invite token created.")
        except Exception as exc:
            st.error(f"Invite failed: {exc}")

    invite_result = st.session_state.get("invite_result")
    if invite_result:
        invite_token = str(invite_result.get("token") or "").strip()
        max_uses_value = invite_result.get("max_uses")
        invite_kind = "Single-use" if max_uses_value is None else f"Multi-use ({int(max_uses_value)} max)"
        st.code(invite_token, language="text")
        st.caption(f"{invite_kind}. Share this token with the employee so they can join via the Signup page.")
        if invite_token:
            invite_link = f"{APP_BASE_URL}/?join={invite_token}"
            if st.button("Copy invite link", key="copy_invite_link_btn"):
                st.session_state["invite_link"] = invite_link
                st.success("Invite link generated. Use the copy icon on the block below.")
            if st.session_state.get("invite_link") == invite_link:
                st.code(invite_link, language="text")

    st.divider()
    st.subheader("Team Members")
    try:
        members_payload = _get("/tenant/admin/members", auth=True)
        members_raw = members_payload.get("items") if isinstance(members_payload, dict) else []
        members: List[Dict[str, str]] = []
        for item in members_raw or []:
            if not isinstance(item, dict):
                continue
            members.append(
                {
                    "Email": str(item.get("email") or ""),
                    "Display Name": str(item.get("display_name") or ""),
                    "Role": str(item.get("role") or ""),
                    "Joined": str(item.get("created_at") or ""),
                }
            )
        if members:
            st.table(members)
        else:
            st.info("No team members found.")
    except Exception as exc:
        st.error(f"Failed to load team members: {exc}")


def _render_tenant_admin_team() -> None:
    _render_workspace_admin_controls()

    st.divider()
    _render_usage_limits_card()
    st.divider()
    st.subheader("Provider Keys")
    _render_provider_keys(form_key_prefix="tenant_admin")

    if st.button("Go to Chat"):
        st.session_state["view"] = "chat"
        st.rerun()


def _render_tenant_admin_policy() -> None:
    st.subheader("Policy")
    try:
        current = _get("/tenant/admin/policy", auth=True)
    except Exception as exc:
        st.error(f"Failed to load tenant policy: {exc}")
        return

    with st.form("tenant_policy_form"):
        pii_action = st.selectbox(
            "PII",
            options=POLICY_ACTION_CHOICES,
            index=_choice_index(POLICY_ACTION_CHOICES, current.get("pii_action"), default=1),
            format_func=lambda value: value.title(),
        )
        financial_action = st.selectbox(
            "Financial",
            options=POLICY_ACTION_CHOICES,
            index=_choice_index(POLICY_ACTION_CHOICES, current.get("financial_action"), default=1),
            format_func=lambda value: value.title(),
        )
        secrets_action = st.selectbox(
            "Secrets",
            options=POLICY_ACTION_CHOICES,
            index=_choice_index(POLICY_ACTION_CHOICES, current.get("secrets_action"), default=2),
            format_func=lambda value: value.title(),
        )
        health_action = st.selectbox(
            "Health",
            options=POLICY_ACTION_CHOICES,
            index=_choice_index(POLICY_ACTION_CHOICES, current.get("health_action"), default=1),
            format_func=lambda value: value.title(),
        )
        ip_action = st.selectbox(
            "Intellectual Property",
            options=POLICY_ACTION_CHOICES,
            index=_choice_index(POLICY_ACTION_CHOICES, current.get("ip_action"), default=1),
            format_func=lambda value: value.title(),
        )
        block_threshold = st.selectbox(
            "Block Threshold",
            options=BLOCK_THRESHOLD_CHOICES,
            index=_choice_index(BLOCK_THRESHOLD_CHOICES, current.get("block_threshold"), default=1),
            format_func=lambda value: value.title(),
        )
        store_original_prompt = st.checkbox(
            "Store original prompt for audit",
            value=bool(current.get("store_original_prompt", True)),
        )
        show_sanitized_prompt_admin = st.checkbox(
            "Show sanitized prompt to admins in request trace",
            value=bool(current.get("show_sanitized_prompt_admin", True)),
        )
        submit = st.form_submit_button("Save Policy")

    if not submit:
        return

    try:
        _put(
            "/tenant/admin/policy",
            {
                "pii_action": pii_action,
                "financial_action": financial_action,
                "secrets_action": secrets_action,
                "health_action": health_action,
                "ip_action": ip_action,
                "block_threshold": block_threshold,
                "store_original_prompt": bool(store_original_prompt),
                "show_sanitized_prompt_admin": bool(show_sanitized_prompt_admin),
            },
            auth=True,
        )
        st.success("Policy saved.")
        st.rerun()
    except Exception as exc:
        st.error(f"Policy save failed: {exc}")


def _render_tenant_admin() -> None:
    st.subheader("Tenant Admin")
    tenant_id, role, is_personal = _resolve_auth_context()
    if is_personal:
        st.error("Forbidden")
        st.stop()

    sections = ["Team Admin", "Risk Dashboard"] if role == "tenant_admin" else ["Team Admin"]
    default_section = st.session_state.get("tenant_admin_section", "Team Admin")
    if default_section not in sections:
        default_section = "Team Admin"
    section = st.radio(
        "Section",
        options=sections,
        index=sections.index(default_section),
        horizontal=True,
        key="tenant_admin_section",
    )

    if section == "Team Admin":
        _render_tenant_admin_team()
        return

    if role != "tenant_admin":
        st.error("Forbidden")
        st.stop()

    st.subheader("Risk Dashboard")
    render_risk_dashboard(tenant_id=tenant_id, show_caption_tip=False)
    if APP_ENV == "dev":
        st.markdown("[Open Standalone Dashboard (Dev)](http://localhost:8502)")


def _render_settings() -> None:
    st.subheader("Settings")
    try:
        me = _get("/me", auth=True)
    except Exception as exc:
        st.error(f"Failed to load settings details: {exc}")
        return

    tenant_id = int(me.get("tenant_id") or st.session_state.get("tenant_id") or 0)
    role = str(me.get("role") or st.session_state.get("role") or "")
    memberships = me.get("memberships") or []
    is_personal = _resolve_is_personal_from_payload(
        me,
        tenant_id,
        fallback=_to_bool(st.session_state.get("is_personal")),
    )
    st.session_state["tenant_id"] = tenant_id
    st.session_state["role"] = role
    st.session_state["is_personal"] = is_personal
    st.session_state["memberships"] = memberships if isinstance(memberships, list) else []
    tabs = st.tabs(["Profile", "Policy", "Provider", "Usage & Limits", "Workspace"])

    with tabs[0]:
        st.write(f"Email: `{str(me.get('email') or st.session_state.get('email') or '')}`")
        st.write(f"Tenant ID: `{tenant_id}`")
        st.write(f"Role: `{role}`")
        st.write(f"Workspace Type: `{'Personal' if is_personal else 'Company'}`")

    with tabs[1]:
        if is_personal:
            st.info("Policy settings are available for company workspaces.")
        elif role != "tenant_admin":
            st.info("Tenant admin role is required to edit policy settings.")
        else:
            _render_tenant_admin_policy()

    with tabs[2]:
        if role != "tenant_admin":
            st.info("Tenant admin role is required to manage provider keys.")
        else:
            st.subheader("Provider")
            _render_provider_keys(form_key_prefix="settings_provider")

    with tabs[3]:
        if is_personal:
            st.info("Usage limits are available for company workspaces.")
        elif role != "tenant_admin":
            st.info("Tenant admin role is required to view usage and limits.")
        else:
            _render_usage_limits_card()

    with tabs[4]:
        st.subheader("Workspace")
        _render_workspace_switcher(me.get("memberships") or [])
        if is_personal:
            st.info("Invite and admin controls are available for company workspaces.")
        elif role != "tenant_admin":
            st.info("Tenant admin role is required for workspace invite/admin controls.")
        else:
            st.divider()
            _render_workspace_admin_controls()


def main() -> None:
    st.set_page_config(page_title="Shadow Gateway Product", layout="wide")
    _bootstrap_local_data()
    _init_state()
    _sync_invite_from_query_params()
    st.title("Shadow Gateway Product App")
    st.caption("Signup, login, tenant admin, and chat for SaaS onboarding.")

    token = st.session_state.get("token", "")
    if not token:
        if st.session_state.get("page") not in {"Signup", "Login"}:
            st.session_state["page"] = "Login"
        st.radio("Page", options=["Signup", "Login"], horizontal=True, key="page")
        if st.session_state.get("page") == "Signup":
            _render_signup()
        else:
            _render_login()
        return

    col1, col2 = st.columns([4, 1])
    with col1:
        st.write(
            f"Signed in as `{st.session_state.get('email', '')}` | Tenant `{st.session_state.get('tenant_id')}` | Role `{st.session_state.get('role')}`"
        )
    with col2:
        if st.button("Logout"):
            _logout()
            st.rerun()

    derived_is_personal = _active_tenant_is_personal(
        st.session_state.get("tenant_id"),
        st.session_state.get("memberships"),
    )
    if derived_is_personal is not None:
        st.session_state["is_personal"] = bool(derived_is_personal)

    role = str(st.session_state.get("role") or "")
    is_personal = _to_bool(st.session_state.get("is_personal"))
    default_view = _default_view_for_user(role, is_personal)
    if st.session_state.get("view") not in {"chat", "tenant_admin", "settings"}:
        st.session_state["view"] = default_view

    nav_options = _nav_options_for_user(role, is_personal)
    if st.session_state.get("view") == "tenant_admin" and "Tenant Admin" not in nav_options:
        st.session_state["view"] = default_view
    nav = st.radio("Page", options=nav_options, horizontal=True)
    if nav == "Tenant Admin":
        st.session_state["view"] = "tenant_admin"
    elif nav == "Chat":
        st.session_state["view"] = "chat"
    else:
        st.session_state["view"] = "settings"

    if st.session_state["view"] == "tenant_admin":
        _render_tenant_admin()
    elif st.session_state["view"] == "settings":
        _render_settings()
    else:
        _render_chat()


if __name__ == "__main__":
    main()

