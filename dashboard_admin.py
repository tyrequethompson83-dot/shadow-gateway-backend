import io
import re
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
import pandas as pd
import streamlit as st


def api_call(
    base_url: str,
    method: str,
    path: str,
    *,
    tenant_id: int,
    x_user: str,
    token: str = "",
    params: Optional[Dict[str, Any]] = None,
    timeout_seconds: float = 30.0,
) -> Dict[str, Any]:
    headers: Dict[str, str] = {"X-Tenant-Id": str(int(tenant_id))}
    if x_user.strip():
        headers["X-User"] = x_user.strip()
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    url = f"{base_url.rstrip('/')}{path}"
    with httpx.Client(timeout=timeout_seconds, http2=False) as client:
        response = client.request(method=method, url=url, headers=headers, params=params)
    if response.status_code >= 400:
        raise RuntimeError(f"{response.status_code}: {response.text}")
    if not response.content:
        return {}
    return response.json()


def api_get_text(
    base_url: str,
    path: str,
    *,
    tenant_id: int,
    x_user: str,
    token: str = "",
    timeout_seconds: float = 15.0,
) -> str:
    headers: Dict[str, str] = {"X-Tenant-Id": str(int(tenant_id))}
    if x_user.strip():
        headers["X-User"] = x_user.strip()
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    url = f"{base_url.rstrip('/')}{path}"
    with httpx.Client(timeout=timeout_seconds, http2=False) as client:
        response = client.get(url, headers=headers)
    if response.status_code >= 400:
        raise RuntimeError(f"{response.status_code}: {response.text}")
    return response.text


def api_download_export(
    base_url: str,
    *,
    tenant_id: int,
    x_user: str,
    token: str,
    job_id: str,
) -> tuple[str, bytes]:
    headers: Dict[str, str] = {"X-Tenant-Id": str(int(tenant_id))}
    if x_user.strip():
        headers["X-User"] = x_user.strip()
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    url = f"{base_url.rstrip('/')}/admin/exports/{job_id}/download"
    with httpx.Client(timeout=120, http2=False) as client:
        response = client.get(url, headers=headers)
    if response.status_code >= 400:
        raise RuntimeError(f"{response.status_code}: {response.text}")
    filename = f"export_{job_id}"
    cd = response.headers.get("content-disposition", "")
    if "filename=" in cd:
        filename = cd.split("filename=", 1)[1].strip().strip('"')
    return filename, response.content


def parse_prometheus(text: str) -> Dict[str, list[dict]]:
    out: Dict[str, list[dict]] = {"requests_total": [], "upstream_errors_total": [], "redactions_total": []}
    line_re = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([0-9.]+)$")
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = line_re.match(line.strip())
        if not match:
            continue
        metric, labels_raw, value_raw = match.groups()
        labels: Dict[str, str] = {}
        for part in labels_raw.split(","):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            labels[k.strip()] = v.strip().strip('"')
        row = dict(labels)
        row["value"] = float(value_raw)
        if metric in out:
            out[metric].append(row)
    return out


st.set_page_config(page_title="Shadow Gateway Admin", layout="wide")
st.title("Shadow AI Gateway - Admin Console")

base_url = st.text_input("API Base URL", value="http://127.0.0.1:8080")
x_user = st.text_input("X-User (header mode)", value="tyreque")
token = st.text_input("Bearer Token (JWT mode)", value=st.session_state.get("bearer_token", ""), type="password")

with st.expander("JWT Login"):
    login_username = st.text_input("Username", value="")
    login_password = st.text_input("Password", value="", type="password")
    login_tenant = st.number_input("Tenant for JWT", min_value=1, value=1, step=1)
    if st.button("Login and Store Token"):
        try:
            with httpx.Client(timeout=30, http2=False) as client:
                resp = client.post(
                    f"{base_url.rstrip('/')}/auth/login",
                    json={
                        "username": login_username,
                        "password": login_password,
                        "tenant_id": int(login_tenant),
                    },
                )
            if resp.status_code >= 400:
                raise RuntimeError(f"{resp.status_code}: {resp.text}")
            login = resp.json()
        except Exception as exc:
            st.error(f"Login failed: {exc}")
            login = None
        if login:
            st.session_state["bearer_token"] = str(login.get("access_token") or "")
            token = st.session_state["bearer_token"]
            st.success("Token stored in session.")

tenant_items = []
tenant_error = None
try:
    tenant_resp = api_call(
        base_url,
        "GET",
        "/admin/tenants",
        tenant_id=1,
        x_user=x_user,
        token=token,
    )
    tenant_items = tenant_resp.get("items", [])
except Exception as exc:
    tenant_error = str(exc)

if tenant_error:
    st.error(f"Failed to load tenants: {tenant_error}")
    st.stop()
if not tenant_items:
    st.warning("No tenants found.")
    st.stop()

default_idx = 0
for i, t in enumerate(tenant_items):
    if int(t.get("id", 0)) == 1:
        default_idx = i
        break
tenant = st.selectbox(
    "Tenant",
    tenant_items,
    index=default_idx,
    format_func=lambda t: f"{t.get('id')} - {t.get('name')}",
)
tenant_id = int(tenant["id"])

tabs = st.tabs(
    [
        "Tenants",
        "Roles",
        "Users",
        "Limits + Quotas",
        "Provider + Smoke",
        "Policies",
        "Audit",
        "Exports",
        "Live Monitoring",
    ]
)

with tabs[0]:
    st.subheader("Tenants")
    st.dataframe(pd.DataFrame(tenant_items), use_container_width=True, hide_index=True)
    with st.form("create_tenant_form"):
        new_name = st.text_input("New Tenant Name", value="Tenant Demo")
        submit = st.form_submit_button("Create Tenant")
    if submit:
        try:
            created = api_call(
                base_url,
                "POST",
                "/admin/tenants",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={"name": new_name},
            )
            st.success(f"Created tenant: {created}")
        except Exception as exc:
            st.error(f"Create tenant failed: {exc}")

with tabs[1]:
    st.subheader("Memberships")
    try:
        memberships = api_call(
            base_url,
            "GET",
            "/admin/memberships",
            tenant_id=tenant_id,
            x_user=x_user,
            token=token,
        )
        items = memberships.get("items", [])
        if items:
            st.dataframe(pd.DataFrame(items), use_container_width=True, hide_index=True)
        else:
            st.info("No memberships found.")
    except Exception as exc:
        st.error(f"Load memberships failed: {exc}")

    st.divider()
    with st.form("grant_role_form"):
        external_user = st.text_input("External User", value="")
        role = st.selectbox("Role", ["admin", "auditor", "user"], index=1)
        submit_role = st.form_submit_button("Grant / Update Role")
    if submit_role:
        try:
            result = api_call(
                base_url,
                "POST",
                "/admin/grant-role",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={"external_user": external_user, "role": role},
            )
            st.success(f"Updated: {result}")
        except Exception as exc:
            st.error(f"Role update failed: {exc}")

with tabs[2]:
    st.subheader("Users")
    try:
        users = api_call(
            base_url,
            "GET",
            "/admin/users",
            tenant_id=tenant_id,
            x_user=x_user,
            token=token,
            params={"limit": 500},
        )
        st.dataframe(pd.DataFrame(users.get("items", [])), use_container_width=True, hide_index=True)
    except Exception as exc:
        st.error(f"Load users failed: {exc}")

    st.divider()
    with st.form("create_user_form"):
        u_name = st.text_input("Username", value="")
        u_pass = st.text_input("Password", value="", type="password")
        u_display = st.text_input("Display Name", value="")
        u_role = st.selectbox("Initial Role", ["user", "auditor", "admin"], index=0)
        create_user_btn = st.form_submit_button("Create User")
    if create_user_btn:
        try:
            created = api_call(
                base_url,
                "POST",
                "/admin/users",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={
                    "username": u_name,
                    "password": u_pass,
                    "display_name": u_display,
                    "role": u_role,
                },
            )
            st.success(f"Created user: {created}")
        except Exception as exc:
            st.error(f"Create user failed: {exc}")

    st.divider()
    with st.form("reset_password_form"):
        reset_user_id = st.number_input("User ID", min_value=1, value=1, step=1)
        new_password = st.text_input("New Password", value="", type="password")
        reset_btn = st.form_submit_button("Reset Password")
    if reset_btn:
        try:
            reset = api_call(
                base_url,
                "POST",
                f"/admin/users/{int(reset_user_id)}/password",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={"new_password": new_password},
            )
            st.success(f"Password reset: {reset}")
        except Exception as exc:
            st.error(f"Reset password failed: {exc}")

with tabs[3]:
    st.subheader("Limits and Daily Quota")
    try:
        limits = api_call(
            base_url,
            "GET",
            "/admin/limits",
            tenant_id=tenant_id,
            x_user=x_user,
            token=token,
        )
        usage = api_call(
            base_url,
            "GET",
            "/admin/usage",
            tenant_id=tenant_id,
            x_user=x_user,
            token=token,
        )
    except Exception as exc:
        st.error(f"Failed to load limits/usage: {exc}")
        limits = None
        usage = None

    if limits:
        c1, c2, c3 = st.columns(3)
        daily = c1.number_input("Daily Request Limit", min_value=1, value=int(limits["daily_requests_limit"]))
        rpm = c2.number_input("RPM Limit", min_value=1, value=int(limits["rpm_limit"]))
        enabled = c3.checkbox("Enabled", value=bool(limits["enabled"]))
        if st.button("Save Limits"):
            try:
                updated = api_call(
                    base_url,
                    "POST",
                    "/admin/limits",
                    tenant_id=tenant_id,
                    x_user=x_user,
                    token=token,
                    params={
                        "daily_requests_limit": int(daily),
                        "rpm_limit": int(rpm),
                        "enabled": bool(enabled),
                    },
                )
                st.success(f"Updated: {updated}")
            except Exception as exc:
                st.error(f"Update failed: {exc}")

    if usage:
        u1, u2, u3 = st.columns(3)
        u1.metric("Requests Today", int(usage.get("usage", {}).get("request_count", 0)))
        u2.metric("Blocked Today", int(usage.get("usage", {}).get("blocked_count", 0)))
        u3.metric("Remaining Today", int(usage.get("remaining_daily_requests", 0)))

with tabs[4]:
    st.subheader("Provider Configuration")
    cfg = None
    try:
        cfg = api_call(
            base_url,
            "GET",
            "/admin/provider",
            tenant_id=tenant_id,
            x_user=x_user,
            token=token,
        )
    except Exception as exc:
        st.error(f"Load provider config failed: {exc}")
    if cfg:
        st.json(cfg)
        with st.form("provider_cfg"):
            provider = st.selectbox("Provider", ["gemini", "openai", "groq", "anthropic"], index=0)
            model = st.text_input("Model", value=str(cfg.get("model", "")))
            api_key = st.text_input("API Key (optional; blank keeps existing)", value="", type="password")
            save_provider = st.form_submit_button("Save Provider")
        if save_provider:
            params = {"provider": provider, "model": model}
            if api_key.strip():
                params["api_key"] = api_key.strip()
            try:
                saved = api_call(
                    base_url,
                    "POST",
                    "/admin/provider",
                    tenant_id=tenant_id,
                    x_user=x_user,
                    token=token,
                    params=params,
                )
                st.success(f"Saved: {saved}")
            except Exception as exc:
                st.error(f"Save failed: {exc}")

    st.divider()
    smoke_prompt = st.text_input("Smoke Prompt", value="ping")
    if st.button("Run Smoke Test"):
        try:
            smoke = api_call(
                base_url,
                "GET",
                "/admin/llm-smoke",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={"prompt": smoke_prompt},
                timeout_seconds=90,
            )
            st.json(smoke)
            if smoke.get("ok"):
                st.success("Smoke passed.")
            else:
                st.warning("Smoke failed.")
        except Exception as exc:
            st.error(f"Smoke test failed: {exc}")

with tabs[5]:
    st.subheader("Policy Rules")
    try:
        rules = api_call(
            base_url,
            "GET",
            "/admin/policies",
            tenant_id=tenant_id,
            x_user=x_user,
            token=token,
        )
        items = rules.get("items", [])
        if items:
            st.dataframe(pd.DataFrame(items), use_container_width=True)
        else:
            st.info("No rules found.")
    except Exception as exc:
        st.error(f"Load rules failed: {exc}")

    st.divider()
    with st.form("create_rule_form"):
        rt = st.selectbox("Rule Type", ["injection", "category", "severity"], index=0)
        match = st.text_input("Match", value="PROMPT_INJECTION")
        action = st.selectbox("Action", ["BLOCK", "REDACT", "ALLOW"], index=0)
        enabled = st.checkbox("Enabled", value=True)
        add_rule = st.form_submit_button("Create Rule")
    if add_rule:
        try:
            created = api_call(
                base_url,
                "POST",
                "/admin/policies",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={
                    "rule_type": rt,
                    "match": match,
                    "action": action,
                    "enabled": bool(enabled),
                },
            )
            st.success(f"Created: {created}")
        except Exception as exc:
            st.error(f"Create failed: {exc}")

    st.divider()
    with st.form("delete_rule_form"):
        rule_id = st.number_input("Rule ID to delete", min_value=1, value=1, step=1)
        delete_rule_btn = st.form_submit_button("Delete Rule")
    if delete_rule_btn:
        try:
            headers = {"X-Tenant-Id": str(tenant_id)}
            if x_user.strip():
                headers["X-User"] = x_user.strip()
            if token.strip():
                headers["Authorization"] = f"Bearer {token.strip()}"
            with httpx.Client(timeout=30, http2=False) as client:
                resp = client.delete(f"{base_url.rstrip('/')}/admin/policies/{int(rule_id)}", headers=headers)
            if resp.status_code >= 400:
                raise RuntimeError(f"{resp.status_code}: {resp.text}")
            st.success(f"Deleted rule {int(rule_id)}")
        except Exception as exc:
            st.error(f"Delete failed: {exc}")

    st.divider()
    st.subheader("Redaction Preview")
    preview_prompt = st.text_area("Preview Prompt", value="My ssn is 123-45-6789 and api_key=abc")
    if st.button("Preview Redaction"):
        try:
            preview = api_call(
                base_url,
                "POST",
                "/admin/policies/preview",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={"prompt": preview_prompt},
            )
            st.json(preview)
        except Exception as exc:
            st.error(f"Preview failed: {exc}")

with tabs[6]:
    st.subheader("Audit")
    limit = st.number_input("Limit", min_value=1, max_value=1000, value=100, step=50)
    offset = st.number_input("Offset", min_value=0, max_value=100000, value=0, step=100)
    if st.button("Load Audit Logs"):
        try:
            logs = api_call(
                base_url,
                "GET",
                "/admin/audit",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={"limit": int(limit), "offset": int(offset)},
            )
            st.dataframe(pd.DataFrame(logs.get("items", [])), use_container_width=True)
        except Exception as exc:
            st.error(f"Load audit failed: {exc}")
    verify_limit = st.number_input("Verify N Rows", min_value=1, max_value=5000, value=500)
    if st.button("Verify Chain"):
        try:
            verify = api_call(
                base_url,
                "GET",
                "/admin/audit/verify",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
                params={"limit": int(verify_limit)},
            )
            st.json(verify)
        except Exception as exc:
            st.error(f"Verify failed: {exc}")

with tabs[7]:
    st.subheader("Exports")
    c1, c2 = st.columns(2)
    if c1.button("Queue PDF Export"):
        try:
            queued = api_call(
                base_url,
                "POST",
                "/admin/exports",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
            )
            st.success(f"Queued PDF export: {queued.get('job_id')}")
        except Exception as exc:
            st.error(f"Queue failed: {exc}")
    if c2.button("Queue Compliance Export"):
        try:
            queued = api_call(
                base_url,
                "POST",
                "/admin/exports/compliance",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
            )
            st.success(f"Queued compliance export: {queued.get('job_id')}")
        except Exception as exc:
            st.error(f"Queue failed: {exc}")

    try:
        jobs = api_call(
            base_url,
            "GET",
            "/admin/jobs",
            tenant_id=tenant_id,
            x_user=x_user,
            token=token,
            params={"limit": 100},
        )
        items = jobs.get("items", [])
        st.dataframe(pd.DataFrame(items), use_container_width=True)
        done = [j for j in items if str(j.get("status")) == "done"]
        if done:
            selected = st.selectbox(
                "Completed Jobs",
                done,
                format_func=lambda r: f"{r.get('id')} ({r.get('type')})",
            )
            if st.button("Download Selected"):
                try:
                    filename, content = api_download_export(
                        base_url,
                        tenant_id=tenant_id,
                        x_user=x_user,
                        token=token,
                        job_id=str(selected.get("id")),
                    )
                    st.download_button(
                        label=f"Save {filename}",
                        data=io.BytesIO(content),
                        file_name=filename,
                    )
                except Exception as exc:
                    st.error(f"Download failed: {exc}")
    except Exception as exc:
        st.error(f"Load jobs failed: {exc}")

with tabs[8]:
    st.subheader("Live Monitoring (/metrics)")
    poll = st.checkbox("Auto refresh every 10s", value=False)
    if st.button("Refresh Metrics") or poll:
        if poll:
            st.experimental_set_query_params(ts=str(datetime.utcnow().timestamp()))
        try:
            raw = api_get_text(
                base_url,
                "/metrics",
                tenant_id=tenant_id,
                x_user=x_user,
                token=token,
            )
            parsed = parse_prometheus(raw)
            st.code(raw[:5000], language="text")

            req_df = pd.DataFrame(parsed.get("requests_total", []))
            err_df = pd.DataFrame(parsed.get("upstream_errors_total", []))
            red_df = pd.DataFrame(parsed.get("redactions_total", []))

            if not req_df.empty:
                st.markdown("**requests_total**")
                st.dataframe(req_df, use_container_width=True)
            if not err_df.empty:
                st.markdown("**upstream_errors_total**")
                st.dataframe(err_df, use_container_width=True)
            if not red_df.empty:
                st.markdown("**redactions_total**")
                st.dataframe(red_df, use_container_width=True)
        except Exception as exc:
            st.error(f"Metrics load failed: {exc}")

st.caption(f"Last refresh: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
