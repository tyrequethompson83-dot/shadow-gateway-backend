import base64
import httpx
import json
import pandas as pd
import streamlit as st

SECURITY_REPORT_ADMIN_ROLES = {"tenant_admin", "platform_admin"}


def _to_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _role_from_jwt(token: str) -> str:
    raw = str(token or "").strip()
    if not raw:
        return ""
    try:
        parts = raw.split(".")
        if len(parts) != 3:
            return ""
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode((payload + padding).encode("utf-8"))
        claims = json.loads(decoded.decode("utf-8"))
        return str(claims.get("role") or "").strip().lower()
    except Exception:
        return ""


def _effective_viewer_role(token: str, selected_role: str) -> str:
    jwt_role = _role_from_jwt(token)
    if jwt_role:
        return jwt_role
    return str(selected_role or "").strip().lower()


def _is_security_admin(role: str) -> bool:
    return str(role or "").strip().lower() in SECURITY_REPORT_ADMIN_ROLES


def _sensitive_data_was_protected(metadata: dict, result: dict) -> bool:
    decision = str(metadata.get("decision") or result.get("decision") or "").strip().upper()
    if decision in {"REDACT", "BLOCK"}:
        return True
    redactions_applied = metadata.get("redactions_applied", result.get("redactions_applied", 0))
    return _to_int(redactions_applied, 0) > 0


def call_chat(
    base_url: str,
    *,
    tenant_id: int,
    x_user: str,
    token: str,
    prompt: str,
    purpose: str,
    rehydrate_response: bool = False,
) -> dict:
    url = f"{base_url.rstrip('/')}/chat"
    headers = {"X-Tenant-Id": str(int(tenant_id))}
    if x_user.strip():
        headers["X-User"] = x_user
    if token.strip():
        headers["Authorization"] = f"Bearer {token.strip()}"
    payload = {
        "prompt": prompt,
        "purpose": purpose or None,
        "rehydrate_response": bool(rehydrate_response),
    }
    with httpx.Client(timeout=60, http2=False) as client:
        response = client.post(url, headers=headers, json=payload)
    if response.status_code >= 400:
        detail = None
        try:
            detail = response.json()
        except Exception:
            detail = response.text
        raise RuntimeError(f"{response.status_code}: {detail}")
    return response.json()


st.set_page_config(page_title="Shadow Gateway Employee Chat", layout="wide")
st.title("Shadow AI Gateway - Employee Chat")
st.caption("Prompts are scrubbed before model calls.")

base_url = st.text_input("API Base URL", value="http://127.0.0.1:8080")
tenant_id = st.number_input("Tenant ID", min_value=1, value=1, step=1)
x_user = st.text_input("X-User", value="employee.demo")
token = st.text_input("Bearer Token (JWT mode)", value="", type="password")
viewer_role = st.selectbox(
    "Viewer Role",
    options=["employee", "viewer", "tenant_admin", "platform_admin"],
    index=0,
    help="Used only when the token does not include a role claim.",
)
purpose = st.text_input("Purpose (optional)", value="General assistance")
rehydrate_response = st.checkbox("Rehydrate placeholders in response (internal only)", value=False)

prompt = st.text_area("Prompt", height=180, placeholder="Enter your request...")

if st.button("Send"):
    if not prompt.strip():
        st.error("Prompt is required.")
    else:
        try:
            result = call_chat(
                base_url,
                tenant_id=int(tenant_id),
                x_user=x_user,
                token=token,
                prompt=prompt,
                purpose=purpose,
                rehydrate_response=rehydrate_response,
            )
        except Exception as exc:
            st.error(f"Chat call failed: {exc}")
        else:
            metadata = result.get("redaction_metadata") if isinstance(result.get("redaction_metadata"), dict) else {}
            effective_role = _effective_viewer_role(token, viewer_role)
            show_security_report = _is_security_admin(effective_role)
            assistant_text = (
                result.get("assistant_response")
                or result.get("ai_response_rehydrated")
                or result.get("ai_response_clean")
                or ""
            )

            st.subheader("AI Response")
            st.write(assistant_text)

            if show_security_report:
                entity_counts = (
                    metadata.get("entity_counts")
                    if isinstance(metadata.get("entity_counts"), dict)
                    else result.get("entity_counts", {})
                )
                entity_labels = []
                for key, value in (entity_counts or {}).items():
                    try:
                        if int(value or 0) > 0:
                            entity_labels.append(str(key))
                    except Exception:
                        continue

                st.divider()
                st.subheader("Security Report")
                c1, c2, c3 = st.columns(3)
                c1.metric("Risk Score", metadata.get("risk_score", result.get("risk_score")))
                c2.metric("Risk Level", metadata.get("risk_level", result.get("risk_level")))
                c3.metric("Policy Decision", metadata.get("decision", result.get("decision")))
                st.caption(f"Severity: {metadata.get('severity', result.get('severity'))}")
                st.caption(f"Redactions Applied: {metadata.get('redactions_applied', result.get('redactions_applied', 0))}")
                st.caption(f"Entities: {', '.join(entity_labels) if entity_labels else 'None'}")
                st.caption(
                    f"Reasons: {', '.join(metadata.get('decision_reasons', result.get('decision_reasons', []))) or 'None'}"
                )

                detections = result.get("detections", [])
                if detections:
                    st.markdown("**Detections**")
                    st.dataframe(pd.DataFrame(detections), use_container_width=True, hide_index=True)
                else:
                    st.info("No detections found.")

                st.markdown("**Entity Counts**")
                st.json(result.get("entity_counts", {}))
                st.markdown("**Risk Categories**")
                st.json(result.get("risk_categories", {}))
            elif _sensitive_data_was_protected(metadata, result):
                st.caption("Sensitive data was protected.")
