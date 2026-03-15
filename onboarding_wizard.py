import httpx
import streamlit as st


def get_status(base_url: str) -> dict:
    url = f"{base_url.rstrip('/')}/onboarding/status"
    with httpx.Client(timeout=15, http2=False) as client:
        response = client.get(url)
    if response.status_code >= 400:
        raise RuntimeError(f"{response.status_code}: {response.text}")
    return response.json()


def bootstrap(
    base_url: str,
    *,
    tenant_name: str,
    admin_external_user: str,
    admin_password: str,
    provider: str,
    model: str,
    api_key: str,
    provider_base_url: str,
) -> dict:
    url = f"{base_url.rstrip('/')}/onboarding/bootstrap"
    payload = {
        "tenant_name": tenant_name,
        "admin_external_user": admin_external_user,
        "admin_password": admin_password or None,
        "provider": provider,
        "model": model or None,
        "api_key": api_key or None,
        "base_url": provider_base_url or None,
    }
    with httpx.Client(timeout=30, http2=False) as client:
        response = client.post(url, json=payload)
    if response.status_code >= 400:
        raise RuntimeError(f"{response.status_code}: {response.text}")
    return response.json()


st.set_page_config(page_title="Shadow Gateway Onboarding", layout="centered")
st.title("Shadow AI Gateway - First Run Wizard")

base_url = st.text_input("API Base URL", value="http://127.0.0.1:8080")

try:
    status = get_status(base_url)
except Exception as exc:
    st.error(f"Failed to read onboarding status: {exc}")
    st.stop()

if not status.get("needs_onboarding", True):
    st.success("Onboarding is already completed.")
    st.stop()

st.info("Set up your first tenant, provider, and admin user.")

with st.form("onboarding_form"):
    tenant_name = st.text_input("Tenant Name", value="Acme Corp")
    admin_external_user = st.text_input("Initial Admin User (X-User)", value="admin.acme")
    admin_password = st.text_input("Initial Admin Password (for JWT mode)", value="", type="password")
    provider = st.selectbox("Provider", ["gemini", "openai", "groq", "anthropic"], index=0)
    if provider == "gemini":
        model_default = "models/gemini-2.0-flash"
    elif provider == "openai":
        model_default = "gpt-4.1-mini"
    elif provider == "groq":
        model_default = "llama-3.1-8b-instant"
    else:
        model_default = "claude-3-5-haiku-latest"
    model = st.text_input("Model", value=model_default)
    base_url_default = "https://api.groq.com/openai/v1" if provider == "groq" else ""
    provider_base_url = st.text_input("Base URL (optional)", value=base_url_default)
    api_key = st.text_input("Provider API Key", type="password", value="")
    submitted = st.form_submit_button("Complete Onboarding")

if submitted:
    try:
        result = bootstrap(
            base_url,
            tenant_name=tenant_name,
            admin_external_user=admin_external_user,
            admin_password=admin_password,
            provider=provider,
            model=model,
            api_key=api_key,
            provider_base_url=provider_base_url,
        )
    except Exception as exc:
        st.error(f"Onboarding failed: {exc}")
    else:
        st.success("Onboarding complete.")
        st.json(result)
