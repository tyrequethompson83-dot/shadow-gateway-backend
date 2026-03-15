import streamlit as st

from db import (
    init_db,
    list_tenants,
)
from enterprise.db_enterprise import ensure_enterprise_schema
from risk_dashboard_ui import render_risk_dashboard


def main() -> None:
    st.set_page_config(page_title="Shadow Gateway Dashboard", layout="wide")
    st.title("Shadow AI Gateway - Risk Dashboard")

    init_db()
    ensure_enterprise_schema()

    tenants = list_tenants()
    default_index = 0
    for i, t in enumerate(tenants):
        if int(t["id"]) == 1:
            default_index = i
            break

    selected_tenant = st.selectbox(
        "Tenant",
        tenants,
        index=default_index,
        format_func=lambda t: f"{t['id']} - {t['name']}",
    )
    tenant_id = int(selected_tenant["id"])

    render_risk_dashboard(tenant_id=tenant_id, show_caption_tip=True)


if __name__ == "__main__":
    main()
