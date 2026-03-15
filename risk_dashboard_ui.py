import json

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

from db import get_recent_requests, get_summary
from enterprise.db_enterprise import write_audit_log
from report_generator import generate_report


def render_risk_dashboard(tenant_id: int, *, show_caption_tip: bool = False) -> None:
    tenant_id = int(tenant_id)

    # -------------------------
    # Top KPIs
    # -------------------------
    summary = get_summary(tenant_id=tenant_id)
    recent = get_recent_requests(tenant_id=tenant_id, limit=200)

    avg_risk = 0.0
    blocked = 0
    if recent:
        df_recent = pd.DataFrame(recent)
        if "risk_score" in df_recent.columns:
            avg_risk = float(df_recent["risk_score"].mean())
        if "decision" in df_recent.columns:
            blocked = int((df_recent["decision"] == "BLOCK").sum())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Requests", summary["total_requests"])
    c2.metric("High/Critical", summary["high_or_critical"])
    c3.metric("Blocked", blocked)
    c4.metric("Avg Risk Score", f"{avg_risk:.1f}")

    st.divider()

    # -------------------------
    # Category Totals
    # -------------------------
    st.subheader("Redaction Categories Totals")
    rows_for_categories = get_recent_requests(tenant_id=tenant_id, limit=2000)
    category_totals: dict[str, int] = {}
    for row in rows_for_categories:
        raw = row.get("risk_categories_json")
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    category_totals[str(k)] = category_totals.get(str(k), 0) + int(v or 0)
        except Exception:
            continue

    if not category_totals:
        st.info("No category totals yet.")
    else:
        df_categories = pd.DataFrame(
            [{"category": k, "count": v} for k, v in category_totals.items()]
        ).sort_values("count", ascending=False)
        left, right = st.columns([1, 1])
        with left:
            st.dataframe(df_categories, use_container_width=True, hide_index=True)
        with right:
            fig = plt.figure()
            plt.bar(df_categories["category"], df_categories["count"])
            plt.xticks(rotation=45, ha="right")
            plt.tight_layout()
            st.pyplot(fig)

    st.divider()

    # -------------------------
    # Severity Trend Over Time
    # -------------------------
    st.subheader("Severity Trend Over Time")
    trend_rows = get_recent_requests(tenant_id=tenant_id, limit=5000)
    if not trend_rows:
        st.info("No trend data yet.")
    else:
        records = []
        for row in trend_rows:
            ts = str(row.get("ts") or "")[:10]
            sev = str(row.get("severity") or row.get("risk_level") or "LOW").upper()
            if ts:
                records.append({"date": ts, "severity": sev, "count": 1})
        if not records:
            st.info("No severity data yet.")
        else:
            df = pd.DataFrame(records)
            pivot = (
                df.groupby(["date", "severity"], as_index=False)["count"]
                .sum()
                .pivot(index="date", columns="severity", values="count")
                .fillna(0)
                .sort_index()
            )
            st.dataframe(pivot.reset_index(), use_container_width=True, hide_index=True)
            fig = plt.figure()
            for severity in pivot.columns:
                plt.plot(pivot.index, pivot[severity], marker="o", label=severity)
            plt.xticks(rotation=45, ha="right")
            plt.ylabel("Requests")
            plt.legend()
            plt.tight_layout()
            st.pyplot(fig)

    st.divider()

    # -------------------------
    # Recent Requests
    # -------------------------
    st.subheader("Recent Requests")
    rows = get_recent_requests(tenant_id=tenant_id, limit=100)
    if not rows:
        st.info("No requests logged yet.")
    else:
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

    st.divider()

    # -------------------------
    # Export Report Button
    # -------------------------
    st.subheader("Export Risk Report")
    col_a, col_b = st.columns([1, 2])

    with col_a:
        if st.button("Generate PDF Report", key=f"generate_report_{tenant_id}"):
            path = generate_report(tenant_id=tenant_id)
            st.success(f"Report generated: {path}")

            try:
                write_audit_log(
                    tenant_id=tenant_id,
                    user_id=None,
                    action="report.exported",
                    target_type="report",
                    target_id=path.split("/")[-1],
                    metadata={"format": "pdf", "path": path, "tenant_id": tenant_id},
                )
            except Exception:
                pass

            with open(path, "rb") as f:
                st.download_button(
                    label="Download report",
                    data=f,
                    file_name=path.split("\\")[-1].split("/")[-1],
                    mime="application/pdf",
                    key=f"download_report_{tenant_id}",
                )

    with col_b:
        if show_caption_tip:
            st.caption("Tip: Pick a tenant, run requests for that tenant, then export.")
