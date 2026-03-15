import os
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from db import get_recent_requests, get_summary, init_db


def generate_report(tenant_id: int = 1, out_path: str = None) -> str:
    init_db()
    os.makedirs("reports", exist_ok=True)

    if not out_path:
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        out_path = os.path.join("reports", f"ai_risk_report_tenant_{tenant_id}_{stamp}.pdf")

    doc = SimpleDocTemplate(out_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("AI Usage Risk Report (Shadow AI Gateway)", styles["Heading1"]))
    elements.append(Paragraph(f"Tenant ID: {tenant_id}", styles["BodyText"]))
    elements.append(Spacer(1, 0.2 * inch))

    s = get_summary(tenant_id=tenant_id)
    elements.append(Paragraph(f"Total requests: {s['total_requests']}", styles["BodyText"]))
    elements.append(Paragraph(f"High/Critical: {s['high_or_critical']}", styles["BodyText"]))
    elements.append(Spacer(1, 0.2 * inch))

    elements.append(Paragraph("Recent Activity (last 25)", styles["Heading2"]))
    elements.append(Spacer(1, 0.1 * inch))

    recent = get_recent_requests(tenant_id=tenant_id, limit=25)
    if not recent:
        elements.append(Paragraph("No data yet.", styles["BodyText"]))
    else:
        for r in recent:
            line = (
                f"{r.get('ts', '')} - {r.get('user', '')} - {r.get('purpose', '')} - "
                f"{r.get('risk_level', '')} ({r.get('risk_score', '')}) - "
                f"{r.get('detections_count', 0)} detections"
            )
            elements.append(Paragraph(line, styles["BodyText"]))

    doc.build(elements)
    return out_path


if __name__ == "__main__":
    path = generate_report()
    print(f"Report saved to: {path}")
