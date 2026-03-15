import csv
import json
import os
import zipfile
from datetime import datetime
from io import StringIO
from typing import Dict

from db import get_compliance_snapshot, init_db


def _stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def generate_compliance_report(tenant_id: int, out_dir: str = "reports") -> str:
    init_db()
    os.makedirs(out_dir, exist_ok=True)
    snapshot = get_compliance_snapshot(tenant_id=int(tenant_id))
    stamp = _stamp()

    csv_name = f"compliance_tenant_{tenant_id}_{stamp}.csv"
    json_name = f"compliance_tenant_{tenant_id}_{stamp}.json"
    zip_name = f"compliance_tenant_{tenant_id}_{stamp}.zip"

    csv_buf = StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(["metric", "value"])
    writer.writerow(["tenant_id", snapshot["tenant_id"]])
    writer.writerow(["total_requests", snapshot["total_requests"]])
    writer.writerow(["allowed", snapshot["allowed"]])
    writer.writerow(["redacted", snapshot["redacted"]])
    writer.writerow(["blocked", snapshot["blocked"]])
    writer.writerow(["injection_attempts", snapshot["injection_attempts"]])
    for category, value in sorted(snapshot["redactions_by_category"].items()):
        writer.writerow([f"redactions_by_category.{category}", value])
    for severity, value in sorted(snapshot["risk_distribution"].items()):
        writer.writerow([f"risk_distribution.{severity}", value])
    for provider, value in sorted(snapshot["provider_usage"].items()):
        writer.writerow([f"provider_usage.{provider}", value])
    for model, value in sorted(snapshot["model_usage"].items()):
        writer.writerow([f"model_usage.{model}", value])
    for idx, user_row in enumerate(snapshot["top_users"], start=1):
        writer.writerow([f"top_user_{idx}", f"{user_row['user']}:{user_row['count']}"])

    json_text = json.dumps(snapshot, indent=2, ensure_ascii=False)

    out_zip = os.path.join(out_dir, zip_name)
    with zipfile.ZipFile(out_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(csv_name, csv_buf.getvalue())
        zf.writestr(json_name, json_text)

    return out_zip
