import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from enterprise.db_enterprise import ensure_enterprise_schema, list_tenants, verify_audit_chain


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Verify tamper-evident audit hash chains.")
    p.add_argument("--tenant-id", type=int, default=None, help="Verify one tenant id. Omit to verify all tenants.")
    p.add_argument("--limit", type=int, default=None, help="Verify last N rows per tenant. Omit to verify all rows.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    ensure_enterprise_schema()

    if args.tenant_id is not None:
        tenant_ids = [int(args.tenant_id)]
    else:
        tenant_ids = [int(t["id"]) for t in list_tenants()]

    overall_ok = True
    for tenant_id in tenant_ids:
        result = verify_audit_chain(tenant_id=tenant_id, limit=args.limit)
        print(result)
        if not result.get("ok", False):
            overall_ok = False

    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
