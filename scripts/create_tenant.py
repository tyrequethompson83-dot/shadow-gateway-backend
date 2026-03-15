import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from enterprise.db_enterprise import create_tenant, ensure_enterprise_schema


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "Tenant 2"
    ensure_enterprise_schema()
    tenant_id = create_tenant(name)

    print(f"created tenant id={tenant_id} name={name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
