import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _env(name: str) -> str:
    return (os.getenv(name, "") or "").strip()


def _app_env() -> str:
    raw = _env("APP_ENV").lower()
    return raw or "dev"


def _is_strict_env() -> bool:
    return _app_env() != "dev"


def _info(message: str) -> None:
    print(f"[prestart] {message}", file=sys.stderr)


def _warn(message: str) -> None:
    print(f"[prestart][warn] {message}", file=sys.stderr)


def _fail(message: str) -> None:
    print(f"[prestart][error] {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_runtime_config() -> None:
    jwt_secret = _env("JWT_SECRET")
    master_key = _env("MASTER_KEY") or _env("SHADOW_MASTER_KEY")
    allowed_origins = _env("ALLOWED_ORIGINS")

    if _is_strict_env():
        if len(jwt_secret) < 32:
            _fail("JWT_SECRET must be set and at least 32 characters when APP_ENV is not dev.")
        if len(master_key) < 32:
            _fail("MASTER_KEY (or SHADOW_MASTER_KEY) must be set and at least 32 characters when APP_ENV is not dev.")
        if not allowed_origins:
            _fail("ALLOWED_ORIGINS must be set when APP_ENV is not dev.")
        return

    if len(jwt_secret) < 32:
        _warn("JWT_SECRET is missing or short; dev fallback token secret behavior is active.")
    if len(master_key) < 32:
        _warn("MASTER_KEY/SHADOW_MASTER_KEY is missing or short; encryption at rest may be disabled in dev.")
    if not allowed_origins:
        _warn("ALLOWED_ORIGINS is empty; dev CORS fallback is active.")


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _column_exists(conn: sqlite3.Connection, table_name: str, column_name: str) -> bool:
    if not _table_exists(conn, table_name):
        return False
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return any(str(row[1]) == column_name for row in rows)


def _default_tenant_exists(conn: sqlite3.Connection) -> bool:
    if not _table_exists(conn, "tenants"):
        return False
    row = conn.execute(
        "SELECT 1 FROM tenants WHERE name = 'Default Tenant' LIMIT 1"
    ).fetchone()
    return row is not None


def _is_effectively_applied(conn: sqlite3.Connection, migration_name: str) -> bool:
    if migration_name == "001_enterprise_foundations.sql":
        return (
            _table_exists(conn, "tenants")
            and _table_exists(conn, "users")
            and _table_exists(conn, "memberships")
            and _table_exists(conn, "audit_logs")
        )

    if migration_name == "002_seed_default_tenant.sql":
        return _default_tenant_exists(conn)

    if migration_name == "003_requests_tenant.sql":
        if not _table_exists(conn, "requests"):
            return True
        return _column_exists(conn, "requests", "tenant_id")

    if migration_name == "004_audit_chain.sql":
        return (
            _column_exists(conn, "audit_logs", "prev_hash")
            and _column_exists(conn, "audit_logs", "row_hash")
            and _column_exists(conn, "audit_logs", "chain_id")
        )

    if migration_name == "005_usage_quota.sql":
        return _table_exists(conn, "tenant_usage_daily") and _table_exists(conn, "tenant_limits")

    if migration_name == "006_jobs.sql":
        return _table_exists(conn, "jobs")

    if migration_name == "007_product_auth.sql":
        return (
            _column_exists(conn, "users", "email")
            and _column_exists(conn, "tenants", "is_personal")
            and _table_exists(conn, "invite_tokens")
        )

    if migration_name == "008_invite_multi_use.sql":
        return (
            _column_exists(conn, "invite_tokens", "max_uses")
            and _column_exists(conn, "invite_tokens", "uses_count")
        )

    if migration_name == "009_tenant_provider_keys.sql":
        return _table_exists(conn, "tenant_provider_keys")

    return False


def _record_applied(conn: sqlite3.Connection, migration_name: str) -> None:
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (filename, applied_at)
        VALUES (?, ?)
        """,
        (migration_name, _now_utc()),
    )
    conn.commit()


def apply_sql_migrations(db_path: str, migrations_dir: str) -> None:
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    migrations_path = Path(migrations_dir)
    if not migrations_path.exists():
        _fail(f"Migrations directory does not exist: {migrations_dir}")

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
              filename TEXT PRIMARY KEY,
              applied_at TEXT NOT NULL
            )
            """
        )
        conn.commit()

        rows = conn.execute("SELECT filename FROM schema_migrations").fetchall()
        applied = {str(row[0]) for row in rows}

        migration_files = sorted(migrations_path.glob("*.sql"), key=lambda p: p.name)
        if not migration_files:
            _warn(f"No migration files found under {migrations_dir}.")
            return

        for migration_file in migration_files:
            migration_name = migration_file.name
            if migration_name in applied:
                continue

            if _is_effectively_applied(conn, migration_name):
                _info(f"Migration already present in schema, marking applied: {migration_name}")
                _record_applied(conn, migration_name)
                continue

            _info(f"Applying migration: {migration_name}")
            sql = migration_file.read_text(encoding="utf-8")
            try:
                conn.executescript(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?)",
                    (migration_name, _now_utc()),
                )
                conn.commit()
            except sqlite3.Error as exc:
                conn.rollback()
                _fail(f"Migration failed ({migration_name}): {exc}")
    finally:
        conn.close()

    _info("Migrations complete.")


def main() -> None:
    validate_runtime_config()

    db_path = _env("DB_PATH") or "/data/app.db"
    migrations_dir = _env("MIGRATIONS_DIR") or "/app/migrations"
    _info(f"Using DB_PATH={db_path}")
    _info(f"Using MIGRATIONS_DIR={migrations_dir}")
    apply_sql_migrations(db_path=db_path, migrations_dir=migrations_dir)


if __name__ == "__main__":
    main()
