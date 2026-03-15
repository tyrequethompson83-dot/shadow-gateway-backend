import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:
    psycopg2 = None
    RealDictCursor = None

from provider_layer import (
    default_base_url_for_provider,
    default_model_for_provider,
    normalize_optional_base_url,
    normalize_provider_name,
    validate_model_for_provider,
)
from security_utils import (
    decrypt_secret,
    encrypt_secret,
    is_encrypted_secret,
    make_password_hash,
    mask_key_tail,
    redact_secrets,
    verify_password,
)

try:
    # Reuse the project's DB_PATH if declared in db.py so we operate on the same SQLite file.
    from db import DB_PATH
except Exception:
    DB_PATH = "app.db"

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()


DEFAULT_AUDIT_SIGNING_KEY = "dev-audit-key-change-me"


def _env_int(name: str, default: int) -> int:
    raw = str(os.getenv(name, str(default)) or "").strip()
    try:
        value = int(raw)
    except Exception:
        value = int(default)
    return value


DEFAULT_DAILY_REQUESTS_LIMIT = max(1, _env_int("TENANT_RPD_DEFAULT", 2000))
DEFAULT_RPM_LIMIT = max(1, _env_int("TENANT_RPM_DEFAULT", 60))
DEFAULT_DAILY_TOKEN_LIMIT = max(0, _env_int("TENANT_MAX_TOKENS_DEFAULT", 200000))
DEFAULT_PROVIDER = "gemini"
ROUTING_PROVIDER_PRIORITY = ("gemini", "openai", "groq", "anthropic")
KEY_PROVIDER_PRIORITY = ROUTING_PROVIDER_PRIORITY + ("tavily",)
PLATFORM_ADMIN_ROLE = "platform_admin"

POLICY_ACTIONS = {"allow", "redact", "block"}
POLICY_BLOCK_THRESHOLDS = {"high", "critical"}
DEFAULT_TENANT_POLICY_SETTINGS: Dict[str, Any] = {
    "pii_action": "redact",
    "financial_action": "redact",
    "secrets_action": "block",
    "health_action": "redact",
    "ip_action": "redact",
    "block_threshold": "critical",
    "store_original_prompt": True,
    "show_sanitized_prompt_admin": True,
}


def _safe_provider_name(provider: Any) -> Optional[str]:
    value = str(provider or "").strip().lower()
    if value in ROUTING_PROVIDER_PRIORITY:
        return value
    return None


def _safe_key_provider(provider: Any) -> Optional[str]:
    value = str(provider or "").strip().lower()
    if value in KEY_PROVIDER_PRIORITY:
        return value
    return None


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_row_hash(payload: Dict[str, Any], prev_hash: str, signing_key: str) -> str:
    """
    Deterministic audit row hash:
      HMAC_SHA256(signing_key, canonical_payload + "|" + prev_hash)
    """
    canonical_payload = _canonical_json(payload)
    message = f"{canonical_payload}|{prev_hash or ''}".encode("utf-8")
    return hmac.new(signing_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


@contextmanager
def get_conn():
    if DATABASE_URL and psycopg2:
        pg_conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        pg_conn.autocommit = True

        class PGWrapper:
            def __init__(self, conn):
                self.conn = conn

            def execute(self, sql: str, params: Any = None):
                translated = sql.replace("?", "%s")
                cur = self.conn.cursor()
                cur.execute(translated, params or [])
                return cur

            def executemany(self, sql: str, seq):
                translated = sql.replace("?", "%s")
                cur = self.conn.cursor()
                cur.executemany(translated, seq)
                return cur

            def commit(self):
                try:
                    self.conn.commit()
                except Exception:
                    pass

            def close(self):
                try:
                    self.conn.close()
                except Exception:
                    pass

        wrapper = PGWrapper(pg_conn)
        try:
            yield wrapper
        finally:
            wrapper.commit()
            wrapper.close()
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
            conn.commit()
        finally:
            conn.close()


def _table_columns(conn: sqlite3.Connection, table_name: str) -> List[str]:
    rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
    return [r[1] for r in rows]


def _normalize_role_name(role: str) -> str:
    role_name = (role or "").strip()
    if role_name == "admin":
        return PLATFORM_ADMIN_ROLE
    return role_name


def _backfill_provider_keys_from_legacy(conn: sqlite3.Connection) -> None:
    """
    Best-effort migration from legacy tenant_provider_configs.api_key into
    tenant_provider_keys. This preserves current behavior while centralizing
    key storage per-tenant/per-provider.
    """
    tables = {
        str(r[0])
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    if "tenant_provider_configs" not in tables or "tenant_provider_keys" not in tables:
        return

    rows = conn.execute(
        """
        SELECT tenant_id, provider, api_key, api_key_tail, created_at, updated_at
        FROM tenant_provider_configs
        WHERE COALESCE(api_key, '') != ''
        """
    ).fetchall()
    for row in rows:
        tenant_id = int(row["tenant_id"])
        provider = _safe_provider_name(row["provider"])
        if not provider:
            continue
        raw_key = (row["api_key"] or "").strip()
        if not raw_key:
            continue

        api_key_enc = raw_key
        api_key_tail = (row["api_key_tail"] or "").strip() or None

        if not is_encrypted_secret(api_key_enc):
            api_key_tail = mask_key_tail(raw_key)
            api_key_enc = encrypt_secret(raw_key)
        elif not api_key_tail:
            try:
                api_key_tail = mask_key_tail(decrypt_secret(api_key_enc))
            except ValueError:
                api_key_tail = None

        created_at = row["created_at"] or _utcnow_iso()
        updated_at = row["updated_at"] or _utcnow_iso()
        conn.execute(
            """
            INSERT INTO tenant_provider_keys
              (tenant_id, provider, api_key_enc, api_key_tail, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, provider) DO NOTHING
            """,
            (tenant_id, provider, api_key_enc, api_key_tail, created_at, updated_at),
        )
        conn.execute(
            """
            UPDATE tenant_provider_configs
            SET api_key = '', api_key_tail = COALESCE(api_key_tail, ?), updated_at = ?
            WHERE tenant_id = ? AND provider = ?
            """,
            (api_key_tail, _utcnow_iso(), tenant_id, provider),
        )


def _backfill_audit_chain_if_needed(conn: sqlite3.Connection) -> None:
    """
    Backfill chain fields for tenants that still have unchained rows.
    This runs only when at least one row has missing chain fields.
    """
    signing_key = os.getenv("AUDIT_SIGNING_KEY", "").strip() or DEFAULT_AUDIT_SIGNING_KEY
    tenants = conn.execute(
        """
        SELECT DISTINCT tenant_id
        FROM audit_logs
        WHERE row_hash IS NULL OR prev_hash IS NULL OR chain_id IS NULL
        ORDER BY tenant_id ASC
        """
    ).fetchall()
    for tenant_row in tenants:
        tenant_id = int(tenant_row["tenant_id"])
        chain_id = f"tenant-{tenant_id}"
        prev_hash = ""
        rows = conn.execute(
            """
            SELECT id, tenant_id, user_id, action, target_type, target_id, metadata_json,
                   ip, user_agent, request_id, created_at
            FROM audit_logs
            WHERE tenant_id = ?
            ORDER BY id ASC
            """,
            (tenant_id,),
        ).fetchall()
        for row in rows:
            payload = {
                "tenant_id": int(row["tenant_id"]),
                "user_id": row["user_id"],
                "action": row["action"],
                "target_type": row["target_type"],
                "target_id": row["target_id"],
                "metadata_json": row["metadata_json"] or "{}",
                "ip": row["ip"],
                "user_agent": row["user_agent"],
                "request_id": row["request_id"],
                "created_at": row["created_at"],
                "chain_id": chain_id,
            }
            row_hash = compute_row_hash(payload=payload, prev_hash=prev_hash, signing_key=signing_key)
            conn.execute(
                """
                UPDATE audit_logs
                SET prev_hash = ?, row_hash = ?, chain_id = ?
                WHERE id = ?
                """,
                (prev_hash, row_hash, chain_id, int(row["id"])),
            )
            prev_hash = row_hash


def ensure_enterprise_schema() -> None:
    """Create enterprise tables if they do not exist and apply additive migrations."""
    with get_conn() as conn:
        # Core tables
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenants (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              external_id TEXT UNIQUE,
              username TEXT UNIQUE,
              display_name TEXT,
              password_hash TEXT,
              password_salt TEXT,
              is_active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS memberships (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id INTEGER NOT NULL,
              user_id INTEGER NOT NULL,
              role TEXT NOT NULL CHECK(role IN ('platform_admin','admin','auditor','user','tenant_admin','employee')),
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              UNIQUE(tenant_id, user_id),
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id INTEGER NOT NULL,
              user_id INTEGER,
              action TEXT NOT NULL,
              target_type TEXT,
              target_id TEXT,
              metadata_json TEXT,
              ip TEXT,
              user_agent TEXT,
              request_id TEXT,
              prev_hash TEXT,
              row_hash TEXT,
              chain_id TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )

        # Additive columns for older DBs
        audit_cols = _table_columns(conn, "audit_logs")
        if "prev_hash" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT")
        if "row_hash" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN row_hash TEXT")
        if "chain_id" not in audit_cols:
            conn.execute("ALTER TABLE audit_logs ADD COLUMN chain_id TEXT")

        _backfill_audit_chain_if_needed(conn)

        # Additive columns for users table
        user_cols = _table_columns(conn, "users")
        if "username" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN username TEXT")
        if "password_hash" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        if "password_salt" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN password_salt TEXT")
        if "is_active" not in user_cols:
            conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

        memberships_sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='memberships'"
        ).fetchone()
        memberships_sql = (memberships_sql_row[0] if memberships_sql_row and memberships_sql_row[0] else "").lower()
        if "platform_admin" not in memberships_sql or "tenant_admin" not in memberships_sql:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS memberships_v2 (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  tenant_id INTEGER NOT NULL,
                  user_id INTEGER NOT NULL,
                  role TEXT NOT NULL CHECK(role IN ('platform_admin','admin','auditor','user','tenant_admin','employee')),
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  UNIQUE(tenant_id, user_id),
                  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
                  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO memberships_v2 (id, tenant_id, user_id, role, created_at)
                SELECT
                  id,
                  tenant_id,
                  user_id,
                  CASE
                    WHEN role = 'admin' THEN 'platform_admin'
                    WHEN role IN ('platform_admin', 'auditor', 'user', 'tenant_admin', 'employee') THEN role
                    ELSE 'user'
                  END,
                  created_at
                FROM memberships
                """
            )
            conn.execute("DROP TABLE memberships")
            conn.execute("ALTER TABLE memberships_v2 RENAME TO memberships")

        # Additive columns for provider config (if table already exists in legacy DB)
        existing_tables = {
            str(r[0]) for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        provider_cols: List[str] = []
        if "tenant_provider_configs" in existing_tables:
            provider_cols = _table_columns(conn, "tenant_provider_configs")
            if "api_key_tail" not in provider_cols:
                conn.execute("ALTER TABLE tenant_provider_configs ADD COLUMN api_key_tail TEXT")
            if "base_url" not in provider_cols:
                conn.execute("ALTER TABLE tenant_provider_configs ADD COLUMN base_url TEXT")
            provider_cols = _table_columns(conn, "tenant_provider_configs")

        # Limits and usage
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_usage_daily (
              tenant_id INTEGER NOT NULL,
              day TEXT NOT NULL,
              request_count INTEGER NOT NULL DEFAULT 0,
              token_count INTEGER NOT NULL DEFAULT 0,
              blocked_count INTEGER NOT NULL DEFAULT 0,
              risk_sum INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL,
              PRIMARY KEY (tenant_id, day),
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            )
            """
        )
        usage_cols = _table_columns(conn, "tenant_usage_daily")
        if "token_count" not in usage_cols:
            conn.execute("ALTER TABLE tenant_usage_daily ADD COLUMN token_count INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_limits (
              tenant_id INTEGER PRIMARY KEY,
              daily_requests_limit INTEGER NOT NULL,
              rpm_limit INTEGER NOT NULL,
              enabled INTEGER NOT NULL DEFAULT 1,
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_provider_configs (
              tenant_id INTEGER PRIMARY KEY,
              provider TEXT NOT NULL CHECK(provider IN ('gemini','openai','groq','anthropic')),
              model TEXT NOT NULL,
              api_key TEXT,
              api_key_tail TEXT,
              base_url TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_provider_keys (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id INTEGER NOT NULL,
              provider TEXT NOT NULL CHECK(provider IN ('gemini','openai','groq','anthropic')),
              api_key_enc TEXT NOT NULL,
              api_key_tail TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now')),
              UNIQUE(tenant_id, provider),
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            )
            """
        )
        provider_sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='tenant_provider_configs'"
        ).fetchone()
        provider_sql = (provider_sql_row[0] if provider_sql_row and provider_sql_row[0] else "").lower()
        provider_cols = _table_columns(conn, "tenant_provider_configs")
        needs_provider_cfg_rebuild = (
            "openai" not in provider_sql
            or "anthropic" not in provider_sql
            or "groq" not in provider_sql
            or "base_url" not in provider_cols
        )
        if needs_provider_cfg_rebuild:
            has_tail_col = "api_key_tail" in provider_cols
            has_base_url_col = "base_url" in provider_cols
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_provider_configs_v2 (
                  tenant_id INTEGER PRIMARY KEY,
                  provider TEXT NOT NULL CHECK(provider IN ('gemini','openai','groq','anthropic')),
                  model TEXT NOT NULL,
                  api_key TEXT,
                  api_key_tail TEXT,
                  base_url TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
                """
            )
            if has_tail_col and has_base_url_col:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tenant_provider_configs_v2
                      (tenant_id, provider, model, api_key, api_key_tail, base_url, created_at, updated_at)
                    SELECT
                      tenant_id,
                      provider,
                      model,
                      api_key,
                      COALESCE(api_key_tail, ''),
                      NULLIF(TRIM(base_url), ''),
                      created_at,
                      updated_at
                    FROM tenant_provider_configs
                    """
                )
            elif has_tail_col:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tenant_provider_configs_v2
                      (tenant_id, provider, model, api_key, api_key_tail, base_url, created_at, updated_at)
                    SELECT
                      tenant_id,
                      provider,
                      model,
                      api_key,
                      COALESCE(api_key_tail, ''),
                      NULL,
                      created_at,
                      updated_at
                    FROM tenant_provider_configs
                    """
                )
            else:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO tenant_provider_configs_v2
                      (tenant_id, provider, model, api_key, api_key_tail, base_url, created_at, updated_at)
                    SELECT
                      tenant_id,
                      provider,
                      model,
                      api_key,
                      '',
                      NULL,
                      created_at,
                      updated_at
                    FROM tenant_provider_configs
                    """
                )
            conn.execute("DROP TABLE tenant_provider_configs")
            conn.execute("ALTER TABLE tenant_provider_configs_v2 RENAME TO tenant_provider_configs")

        provider_keys_sql_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='tenant_provider_keys'"
        ).fetchone()
        provider_keys_sql = (provider_keys_sql_row[0] if provider_keys_sql_row and provider_keys_sql_row[0] else "").lower()
        needs_provider_keys_rebuild = (
            "openai" not in provider_keys_sql
            or "anthropic" not in provider_keys_sql
            or "groq" not in provider_keys_sql
        )
        if needs_provider_keys_rebuild:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_provider_keys_v2 (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  tenant_id INTEGER NOT NULL,
                  provider TEXT NOT NULL CHECK(provider IN ('gemini','openai','groq','anthropic')),
                  api_key_enc TEXT NOT NULL,
                  api_key_tail TEXT,
                  created_at TEXT NOT NULL DEFAULT (datetime('now')),
                  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                  UNIQUE(tenant_id, provider),
                  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                """
                INSERT OR REPLACE INTO tenant_provider_keys_v2
                  (id, tenant_id, provider, api_key_enc, api_key_tail, created_at, updated_at)
                SELECT
                  id, tenant_id, provider, api_key_enc, api_key_tail, created_at, updated_at
                FROM tenant_provider_keys
                """
            )
            conn.execute("DROP TABLE tenant_provider_keys")
            conn.execute("ALTER TABLE tenant_provider_keys_v2 RENAME TO tenant_provider_keys")
        conn.execute("DELETE FROM tenant_provider_keys WHERE provider = 'mock'")
        conn.execute("DELETE FROM tenant_provider_configs WHERE provider = 'mock'")
        _backfill_provider_keys_from_legacy(conn)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_policies (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id INTEGER NOT NULL,
              rule_type TEXT NOT NULL CHECK(rule_type IN ('injection','category','severity')),
              match TEXT NOT NULL,
              action TEXT NOT NULL CHECK(action IN ('ALLOW','REDACT','BLOCK')),
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tenant_policy_settings (
              tenant_id INTEGER PRIMARY KEY,
              pii_action TEXT NOT NULL DEFAULT 'redact',
              financial_action TEXT NOT NULL DEFAULT 'redact',
              secrets_action TEXT NOT NULL DEFAULT 'block',
              health_action TEXT NOT NULL DEFAULT 'redact',
              ip_action TEXT NOT NULL DEFAULT 'redact',
              block_threshold TEXT NOT NULL DEFAULT 'critical',
              store_original_prompt INTEGER NOT NULL DEFAULT 1,
              show_sanitized_prompt_admin INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              updated_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            )
            """
        )

        # Jobs
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY,
              tenant_id INTEGER NOT NULL,
              user_id INTEGER,
              type TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('queued','running','done','failed')),
              input_json TEXT,
              output_path TEXT,
              error TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )

        # Indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_memberships_tenant_role ON memberships(tenant_id, role)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_chain_id ON audit_logs(tenant_id, chain_id, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_tenant_day ON tenant_usage_daily(tenant_id, day)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_provider_cfg_provider ON tenant_provider_configs(provider)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_provider_cfg_tenant ON tenant_provider_configs(tenant_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_provider_keys_tenant ON tenant_provider_keys(tenant_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_tenant_type ON tenant_policies(tenant_id, rule_type, enabled)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_tenant_created ON jobs(tenant_id, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status_created ON jobs(status, created_at)")

        # Seed default tenant if missing
        conn.execute(
            """
            INSERT INTO tenants (name)
            SELECT 'Default Tenant'
            WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE name = 'Default Tenant')
            """
        )

        # Seed limits for all existing tenants if missing
        conn.execute(
            """
            INSERT INTO tenant_limits (tenant_id, daily_requests_limit, rpm_limit, enabled)
            SELECT t.id, ?, ?, 1
            FROM tenants t
            LEFT JOIN tenant_limits l ON l.tenant_id = t.id
            WHERE l.tenant_id IS NULL
            """,
            (DEFAULT_DAILY_REQUESTS_LIMIT, DEFAULT_RPM_LIMIT),
        )
        conn.execute(
            """
            INSERT INTO tenant_policy_settings (
              tenant_id,
              pii_action,
              financial_action,
              secrets_action,
              health_action,
              ip_action,
              block_threshold,
              store_original_prompt,
              show_sanitized_prompt_admin,
              created_at,
              updated_at
            )
            SELECT
              t.id,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?
            FROM tenants t
            LEFT JOIN tenant_policy_settings s ON s.tenant_id = t.id
            WHERE s.tenant_id IS NULL
            """,
            (
                str(DEFAULT_TENANT_POLICY_SETTINGS["pii_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["financial_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["secrets_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["health_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["ip_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["block_threshold"]),
                int(bool(DEFAULT_TENANT_POLICY_SETTINGS["store_original_prompt"])),
                int(bool(DEFAULT_TENANT_POLICY_SETTINGS["show_sanitized_prompt_admin"])),
                _utcnow_iso(),
                _utcnow_iso(),
            ),
        )

        conn.execute(
            """
            UPDATE users
            SET username = external_id
            WHERE (username IS NULL OR username = '')
              AND external_id IS NOT NULL
              AND external_id != ''
            """
        )

        now = _utcnow_iso()
        conn.execute(
            """
            INSERT INTO tenant_policies (tenant_id, rule_type, match, action, enabled, created_at, updated_at)
            SELECT t.id, 'injection', 'PROMPT_INJECTION', 'BLOCK', 1, ?, ?
            FROM tenants t
            LEFT JOIN tenant_policies p
              ON p.tenant_id = t.id
             AND p.rule_type = 'injection'
             AND p.match = 'PROMPT_INJECTION'
            WHERE p.id IS NULL
            """,
            (now, now),
        )


def ensure_user(external_id: Optional[str]) -> Optional[int]:
    if not external_id:
        return None
    ensure_enterprise_schema()
    with get_conn() as conn:
        cur = conn.execute("SELECT id, username FROM users WHERE external_id = ?", (external_id,))
        row = cur.fetchone()
        if row:
            if not row["username"]:
                conn.execute("UPDATE users SET username = ? WHERE id = ?", (external_id, int(row["id"])))
            return int(row["id"])
        cur = conn.execute(
            "INSERT INTO users (external_id, username, display_name) VALUES (?, ?, ?)",
            (external_id, external_id, external_id),
        )
        return int(cur.lastrowid)


def get_default_tenant_id() -> int:
    ensure_enterprise_schema()
    with get_conn() as conn:
        cur = conn.execute("SELECT id FROM tenants ORDER BY id ASC LIMIT 1")
        row = cur.fetchone()
        if row:
            return int(row["id"])
        cur = conn.execute("INSERT INTO tenants (name) VALUES ('Default Tenant')")
        return int(cur.lastrowid)


def create_tenant(name: str) -> int:
    ensure_enterprise_schema()
    name = (name or "").strip() or "Unnamed Tenant"
    with get_conn() as conn:
        cur = conn.execute("INSERT INTO tenants (name) VALUES (?)", (name,))
        tenant_id = int(cur.lastrowid)
        now = _utcnow_iso()
        conn.execute(
            """
            INSERT OR IGNORE INTO tenant_limits (tenant_id, daily_requests_limit, rpm_limit, enabled)
            VALUES (?, ?, ?, 1)
            """,
            (tenant_id, DEFAULT_DAILY_REQUESTS_LIMIT, DEFAULT_RPM_LIMIT),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO tenant_policy_settings (
              tenant_id,
              pii_action,
              financial_action,
              secrets_action,
              health_action,
              ip_action,
              block_threshold,
              store_original_prompt,
              show_sanitized_prompt_admin,
              created_at,
              updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                str(DEFAULT_TENANT_POLICY_SETTINGS["pii_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["financial_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["secrets_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["health_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["ip_action"]),
                str(DEFAULT_TENANT_POLICY_SETTINGS["block_threshold"]),
                int(bool(DEFAULT_TENANT_POLICY_SETTINGS["store_original_prompt"])),
                int(bool(DEFAULT_TENANT_POLICY_SETTINGS["show_sanitized_prompt_admin"])),
                now,
                now,
            ),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO tenant_policies (tenant_id, rule_type, match, action, enabled, created_at, updated_at)
            VALUES (?, 'injection', 'PROMPT_INJECTION', 'BLOCK', 1, ?, ?)
            """,
            (tenant_id, now, now),
        )
        return tenant_id


def list_tenants() -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        rows = conn.execute("SELECT id, name, created_at FROM tenants ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]


def _env_default_provider_config() -> Dict[str, Any]:
    raw_provider = str(os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER) or "").strip().lower()
    provider = raw_provider if raw_provider in ROUTING_PROVIDER_PRIORITY else DEFAULT_PROVIDER
    model = default_model_for_provider(provider)
    api_key = _provider_env_api_key(provider)
    base_url = default_base_url_for_provider(provider)
    return {
        "provider": provider,
        "model": model,
        "api_key": api_key,
        "api_key_tail": mask_key_tail(api_key),
        "base_url": base_url,
        "source": "env",
    }


def _provider_env_api_key(provider: str) -> str:
    provider_name = _safe_provider_name(provider)
    if not provider_name:
        return ""
    if provider_name == "gemini":
        return os.getenv("GEMINI_API_KEY", "").strip()
    if provider_name == "openai":
        return os.getenv("OPENAI_API_KEY", "").strip()
    if provider_name == "groq":
        return os.getenv("GROQ_API_KEY", "").strip()
    if provider_name == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY", "").strip()
    return ""


def upsert_tenant_key(tenant_id: int, provider: str, api_key_plain: str) -> Dict[str, Any]:
    ensure_enterprise_schema()
    provider_normalized = (provider or "").strip().lower()
    if provider_normalized == "tavily":
        provider_name = "tavily"
    else:
        provider_name = normalize_provider_name(provider)
    plain = (api_key_plain or "").strip()
    if not plain:
        raise ValueError("api_key is required")

    encrypted = encrypt_secret(plain)
    tail = mask_key_tail(plain)
    now = _utcnow_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_provider_keys (tenant_id, provider, api_key_enc, api_key_tail, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, provider) DO UPDATE SET
              api_key_enc = excluded.api_key_enc,
              api_key_tail = excluded.api_key_tail,
              updated_at = excluded.updated_at
            """,
            (int(tenant_id), provider_name, encrypted, tail, now, now),
        )
    return {
        "provider": provider_name,
        "has_key": bool(plain),
        "api_key_tail": tail,
        "updated_at": now,
    }


def list_tenant_keys(tenant_id: int) -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT provider, api_key_enc, api_key_tail, updated_at
            FROM tenant_provider_keys
            WHERE tenant_id = ?
            ORDER BY provider ASC
            """,
            (int(tenant_id),),
        ).fetchall()

    by_provider: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        provider = _safe_key_provider(row["provider"])
        if not provider:
            continue
        by_provider[provider] = {
            "provider": provider,
            "has_key": bool((row["api_key_enc"] or "").strip()),
            "api_key_tail": (row["api_key_tail"] or "").strip() or None,
            "updated_at": row["updated_at"],
        }

    ordered = KEY_PROVIDER_PRIORITY
    items: List[Dict[str, Any]] = []
    for provider in ordered:
        if provider in by_provider:
            items.append(by_provider[provider])
        else:
            items.append(
                {
                    "provider": provider,
                    "has_key": False,
                    "api_key_tail": None,
                    "updated_at": None,
                }
            )
    for provider in by_provider:
        if provider not in ordered:
            items.append(by_provider[provider])
    return items


def delete_tenant_key(tenant_id: int, provider: str) -> bool:
    ensure_enterprise_schema()
    provider_normalized = (provider or "").strip().lower()
    if provider_normalized == "tavily":
        provider_name = "tavily"
    else:
        provider_name = normalize_provider_name(provider)
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM tenant_provider_keys WHERE tenant_id = ? AND provider = ?",
            (int(tenant_id), provider_name),
        )
    return int(cur.rowcount or 0) > 0


def get_tenant_tavily_key(tenant_id: int) -> Dict[str, Any]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT api_key_enc, api_key_tail, updated_at
            FROM tenant_provider_keys
            WHERE tenant_id = ? AND provider = 'tavily'
            """,
            (int(tenant_id),),
        ).fetchone()
    if row and (row["api_key_enc"] or "").strip():
        try:
            key = decrypt_secret(row["api_key_enc"])
        except Exception:
            key = ""
        tail = (row["api_key_tail"] or "").strip() or (mask_key_tail(key) if key else None)
        return {
            "api_key": key,
            "api_key_tail": tail,
            "source": "tenant",
            "updated_at": row["updated_at"],
        }
    env_key = os.getenv("TAVILY_API_KEY", "").strip()
    return {
        "api_key": env_key,
        "api_key_tail": mask_key_tail(env_key) if env_key else None,
        "source": "env" if env_key else "none",
        "updated_at": None,
    }


def _resolve_provider_key_runtime(
    tenant_id: int,
    provider: str,
    *,
    legacy_key: Optional[str] = None,
    legacy_tail: Optional[str] = None,
) -> Dict[str, Any]:
    provider_name = normalize_provider_name(provider)

    with get_conn() as conn:
        key_row = conn.execute(
            """
            SELECT api_key_enc, api_key_tail, updated_at
            FROM tenant_provider_keys
            WHERE tenant_id = ? AND provider = ?
            """,
            (int(tenant_id), provider_name),
        ).fetchone()

    if key_row:
        stored_key = (key_row["api_key_enc"] or "").strip()
        stored_tail = (key_row["api_key_tail"] or "").strip() or None

        if stored_key and not is_encrypted_secret(stored_key):
            plain_legacy = stored_key
            encrypted = encrypt_secret(plain_legacy)
            migrated_tail = mask_key_tail(plain_legacy)
            with get_conn() as conn:
                conn.execute(
                    """
                    UPDATE tenant_provider_keys
                    SET api_key_enc = ?, api_key_tail = ?, updated_at = ?
                    WHERE tenant_id = ? AND provider = ?
                    """,
                    (encrypted, migrated_tail, _utcnow_iso(), int(tenant_id), provider_name),
                )
            stored_key = encrypted
            stored_tail = migrated_tail

        try:
            plain = decrypt_secret(stored_key)
        except ValueError:
            plain = ""
        return {
            "api_key": plain,
            "api_key_tail": stored_tail or mask_key_tail(plain),
            "source": "tenant_keys",
        }

    legacy_stored_key = (legacy_key or "").strip()
    legacy_stored_tail = (legacy_tail or "").strip() or None
    if legacy_stored_key:
        if not is_encrypted_secret(legacy_stored_key):
            plain_legacy = legacy_stored_key
            encrypted = encrypt_secret(plain_legacy)
            migrated_tail = mask_key_tail(plain_legacy)
            with get_conn() as conn:
                conn.execute(
                    """
                    UPDATE tenant_provider_configs
                    SET api_key = ?, api_key_tail = ?, updated_at = ?
                    WHERE tenant_id = ?
                    """,
                    (encrypted, migrated_tail, _utcnow_iso(), int(tenant_id)),
                )
            legacy_stored_key = encrypted
            legacy_stored_tail = migrated_tail

        try:
            plain_legacy_key = decrypt_secret(legacy_stored_key)
        except ValueError:
            plain_legacy_key = ""

        if plain_legacy_key:
            try:
                upsert_tenant_key(tenant_id=tenant_id, provider=provider_name, api_key_plain=plain_legacy_key)
                with get_conn() as conn:
                    conn.execute(
                        """
                        UPDATE tenant_provider_configs
                        SET api_key = '', api_key_tail = COALESCE(api_key_tail, ?), updated_at = ?
                        WHERE tenant_id = ?
                        """,
                        (mask_key_tail(plain_legacy_key), _utcnow_iso(), int(tenant_id)),
                    )
            except Exception:
                pass
        return {
            "api_key": plain_legacy_key,
            "api_key_tail": legacy_stored_tail or mask_key_tail(plain_legacy_key),
            "source": "legacy_config",
        }

    env_key = _provider_env_api_key(provider_name)
    return {
        "api_key": env_key,
        "api_key_tail": mask_key_tail(env_key),
        "source": "env",
    }


def get_tenant_provider_runtime_config(tenant_id: int) -> Dict[str, Any]:
    """
    Internal provider config including raw API key.
    Falls back to environment defaults when tenant config is missing.
    """
    ensure_enterprise_schema()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT tenant_id, provider, model, api_key, api_key_tail, base_url, created_at, updated_at
            FROM tenant_provider_configs
            WHERE tenant_id = ?
            """,
            (int(tenant_id),),
        ).fetchone()

    row_provider = _safe_provider_name(row["provider"]) if row else None
    row_model = (row["model"] or "").strip() if row else ""
    row_base_url = normalize_optional_base_url((row["base_url"] or "").strip()) if row else None
    row_created_at = row["created_at"] if row else None
    row_updated_at = row["updated_at"] if row else None

    if row_provider and row_model:
        try:
            normalized_row_model = validate_model_for_provider(row_provider, row_model)
        except ValueError:
            normalized_row_model = default_model_for_provider(row_provider)

        if normalized_row_model != row_model:
            row_model = normalized_row_model
            row_updated_at = _utcnow_iso()
            try:
                with get_conn() as conn:
                    conn.execute(
                        """
                        UPDATE tenant_provider_configs
                        SET model = ?, updated_at = ?
                        WHERE tenant_id = ? AND provider = ?
                        """,
                        (row_model, row_updated_at, int(tenant_id), row_provider),
                    )
            except Exception:
                pass

    candidates: List[str] = []
    if row_provider:
        candidates.append(row_provider)
    for provider in ROUTING_PROVIDER_PRIORITY:
        if provider not in candidates:
            candidates.append(provider)

    for provider in candidates:
        key_state = _resolve_provider_key_runtime(
            tenant_id=int(tenant_id),
            provider=provider,
            legacy_key=(row["api_key"] or "").strip() if row and provider == row_provider else None,
            legacy_tail=((row["api_key_tail"] or "").strip() or None) if row and provider == row_provider else None,
        )
        api_key = (key_state.get("api_key") or "").strip()
        if not api_key:
            continue

        if provider == row_provider and row_model:
            model = row_model
        else:
            model = default_model_for_provider(provider)
        if provider == row_provider:
            base_url = row_base_url
        else:
            base_url = default_base_url_for_provider(provider)
        if provider == "groq" and not base_url:
            base_url = default_base_url_for_provider("groq")
        if provider not in ("openai", "groq"):
            base_url = None

        if row and provider == row_provider:
            source = "tenant"
        elif key_state.get("source") == "env" and not row:
            source = "env"
        else:
            source = "fallback"

        return {
            "tenant_id": int(tenant_id),
            "provider": provider,
            "model": model,
            "api_key": api_key,
            "api_key_tail": key_state.get("api_key_tail") or mask_key_tail(api_key),
            "base_url": base_url,
            "source": source,
            "created_at": row_created_at,
            "updated_at": row_updated_at,
        }

    return {
        "tenant_id": int(tenant_id),
        "provider": "none",
        "model": "",
        "api_key": "",
        "api_key_tail": None,
        "base_url": None,
        "source": "none",
        "created_at": row_created_at,
        "updated_at": row_updated_at,
    }


def get_tenant_provider_config(tenant_id: int) -> Dict[str, Any]:
    """Safe provider config for API responses (key tail only, no secret decryption)."""
    runtime = get_tenant_provider_runtime_config(tenant_id)
    api_key = (runtime.get("api_key") or "").strip()
    return {
        "tenant_id": int(runtime["tenant_id"]),
        "provider": str(runtime.get("provider") or "none"),
        "model": str(runtime.get("model") or ""),
        "base_url": runtime.get("base_url"),
        "source": str(runtime.get("source") or "none"),
        "has_api_key": bool(api_key),
        "api_key_tail": runtime.get("api_key_tail"),
        "created_at": runtime.get("created_at"),
        "updated_at": runtime.get("updated_at"),
    }


def upsert_tenant_provider_config(
    tenant_id: int,
    provider: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    provider_name = normalize_provider_name(provider)
    normalized_model = validate_model_for_provider(
        provider_name,
        (model or "").strip() or default_model_for_provider(provider_name),
    )
    incoming_key = (api_key or "").strip() if api_key is not None else None
    incoming_base_url = normalize_optional_base_url(base_url)

    if incoming_key is not None:
        upsert_tenant_key(tenant_id=tenant_id, provider=provider_name, api_key_plain=incoming_key)

    with get_conn() as conn:
        existing_row = conn.execute(
            """
            SELECT provider, base_url
            FROM tenant_provider_configs
            WHERE tenant_id = ?
            """,
            (int(tenant_id),),
        ).fetchone()

    existing_provider = _safe_provider_name(existing_row["provider"]) if existing_row else None
    existing_base_url = (
        normalize_optional_base_url((existing_row["base_url"] or "").strip()) if existing_row else None
    )
    if incoming_base_url is None and existing_provider == provider_name:
        normalized_base_url = existing_base_url
    else:
        normalized_base_url = incoming_base_url
    if provider_name == "groq" and not normalized_base_url:
        normalized_base_url = default_base_url_for_provider("groq")
    if provider_name not in ("openai", "groq"):
        normalized_base_url = None

    key_tail = None
    key_map = {
        str(item["provider"]): item
        for item in list_tenant_keys(int(tenant_id))
        if isinstance(item, dict)
    }
    if provider_name in key_map:
        key_tail = key_map[provider_name].get("api_key_tail")

    now = _utcnow_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_provider_configs (
              tenant_id, provider, model, api_key, api_key_tail, base_url, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
              provider = excluded.provider,
              model = excluded.model,
              api_key = excluded.api_key,
              api_key_tail = excluded.api_key_tail,
              base_url = excluded.base_url,
              updated_at = excluded.updated_at
            """,
            (int(tenant_id), provider_name, normalized_model, "", key_tail, normalized_base_url, now, now),
        )
    return get_tenant_provider_config(tenant_id)


def _normalize_policy_action(value: str, field_name: str) -> str:
    action = str(value or "").strip().lower()
    if action not in POLICY_ACTIONS:
        raise ValueError(f"{field_name} must be one of: allow, redact, block")
    return action


def _normalize_block_threshold(value: str) -> str:
    threshold = str(value or "").strip().lower()
    if threshold not in POLICY_BLOCK_THRESHOLDS:
        raise ValueError("block_threshold must be one of: high, critical")
    return threshold


def get_tenant_policy_settings(tenant_id: int) -> Dict[str, Any]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT
              tenant_id,
              pii_action,
              financial_action,
              secrets_action,
              health_action,
              ip_action,
              block_threshold,
              store_original_prompt,
              show_sanitized_prompt_admin,
              created_at,
              updated_at
            FROM tenant_policy_settings
            WHERE tenant_id = ?
            """,
            (int(tenant_id),),
        ).fetchone()
        if not row:
            now = _utcnow_iso()
            conn.execute(
                """
                INSERT INTO tenant_policy_settings (
                  tenant_id,
                  pii_action,
                  financial_action,
                  secrets_action,
                  health_action,
                  ip_action,
                  block_threshold,
                  store_original_prompt,
                  show_sanitized_prompt_admin,
                  created_at,
                  updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(tenant_id),
                    str(DEFAULT_TENANT_POLICY_SETTINGS["pii_action"]),
                    str(DEFAULT_TENANT_POLICY_SETTINGS["financial_action"]),
                    str(DEFAULT_TENANT_POLICY_SETTINGS["secrets_action"]),
                    str(DEFAULT_TENANT_POLICY_SETTINGS["health_action"]),
                    str(DEFAULT_TENANT_POLICY_SETTINGS["ip_action"]),
                    str(DEFAULT_TENANT_POLICY_SETTINGS["block_threshold"]),
                    int(bool(DEFAULT_TENANT_POLICY_SETTINGS["store_original_prompt"])),
                    int(bool(DEFAULT_TENANT_POLICY_SETTINGS["show_sanitized_prompt_admin"])),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                """
                SELECT
                  tenant_id,
                  pii_action,
                  financial_action,
                  secrets_action,
                  health_action,
                  ip_action,
                  block_threshold,
                  store_original_prompt,
                  show_sanitized_prompt_admin,
                  created_at,
                  updated_at
                FROM tenant_policy_settings
                WHERE tenant_id = ?
                """,
                (int(tenant_id),),
            ).fetchone()

    return {
        "tenant_id": int(row["tenant_id"]),
        "pii_action": str(row["pii_action"]).lower(),
        "financial_action": str(row["financial_action"]).lower(),
        "secrets_action": str(row["secrets_action"]).lower(),
        "health_action": str(row["health_action"]).lower(),
        "ip_action": str(row["ip_action"]).lower(),
        "block_threshold": str(row["block_threshold"]).lower(),
        "store_original_prompt": bool(int(row["store_original_prompt"])),
        "show_sanitized_prompt_admin": bool(int(row["show_sanitized_prompt_admin"])),
        "created_at": str(row["created_at"] or ""),
        "updated_at": str(row["updated_at"] or ""),
    }


def upsert_tenant_policy_settings(
    tenant_id: int,
    *,
    pii_action: Optional[str] = None,
    financial_action: Optional[str] = None,
    secrets_action: Optional[str] = None,
    health_action: Optional[str] = None,
    ip_action: Optional[str] = None,
    block_threshold: Optional[str] = None,
    store_original_prompt: Optional[bool] = None,
    show_sanitized_prompt_admin: Optional[bool] = None,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    current = get_tenant_policy_settings(int(tenant_id))

    resolved = {
        "pii_action": _normalize_policy_action(
            pii_action if pii_action is not None else str(current["pii_action"]),
            "pii_action",
        ),
        "financial_action": _normalize_policy_action(
            financial_action if financial_action is not None else str(current["financial_action"]),
            "financial_action",
        ),
        "secrets_action": _normalize_policy_action(
            secrets_action if secrets_action is not None else str(current["secrets_action"]),
            "secrets_action",
        ),
        "health_action": _normalize_policy_action(
            health_action if health_action is not None else str(current["health_action"]),
            "health_action",
        ),
        "ip_action": _normalize_policy_action(
            ip_action if ip_action is not None else str(current["ip_action"]),
            "ip_action",
        ),
        "block_threshold": _normalize_block_threshold(
            block_threshold if block_threshold is not None else str(current["block_threshold"])
        ),
        "store_original_prompt": (
            bool(store_original_prompt)
            if store_original_prompt is not None
            else bool(current["store_original_prompt"])
        ),
        "show_sanitized_prompt_admin": (
            bool(show_sanitized_prompt_admin)
            if show_sanitized_prompt_admin is not None
            else bool(current["show_sanitized_prompt_admin"])
        ),
    }

    now = _utcnow_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_policy_settings (
              tenant_id,
              pii_action,
              financial_action,
              secrets_action,
              health_action,
              ip_action,
              block_threshold,
              store_original_prompt,
              show_sanitized_prompt_admin,
              created_at,
              updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
              pii_action = excluded.pii_action,
              financial_action = excluded.financial_action,
              secrets_action = excluded.secrets_action,
              health_action = excluded.health_action,
              ip_action = excluded.ip_action,
              block_threshold = excluded.block_threshold,
              store_original_prompt = excluded.store_original_prompt,
              show_sanitized_prompt_admin = excluded.show_sanitized_prompt_admin,
              updated_at = excluded.updated_at
            """,
            (
                int(tenant_id),
                resolved["pii_action"],
                resolved["financial_action"],
                resolved["secrets_action"],
                resolved["health_action"],
                resolved["ip_action"],
                resolved["block_threshold"],
                int(resolved["store_original_prompt"]),
                int(resolved["show_sanitized_prompt_admin"]),
                str(current.get("created_at") or now),
                now,
            ),
        )
    return get_tenant_policy_settings(int(tenant_id))


def list_policy_rules(tenant_id: int) -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, tenant_id, rule_type, match, action, enabled, created_at, updated_at
            FROM tenant_policies
            WHERE tenant_id = ?
            ORDER BY id ASC
            """,
            (int(tenant_id),),
        ).fetchall()
        return [dict(r) for r in rows]


def create_policy_rule(
    tenant_id: int,
    *,
    rule_type: str,
    match: str,
    action: str,
    enabled: bool = True,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    rt = (rule_type or "").strip().lower()
    mv = (match or "").strip()
    act = (action or "").strip().upper()
    if rt not in {"injection", "category", "severity"}:
        raise ValueError("Invalid rule_type")
    if not mv:
        raise ValueError("match is required")
    if act not in {"ALLOW", "REDACT", "BLOCK"}:
        raise ValueError("Invalid action")
    now = _utcnow_iso()
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO tenant_policies (tenant_id, rule_type, match, action, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (int(tenant_id), rt, mv.upper(), act, int(bool(enabled)), now, now),
        )
        rule_id = int(cur.lastrowid)
        row = conn.execute(
            """
            SELECT id, tenant_id, rule_type, match, action, enabled, created_at, updated_at
            FROM tenant_policies
            WHERE id = ?
            """,
            (rule_id,),
        ).fetchone()
    return dict(row)


def update_policy_rule(
    tenant_id: int,
    rule_id: int,
    *,
    rule_type: Optional[str] = None,
    match: Optional[str] = None,
    action: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    current = None
    with get_conn() as conn:
        current = conn.execute(
            """
            SELECT id, tenant_id, rule_type, match, action, enabled, created_at, updated_at
            FROM tenant_policies
            WHERE id = ? AND tenant_id = ?
            """,
            (int(rule_id), int(tenant_id)),
        ).fetchone()
        if not current:
            raise ValueError("Rule not found")

        new_rule_type = (rule_type or current["rule_type"]).strip().lower()
        new_match = (match or current["match"]).strip().upper()
        new_action = (action or current["action"]).strip().upper()
        new_enabled = int(bool(enabled)) if enabled is not None else int(current["enabled"])

        if new_rule_type not in {"injection", "category", "severity"}:
            raise ValueError("Invalid rule_type")
        if not new_match:
            raise ValueError("match is required")
        if new_action not in {"ALLOW", "REDACT", "BLOCK"}:
            raise ValueError("Invalid action")

        conn.execute(
            """
            UPDATE tenant_policies
            SET rule_type = ?, match = ?, action = ?, enabled = ?, updated_at = ?
            WHERE id = ? AND tenant_id = ?
            """,
            (new_rule_type, new_match, new_action, new_enabled, _utcnow_iso(), int(rule_id), int(tenant_id)),
        )
        row = conn.execute(
            """
            SELECT id, tenant_id, rule_type, match, action, enabled, created_at, updated_at
            FROM tenant_policies
            WHERE id = ?
            """,
            (int(rule_id),),
        ).fetchone()
    return dict(row)


def delete_policy_rule(tenant_id: int, rule_id: int) -> bool:
    ensure_enterprise_schema()
    with get_conn() as conn:
        cur = conn.execute(
            "DELETE FROM tenant_policies WHERE id = ? AND tenant_id = ?",
            (int(rule_id), int(tenant_id)),
        )
        return int(cur.rowcount or 0) > 0


def has_any_admin_membership() -> bool:
    ensure_enterprise_schema()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT COUNT(1) AS c
            FROM memberships
            WHERE role IN ('platform_admin', 'admin')
            """
        ).fetchone()
        return bool(row and int(row["c"]) > 0)


def bootstrap_first_run(
    *,
    tenant_name: str,
    admin_external_user: str,
    provider: str,
    model: Optional[str],
    api_key: Optional[str],
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    if has_any_admin_membership():
        raise ValueError("Onboarding already completed")

    safe_tenant_name = (tenant_name or "").strip() or "Default Tenant"
    safe_admin_user = (admin_external_user or "").strip()
    if not safe_admin_user:
        raise ValueError("admin_external_user is required")

    tenant_id = create_tenant(safe_tenant_name)
    user_id = ensure_user(safe_admin_user)
    upsert_membership(tenant_id=tenant_id, user_id=int(user_id), role=PLATFORM_ADMIN_ROLE)
    provider_cfg = upsert_tenant_provider_config(
        tenant_id=tenant_id,
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )

    try:
        write_audit_log(
            tenant_id=tenant_id,
            user_id=user_id,
            action="onboarding.completed",
            target_type="tenant",
            target_id=str(tenant_id),
            metadata={
                "tenant_name": safe_tenant_name,
                "admin_external_user": safe_admin_user,
                "provider": provider_cfg["provider"],
                "model": provider_cfg["model"],
                "base_url": provider_cfg.get("base_url"),
                "api_key_tail": provider_cfg["api_key_tail"],
            },
        )
    except Exception:
        pass

    return {
        "ok": True,
        "tenant_id": int(tenant_id),
        "tenant_name": safe_tenant_name,
        "admin_external_user": safe_admin_user,
        "provider": provider_cfg,
    }


def get_role(tenant_id: int, user_id: Optional[int]) -> str:
    if not user_id:
        return "user"
    ensure_enterprise_schema()
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT role FROM memberships WHERE tenant_id = ? AND user_id = ?",
            (tenant_id, user_id),
        )
        row = cur.fetchone()
        return _normalize_role_name(str(row["role"])) if row else "user"


def upsert_membership(tenant_id: int, user_id: int, role: str) -> None:
    role_name = _normalize_role_name(role)
    if role_name not in ("platform_admin", "admin", "auditor", "user", "tenant_admin", "employee"):
        raise ValueError("Invalid role")
    ensure_enterprise_schema()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO memberships (tenant_id, user_id, role)
            VALUES (?, ?, ?)
            ON CONFLICT(tenant_id, user_id) DO UPDATE SET role = excluded.role
            """,
            (tenant_id, user_id, role_name),
        )


def list_memberships(tenant_id: int) -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT m.tenant_id, m.user_id, u.external_id, u.display_name, m.role, m.created_at
            FROM memberships m
            JOIN users u ON u.id = m.user_id
            WHERE m.tenant_id = ?
            ORDER BY u.external_id ASC
            """,
            (tenant_id,),
        ).fetchall()
        out: List[Dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["role"] = _normalize_role_name(str(item.get("role") or ""))
            out.append(item)
        return out


def get_user_by_external_id(external_id: str) -> Optional[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        cur = conn.execute(
            "SELECT id, external_id, display_name, created_at FROM users WHERE external_id = ?",
            (external_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        cur = conn.execute(
            """
            SELECT id, external_id, username, display_name, password_hash, password_salt, is_active, created_at
            FROM users
            WHERE username = ?
            """,
            ((username or "").strip(),),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def list_users(limit: int = 200) -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    cap = max(1, min(int(limit), 1000))
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, external_id, username, display_name, is_active, created_at
            FROM users
            ORDER BY id ASC
            LIMIT ?
            """,
            (cap,),
        ).fetchall()
        return [dict(r) for r in rows]


def create_auth_user(
    *,
    username: str,
    password: str,
    display_name: Optional[str] = None,
    external_id: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    uname = (username or "").strip()
    if not uname:
        raise ValueError("username is required")
    if get_user_by_username(uname):
        raise ValueError("username already exists")

    pw = make_password_hash(password)
    ext = (external_id or uname).strip() or uname
    name = (display_name or uname).strip() or uname
    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE external_id = ?",
            (ext,),
        ).fetchone()
        if existing:
            user_id = int(existing["id"])
            conn.execute(
                """
                UPDATE users
                SET username = ?, display_name = ?, password_hash = ?, password_salt = ?, is_active = 1
                WHERE id = ?
                """,
                (uname, name, pw["password_hash"], pw["password_salt"], user_id),
            )
        else:
            cur = conn.execute(
                """
                INSERT INTO users (external_id, username, display_name, password_hash, password_salt, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
                """,
                (ext, uname, name, pw["password_hash"], pw["password_salt"]),
            )
            user_id = int(cur.lastrowid)
    row = get_user_by_username(uname)
    return {
        "id": user_id,
        "external_id": row.get("external_id") if row else ext,
        "username": uname,
        "display_name": name,
        "is_active": True,
    }


def set_user_password(user_id: int, new_password: str) -> Dict[str, Any]:
    ensure_enterprise_schema()
    password_pack = make_password_hash(new_password)
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, password_salt = ?, is_active = 1
            WHERE id = ?
            """,
            (password_pack["password_hash"], password_pack["password_salt"], int(user_id)),
        )
        row = conn.execute(
            "SELECT id, external_id, username, display_name, is_active, created_at FROM users WHERE id = ?",
            (int(user_id),),
        ).fetchone()
    if not row:
        raise ValueError("user not found")
    return dict(row)


def verify_user_credentials(username: str, password: str) -> Optional[Dict[str, Any]]:
    row = get_user_by_username((username or "").strip())
    if not row:
        return None
    if int(row.get("is_active", 0) or 0) != 1:
        return None
    if not verify_password(password, str(row.get("password_hash") or ""), str(row.get("password_salt") or "")):
        return None
    return row


def write_audit_log(
    tenant_id: int,
    user_id: Optional[int],
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
) -> None:
    ensure_enterprise_schema()
    signing_key = os.getenv("AUDIT_SIGNING_KEY", "").strip() or DEFAULT_AUDIT_SIGNING_KEY
    metadata_json = _canonical_json(redact_secrets(metadata or {}))

    with get_conn() as conn:
        last_row = conn.execute(
            """
            SELECT id, row_hash, chain_id
            FROM audit_logs
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (tenant_id,),
        ).fetchone()

        prev_hash = str(last_row["row_hash"]) if last_row and last_row["row_hash"] else ""
        chain_id = str(last_row["chain_id"]) if last_row and last_row["chain_id"] else f"tenant-{tenant_id}"
        created_at = _utcnow_iso()

        payload = {
            "tenant_id": int(tenant_id),
            "user_id": user_id,
            "action": action,
            "target_type": target_type,
            "target_id": target_id,
            "metadata_json": metadata_json,
            "ip": ip,
            "user_agent": user_agent,
            "request_id": request_id,
            "created_at": created_at,
            "chain_id": chain_id,
        }
        row_hash = compute_row_hash(payload, prev_hash=prev_hash, signing_key=signing_key)

        conn.execute(
            """
            INSERT INTO audit_logs
              (tenant_id, user_id, action, target_type, target_id, metadata_json, ip, user_agent, request_id, prev_hash, row_hash, chain_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_id,
                user_id,
                action,
                target_type,
                target_id,
                metadata_json,
                ip,
                user_agent,
                request_id,
                prev_hash,
                row_hash,
                chain_id,
                created_at,
            ),
        )


def list_audit_logs(tenant_id: int, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))

    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
              id, tenant_id, user_id, action, target_type, target_id,
              metadata_json, ip, user_agent, request_id, prev_hash, row_hash, chain_id, created_at
            FROM audit_logs
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
            """,
            (tenant_id, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]


def verify_audit_chain(tenant_id: int, limit: Optional[int] = 500) -> Dict[str, Any]:
    ensure_enterprise_schema()
    signing_key = os.getenv("AUDIT_SIGNING_KEY", "").strip() or DEFAULT_AUDIT_SIGNING_KEY

    with get_conn() as conn:
        if limit is None:
            rows = conn.execute(
                """
                SELECT id, tenant_id, user_id, action, target_type, target_id, metadata_json,
                       ip, user_agent, request_id, prev_hash, row_hash, chain_id, created_at
                FROM audit_logs
                WHERE tenant_id = ?
                ORDER BY id ASC
                """,
                (tenant_id,),
            ).fetchall()
        else:
            limit = max(1, min(int(limit), 5000))
            rows = conn.execute(
                """
                SELECT id, tenant_id, user_id, action, target_type, target_id, metadata_json,
                       ip, user_agent, request_id, prev_hash, row_hash, chain_id, created_at
                FROM audit_logs
                WHERE tenant_id = ?
                  AND id IN (
                    SELECT id FROM audit_logs
                    WHERE tenant_id = ?
                    ORDER BY id DESC
                    LIMIT ?
                  )
                ORDER BY id ASC
                """,
                (tenant_id, tenant_id, limit),
            ).fetchall()

        if not rows:
            return {"ok": True, "tenant_id": tenant_id, "checked": 0, "limit": limit}

        first_id = int(rows[0]["id"])
        prev_row = conn.execute(
            "SELECT row_hash FROM audit_logs WHERE tenant_id = ? AND id < ? ORDER BY id DESC LIMIT 1",
            (tenant_id, first_id),
        ).fetchone()
        expected_prev_hash = str(prev_row["row_hash"]) if prev_row and prev_row["row_hash"] else ""

        checked = 0
        for row in rows:
            row_id = int(row["id"])
            actual_prev = row["prev_hash"] or ""
            if actual_prev != expected_prev_hash:
                return {
                    "ok": False,
                    "tenant_id": tenant_id,
                    "checked": checked,
                    "first_bad_id": row_id,
                    "reason": "prev_hash_mismatch",
                    "limit": limit,
                }

            payload = {
                "tenant_id": int(row["tenant_id"]),
                "user_id": row["user_id"],
                "action": row["action"],
                "target_type": row["target_type"],
                "target_id": row["target_id"],
                "metadata_json": row["metadata_json"] or "{}",
                "ip": row["ip"],
                "user_agent": row["user_agent"],
                "request_id": row["request_id"],
                "created_at": row["created_at"],
                "chain_id": row["chain_id"] or f"tenant-{tenant_id}",
            }
            expected_hash = compute_row_hash(
                payload=payload,
                prev_hash=expected_prev_hash,
                signing_key=signing_key,
            )
            actual_hash = row["row_hash"] or ""
            if actual_hash != expected_hash:
                return {
                    "ok": False,
                    "tenant_id": tenant_id,
                    "checked": checked,
                    "first_bad_id": row_id,
                    "reason": "row_hash_mismatch",
                    "limit": limit,
                }

            expected_prev_hash = actual_hash
            checked += 1

        return {"ok": True, "tenant_id": tenant_id, "checked": checked, "limit": limit}


def get_tenant_limits(tenant_id: int) -> Dict[str, Any]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT tenant_id, daily_requests_limit, rpm_limit, enabled
            FROM tenant_limits
            WHERE tenant_id = ?
            """,
            (tenant_id,),
        ).fetchone()
        if not row:
            conn.execute(
                """
                INSERT INTO tenant_limits (tenant_id, daily_requests_limit, rpm_limit, enabled)
                VALUES (?, ?, ?, 1)
                """,
                (tenant_id, DEFAULT_DAILY_REQUESTS_LIMIT, DEFAULT_RPM_LIMIT),
            )
            row = conn.execute(
                """
                SELECT tenant_id, daily_requests_limit, rpm_limit, enabled
                FROM tenant_limits
                WHERE tenant_id = ?
                """,
                (tenant_id,),
            ).fetchone()
        return {
            "tenant_id": int(row["tenant_id"]),
            "daily_requests_limit": int(row["daily_requests_limit"]),
            "rpm_limit": int(row["rpm_limit"]),
            "enabled": bool(int(row["enabled"])),
        }


def upsert_tenant_limits(
    tenant_id: int,
    daily_requests_limit: Optional[int] = None,
    rpm_limit: Optional[int] = None,
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    current = get_tenant_limits(tenant_id)
    daily_requests_limit = (
        int(daily_requests_limit) if daily_requests_limit is not None else current["daily_requests_limit"]
    )
    rpm_limit = int(rpm_limit) if rpm_limit is not None else current["rpm_limit"]
    enabled_int = int(enabled) if enabled is not None else int(current["enabled"])

    if daily_requests_limit < 1:
        raise ValueError("daily_requests_limit must be >= 1")
    if rpm_limit < 1:
        raise ValueError("rpm_limit must be >= 1")

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_limits (tenant_id, daily_requests_limit, rpm_limit, enabled)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO UPDATE SET
              daily_requests_limit = excluded.daily_requests_limit,
              rpm_limit = excluded.rpm_limit,
              enabled = excluded.enabled
            """,
            (tenant_id, daily_requests_limit, rpm_limit, enabled_int),
        )
    return get_tenant_limits(tenant_id)


def increment_tenant_usage_daily(
    tenant_id: int,
    blocked: bool = False,
    risk_delta: int = 0,
    token_delta: int = 0,
    request_delta: int = 1,
    day: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    if day is None:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    request_delta = max(0, int(request_delta))
    blocked_delta = 1 if blocked else 0
    updated_at = _utcnow_iso()

    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_usage_daily (
              tenant_id, day, request_count, token_count, blocked_count, risk_sum, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id, day) DO UPDATE SET
              request_count = tenant_usage_daily.request_count + excluded.request_count,
              token_count = tenant_usage_daily.token_count + excluded.token_count,
              blocked_count = tenant_usage_daily.blocked_count + excluded.blocked_count,
              risk_sum = tenant_usage_daily.risk_sum + excluded.risk_sum,
              updated_at = excluded.updated_at
            """,
            (tenant_id, day, request_delta, int(token_delta), blocked_delta, int(risk_delta), updated_at),
        )
        row = conn.execute(
            """
            SELECT tenant_id, day, request_count, token_count, blocked_count, risk_sum, updated_at
            FROM tenant_usage_daily
            WHERE tenant_id = ? AND day = ?
            """,
            (tenant_id, day),
        ).fetchone()
        return dict(row)


def get_tenant_usage_daily(tenant_id: int, day: Optional[str] = None) -> Dict[str, Any]:
    ensure_enterprise_schema()
    if day is None:
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT tenant_id, day, request_count, token_count, blocked_count, risk_sum, updated_at
            FROM tenant_usage_daily
            WHERE tenant_id = ? AND day = ?
            """,
            (tenant_id, day),
        ).fetchone()
        if not row:
            return {
                "tenant_id": int(tenant_id),
                "day": day,
                "request_count": 0,
                "token_count": 0,
                "blocked_count": 0,
                "risk_sum": 0,
                "updated_at": "",
            }
        return dict(row)


def create_job(
    tenant_id: int,
    user_id: Optional[int],
    job_type: str,
    input_payload: Optional[Dict[str, Any]] = None,
) -> str:
    ensure_enterprise_schema()
    job_id = str(uuid.uuid4())
    now = _utcnow_iso()
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO jobs (id, tenant_id, user_id, type, status, input_json, output_path, error, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'queued', ?, NULL, NULL, ?, ?)
            """,
            (
                job_id,
                tenant_id,
                user_id,
                job_type,
                _canonical_json(input_payload or {}),
                now,
                now,
            ),
        )
    return job_id


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT id, tenant_id, user_id, type, status, input_json, output_path, error, created_at, updated_at
            FROM jobs
            WHERE id = ?
            """,
            (job_id,),
        ).fetchone()
        return dict(row) if row else None


def claim_next_job(job_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    ensure_enterprise_schema()
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        if job_type:
            row = conn.execute(
                """
                SELECT id
                FROM jobs
                WHERE status = 'queued' AND type = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (job_type,),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT id
                FROM jobs
                WHERE status = 'queued'
                ORDER BY created_at ASC
                LIMIT 1
                """
            ).fetchone()
        if not row:
            conn.execute("COMMIT")
            return None

        job_id = row["id"]
        now = _utcnow_iso()
        conn.execute(
            "UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ? AND status = 'queued'",
            (now, job_id),
        )
        claimed = conn.execute(
            """
            SELECT id, tenant_id, user_id, type, status, input_json, output_path, error, created_at, updated_at
            FROM jobs
            WHERE id = ?
            """,
            (job_id,),
        ).fetchone()
        conn.execute("COMMIT")
        return dict(claimed) if claimed else None
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def update_job(
    job_id: str,
    status: str,
    output_path: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    if status not in ("queued", "running", "done", "failed"):
        raise ValueError("Invalid job status")
    ensure_enterprise_schema()
    with get_conn() as conn:
        conn.execute(
            """
            UPDATE jobs
            SET status = ?, output_path = ?, error = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, output_path, error, _utcnow_iso(), job_id),
        )


def list_jobs(tenant_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    limit = max(1, min(int(limit), 1000))
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, tenant_id, user_id, type, status, input_json, output_path, error, created_at, updated_at
            FROM jobs
            WHERE tenant_id = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
