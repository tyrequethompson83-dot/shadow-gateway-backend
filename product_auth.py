import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from passlib.context import CryptContext
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

import enterprise.db_enterprise as db_enterprise
from security_utils import verify_password as verify_legacy_password

# Roles
PRODUCT_ADMIN_ROLE = "tenant_admin"
PLATFORM_ADMIN_ROLE = "platform_admin"
PRODUCT_EMPLOYEE_ROLE = "employee"
PRODUCT_ROLES = {PRODUCT_ADMIN_ROLE, PRODUCT_EMPLOYEE_ROLE}
LEGACY_ROLES = {"platform_admin", "admin", "auditor", "user"}
ALL_MEMBERSHIP_ROLES = PRODUCT_ROLES | LEGACY_ROLES
INVITE_ROLES = PRODUCT_ROLES

# Login constants
FAILED_LOGIN_WINDOW_MINUTES = 15
FAILED_LOGIN_THRESHOLD = 10
LOCKOUT_MINUTES = 10
COMMON_WEAK_PASSWORDS = {
    "password",
    "password123",
    "1234567890",
    "123456789",
    "qwertyuiop",
    "qwerty123",
    "letmein123",
    "welcome123",
    "admin123456",
    "iloveyou123",
}

# Password hashing
_PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")

class LoginError(ValueError):
    def __init__(self, message: str, *, code: str):
        super().__init__(message)
        self.code = code


# --- Utility Functions ---

def _ensure_enterprise_schema() -> None:
    db_enterprise.ensure_enterprise_schema()

def _get_conn():
    return db_enterprise.get_conn()

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _normalize_email(value: str) -> str:
    email = (value or "").strip().lower()
    if not email:
        raise ValueError("email is required")
    if "@" not in email or email.startswith("@") or email.endswith("@"):
        raise ValueError("email is invalid")
    return email

def _table_columns(conn: Connection, table_name: str) -> List[str]:
    """Get columns of a table using SQLAlchemy inspector."""
    inspector = inspect(conn)
    if table_name not in inspector.get_table_names():
        return []
    return [col["name"] for col in inspector.get_columns(table_name)]

def _normalize_role_name(role: str) -> str:
    role_name = (role or "").strip()
    if role_name == "admin":
        return PLATFORM_ADMIN_ROLE
    return role_name

def _validate_password_policy(password: str) -> str:
    raw = (password or "").strip()
    if len(raw) < 10:
        raise ValueError("password must be at least 10 characters")
    if raw.lower() in COMMON_WEAK_PASSWORDS:
        raise ValueError("password is too common")
    return raw

def _hash_password(password: str) -> str:
    raw = _validate_password_policy(password)
    return _PWD_CONTEXT.hash(raw)

def _verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    hashed = (password_hash or "").strip()
    if not hashed:
        return False
    if hashed.startswith("$2"):
        try:
            return bool(_PWD_CONTEXT.verify(password or "", hashed))
        except Exception:
            return False
    return verify_legacy_password(password or "", hashed, password_salt or "")

def _parse_iso_utc(value: Optional[str]) -> Optional[datetime]:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


# --- Schema & Migration ---

def ensure_product_auth_schema() -> None:
    """Ensure all auth-related tables and columns exist; safe for SQLite & Postgres."""
    _ensure_enterprise_schema()
    with _get_conn() as conn:
        inspector = inspect(conn)

        # --- Users table ---
        user_cols = [c["name"] for c in inspector.get_columns("users")] if "users" in inspector.get_table_names() else []

        if "email" not in user_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN email TEXT"))
        if "locked_until" not in user_cols:
            conn.execute(text("ALTER TABLE users ADD COLUMN locked_until TEXT"))

        # Normalize emails safely
        if "users" in inspector.get_table_names():
            conn.execute(text("""
                UPDATE users
                SET email = LOWER(username)
                WHERE (email IS NULL OR email = '')
                  AND username IS NOT NULL
                  AND username LIKE :pattern
            """), {"pattern": "%@%"})

            conn.execute(text("""
                UPDATE users
                SET email = LOWER(external_id)
                WHERE (email IS NULL OR email = '')
                  AND external_id IS NOT NULL
                  AND external_id LIKE :pattern
            """), {"pattern": "%@%"})

        # Unique index on email
        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email IS NOT NULL"))

        # --- Tenants table ---
        tenant_cols = [c["name"] for c in inspector.get_columns("tenants")] if "tenants" in inspector.get_table_names() else []
        if "is_personal" not in tenant_cols:
            conn.execute(text("ALTER TABLE tenants ADD COLUMN is_personal INTEGER NOT NULL DEFAULT 0"))

        # Deduplicate tenant names
        duplicates = conn.execute(text("""
            SELECT name
            FROM tenants
            GROUP BY name
            HAVING COUNT(1) > 1
        """)).fetchall()

        for dup in duplicates:
            name = str(dup["name"] or "")
            rows = conn.execute(text("SELECT id FROM tenants WHERE name = :name ORDER BY id ASC"), {"name": name}).fetchall()
            for row in rows[1:]:
                tenant_id = int(row["id"])
                conn.execute(text("UPDATE tenants SET name = :new_name WHERE id = :id"), {"new_name": f"{name} ({tenant_id})", "id": tenant_id})

        conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_name_unique ON tenants(name)"))

        # --- Memberships table ---
        memberships_exist = "memberships" in inspector.get_table_names()
        if memberships_exist:
            memberships_sql_row = conn.execute(text(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='memberships'"
            )).fetchone()
            memberships_sql = (memberships_sql_row[0] if memberships_sql_row and memberships_sql_row[0] else "").lower()
        else:
            memberships_sql = ""

        if any(k not in memberships_sql for k in ("tenant_admin", "employee", "platform_admin")):
            conn.execute(text("""
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
            """))
            conn.execute(text("""
                INSERT OR REPLACE INTO memberships_v2 (id, tenant_id, user_id, role, created_at)
                SELECT
                  id,
                  tenant_id,
                  user_id,
                  CASE
                    WHEN role = 'admin' THEN 'platform_admin'
                    WHEN role IN ('platform_admin', 'auditor', 'user', 'tenant_admin', 'employee') THEN role
                    ELSE 'employee'
                  END,
                  created_at
                FROM memberships
            """))
            conn.execute(text("DROP TABLE memberships"))
            conn.execute(text("ALTER TABLE memberships_v2 RENAME TO memberships"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS idx_memberships_tenant_role ON memberships(tenant_id, role)"))

        # --- Invite tokens ---
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS invite_tokens (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              tenant_id INTEGER NOT NULL,
              token TEXT NOT NULL UNIQUE,
              email TEXT,
              role TEXT NOT NULL CHECK(role IN ('tenant_admin','employee')),
              expires_at TEXT NOT NULL,
              max_uses INTEGER,
              uses_count INTEGER NOT NULL DEFAULT 0,
              used_at TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
            )
        """))

        invite_cols = [c["name"] for c in inspector.get_columns("invite_tokens")] if "invite_tokens" in inspector.get_table_names() else []
        if "max_uses" not in invite_cols:
            conn.execute(text("ALTER TABLE invite_tokens ADD COLUMN max_uses INTEGER"))
        if "uses_count" not in invite_cols:
            conn.execute(text("ALTER TABLE invite_tokens ADD COLUMN uses_count INTEGER NOT NULL DEFAULT 0"))

        conn.execute(text("""
            UPDATE invite_tokens
            SET uses_count = CASE
              WHEN used_at IS NOT NULL AND COALESCE(max_uses, 0) = 0 THEN 1
              ELSE COALESCE(uses_count, 0)
            END
        """))

        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_invite_tokens_tenant ON invite_tokens(tenant_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_invite_tokens_token ON invite_tokens(token)"))

        # --- Auth login events ---
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS auth_login_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER,
              email TEXT NOT NULL,
              success INTEGER NOT NULL CHECK(success IN (0,1)),
              ip_address TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_auth_login_email_created ON auth_login_events(email, created_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_auth_login_user_created ON auth_login_events(user_id, created_at)"))

        # --- Revoked tokens ---
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
              jti TEXT PRIMARY KEY,
              user_id INTEGER,
              tenant_id INTEGER,
              revoked_at TEXT NOT NULL,
              expires_at INTEGER NOT NULL
            )
        """))
        conn.execute(text("CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON revoked_tokens(expires_at)"))

# --- Remaining business logic ---
# All other functions like create_user_account, authenticate_login, signup_with_invite, etc.
# can remain almost identical, only ensure that any SQLite-specific syntax is removed:
# - Replace INTEGER PRIMARY KEY AUTOINCREMENT with SERIAL PRIMARY KEY
# - Replace TEXT default datetime('now') with TIMESTAMP default now()
# - Remove PRAGMA and sqlite_master usage
# - Use standard SQLAlchemy or Postgres-compatible SQL for all schema operations


def _parse_iso_utc(value: Optional[str]) -> Optional[datetime]:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _record_login_event(*, user_id: Optional[int], email: str, success: bool, ip_address: Optional[str]) -> None:
    ensure_product_auth_schema()
    normalized_email = (email or "").strip().lower()
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO auth_login_events (user_id, email, success, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                int(user_id) if user_id is not None else None,
                normalized_email,
                int(bool(success)),
                (ip_address or "").strip() or None,
                _utcnow_iso(),
            ),
        )


def _failed_login_count_in_window(*, user_id: int, email: str, minutes: int) -> int:
    ensure_product_auth_schema()
    threshold = (datetime.now(timezone.utc) - timedelta(minutes=max(1, int(minutes)))).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT COUNT(1) AS c
            FROM auth_login_events
            WHERE success = 0
              AND created_at >= ?
              AND (user_id = ? OR email = ?)
            """,
            (threshold, int(user_id), (email or "").strip().lower()),
        ).fetchone()
    return int(row["c"] or 0) if row else 0


def _set_user_lockout(user_id: int, until_utc: datetime) -> None:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        conn.execute(
            "UPDATE users SET locked_until = ? WHERE id = ?",
            (until_utc.strftime("%Y-%m-%dT%H:%M:%SZ"), int(user_id)),
        )


def _clear_user_lockout(user_id: int) -> None:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        conn.execute("UPDATE users SET locked_until = NULL WHERE id = ?", (int(user_id),))


def purge_expired_revoked_tokens(now_ts: Optional[int] = None) -> None:
    ensure_product_auth_schema()
    current = int(now_ts) if now_ts is not None else int(datetime.now(timezone.utc).timestamp())
    with _get_conn() as conn:
        conn.execute("DELETE FROM revoked_tokens WHERE expires_at <= ?", (current,))


def revoke_token_jti(*, jti: str, user_id: Optional[int], tenant_id: Optional[int], expires_at: int) -> None:
    ensure_product_auth_schema()
    token_jti = (jti or "").strip()
    if not token_jti:
        raise ValueError("jti is required")
    purge_expired_revoked_tokens()
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO revoked_tokens (jti, user_id, tenant_id, revoked_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(jti) DO UPDATE SET
              user_id = excluded.user_id,
              tenant_id = excluded.tenant_id,
              revoked_at = excluded.revoked_at,
              expires_at = excluded.expires_at
            """,
            (
                token_jti,
                int(user_id) if user_id is not None else None,
                int(tenant_id) if tenant_id is not None else None,
                _utcnow_iso(),
                int(expires_at),
            ),
        )


def is_token_revoked(jti: Optional[str]) -> bool:
    token_jti = (jti or "").strip()
    if not token_jti:
        return False
    ensure_product_auth_schema()
    purge_expired_revoked_tokens()
    with _get_conn() as conn:
        row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ? LIMIT 1", (token_jti,)).fetchone()
    return bool(row)


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    ensure_product_auth_schema()
    try:
        normalized = _normalize_email(email)
    except ValueError:
        return None
    return get_user_by_identifier(normalized)


def get_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    ensure_product_auth_schema()
    normalized = (identifier or "").strip().lower()
    if not normalized:
        return None
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT id, email, username, external_id, display_name, password_hash, password_salt, is_active, locked_until, created_at
            FROM users
            WHERE LOWER(COALESCE(email, '')) = ?
               OR LOWER(COALESCE(username, '')) = ?
               OR LOWER(COALESCE(external_id, '')) = ?
            LIMIT 1
            """,
            (normalized, normalized, normalized),
        ).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT id, email, username, external_id, display_name, password_hash, password_salt, is_active, locked_until, created_at
            FROM users
            WHERE id = ?
            """,
            (int(user_id),),
        ).fetchone()
        return dict(row) if row else None


def create_user_account(email: str, password: str) -> Dict[str, Any]:
    ensure_product_auth_schema()
    normalized = _normalize_email(email)
    existing = get_user_by_email(normalized)
    if existing:
        raise ValueError("email already registered")

    pw_hash = _hash_password(password)
    display_name = normalized.split("@", 1)[0]
    with _get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO users (email, external_id, username, display_name, password_hash, password_salt, is_active)
            VALUES (?, ?, ?, ?, ?, '', 1)
            """,
            (normalized, normalized, normalized, display_name, pw_hash),
        )
        user_id = int(cur.lastrowid)

    row = get_user_by_id(user_id)
    if not row:
        raise ValueError("failed to create user")
    return row


def update_user_password(user_id: int, password: str) -> None:
    ensure_product_auth_schema()
    pw_hash = _hash_password(password)
    with _get_conn() as conn:
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, password_salt = '', is_active = 1, locked_until = NULL
            WHERE id = ?
            """,
            (pw_hash, int(user_id)),
        )


def create_membership(tenant_id: int, user_id: int, role: str) -> None:
    ensure_product_auth_schema()
    role_name = _normalize_role_name(role)
    if role_name not in ALL_MEMBERSHIP_ROLES:
        raise ValueError("invalid role")
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO memberships (tenant_id, user_id, role)
            VALUES (?, ?, ?)
            ON CONFLICT(tenant_id, user_id) DO UPDATE SET role = excluded.role
            """,
            (int(tenant_id), int(user_id), role_name),
        )


def has_membership(user_id: int, tenant_id: int) -> bool:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT COUNT(1) AS c
            FROM memberships
            WHERE tenant_id = ? AND user_id = ?
            """,
            (int(tenant_id), int(user_id)),
        ).fetchone()
    return bool(row and int(row["c"]) > 0)


def get_membership_role(user_id: int, tenant_id: int) -> Optional[str]:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT role
            FROM memberships
            WHERE tenant_id = ? AND user_id = ?
            """,
            (int(tenant_id), int(user_id)),
        ).fetchone()
    return _normalize_role_name(str(row["role"])) if row else None


def is_personal_tenant(tenant_id: int) -> bool:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT COALESCE(is_personal, 0) AS is_personal
            FROM tenants
            WHERE id = ?
            LIMIT 1
            """,
            (int(tenant_id),),
        ).fetchone()
    return bool(row and int(row["is_personal"] or 0))


def list_user_memberships(user_id: int) -> List[Dict[str, Any]]:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
              m.tenant_id,
              t.name AS tenant_name,
              COALESCE(t.is_personal, 0) AS is_personal,
              m.role
            FROM memberships m
            JOIN tenants t ON t.id = m.tenant_id
            WHERE m.user_id = ?
            ORDER BY m.tenant_id ASC
            """,
            (int(user_id),),
        ).fetchall()
    normalized: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["role"] = _normalize_role_name(str(item.get("role") or ""))
        normalized.append(item)
    return normalized


def list_tenant_members(tenant_id: int) -> List[Dict[str, Any]]:
    ensure_product_auth_schema()
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT
              m.tenant_id,
              m.user_id,
              COALESCE(u.email, u.username, u.external_id) AS email,
              u.display_name,
              m.role,
              m.created_at
            FROM memberships m
            JOIN users u ON u.id = m.user_id
            WHERE m.tenant_id = ?
            ORDER BY m.created_at ASC, m.user_id ASC
            """,
            (int(tenant_id),),
        ).fetchall()
    items: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["role"] = _normalize_role_name(str(item.get("role") or ""))
        item["tenant_id"] = int(item["tenant_id"])
        item["user_id"] = int(item["user_id"])
        item["email"] = str(item.get("email") or "")
        item["display_name"] = str(item.get("display_name") or "")
        item["created_at"] = str(item.get("created_at") or "")
        items.append(item)
    return items


def _role_priority(role: str) -> int:
    order = {
        PLATFORM_ADMIN_ROLE: 60,
        PRODUCT_ADMIN_ROLE: 50,
        "admin": 40,
        "auditor": 30,
        PRODUCT_EMPLOYEE_ROLE: 20,
        "user": 10,
    }
    return int(order.get(_normalize_role_name(str(role or "").strip()), 0))


def choose_membership(
    memberships: List[Dict[str, Any]],
    preferred_tenant_id: Optional[int] = None,
) -> Dict[str, Any]:
    if not memberships:
        raise ValueError("user has no memberships")

    if preferred_tenant_id is not None:
        for item in memberships:
            if int(item["tenant_id"]) == int(preferred_tenant_id):
                return item
        raise ValueError("requested tenant is not linked to this user")

    ranked = sorted(
        memberships,
        key=lambda x: (-_role_priority(str(x.get("role"))), int(x.get("tenant_id") or 0)),
    )
    return ranked[0]


def _tenant_exists_by_name(name: str) -> bool:
    with _get_conn() as conn:
        row = conn.execute("SELECT 1 FROM tenants WHERE name = ? LIMIT 1", (name,)).fetchone()
    return bool(row)


def _create_tenant(name: str, is_personal: bool) -> int:
    ensure_product_auth_schema()
    safe_name = (name or "").strip()
    if not safe_name:
        raise ValueError("tenant name is required")
    tenant_id = int(db_enterprise.create_tenant(safe_name))
    with _get_conn() as conn:
        conn.execute(
            "UPDATE tenants SET is_personal = ? WHERE id = ?",
            (1 if is_personal else 0, tenant_id),
        )
    return tenant_id


def create_company_signup(*, company_name: str, admin_email: str, password: str) -> Dict[str, Any]:
    ensure_product_auth_schema()
    safe_name = (company_name or "").strip()
    if not safe_name:
        raise ValueError("company_name is required")
    if _tenant_exists_by_name(safe_name):
        raise ValueError("company already exists")

    user = create_user_account(admin_email, password)
    try:
        tenant_id = _create_tenant(safe_name, is_personal=False)
    except Exception as exc:
        with _get_conn() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (int(user["id"]),))
        if isinstance(exc, sqlite3.IntegrityError):
            raise ValueError("company already exists") from exc
        raise
    create_membership(tenant_id=tenant_id, user_id=int(user["id"]), role=PRODUCT_ADMIN_ROLE)
    memberships = list_user_memberships(int(user["id"]))
    return {
        "user": user,
        "tenant_id": int(tenant_id),
        "role": PRODUCT_ADMIN_ROLE,
        "memberships": memberships,
    }


def create_individual_signup(
    *,
    email: str,
    password: str,
    name_or_label: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_product_auth_schema()
    normalized = _normalize_email(email)
    user = create_user_account(normalized, password)
    tenant_name = f"{normalized} Personal"
    try:
        tenant_id = _create_tenant(tenant_name, is_personal=True)
    except Exception:
        with _get_conn() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (int(user["id"]),))
        raise
    create_membership(tenant_id=tenant_id, user_id=int(user["id"]), role=PRODUCT_ADMIN_ROLE)
    memberships = list_user_memberships(int(user["id"]))
    return {
        "user": user,
        "tenant_id": int(tenant_id),
        "role": PRODUCT_ADMIN_ROLE,
        "memberships": memberships,
    }


def authenticate_login(
    *,
    email: str,
    password: str,
    tenant_id: Optional[int] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    ensure_product_auth_schema()
    identifier = (email or "").strip().lower()
    user = get_user_by_identifier(identifier)
    if not user:
        _record_login_event(user_id=None, email=identifier, success=False, ip_address=ip_address)
        raise LoginError("invalid credentials", code="invalid_credentials")
    if int(user.get("is_active", 0) or 0) != 1:
        _record_login_event(user_id=int(user["id"]), email=identifier, success=False, ip_address=ip_address)
        raise LoginError("invalid credentials", code="invalid_credentials")
    lockout_until = _parse_iso_utc(str(user.get("locked_until") or ""))
    now = datetime.now(timezone.utc)
    if lockout_until and lockout_until > now:
        _record_login_event(user_id=int(user["id"]), email=identifier, success=False, ip_address=ip_address)
        raise LoginError("account locked. try again later", code="account_locked")
    if not _verify_password(password, str(user.get("password_hash") or ""), str(user.get("password_salt") or "")):
        _record_login_event(user_id=int(user["id"]), email=identifier, success=False, ip_address=ip_address)
        failures = _failed_login_count_in_window(
            user_id=int(user["id"]),
            email=identifier,
            minutes=FAILED_LOGIN_WINDOW_MINUTES,
        )
        if failures >= FAILED_LOGIN_THRESHOLD:
            lockout = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
            _set_user_lockout(int(user["id"]), lockout)
            raise LoginError("account locked. try again later", code="account_locked")
        raise LoginError("invalid credentials", code="invalid_credentials")

    _record_login_event(user_id=int(user["id"]), email=identifier, success=True, ip_address=ip_address)
    _clear_user_lockout(int(user["id"]))
    user = get_user_by_id(int(user["id"])) or user

    memberships = list_user_memberships(int(user["id"]))
    current = choose_membership(memberships, preferred_tenant_id=tenant_id)
    return {
        "user": user,
        "tenant_id": int(current["tenant_id"]),
        "role": _normalize_role_name(str(current["role"])),
        "memberships": memberships,
    }


def get_user_profile(user_id: int) -> Dict[str, Any]:
    user = get_user_by_id(user_id)
    if not user:
        raise ValueError("user not found")
    memberships = list_user_memberships(int(user_id))
    return {
        "id": int(user["id"]),
        "email": user.get("email") or user.get("username") or user.get("external_id"),
        "display_name": user.get("display_name"),
        "created_at": user.get("created_at"),
        "memberships": memberships,
    }


def create_invite(
    *,
    tenant_id: int,
    role: str = PRODUCT_EMPLOYEE_ROLE,
    email: Optional[str] = None,
    expires_hours: int = 72,
    max_uses: Optional[int] = None,
) -> Dict[str, Any]:
    ensure_product_auth_schema()
    role_name = (role or "").strip()
    if role_name not in INVITE_ROLES:
        raise ValueError("role must be tenant_admin or employee")
    max_uses_int: Optional[int] = None
    if max_uses is not None:
        max_uses_int = int(max_uses)
        if max_uses_int < 1:
            raise ValueError("max_uses must be at least 1 when provided")

    normalized_email = _normalize_email(email) if email else None
    token = secrets.token_urlsafe(24)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=max(1, int(expires_hours)))).strftime("%Y-%m-%dT%H:%M:%SZ")
    with _get_conn() as conn:
        conn.execute(
            """
            INSERT INTO invite_tokens (tenant_id, token, email, role, expires_at, max_uses, uses_count, used_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, NULL)
            """,
            (int(tenant_id), token, normalized_email, role_name, expires_at, max_uses_int),
        )
    return {
        "tenant_id": int(tenant_id),
        "token": token,
        "email": normalized_email,
        "role": role_name,
        "expires_at": expires_at,
        "max_uses": max_uses_int,
        "uses_count": 0,
    }


def signup_with_invite(*, token: str, email: str, password: str) -> Dict[str, Any]:
    ensure_product_auth_schema()
    raw_token = (token or "").strip()
    if not raw_token:
        raise ValueError("token is required")
    normalized_email = _normalize_email(email)

    with _get_conn() as conn:
        invite = conn.execute(
            """
            SELECT id, tenant_id, token, email, role, expires_at, used_at, max_uses, COALESCE(uses_count, 0) AS uses_count
            FROM invite_tokens
            WHERE token = ?
            LIMIT 1
            """,
            (raw_token,),
        ).fetchone()
    if not invite:
        raise ValueError("invite token is invalid")
    invite_data = dict(invite)
    if str(invite_data.get("expires_at") or "") <= _utcnow_iso():
        raise ValueError("invite token is expired")

    max_uses_raw = invite_data.get("max_uses")
    max_uses = int(max_uses_raw) if max_uses_raw is not None else None
    uses_count = int(invite_data.get("uses_count") or 0)
    if max_uses is None:
        if invite_data.get("used_at"):
            raise ValueError("invite link already used")
    else:
        if uses_count >= max_uses:
            raise ValueError("invite link max uses reached")
        if invite_data.get("used_at") and uses_count >= max_uses:
            raise ValueError("invite link max uses reached")

    invite_email = (invite_data.get("email") or "").strip().lower()
    if invite_email and invite_email != normalized_email:
        raise ValueError("invite token is bound to a different email")

    user = get_user_by_email(normalized_email)
    if user:
        update_user_password(int(user["id"]), password)
    else:
        user = create_user_account(normalized_email, password)

    tenant_id = int(invite_data["tenant_id"])
    role = str(invite_data["role"])
    create_membership(tenant_id=tenant_id, user_id=int(user["id"]), role=role)

    redeemed_at = _utcnow_iso()
    with _get_conn() as conn:
        if max_uses is None:
            cur = conn.execute(
                """
                UPDATE invite_tokens
                SET uses_count = COALESCE(uses_count, 0) + 1,
                    used_at = ?
                WHERE id = ?
                  AND max_uses IS NULL
                  AND used_at IS NULL
                """,
                (redeemed_at, int(invite_data["id"])),
            )
            if int(cur.rowcount or 0) == 0:
                raise ValueError("invite link already used")
        else:
            cur = conn.execute(
                """
                UPDATE invite_tokens
                SET uses_count = COALESCE(uses_count, 0) + 1,
                    used_at = CASE
                      WHEN COALESCE(uses_count, 0) + 1 >= max_uses THEN ?
                      ELSE used_at
                    END
                WHERE id = ?
                  AND max_uses IS NOT NULL
                  AND COALESCE(uses_count, 0) < max_uses
                """,
                (redeemed_at, int(invite_data["id"])),
            )
            if int(cur.rowcount or 0) == 0:
                raise ValueError("invite link max uses reached")

    memberships = list_user_memberships(int(user["id"]))
    return {
        "user": user,
        "tenant_id": tenant_id,
        "role": role,
        "memberships": memberships,
    }
