"""
Enterprise database access layer.

Postgres is the primary target (via DATABASE_URL); a local SQLite file is used
only when DATABASE_URL is absent, mainly for local development. All functions
return dictionaries to keep the calling code JSON‑friendly.
"""

import hashlib
import hmac
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    and_,
    case,
    delete,
    create_engine,
    func,
    select,
    text,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

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
    mask_key_tail,
    make_password_hash,
)

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

DB_PATH = os.getenv("DB_PATH", "app.db")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
DEFAULT_AUDIT_SIGNING_KEY = "dev-audit-key-change-me"

DEFAULT_PROVIDER = "gemini"
ROUTING_PROVIDER_PRIORITY = ("gemini", "openai", "groq", "anthropic")
KEY_PROVIDER_PRIORITY = ROUTING_PROVIDER_PRIORITY + ("tavily",)
PLATFORM_ADMIN_ROLE = "platform_admin"
POLICY_ACTIONS = {"allow", "redact", "block"}
POLICY_BLOCK_THRESHOLDS = {"high", "critical"}


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


def _database_url() -> str:
    return DATABASE_URL or f"sqlite:///{DB_PATH}"


engine: Engine = create_engine(_database_url(), future=True, echo=False)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)
Base = declarative_base()


# --------------------------------------------------------------------------- #
# Utility helpers
# --------------------------------------------------------------------------- #

def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _now_dt().strftime("%Y-%m-%dT%H:%M:%SZ")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def compute_row_hash(payload: Dict[str, Any], prev_hash: str, signing_key: str) -> str:
    canonical_payload = _canonical_json(payload)
    message = f"{canonical_payload}|{prev_hash or ''}".encode("utf-8")
    return hmac.new(signing_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _model_to_dict(obj: Any) -> Dict[str, Any]:
    return {c.name: getattr(obj, c.name) for c in obj.__table__.columns}


def _row_to_dict(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    if hasattr(row, "_mapping"):
        return dict(row._mapping)
    try:
        return dict(row)
    except Exception:
        return {}


def _rows_to_dicts(rows: Iterable[Any]) -> List[Dict[str, Any]]:
    return [_row_to_dict(r) for r in rows]


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


def _normalize_role_name(role: str) -> str:
    role_name = (role or "").strip()
    if role_name == "admin":
        return PLATFORM_ADMIN_ROLE
    return role_name


def _dialect_insert(model):
    return pg_insert(model) if engine.dialect.name == "postgresql" else sqlite_insert(model)


# --------------------------------------------------------------------------- #
# Metadata helpers (information_schema first)
# --------------------------------------------------------------------------- #

def table_exists(table_name: str, *, schema: str = "public") -> bool:
    if engine.dialect.name == "postgresql":
        query = text(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = :schema AND table_name = :table
            LIMIT 1
            """
        )
        with engine.connect() as conn:
            row = conn.execute(query, {"schema": schema, "table": table_name}).first()
            return bool(row)

    from sqlalchemy import inspect  # lazy import to avoid unused on Postgres

    inspector = inspect(engine)
    return table_name in inspector.get_table_names()


def list_columns(table_name: str, *, schema: str = "public") -> List[str]:
    if engine.dialect.name == "postgresql":
        query = text(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = :schema AND table_name = :table
            ORDER BY ordinal_position
            """
        )
        with engine.connect() as conn:
            return [str(r[0]) for r in conn.execute(query, {"schema": schema, "table": table_name}).all()]

    from sqlalchemy import inspect

    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return []
    return [c["name"] for c in inspector.get_columns(table_name)]


# --------------------------------------------------------------------------- #
# ORM models
# --------------------------------------------------------------------------- #

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_personal = Column(Boolean, nullable=False, server_default=text("false"))


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    external_id = Column(String, unique=True)
    username = Column(String, unique=True)
    display_name = Column(String)
    email = Column(String, unique=True)
    password_hash = Column(String)
    password_salt = Column(String)
    is_active = Column(Boolean, default=True, nullable=False, server_default=text("true"))
    locked_until = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Membership(Base):
    __tablename__ = "memberships"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_membership"),
        CheckConstraint(
            "role IN ('platform_admin','admin','auditor','user','tenant_admin','employee')",
            name="ck_membership_role",
        ),
        Index("idx_memberships_tenant_role", "tenant_id", "role"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    action = Column(String, nullable=False)
    target_type = Column(String)
    target_id = Column(String)
    metadata_json = Column(Text)
    ip = Column(String)
    user_agent = Column(String)
    request_id = Column(String)
    prev_hash = Column(String)
    row_hash = Column(String)
    chain_id = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("idx_audit_logs_tenant_created", "tenant_id", "created_at"),
        Index("idx_audit_logs_tenant_id", "tenant_id", "id"),
        Index("idx_audit_logs_tenant_chain_id", "tenant_id", "chain_id", "id"),
    )


class TenantUsageDaily(Base):
    __tablename__ = "tenant_usage_daily"

    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    day = Column(String, primary_key=True)
    request_count = Column(Integer, nullable=False, default=0)
    token_count = Column(Integer, nullable=False, default=0)
    blocked_count = Column(Integer, nullable=False, default=0)
    risk_sum = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    __table_args__ = (Index("idx_usage_tenant_day", "tenant_id", "day"),)


class TenantLimits(Base):
    __tablename__ = "tenant_limits"

    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    daily_requests_limit = Column(Integer, nullable=False)
    rpm_limit = Column(Integer, nullable=False)
    daily_token_limit = Column(
        Integer,
        nullable=False,
        default=DEFAULT_DAILY_TOKEN_LIMIT,
        server_default=text(str(DEFAULT_DAILY_TOKEN_LIMIT)),
    )
    enabled = Column(Boolean, nullable=False, default=True, server_default=text("true"))

class TenantProviderConfig(Base):
    __tablename__ = "tenant_provider_configs"

    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    provider = Column(String, nullable=False)
    model = Column(String, nullable=False)
    api_key = Column(Text)
    api_key_tail = Column(String)
    base_url = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint(
            "provider IN ('gemini','openai','groq','anthropic','tavily')",
            name="ck_provider_cfg_provider",
        ),
        Index("idx_provider_cfg_provider", "provider"),
        Index("idx_provider_cfg_tenant", "tenant_id"),
    )


class TenantProviderKey(Base):
    __tablename__ = "tenant_provider_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provider = Column(String, nullable=False)
    api_key_enc = Column(Text, nullable=False)
    api_key_tail = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        UniqueConstraint("tenant_id", "provider", name="uq_tenant_provider_key"),
        CheckConstraint(
            "provider IN ('gemini','openai','groq','anthropic','tavily')",
            name="ck_provider_key_provider",
        ),
        Index("idx_provider_keys_tenant", "tenant_id"),
    )


class TenantPolicy(Base):
    __tablename__ = "tenant_policies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    rule_type = Column(String, nullable=False)
    match = Column(String, nullable=False)
    action = Column(String, nullable=False)
    enabled = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("rule_type IN ('injection','category','severity')", name="ck_policy_rule_type"),
        CheckConstraint("action IN ('ALLOW','REDACT','BLOCK')", name="ck_policy_action"),
        Index("idx_policy_tenant_type", "tenant_id", "rule_type", "enabled"),
    )


class TenantPolicySettings(Base):
    __tablename__ = "tenant_policy_settings"

    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    pii_action = Column(String, nullable=False, server_default=text("'redact'"))
    financial_action = Column(String, nullable=False, server_default=text("'redact'"))
    secrets_action = Column(String, nullable=False, server_default=text("'block'"))
    health_action = Column(String, nullable=False, server_default=text("'redact'"))
    ip_action = Column(String, nullable=False, server_default=text("'redact'"))
    block_threshold = Column(String, nullable=False, server_default=text("'critical'"))
    store_original_prompt = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    show_sanitized_prompt_admin = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Job(Base):
    __tablename__ = "jobs"

    id = Column(String, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    type = Column(String, nullable=False)
    status = Column(String, nullable=False)
    input_json = Column(Text)
    output_path = Column(String)
    error = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    __table_args__ = (
        CheckConstraint("status IN ('queued','running','done','failed')", name="ck_job_status"),
        Index("idx_jobs_tenant_created", "tenant_id", "created_at"),
        Index("idx_jobs_status_created", "status", "created_at"),
    )


class Request(Base):
    """Requests table kept in enterprise layer for audit parity."""

    __tablename__ = "requests"

    id = Column(String, primary_key=True)
    ts = Column(String)
    user = Column(String)
    purpose = Column(String)
    model = Column(String)
    provider = Column(String)
    cleaned_prompt_preview = Column(Text)
    prompt_original_preview = Column(Text)
    prompt_sent_to_ai_preview = Column(Text)
    detections_count = Column(Integer)
    entity_counts_json = Column(Text)
    risk_categories_json = Column(Text)
    risk_score = Column(Integer)
    risk_level = Column(String)
    severity = Column(String)
    decision = Column(String)
    injection_detected = Column(Integer, default=0)
    tenant_id = Column(Integer, default=1)

    __table_args__ = (
        Index("idx_requests_tenant_created", "tenant_id", "ts"),
        Index("idx_requests_tenant_decision", "tenant_id", "decision"),
        Index("idx_requests_tenant_provider", "tenant_id", "provider"),
    )


# --------------------------------------------------------------------------- #
# Session / connection helpers
# --------------------------------------------------------------------------- #

def get_engine() -> Engine:
    return engine


@contextmanager
def get_session():
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@contextmanager
def get_conn():
    """Provide a low‑level connection for legacy callers (uses SQLAlchemy engine)."""

    with engine.begin() as conn:
        yield conn


def ensure_enterprise_schema() -> None:
    """Create all enterprise tables if missing."""

    Base.metadata.create_all(bind=engine)


# --------------------------------------------------------------------------- #
# Tenant helpers
# --------------------------------------------------------------------------- #

def _ensure_default_tenant(session) -> Tenant:
    tenant = session.execute(select(Tenant).order_by(Tenant.id).limit(1)).scalar_one_or_none()
    if tenant:
        return tenant
    tenant = Tenant(name="Default Tenant", is_personal=False)
    session.add(tenant)
    session.flush()
    return tenant


def get_default_tenant_id() -> int:
    ensure_enterprise_schema()
    with get_session() as session:
        tenant = _ensure_default_tenant(session)
        return int(tenant.id)


def create_tenant(name: str, *, is_personal: bool = False) -> int:
    """Create a tenant and return its id."""

    ensure_enterprise_schema()
    safe_name = (name or "").strip()
    if not safe_name:
        raise ValueError("tenant name is required")
    with get_session() as session:
        tenant = Tenant(name=safe_name, is_personal=bool(is_personal))
        session.add(tenant)
        session.flush()
        return int(tenant.id)


def list_tenants() -> List[Dict[str, Any]]:
    """List all tenants."""

    ensure_enterprise_schema()
    with get_session() as session:
        rows = session.execute(select(Tenant).order_by(Tenant.id)).scalars().all()
        return [_model_to_dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# User helpers
# --------------------------------------------------------------------------- #

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    ensure_enterprise_schema()
    value = (username or "").strip()
    if not value:
        return None
    with get_session() as session:
        row = session.execute(
            select(User).where(func.lower(User.username) == func.lower(value))
        ).scalar_one_or_none()
        return _model_to_dict(row) if row else None


def ensure_user(external_user: Optional[str]) -> Optional[int]:
    ensure_enterprise_schema()
    username = (external_user or "").strip()
    if not username:
        return None

    with get_session() as session:
        existing = session.execute(
            select(User).where(func.lower(User.username) == func.lower(username))
        ).scalar_one_or_none()
        if existing:
            return int(existing.id)
        user = User(
            external_id=username,
            username=username,
            display_name=username,
            email=username if "@" in username else None,
            is_active=True,
        )
        session.add(user)
        session.flush()
        return int(user.id)


def get_user_by_external_id(external_id: str) -> Optional[Dict[str, Any]]:
    """Lookup a user by external_id (case-insensitive)."""

    ensure_enterprise_schema()
    value = (external_id or "").strip()
    if not value:
        return None
    with get_session() as session:
        row = session.execute(
            select(User).where(func.lower(User.external_id) == func.lower(value))
        ).scalar_one_or_none()
        return _model_to_dict(row) if row else None


def has_any_admin_membership() -> bool:
    """Return True when any admin-level membership exists."""

    ensure_enterprise_schema()
    with get_session() as session:
        row = (
            session.execute(
                select(Membership.id).where(
                    Membership.role.in_(("platform_admin", "admin", "tenant_admin"))
                ).limit(1)
            )
            .scalar_one_or_none()
        )
        return bool(row)


def set_user_password(user_id: int, new_password: str) -> Dict[str, Any]:
    """Set a user's password using PBKDF2 hashing (non-legacy)."""

    ensure_enterprise_schema()
    user_id_int = int(user_id)
    hashes = make_password_hash(new_password)
    with get_session() as session:
        user = session.get(User, user_id_int)
        if not user:
            raise ValueError("user not found")
        user.password_hash = hashes["password_hash"]
        user.password_salt = hashes["password_salt"]
        user.locked_until = None
        user.is_active = True
        session.flush()
        return _model_to_dict(user)


def list_users(limit: int = 200) -> List[Dict[str, Any]]:
    """List users with an optional limit."""

    ensure_enterprise_schema()
    cap = max(1, min(int(limit), 5000))
    with get_session() as session:
        rows = (
            session.execute(select(User).order_by(User.id).limit(cap))
            .scalars()
            .all()
        )
        return [_model_to_dict(r) for r in rows]


def create_auth_user(username: str, password: str, display_name: Optional[str] = None) -> Dict[str, Any]:
    """Create a user with hashed password; username also populates external_id/email when applicable."""

    ensure_enterprise_schema()
    uname = (username or "").strip()
    if not uname:
        raise ValueError("username is required")

    with get_session() as session:
        existing = session.execute(
            select(User).where(func.lower(User.username) == func.lower(uname))
        ).scalar_one_or_none()
        if existing:
            raise ValueError("user already exists")

        hashes = make_password_hash(password)
        email_val = uname if "@" in uname else None
        user = User(
            external_id=uname,
            username=uname,
            display_name=display_name or uname,
            email=email_val,
            password_hash=hashes["password_hash"],
            password_salt=hashes["password_salt"],
            is_active=True,
        )
        session.add(user)
        session.flush()
        return _model_to_dict(user)


def get_role(tenant_id: int, user_id: Optional[int]) -> str:
    ensure_enterprise_schema()
    if not user_id:
        return "user"
    with get_session() as session:
        membership = session.execute(
            select(Membership.role).where(
                Membership.tenant_id == int(tenant_id), Membership.user_id == int(user_id)
            )
        ).scalar_one_or_none()
        return _normalize_role_name(membership or "user")


def list_memberships(tenant_id: int) -> List[Dict[str, Any]]:
    """List memberships for a tenant."""

    ensure_enterprise_schema()
    with get_session() as session:
        rows = (
            session.execute(
                select(Membership).where(Membership.tenant_id == int(tenant_id)).order_by(Membership.id)
            )
            .scalars()
            .all()
        )
        return [_model_to_dict(r) for r in rows]


def upsert_membership(tenant_id: int, user_id: int, role: str) -> Dict[str, Any]:
    """Create or update a membership."""

    ensure_enterprise_schema()
    role_name = _normalize_role_name(role)
    if role_name not in (
        "platform_admin",
        "admin",
        "auditor",
        "tenant_admin",
        "user",
        "employee",
    ):
        raise ValueError("invalid role")

    with get_session() as session:
        existing = session.execute(
            select(Membership).where(
                Membership.tenant_id == int(tenant_id),
                Membership.user_id == int(user_id),
            )
        ).scalar_one_or_none()
        if existing:
            existing.role = role_name
            session.flush()
            return _model_to_dict(existing)

        membership = Membership(tenant_id=int(tenant_id), user_id=int(user_id), role=role_name)
        session.add(membership)
        session.flush()
        return _model_to_dict(membership)


# --------------------------------------------------------------------------- #
# Provider configuration helpers
# --------------------------------------------------------------------------- #

def _env_api_key(provider: str) -> str:
    # Tavily is a key-only provider (web search), not an LLM provider.
    raw = (provider or "").strip().lower()
    if raw == "tavily":
        return os.getenv("TAVILY_API_KEY", "").strip()

    name = normalize_provider_name(provider)
    if name == "gemini":
        return os.getenv("GEMINI_API_KEY", "").strip()
    if name == "openai":
        return os.getenv("OPENAI_API_KEY", "").strip()
    if name == "groq":
        return os.getenv("GROQ_API_KEY", "").strip()
    if name == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY", "").strip()
    return ""


def _ensure_provider_config(session, tenant_id: int) -> TenantProviderConfig:
    # Historical deployments may have allowed duplicate rows (missing/incorrect PK/unique constraint).
    # Limit(1) avoids 500s from scalar_one_or_none() until repair migrations de-dupe/enforce uniqueness.
    cfg = session.execute(
        select(TenantProviderConfig)
        .where(TenantProviderConfig.tenant_id == int(tenant_id))
        .limit(1)
    ).scalar_one_or_none()
    if cfg:
        return cfg

    provider = normalize_provider_name(os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER))
    model = validate_model_for_provider(provider, None)
    base_url = normalize_optional_base_url(default_base_url_for_provider(provider))
    cfg = TenantProviderConfig(
        tenant_id=int(tenant_id),
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=None,
        api_key_tail=None,
    )
    session.add(cfg)
    session.flush()
    return cfg


def set_tenant_provider_key(tenant_id: int, provider: str, api_key: str) -> Dict[str, Any]:
    """Upsert an encrypted provider key for a tenant."""

    ensure_enterprise_schema()
    provider_name = _safe_key_provider(provider) or normalize_provider_name(provider)
    enc = encrypt_secret(api_key)
    tail = mask_key_tail(api_key)
    values = {
        "tenant_id": int(tenant_id),
        "provider": provider_name,
        "api_key_enc": enc,
        "api_key_tail": tail,
    }
    with get_session() as session:
        stmt = _dialect_insert(TenantProviderKey).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[TenantProviderKey.tenant_id, TenantProviderKey.provider],
            set_=values,
        )
        session.execute(stmt)
        session.flush()
        return values


def get_tenant_provider_config(tenant_id: int) -> Dict[str, Any]:
    """Return provider configuration metadata (excludes decrypted key)."""

    ensure_enterprise_schema()
    with get_session() as session:
        _ensure_default_tenant(session)
        cfg = _ensure_provider_config(session, tenant_id)
        key_row = session.execute(
            select(TenantProviderKey).where(
                TenantProviderKey.tenant_id == int(tenant_id),
                TenantProviderKey.provider == cfg.provider,
            )
            .limit(1)
        ).scalar_one_or_none()

    env_key = _env_api_key(cfg.provider)
    has_api_key = bool((key_row and key_row.api_key_enc) or env_key)
    api_key_tail = key_row.api_key_tail if key_row else mask_key_tail(env_key)

    return {
        "tenant_id": int(tenant_id),
        "provider": cfg.provider,
        "model": cfg.model,
        "base_url": cfg.base_url,
        "source": "db" if key_row else "env" if env_key else "none",
        "has_api_key": has_api_key,
        "api_key_tail": api_key_tail,
    }


def get_tenant_provider_runtime_config(tenant_id: int) -> Dict[str, Any]:
    """Return provider configuration including the decrypted API key."""

    ensure_enterprise_schema()
    with get_session() as session:
        _ensure_default_tenant(session)
        cfg = _ensure_provider_config(session, tenant_id)
        key_row = session.execute(
            select(TenantProviderKey).where(
                TenantProviderKey.tenant_id == int(tenant_id),
                TenantProviderKey.provider == cfg.provider,
            )
            .limit(1)
        ).scalar_one_or_none()

    env_key = _env_api_key(cfg.provider)
    api_key = ""
    source = "none"
    if key_row and key_row.api_key_enc:
        api_key = decrypt_secret(key_row.api_key_enc)
        source = "db"
    elif env_key:
        api_key = env_key
        source = "env"

    return {
        "tenant_id": int(tenant_id),
        "provider": cfg.provider,
        "model": cfg.model,
        "base_url": cfg.base_url,
        "api_key": api_key,
        "api_key_tail": key_row.api_key_tail if key_row else mask_key_tail(api_key),
        "source": source,
        "has_api_key": bool(api_key),
    }


# --------------------------------------------------------------------------- #
# Provider key management
# --------------------------------------------------------------------------- #

def upsert_tenant_provider_config(
    *,
    tenant_id: int,
    provider: str,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Update the active provider config for a tenant and optionally store an API key."""

    ensure_enterprise_schema()
    provider_name = normalize_provider_name(provider)
    model_name = validate_model_for_provider(provider_name, model)
    base_url_clean = normalize_optional_base_url(base_url) or default_base_url_for_provider(provider_name)

    tail: Optional[str] = None
    with get_session() as session:
        _ensure_default_tenant(session)
        cfg = _ensure_provider_config(session, tenant_id)
        cfg.provider = provider_name
        cfg.model = model_name
        cfg.base_url = base_url_clean
        cfg.updated_at = func.now()
        if api_key:
            enc = encrypt_secret(api_key)
            tail = mask_key_tail(api_key)
            stmt = _dialect_insert(TenantProviderKey).values(
                tenant_id=int(tenant_id),
                provider=provider_name,
                api_key_enc=enc,
                api_key_tail=tail,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[TenantProviderKey.tenant_id, TenantProviderKey.provider],
                set_={
                    "api_key_enc": enc,
                    "api_key_tail": tail,
                    "updated_at": func.now(),
                },
            )
            session.execute(stmt)
            cfg.api_key_tail = tail
        session.flush()

    return {
        "tenant_id": int(tenant_id),
        "provider": provider_name,
        "model": model_name,
        "base_url": base_url_clean,
        "has_api_key": bool(tail),
        "api_key_tail": tail,
    }


def upsert_tenant_key(*, tenant_id: int, provider: str, api_key_plain: str) -> Dict[str, Any]:
    """Upsert an encrypted key for providers that use the key-only table (e.g., tavily)."""

    ensure_enterprise_schema()
    provider_name = (provider or "").strip().lower()
    if provider_name not in KEY_PROVIDER_PRIORITY:
        raise ValueError("unsupported provider")
    api_key = (api_key_plain or "").strip()
    if not api_key:
        raise ValueError("api_key is required")
    values = set_tenant_provider_key(tenant_id=tenant_id, provider=provider_name, api_key=api_key)
    return {
        "tenant_id": int(tenant_id),
        "provider": provider_name,
        "has_key": True,
        "api_key_tail": values.get("api_key_tail"),
    }


def delete_tenant_key(*, tenant_id: int, provider: str) -> bool:
    """Delete a stored API key for a tenant/provider."""

    ensure_enterprise_schema()
    provider_name = (provider or "").strip().lower()
    if provider_name not in KEY_PROVIDER_PRIORITY:
        raise ValueError("unsupported provider")
    with get_session() as session:
        result = session.execute(
            delete(TenantProviderKey).where(
                TenantProviderKey.tenant_id == int(tenant_id),
                TenantProviderKey.provider == provider_name,
            )
        )
        cfg = session.execute(
            select(TenantProviderConfig).where(TenantProviderConfig.tenant_id == int(tenant_id))
        ).scalar_one_or_none()
        if cfg and cfg.provider == provider_name:
            cfg.api_key_tail = None
        return int(result.rowcount or 0) > 0


def list_tenant_keys(tenant_id: int) -> List[Dict[str, Any]]:
    """List provider keys for a tenant (db + env fallback)."""

    ensure_enterprise_schema()
    with get_session() as session:
        _ensure_default_tenant(session)
        rows = session.execute(
            select(TenantProviderKey).where(TenantProviderKey.tenant_id == int(tenant_id))
        ).scalars().all()
    key_by_provider = {r.provider: r for r in rows}

    items: List[Dict[str, Any]] = []
    for provider in KEY_PROVIDER_PRIORITY:
        env_key = _env_api_key(provider)
        key_row = key_by_provider.get(provider)
        api_key_tail = None
        source = "none"
        if key_row and key_row.api_key_enc:
            api_key_tail = key_row.api_key_tail
            source = "db"
        elif env_key:
            api_key_tail = mask_key_tail(env_key)
            source = "env"

        has_key = bool((key_row and key_row.api_key_enc) or env_key)
        items.append(
            {
                "provider": provider,
                "has_key": has_key,
                "api_key_tail": api_key_tail,
                "source": source,
            }
        )
    return items


def get_tenant_tavily_key(tenant_id: int) -> str:
    """Return the Tavily key for a tenant (db first, env fallback)."""

    ensure_enterprise_schema()
    with get_session() as session:
        row = session.execute(
            select(TenantProviderKey).where(
                TenantProviderKey.tenant_id == int(tenant_id),
                TenantProviderKey.provider == "tavily",
            )
            .limit(1)
        ).scalar_one_or_none()
    if row and row.api_key_enc:
        return decrypt_secret(row.api_key_enc)
    return os.getenv("TAVILY_API_KEY", "").strip()


# --------------------------------------------------------------------------- #
# Limits and usage
# --------------------------------------------------------------------------- #

def _ensure_tenant_limits(session, tenant_id: int) -> TenantLimits:
    limits = session.execute(
        select(TenantLimits).where(TenantLimits.tenant_id == int(tenant_id))
    ).scalar_one_or_none()
    if limits:
        return limits
    limits = TenantLimits(
        tenant_id=int(tenant_id),
        daily_requests_limit=DEFAULT_DAILY_REQUESTS_LIMIT,
        rpm_limit=DEFAULT_RPM_LIMIT,
        daily_token_limit=DEFAULT_DAILY_TOKEN_LIMIT,
        enabled=True,
    )
    session.add(limits)
    session.flush()
    return limits


def get_tenant_limits(tenant_id: int) -> Dict[str, Any]:
    ensure_enterprise_schema()
    with get_session() as session:
        _ensure_default_tenant(session)
        limits = _ensure_tenant_limits(session, tenant_id)
        return _model_to_dict(limits)


def upsert_tenant_limits(
    tenant_id: int,
    *,
    daily_requests_limit: Optional[int] = None,
    rpm_limit: Optional[int] = None,
    daily_token_limit: Optional[int] = None,
    enabled: Optional[bool] = None,
) -> Dict[str, Any]:
    """Update tenant limits and return the row."""

    ensure_enterprise_schema()
    with get_session() as session:
        _ensure_default_tenant(session)
        limits = _ensure_tenant_limits(session, tenant_id)
        if daily_requests_limit is not None:
            limits.daily_requests_limit = max(1, int(daily_requests_limit))
        if rpm_limit is not None:
            limits.rpm_limit = max(1, int(rpm_limit))
        if daily_token_limit is not None:
            limits.daily_token_limit = max(0, int(daily_token_limit))
        if enabled is not None:
            limits.enabled = bool(enabled)
        session.flush()
        return _model_to_dict(limits)


def _ensure_usage_row(session, tenant_id: int, day: str) -> TenantUsageDaily:
    row = session.execute(
        select(TenantUsageDaily).where(
            TenantUsageDaily.tenant_id == int(tenant_id), TenantUsageDaily.day == str(day)
        )
    ).scalar_one_or_none()
    if row:
        return row
    row = TenantUsageDaily(
        tenant_id=int(tenant_id),
        day=str(day),
        request_count=0,
        token_count=0,
        blocked_count=0,
        risk_sum=0,
    )
    session.add(row)
    session.flush()
    return row


def get_tenant_usage_daily(tenant_id: int, day: Optional[str] = None) -> Dict[str, Any]:
    ensure_enterprise_schema()
    day_val = day or _now_dt().strftime("%Y-%m-%d")
    with get_session() as session:
        _ensure_default_tenant(session)
        row = _ensure_usage_row(session, tenant_id, day_val)
        return _model_to_dict(row)


def increment_tenant_usage_daily(
    tenant_id: int,
    *,
    day: Optional[str] = None,
    request_delta: int = 1,
    token_delta: int = 0,
    blocked: bool = False,
    risk_delta: int = 0,
) -> None:
    ensure_enterprise_schema()
    day_val = day or _now_dt().strftime("%Y-%m-%d")
    req_delta = max(0, int(request_delta))
    tok_delta = max(0, int(token_delta))
    blk_delta = 1 if blocked else 0
    risk_delta = int(risk_delta)

    with get_session() as session:
        values = {
            "tenant_id": int(tenant_id),
            "day": day_val,
            "request_count": req_delta,
            "token_count": tok_delta,
            "blocked_count": blk_delta,
            "risk_sum": risk_delta,
        }
        stmt = _dialect_insert(TenantUsageDaily).values(**values)
        stmt = stmt.on_conflict_do_update(
            index_elements=[TenantUsageDaily.tenant_id, TenantUsageDaily.day],
            set_={
                "request_count": TenantUsageDaily.request_count + req_delta,
                "token_count": TenantUsageDaily.token_count + tok_delta,
                "blocked_count": TenantUsageDaily.blocked_count + blk_delta,
                "risk_sum": TenantUsageDaily.risk_sum + risk_delta,
                "updated_at": func.now(),
            },
        )
        session.execute(stmt)


# --------------------------------------------------------------------------- #
# Tenant policy settings
# --------------------------------------------------------------------------- #

def _ensure_policy_settings(session, tenant_id: int) -> TenantPolicySettings:
    settings = session.execute(
        select(TenantPolicySettings).where(TenantPolicySettings.tenant_id == int(tenant_id))
    ).scalar_one_or_none()
    if settings:
        return settings
    settings = TenantPolicySettings(
        tenant_id=int(tenant_id),
        pii_action="redact",
        financial_action="redact",
        secrets_action="block",
        health_action="redact",
        ip_action="redact",
        block_threshold="critical",
        store_original_prompt=True,
        show_sanitized_prompt_admin=True,
    )
    session.add(settings)
    session.flush()
    return settings


def get_tenant_policy_settings(tenant_id: int) -> Dict[str, Any]:
    ensure_enterprise_schema()
    with get_session() as session:
        _ensure_default_tenant(session)
        settings = _ensure_policy_settings(session, tenant_id)
        session.flush()
        return _model_to_dict(settings)


def _validate_policy_action(value: Optional[str]) -> str:
    if value is None:
        raise ValueError("policy action is required")
    action = str(value).strip().lower()
    if action not in ("allow", "redact", "block"):
        raise ValueError("policy action must be allow, redact, or block")
    return action


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
    with get_session() as session:
        _ensure_default_tenant(session)
        settings = _ensure_policy_settings(session, tenant_id)

        if pii_action is not None:
            settings.pii_action = _validate_policy_action(pii_action)
        if financial_action is not None:
            settings.financial_action = _validate_policy_action(financial_action)
        if secrets_action is not None:
            settings.secrets_action = _validate_policy_action(secrets_action)
        if health_action is not None:
            settings.health_action = _validate_policy_action(health_action)
        if ip_action is not None:
            settings.ip_action = _validate_policy_action(ip_action)
        if block_threshold is not None:
            threshold = str(block_threshold or "").strip().lower()
            if threshold not in ("high", "critical"):
                raise ValueError("block_threshold must be high or critical")
            settings.block_threshold = threshold
        if store_original_prompt is not None:
            settings.store_original_prompt = bool(store_original_prompt)
        if show_sanitized_prompt_admin is not None:
            settings.show_sanitized_prompt_admin = bool(show_sanitized_prompt_admin)

        session.flush()
        return _model_to_dict(settings)


# --------------------------------------------------------------------------- #
# Policy rules (legacy / admin UI)
# --------------------------------------------------------------------------- #

def create_policy_rule(
    *,
    tenant_id: int,
    rule_type: str,
    match: str,
    action: str,
    enabled: bool = True,
) -> Dict[str, Any]:
    ensure_enterprise_schema()
    rule_type_norm = str(rule_type or "").strip().lower()
    if rule_type_norm not in ("injection", "category", "severity"):
        raise ValueError("rule_type must be injection, category, or severity")
    action_norm = str(action or "").strip().upper()
    if action_norm not in ("ALLOW", "REDACT", "BLOCK"):
        raise ValueError("action must be ALLOW, REDACT, or BLOCK")

    with get_session() as session:
        rule = TenantPolicy(
            tenant_id=int(tenant_id),
            rule_type=rule_type_norm,
            match=str(match or "").strip(),
            action=action_norm,
            enabled=bool(enabled),
        )
        session.add(rule)
        session.flush()
        return _model_to_dict(rule)


def list_policy_rules(tenant_id: int, rule_type: Optional[str] = None) -> List[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_session() as session:
        query = select(TenantPolicy).where(TenantPolicy.tenant_id == int(tenant_id))
        if rule_type:
            query = query.where(TenantPolicy.rule_type == str(rule_type).strip().lower())
        rows = session.execute(query.order_by(TenantPolicy.id)).scalars().all()
        return [_model_to_dict(r) for r in rows]


def update_policy_rule(
    rule_id: int,
    *,
    match: Optional[str] = None,
    action: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> Optional[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_session() as session:
        rule = session.get(TenantPolicy, int(rule_id))
        if not rule:
            return None
        if match is not None:
            rule.match = str(match).strip()
        if action is not None:
            action_norm = str(action or "").strip().upper()
            if action_norm not in ("ALLOW", "REDACT", "BLOCK"):
                raise ValueError("action must be ALLOW, REDACT, or BLOCK")
            rule.action = action_norm
        if enabled is not None:
            rule.enabled = bool(enabled)
        session.flush()
        return _model_to_dict(rule)


def delete_policy_rule(rule_id: int) -> bool:
    ensure_enterprise_schema()
    with get_session() as session:
        result = session.execute(delete(TenantPolicy).where(TenantPolicy.id == int(rule_id)))
        return int(result.rowcount or 0) > 0


# --------------------------------------------------------------------------- #
# Onboarding bootstrap
# --------------------------------------------------------------------------- #

def bootstrap_first_run(
    *,
    tenant_name: str,
    admin_external_user: str,
    provider: str = "gemini",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """One-time bootstrap to create tenant, admin membership, and provider config."""

    ensure_enterprise_schema()
    if has_any_admin_membership():
        raise ValueError("Onboarding already completed")

    safe_tenant_name = (tenant_name or "Default Tenant").strip() or "Default Tenant"
    admin_user = (admin_external_user or "").strip()
    if not admin_user:
        raise ValueError("admin_external_user is required")

    provider_name = normalize_provider_name(provider)
    model_name = validate_model_for_provider(provider_name, model)
    base_url_clean = normalize_optional_base_url(base_url) or default_base_url_for_provider(provider_name)

    with get_session() as session:
        tenant = _ensure_default_tenant(session)
        tenant.name = safe_tenant_name
        session.flush()

        user = session.execute(
            select(User).where(func.lower(User.external_id) == func.lower(admin_user))
        ).scalar_one_or_none()
        if not user:
            user = User(
                external_id=admin_user,
                username=admin_user,
                display_name=admin_user,
                email=admin_user if "@" in admin_user else None,
                is_active=True,
            )
            session.add(user)
            session.flush()

        membership = session.execute(
            select(Membership).where(
                Membership.tenant_id == int(tenant.id), Membership.user_id == int(user.id)
            )
        ).scalar_one_or_none()
        if not membership:
            membership = Membership(
                tenant_id=int(tenant.id),
                user_id=int(user.id),
                role=PLATFORM_ADMIN_ROLE,
            )
            session.add(membership)
        session.flush()
        tenant_id = int(tenant.id)
        user_id = int(user.id)

    upsert_tenant_provider_config(
        tenant_id=tenant_id,
        provider=provider_name,
        model=model_name,
        api_key=api_key,
        base_url=base_url_clean,
    )
    get_tenant_policy_settings(tenant_id)

    return {
        "ok": True,
        "tenant_id": tenant_id,
        "tenant_name": safe_tenant_name,
        "admin_user_id": user_id,
        "provider": provider_name,
        "model": model_name,
        "base_url": base_url_clean,
        "has_api_key": bool(api_key),
    }


# --------------------------------------------------------------------------- #
# Audit logging
# --------------------------------------------------------------------------- #

def write_audit_log(
    *,
    tenant_id: int,
    user_id: Optional[int],
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    chain_id: Optional[str] = None,
    signing_key: Optional[str] = None,
) -> int:
    ensure_enterprise_schema()
    payload = {
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "metadata": metadata or {},
        "ip": ip,
        "user_agent": user_agent,
        "request_id": request_id,
    }
    chain_val = chain_id or request_id or str(uuid.uuid4())
    signing = signing_key or os.getenv("AUDIT_SIGNING_KEY", DEFAULT_AUDIT_SIGNING_KEY)

    with get_session() as session:
        prev = session.execute(
            select(AuditLog)
            .where(and_(AuditLog.tenant_id == int(tenant_id), AuditLog.chain_id == chain_val))
            .order_by(AuditLog.id.desc())
        ).scalar_one_or_none()
        prev_hash = prev.row_hash if prev else ""
        row_hash = compute_row_hash(payload, prev_hash, signing)
        log = AuditLog(
            tenant_id=int(tenant_id),
            user_id=int(user_id) if user_id is not None else None,
            action=str(action),
            target_type=target_type,
            target_id=target_id,
            metadata_json=_canonical_json(metadata or {}),
            ip=ip,
            user_agent=user_agent,
            request_id=request_id,
            prev_hash=prev_hash or None,
            row_hash=row_hash,
            chain_id=chain_val,
        )
        session.add(log)
        session.flush()
        return int(log.id)


def list_audit_logs(tenant_id: int, *, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """List audit logs for a tenant (newest first)."""

    ensure_enterprise_schema()
    cap = max(1, min(int(limit), 5000))
    off = max(0, int(offset))
    with get_session() as session:
        rows = (
            session.execute(
                select(AuditLog)
                .where(AuditLog.tenant_id == int(tenant_id))
                .order_by(AuditLog.id.desc())
                .offset(off)
                .limit(cap)
            )
            .scalars()
            .all()
        )
        return [_model_to_dict(r) for r in rows]


def verify_audit_chain(tenant_id: int, *, limit: int = 500) -> Dict[str, Any]:
    """Verify hash chain integrity for recent audit logs."""

    ensure_enterprise_schema()
    cap = max(1, min(int(limit), 2000))
    with get_session() as session:
        rows = (
            session.execute(
                select(AuditLog)
                .where(AuditLog.tenant_id == int(tenant_id))
                .order_by(AuditLog.id)
                .limit(cap)
            )
            .scalars()
            .all()
        )

    prev_hash_by_chain: Dict[str, str] = {}
    failures: List[Dict[str, Any]] = []
    for row in rows:
        payload = {
            "action": row.action,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "metadata": json.loads(row.metadata_json or "{}") if row.metadata_json else {},
            "ip": row.ip,
            "user_agent": row.user_agent,
            "request_id": row.request_id,
        }
        chain = row.chain_id or row.request_id or ""
        prev = prev_hash_by_chain.get(chain, "") if chain else ""
        expected = compute_row_hash(payload, prev, os.getenv("AUDIT_SIGNING_KEY", DEFAULT_AUDIT_SIGNING_KEY))
        if expected != (row.row_hash or ""):
            failures.append(
                {
                    "id": int(row.id),
                    "chain_id": chain,
                    "stored_hash": row.row_hash,
                    "expected_hash": expected,
                    "prev_hash": prev,
                }
            )
        prev_hash_by_chain[chain] = row.row_hash or ""

    return {"ok": len(failures) == 0, "checked": len(rows), "failures": failures}


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #

def create_job(
    *,
    tenant_id: int,
    job_type: str,
    input_json: Optional[str] = None,
    user_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create a queued job."""

    ensure_enterprise_schema()
    job_id = str(uuid.uuid4())
    with get_session() as session:
        job = Job(
            id=job_id,
            tenant_id=int(tenant_id),
            user_id=int(user_id) if user_id is not None else None,
            type=str(job_type),
            status="queued",
            input_json=input_json,
        )
        session.add(job)
        session.flush()
        return _model_to_dict(job)


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a job by id."""

    ensure_enterprise_schema()
    with get_session() as session:
        job = session.get(Job, str(job_id))
        return _model_to_dict(job) if job else None


def list_jobs(tenant_id: Optional[int] = None, status: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    """List jobs with optional filters."""

    ensure_enterprise_schema()
    cap = max(1, min(int(limit), 1000))
    with get_session() as session:
        query = select(Job)
        if tenant_id is not None:
            query = query.where(Job.tenant_id == int(tenant_id))
        if status:
            query = query.where(Job.status == str(status))
        rows = session.execute(query.order_by(Job.created_at.desc()).limit(cap)).scalars().all()
        return [_model_to_dict(r) for r in rows]


def claim_next_job(job_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Atomically claim the oldest queued job (skip locked on Postgres)."""

    ensure_enterprise_schema()
    with get_session() as session:
        query = select(Job).where(Job.status == "queued")
        if job_type:
            query = query.where(Job.type == job_type)
        if engine.dialect.name == "postgresql":
            query = query.order_by(Job.created_at).with_for_update(skip_locked=True)
        else:
            query = query.order_by(Job.created_at)
        job = session.execute(query.limit(1)).scalar_one_or_none()
        if not job:
            return None
        job.status = "running"
        job.updated_at = func.now()
        session.flush()
        return _model_to_dict(job)


def update_job(
    *,
    job_id: str,
    status: Optional[str] = None,
    output_path: Optional[str] = None,
    error: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    ensure_enterprise_schema()
    with get_session() as session:
        job = session.get(Job, job_id)
        if not job:
            return None
        if status:
            job.status = status
        job.output_path = output_path
        job.error = error
        job.updated_at = func.now()
        session.flush()
        return _model_to_dict(job)


# --------------------------------------------------------------------------- #
# Request logging (enterprise parity)
# --------------------------------------------------------------------------- #

def insert_request(row: Dict[str, Any], tenant_id: int) -> None:
    values = {
        "id": row.get("id"),
        "ts": row.get("ts") or _utcnow_iso(),
        "user": row.get("user"),
        "purpose": row.get("purpose"),
        "model": row.get("model"),
        "provider": row.get("provider"),
        "cleaned_prompt_preview": row.get("cleaned_prompt_preview"),
        "prompt_original_preview": row.get("prompt_original_preview"),
        "prompt_sent_to_ai_preview": row.get("prompt_sent_to_ai_preview"),
        "detections_count": row.get("detections_count"),
        "entity_counts_json": row.get("entity_counts_json"),
        "risk_categories_json": row.get("risk_categories_json"),
        "risk_score": row.get("risk_score"),
        "risk_level": row.get("risk_level"),
        "severity": row.get("severity") or row.get("risk_level"),
        "decision": row.get("decision"),
        "injection_detected": int(row.get("injection_detected", 0) or 0),
        "tenant_id": int(tenant_id),
    }
    with get_session() as session:
        stmt = _dialect_insert(Request).values(**values)
        stmt = stmt.on_conflict_do_update(index_elements=[Request.id], set_=values)
        session.execute(stmt)
