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
    is_personal = Column(Boolean, nullable=False, server_default=text("0"))


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    external_id = Column(String, unique=True)
    username = Column(String, unique=True)
    display_name = Column(String)
    email = Column(String, unique=True)
    password_hash = Column(String)
    password_salt = Column(String)
    is_active = Column(Boolean, nullable=False, server_default=text("1"))
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
    daily_token_limit = Column(Integer, nullable=False, default=DEFAULT_DAILY_TOKEN_LIMIT)
    enabled = Column(Boolean, nullable=False, default=True, server_default=text("1"))


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
    enabled = Column(Boolean, nullable=False, default=True, server_default=text("1"))
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
    store_original_prompt = Column(Boolean, nullable=False, default=True, server_default=text("1"))
    show_sanitized_prompt_admin = Column(Boolean, nullable=False, default=True, server_default=text("1"))
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
    tenant = session.execute(select(Tenant).order_by(Tenant.id)).scalar_one_or_none()
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


# --------------------------------------------------------------------------- #
# Provider configuration helpers
# --------------------------------------------------------------------------- #

def _env_api_key(provider: str) -> str:
    name = normalize_provider_name(provider)
    if name == "gemini":
        return os.getenv("GEMINI_API_KEY", "").strip()
    if name == "openai":
        return os.getenv("OPENAI_API_KEY", "").strip()
    if name == "groq":
        return os.getenv("GROQ_API_KEY", "").strip()
    if name == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY", "").strip()
    if name == "tavily":
        return os.getenv("TAVILY_API_KEY", "").strip()
    return ""


def _ensure_provider_config(session, tenant_id: int) -> TenantProviderConfig:
    cfg = session.execute(
        select(TenantProviderConfig).where(TenantProviderConfig.tenant_id == int(tenant_id))
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


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #

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

