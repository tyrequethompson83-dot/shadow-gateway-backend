"""
Database access layer for core (non‑enterprise) features.

Primary target is Postgres when `DATABASE_URL` is set. Falls back to a local
SQLite file for convenience during local development and tests.

All queries return dictionaries to make the call sites serialization‑friendly.
"""

import json
import os
from collections import Counter
from contextlib import contextmanager
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    Index,
    case,
    create_engine,
    func,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, sessionmaker

# --------------------------------------------------------------------------- #
# Engine / session configuration
# --------------------------------------------------------------------------- #

DB_PATH = os.getenv("DB_PATH", "app.db")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()


def _database_url() -> str:
    """Prefer DATABASE_URL (Postgres); otherwise use local SQLite."""

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
# ORM models
# --------------------------------------------------------------------------- #

class Request(Base):
    """Requests table mapped for SQLAlchemy with multi‑tenant indexes."""

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


class Tenant(Base):
    """Minimal tenant mapping used by dashboard helpers."""

    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=False)
    created_at = Column(String, server_default=func.now())


# --------------------------------------------------------------------------- #
# Session / connection helpers
# --------------------------------------------------------------------------- #

def get_engine() -> Engine:
    """Expose the shared engine for callers that need low‑level access."""

    return engine


@contextmanager
def get_session():
    """Context manager that yields a SQLAlchemy session with safe commit/rollback."""

    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create tables and indexes if they do not exist."""

    Base.metadata.create_all(bind=engine)


# --------------------------------------------------------------------------- #
# Metadata helpers (information_schema for Postgres; inspector for SQLite)
# --------------------------------------------------------------------------- #

def table_exists(table_name: str, *, schema: str = "public") -> bool:
    """Check table existence without using SQLite‑specific sqlite_master/PRAGMA."""

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

    # Fallback for SQLite/local dev uses SQLAlchemy's inspector (no raw PRAGMA here)
    from sqlalchemy import inspect  # imported lazily to avoid unused warning on Postgres

    inspector = inspect(engine)
    return table_name in inspector.get_table_names()


def list_columns(table_name: str, *, schema: str = "public") -> List[str]:
    """List columns using information_schema on Postgres; inspector elsewhere."""

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
            rows = conn.execute(query, {"schema": schema, "table": table_name}).all()
            return [str(r[0]) for r in rows]

    from sqlalchemy import inspect

    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return []
    return [c["name"] for c in inspector.get_columns(table_name)]


# --------------------------------------------------------------------------- #
# Utility converters
# --------------------------------------------------------------------------- #

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


# --------------------------------------------------------------------------- #
# Request upsert helper
# --------------------------------------------------------------------------- #

def _request_insert(values: Dict[str, Any]):
    """Dialect‑aware upsert for the requests table."""

    if engine.dialect.name == "postgresql":
        stmt = pg_insert(Request).values(**values)
    else:
        stmt = sqlite_insert(Request).values(**values)
    return stmt.on_conflict_do_update(index_elements=[Request.id], set_=values)


# --------------------------------------------------------------------------- #
# Public operations
# --------------------------------------------------------------------------- #

def insert_request(row: Dict[str, Any], tenant_id: int) -> None:
    """Insert or update a request row scoped to a tenant."""

    init_db()
    values = {
        "id": row.get("id"),
        "ts": row.get("ts"),
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
        session.execute(_request_insert(values))


def get_summary(tenant_id: Optional[int] = None) -> Dict[str, Optional[int]]:
    """Return aggregate stats for all requests or a single tenant."""

    init_db()
    with get_session() as session:
        filters = []
        if tenant_id is not None:
            filters.append(Request.tenant_id == int(tenant_id))

        total = session.execute(select(func.count(Request.id)).where(*filters)).scalar_one()
        avg_val = session.execute(select(func.avg(Request.risk_score)).where(*filters)).scalar()
        high_or_critical = session.execute(
            select(
                func.sum(
                    case(
                        (Request.risk_level.in_(["HIGH", "CRITICAL"]), 1),
                        else_=0,
                    )
                )
            ).where(*filters)
        ).scalar()

    return {
        "total_requests": int(total or 0),
        "avg_risk_score": float(avg_val or 0.0),
        "high_or_critical": int(high_or_critical or 0),
    }


def get_entity_totals(tenant_id: int = 1) -> Dict[str, int]:
    """Aggregate entity counts for a tenant."""

    init_db()
    totals = Counter()
    with get_session() as session:
        rows = session.execute(
            select(Request.entity_counts_json).where(Request.tenant_id == int(tenant_id))
        ).all()
    for raw_json, in rows:
        if not raw_json:
            continue
        try:
            totals.update(json.loads(raw_json))
        except Exception:
            continue
    return dict(totals)


def get_risk_trend(tenant_id: int = 1, days: int = 14) -> List[Dict[str, Any]]:
    """Return rolling average risk per day for plotting."""

    init_db()
    with get_session() as session:
        rows = session.execute(
            select(Request.ts, Request.risk_score)
            .where(Request.tenant_id == int(tenant_id))
            .order_by(Request.ts.desc())
            .limit(5000)
        ).all()

    by_day: Dict[str, Dict[str, float]] = {}
    for ts, risk in rows:
        try:
            day = (ts or "")[:10]
            risk_val = float(risk)
        except Exception:
            continue
        bucket = by_day.setdefault(day, {"sum": 0.0, "count": 0})
        bucket["sum"] += risk_val
        bucket["count"] += 1

    days_sorted = sorted(by_day.keys())[-days:]
    out: List[Dict[str, Any]] = []
    for d in days_sorted:
        c = by_day[d]["count"]
        avg = (by_day[d]["sum"] / c) if c else 0.0
        out.append({"date": d, "avg_risk": avg, "count": c})
    return out


def get_recent_requests(tenant_id: int = 1, limit: int = 100) -> List[Dict[str, Any]]:
    """Return recent requests for a tenant as dictionaries."""

    init_db()
    cap = max(1, min(int(limit), 5000))
    with get_session() as session:
        rows = (
            session.execute(
                select(Request)
                .where(Request.tenant_id == int(tenant_id))
                .order_by(Request.ts.desc())
                .limit(cap)
            )
            .scalars()
            .all()
        )
    return [_model_to_dict(r) for r in rows]


def list_tenants() -> List[Dict[str, Any]]:
    """List tenants if the table exists; otherwise return a default placeholder."""

    init_db()
    if not table_exists("tenants"):
        return [{"id": 1, "name": "Default Tenant"}]
    with get_session() as session:
        rows = session.execute(select(Tenant).order_by(Tenant.id)).scalars().all()
    out = [_model_to_dict(r) for r in rows]
    return out or [{"id": 1, "name": "Default Tenant"}]


def get_risk_timeseries(days: int = 14, tenant_id: int = 1) -> List[Dict[str, Any]]:
    return get_risk_trend(tenant_id=tenant_id, days=days)


def get_recent(limit: int = 100, tenant_id: Optional[int] = None) -> List[Dict[str, Any]]:
    if tenant_id is None:
        tenant_id = 1
    return get_recent_requests(tenant_id=tenant_id, limit=limit)


def get_compliance_snapshot(tenant_id: int) -> Dict[str, Any]:
    """Summarize decision, severity, and provider/model usage for a tenant."""

    init_db()
    with get_session() as session:
        rows = (
            session.execute(
                select(
                    Request.user,
                    Request.provider,
                    Request.model,
                    Request.decision,
                    Request.risk_level,
                    Request.severity,
                    Request.injection_detected,
                    Request.entity_counts_json,
                    Request.risk_categories_json,
                ).where(Request.tenant_id == int(tenant_id))
            ).all()
        )

    decisions = Counter()
    category_totals = Counter()
    severity_totals = Counter()
    user_totals = Counter()
    provider_usage = Counter()
    model_usage = Counter()
    injection_attempts = 0

    for row in rows:
        (
            user,
            provider,
            model,
            decision,
            risk_level,
            severity,
            inj,
            entity_json,
            category_json,
        ) = row
        decision_val = str(decision or "ALLOW").upper()
        severity_val = str(severity or risk_level or "LOW").upper()
        user_val = str(user or "unknown")
        provider_val = str(provider or "unknown")
        model_val = str(model or "unknown")

        decisions[decision_val] += 1
        severity_totals[severity_val] += 1
        user_totals[user_val] += 1
        provider_usage[provider_val] += 1
        model_usage[model_val] += 1
        if int(inj or 0) > 0:
            injection_attempts += 1

        try:
            parsed_categories = json.loads(category_json or "{}")
            if isinstance(parsed_categories, dict):
                for k, v in parsed_categories.items():
                    category_totals[str(k)] += int(v or 0)
        except Exception:
            pass

    top_users = [{"user": u, "count": c} for u, c in user_totals.most_common(10)]
    return {
        "tenant_id": int(tenant_id),
        "total_requests": int(sum(decisions.values())),
        "allowed": int(decisions.get("ALLOW", 0)),
        "redacted": int(decisions.get("REDACT", 0)),
        "blocked": int(decisions.get("BLOCK", 0)),
        "redactions_by_category": dict(category_totals),
        "injection_attempts": int(injection_attempts),
        "top_users": top_users,
        "risk_distribution": dict(severity_totals),
        "provider_usage": dict(provider_usage),
        "model_usage": dict(model_usage),
    }

