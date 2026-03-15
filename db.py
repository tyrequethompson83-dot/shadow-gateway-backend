import json
import os
import sqlite3
from collections import Counter
from typing import Any, Dict, List, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:  # psycopg2 may be absent in pure SQLite mode
    psycopg2 = None
    RealDictCursor = None

# Minimal DB helpers with Postgres first, falling back to SQLite.
DB_PATH = os.getenv("DB_PATH", "app.db")
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()


def _conn():
    if DATABASE_URL and psycopg2:
        pg_conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        pg_conn.autocommit = True

        class PGWrapper:
            def __init__(self, conn):
                self.conn = conn

            def execute(self, sql: str, params: Any = None):
                # Translate SQLite-style ? placeholders to %s for psycopg2
                translated = sql.replace("?", "%s")
                cur = self.conn.cursor()
                cur.execute(translated, params or [])
                return cur

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                self.conn.close()

        return PGWrapper(pg_conn)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _request_columns(con: sqlite3.Connection) -> List[str]:
    rows = con.execute("PRAGMA table_info(requests)").fetchall()
    return [r[1] for r in rows]


def _request_ts_column(cols: List[str]) -> Optional[str]:
    if "created_at" in cols:
        return "created_at"
    if "ts" in cols:
        return "ts"
    return None


def init_db():
    """
    Create `requests` table and run additive tenant migration steps:
    - add tenant_id column if missing
    - backfill tenant_id to 1
    - create tenant/time index
    """
    with _conn() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                ts TEXT,
                user TEXT,
                purpose TEXT,
                model TEXT,
                provider TEXT,
                cleaned_prompt_preview TEXT,
                prompt_original_preview TEXT,
                prompt_sent_to_ai_preview TEXT,
                detections_count INTEGER,
                entity_counts_json TEXT,
                risk_categories_json TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                severity TEXT,
                decision TEXT,
                injection_detected INTEGER DEFAULT 0,
                tenant_id INTEGER
            )
            """
        )

        cols = _request_columns(con)
        if "tenant_id" not in cols:
            con.execute("ALTER TABLE requests ADD COLUMN tenant_id INTEGER")
            cols = _request_columns(con)
        if "provider" not in cols:
            con.execute("ALTER TABLE requests ADD COLUMN provider TEXT")
            cols = _request_columns(con)
        if "risk_categories_json" not in cols:
            con.execute("ALTER TABLE requests ADD COLUMN risk_categories_json TEXT")
            cols = _request_columns(con)
        if "prompt_original_preview" not in cols:
            con.execute("ALTER TABLE requests ADD COLUMN prompt_original_preview TEXT")
            cols = _request_columns(con)
        if "prompt_sent_to_ai_preview" not in cols:
            con.execute("ALTER TABLE requests ADD COLUMN prompt_sent_to_ai_preview TEXT")
            cols = _request_columns(con)
        if "severity" not in cols:
            con.execute("ALTER TABLE requests ADD COLUMN severity TEXT")
            cols = _request_columns(con)
        if "injection_detected" not in cols:
            con.execute("ALTER TABLE requests ADD COLUMN injection_detected INTEGER DEFAULT 0")
            cols = _request_columns(con)

        con.execute("UPDATE requests SET tenant_id = 1 WHERE tenant_id IS NULL")
        con.execute("UPDATE requests SET severity = COALESCE(severity, risk_level) WHERE severity IS NULL")
        con.execute("UPDATE requests SET provider = COALESCE(provider, 'gemini') WHERE provider IS NULL")
        con.execute("UPDATE requests SET injection_detected = COALESCE(injection_detected, 0) WHERE injection_detected IS NULL")

        ts_col = _request_ts_column(cols)
        if ts_col:
            con.execute(
                f"CREATE INDEX IF NOT EXISTS idx_requests_tenant_created ON requests(tenant_id, {ts_col})"
            )
        con.execute("CREATE INDEX IF NOT EXISTS idx_requests_tenant_decision ON requests(tenant_id, decision)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_requests_tenant_provider ON requests(tenant_id, provider)")


def insert_request(row: Dict, tenant_id: int):
    """Insert a request row dict into the requests table with tenant scope."""
    init_db()
    with _conn() as con:
        cols = _request_columns(con)
        if "tenant_id" in cols:
            con.execute(
                """
                INSERT OR REPLACE INTO requests
                    (id, ts, user, purpose, model, provider, cleaned_prompt_preview, prompt_original_preview, prompt_sent_to_ai_preview, detections_count, entity_counts_json, risk_categories_json, risk_score, risk_level, severity, decision, injection_detected, tenant_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.get("id"),
                    row.get("ts"),
                    row.get("user"),
                    row.get("purpose"),
                    row.get("model"),
                    row.get("provider"),
                    row.get("cleaned_prompt_preview"),
                    row.get("prompt_original_preview"),
                    row.get("prompt_sent_to_ai_preview"),
                    row.get("detections_count"),
                    row.get("entity_counts_json"),
                    row.get("risk_categories_json"),
                    row.get("risk_score"),
                    row.get("risk_level"),
                    row.get("severity"),
                    row.get("decision"),
                    int(row.get("injection_detected", 0) or 0),
                    int(tenant_id),
                ),
            )
        else:
            # Fallback for pre-migration databases.
            con.execute(
                """
                INSERT OR REPLACE INTO requests
                    (id, ts, user, purpose, model, cleaned_prompt_preview, detections_count, entity_counts_json, risk_score, risk_level, decision)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.get("id"),
                    row.get("ts"),
                    row.get("user"),
                    row.get("purpose"),
                    row.get("model"),
                    row.get("cleaned_prompt_preview"),
                    row.get("detections_count"),
                    row.get("entity_counts_json"),
                    row.get("risk_score"),
                    row.get("risk_level"),
                    row.get("decision"),
                ),
            )


def get_summary(tenant_id: Optional[int] = None) -> Dict[str, Optional[int]]:
    """Return request summary stats, optionally tenant-scoped."""
    init_db()
    with _conn() as con:
        cols = _request_columns(con)
        has_tenant = "tenant_id" in cols

        if has_tenant and tenant_id is not None:
            params = (int(tenant_id),)
            total = con.execute(
                "SELECT COUNT(1) AS c FROM requests WHERE tenant_id = ?",
                params,
            ).fetchone()["c"]
            avg_row = con.execute(
                "SELECT AVG(risk_score) AS avg FROM requests WHERE tenant_id = ?",
                params,
            ).fetchone()
            hc_row = con.execute(
                """
                SELECT SUM(CASE WHEN UPPER(COALESCE(risk_level, '')) IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) AS hc
                FROM requests
                WHERE tenant_id = ?
                """,
                params,
            ).fetchone()
        else:
            total = con.execute("SELECT COUNT(1) AS c FROM requests").fetchone()["c"]
            avg_row = con.execute("SELECT AVG(risk_score) AS avg FROM requests").fetchone()
            hc_row = con.execute(
                """
                SELECT SUM(CASE WHEN UPPER(COALESCE(risk_level, '')) IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) AS hc
                FROM requests
                """
            ).fetchone()

    avg = avg_row["avg"] if avg_row and avg_row["avg"] is not None else 0
    high_or_critical = hc_row["hc"] if hc_row and hc_row["hc"] is not None else 0
    return {
        "total_requests": int(total),
        "avg_risk_score": float(avg),
        "high_or_critical": int(high_or_critical),
    }


def get_entity_totals(tenant_id: int = 1) -> Dict[str, int]:
    """Sums entity_counts_json for a single tenant."""
    init_db()
    totals = Counter()
    with _conn() as con:
        cols = _request_columns(con)
        has_tenant = "tenant_id" in cols
        if has_tenant:
            rows = con.execute(
                "SELECT entity_counts_json FROM requests WHERE tenant_id = ?",
                (int(tenant_id),),
            ).fetchall()
        else:
            rows = con.execute("SELECT entity_counts_json FROM requests").fetchall()

        for r in rows:
            raw = r["entity_counts_json"]
            if not raw:
                continue
            try:
                totals.update(json.loads(raw))
            except Exception:
                continue
    return dict(totals)


def get_risk_trend(tenant_id: int = 1, days: int = 14) -> List[Dict]:
    """
    Returns rows for plotting:
    [{"date":"2026-03-03","avg_risk":23.5,"count":12}, ...]
    """
    init_db()
    with _conn() as con:
        cols = _request_columns(con)
        has_tenant = "tenant_id" in cols
        if has_tenant:
            rows = con.execute(
                """
                SELECT ts, risk_score
                FROM requests
                WHERE tenant_id = ?
                ORDER BY ts DESC
                LIMIT 5000
                """,
                (int(tenant_id),),
            ).fetchall()
        else:
            rows = con.execute(
                """
                SELECT ts, risk_score
                FROM requests
                ORDER BY ts DESC
                LIMIT 5000
                """
            ).fetchall()

    by_day = {}
    for r in rows:
        ts = r["ts"] or ""
        risk = r["risk_score"]
        try:
            day = ts[:10]
            float(risk)
        except Exception:
            continue

        if day not in by_day:
            by_day[day] = {"sum": 0.0, "count": 0}
        by_day[day]["sum"] += float(risk)
        by_day[day]["count"] += 1

    days_sorted = sorted(by_day.keys())[-days:]
    out = []
    for d in days_sorted:
        c = by_day[d]["count"]
        avg = (by_day[d]["sum"] / c) if c else 0.0
        out.append({"date": d, "avg_risk": avg, "count": c})
    return out


def get_recent_requests(tenant_id: int = 1, limit: int = 100) -> List[Dict]:
    """Return recent requests for a single tenant."""
    init_db()
    with _conn() as con:
        cols = _request_columns(con)
        has_tenant = "tenant_id" in cols
        if has_tenant:
            rows = con.execute(
                "SELECT * FROM requests WHERE tenant_id = ? ORDER BY ts DESC LIMIT ?",
                (int(tenant_id), int(limit)),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM requests ORDER BY ts DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
    return [dict(r) for r in rows]


def list_tenants() -> List[Dict]:
    """Return tenants for dashboard selection."""
    init_db()
    with _conn() as con:
        tables = {
            r[0]
            for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "tenants" not in tables:
            return [{"id": 1, "name": "Default Tenant"}]
        rows = con.execute("SELECT id, name FROM tenants ORDER BY id ASC").fetchall()
        out = [dict(r) for r in rows]
        return out or [{"id": 1, "name": "Default Tenant"}]


# Backward-compatible wrappers
def get_risk_timeseries(days: int = 14, tenant_id: int = 1) -> List[Dict]:
    return get_risk_trend(tenant_id=tenant_id, days=days)


def get_recent(limit: int = 100, tenant_id: Optional[int] = None) -> List[Dict]:
    if tenant_id is None:
        tenant_id = 1
    return get_recent_requests(tenant_id=tenant_id, limit=limit)


def get_compliance_snapshot(tenant_id: int) -> Dict[str, Any]:
    init_db()
    with _conn() as con:
        rows = con.execute(
            """
            SELECT
              user, provider, model, decision, risk_level, severity, injection_detected,
              entity_counts_json, risk_categories_json
            FROM requests
            WHERE tenant_id = ?
            """,
            (int(tenant_id),),
        ).fetchall()

    total = len(rows)
    decisions = Counter()
    category_totals = Counter()
    severity_totals = Counter()
    user_totals = Counter()
    provider_usage = Counter()
    model_usage = Counter()
    injection_attempts = 0

    for row in rows:
        decision = str(row["decision"] or "ALLOW").upper()
        severity = str(row["severity"] or row["risk_level"] or "LOW").upper()
        user = str(row["user"] or "unknown")
        provider = str(row["provider"] or "unknown")
        model = str(row["model"] or "unknown")

        decisions[decision] += 1
        severity_totals[severity] += 1
        user_totals[user] += 1
        provider_usage[provider] += 1
        model_usage[model] += 1
        if int(row["injection_detected"] or 0) > 0:
            injection_attempts += 1

        raw_categories = row["risk_categories_json"] or "{}"
        try:
            parsed_categories = json.loads(raw_categories)
            if isinstance(parsed_categories, dict):
                for category, count in parsed_categories.items():
                    category_totals[str(category)] += int(count or 0)
        except Exception:
            pass

    top_users = [{"user": u, "count": c} for u, c in user_totals.most_common(10)]
    return {
        "tenant_id": int(tenant_id),
        "total_requests": int(total),
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
