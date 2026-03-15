import importlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    db_path = tmp_path / "test_app.db"

    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("ENABLE_JOB_WORKER", "false")
    monkeypatch.setenv("ENABLE_TENANT_LIMITS", "true")
    monkeypatch.setenv("AUDIT_SIGNING_KEY", "test-signing-key")
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("MASTER_KEY", "test-master-key-32-characters-long!!")
    monkeypatch.setenv("SHADOW_MASTER_KEY", "test-master-key")
    monkeypatch.setenv("ENTERPRISE_MODE", "true")
    monkeypatch.setenv("ENFORCE_RBAC", "true")
    monkeypatch.setenv("AUTH_MODE", "header")
    monkeypatch.setenv("JWT_SECRET", "test-jwt-secret-value-32-characters-minimum")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("GROQ_API_KEY", "")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")

    import db
    import auth_rate_limit
    import enterprise.db_enterprise as db_enterprise
    import enterprise.jobs as jobs
    import enterprise.limits as limits
    import enterprise.rbac as rbac
    import policy_engine
    import policies
    import routes.admin as admin
    import main

    db = importlib.reload(db)
    auth_rate_limit = importlib.reload(auth_rate_limit)
    db_enterprise = importlib.reload(db_enterprise)
    jobs = importlib.reload(jobs)
    limits = importlib.reload(limits)
    rbac = importlib.reload(rbac)
    policy_engine = importlib.reload(policy_engine)
    policies = importlib.reload(policies)
    admin = importlib.reload(admin)
    main = importlib.reload(main)

    limits.reset_rate_limit_state()
    auth_rate_limit.reset_in_memory_rate_limiter()
    db.init_db()
    db_enterprise.ensure_enterprise_schema()

    with TestClient(main.app) as client:
        yield {
            "client": client,
            "db": db,
            "db_enterprise": db_enterprise,
            "limits": limits,
            "db_path": Path(str(db_path)),
        }
