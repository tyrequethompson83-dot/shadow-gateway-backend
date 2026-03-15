import importlib

from fastapi.testclient import TestClient


def _auth_headers(token: str, tenant_id: int, **extra_headers: str) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": str(int(tenant_id)),
    }
    headers.update(extra_headers)
    return headers


def test_login_bruteforce_rate_limit_returns_429(app_ctx):
    client = app_ctx["client"]

    for _ in range(5):
        resp = client.post(
            "/auth/login",
            json={"email": "nobody@example.test", "password": "WrongPassword123!"},
        )
        assert resp.status_code == 401

    blocked = client.post(
        "/auth/login",
        json={"email": "nobody@example.test", "password": "WrongPassword123!"},
    )
    assert blocked.status_code == 429


def test_login_lockout_after_repeated_failures(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Lockout Corp",
            "admin_email": "lockout-admin@example.test",
            "password": "LockoutPass123!",
        },
    )
    assert signup.status_code == 200

    for idx in range(9):
        failed = client.post(
            "/auth/login",
            json={"email": "lockout-admin@example.test", "password": "WrongPassword123!"},
            headers={"X-Forwarded-For": f"10.0.0.{idx + 1}"},
        )
        assert failed.status_code == 401

    tenth = client.post(
        "/auth/login",
        json={"email": "lockout-admin@example.test", "password": "WrongPassword123!"},
        headers={"X-Forwarded-For": "10.0.0.99"},
    )
    assert tenth.status_code == 423

    locked = client.post(
        "/auth/login",
        json={"email": "lockout-admin@example.test", "password": "LockoutPass123!"},
        headers={"X-Forwarded-For": "10.0.0.100"},
    )
    assert locked.status_code == 423


def test_cross_tenant_header_override_blocked_in_jwt_mode(app_ctx):
    client = app_ctx["client"]

    signup_a = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Tenant A Inc",
            "admin_email": "admin-a@example.test",
            "password": "AdminPassA123!",
        },
    )
    assert signup_a.status_code == 200
    tenant_a = int(signup_a.json()["tenant_id"])
    token_a = str(signup_a.json()["access_token"])

    signup_b = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Tenant B Inc",
            "admin_email": "admin-b@example.test",
            "password": "AdminPassB123!",
        },
    )
    assert signup_b.status_code == 200
    tenant_b = int(signup_b.json()["tenant_id"])

    blocked = client.get(
        "/summary",
        headers=_auth_headers(token_a, tenant_b),
    )
    assert blocked.status_code == 400

    allowed = client.get(
        "/summary",
        headers=_auth_headers(token_a, tenant_a),
    )
    assert allowed.status_code == 200


def test_employee_blocked_from_admin_spaces(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Role Guard Ltd",
            "admin_email": "owner@roleguard.test",
            "password": "OwnerPass123!",
        },
    )
    assert signup.status_code == 200
    tenant_id = int(signup.json()["tenant_id"])
    admin_token = str(signup.json()["access_token"])

    invite = client.post(
        "/tenant/admin/invite",
        json={"email": "employee@roleguard.test", "role": "employee"},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert invite.status_code == 200
    invite_token = str(invite.json()["token"])

    employee_signup = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "employee@roleguard.test",
            "password": "EmployeePass123!",
        },
    )
    assert employee_signup.status_code == 200
    employee_token = str(employee_signup.json()["access_token"])

    blocked_admin = client.get("/admin/whoami", headers=_auth_headers(employee_token, tenant_id))
    assert blocked_admin.status_code == 403

    blocked_tenant_admin = client.post(
        "/tenant/admin/invite",
        json={"email": "denied@roleguard.test", "role": "employee"},
        headers=_auth_headers(employee_token, tenant_id),
    )
    assert blocked_tenant_admin.status_code == 403


def test_x_user_header_rejected_in_prod(monkeypatch, tmp_path):
    db_path = tmp_path / "prod_mode_test.db"

    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("ENABLE_JOB_WORKER", "false")
    monkeypatch.setenv("ENABLE_TENANT_LIMITS", "true")
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ALLOWED_ORIGINS", "https://app.example.test")
    monkeypatch.setenv("MASTER_KEY", "prod-master-key-32-characters-long!!")
    monkeypatch.setenv("JWT_SECRET", "prod-jwt-secret-value-32-characters!")
    monkeypatch.setenv("AUTH_MODE", "jwt")
    monkeypatch.setenv("AUDIT_SIGNING_KEY", "test-signing-key")
    monkeypatch.setenv("ENTERPRISE_MODE", "true")
    monkeypatch.setenv("ENFORCE_RBAC", "true")

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
        resp = client.get("/health", headers={"X-User": "dev-header-user"})
        assert resp.status_code == 400
