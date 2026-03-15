def _auth_headers(token: str, tenant_id: int) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": str(int(tenant_id)),
    }


def _signup_company_tenant_admin(client, company_name: str, admin_email: str) -> tuple[int, str]:
    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": company_name,
            "admin_email": admin_email,
            "password": "OwnerPass123!",
        },
    )
    assert signup.status_code == 200
    body = signup.json()
    return int(body["tenant_id"]), str(body["access_token"])


def test_usage_summary_endpoint_returns_expected_values(app_ctx):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    tenant_id, token = _signup_company_tenant_admin(client, "Usage Summary Org", "owner@usage-summary.test")

    db_enterprise.upsert_tenant_limits(
        tenant_id=tenant_id,
        daily_requests_limit=100,
        rpm_limit=25,
        enabled=True,
    )
    db_enterprise.increment_tenant_usage_daily(
        tenant_id=tenant_id,
        request_delta=40,
        token_delta=1234,
    )

    resp = client.get("/tenant/admin/usage-summary", headers=_auth_headers(token, tenant_id))
    assert resp.status_code == 200
    body = resp.json()

    assert int(body["tenant_id"]) == tenant_id
    assert int(body["daily_requests_limit"]) == 100
    assert int(body["rpm_limit"]) == 25
    assert int(body["today_request_count"]) == 40
    assert int(body["today_token_count"]) == 1234
    assert int(body["daily_requests_remaining"]) == 60
    assert float(body["daily_percent_used"]) == 40.0


def test_usage_summary_percent_and_remaining_calculation(app_ctx):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    tenant_id, token = _signup_company_tenant_admin(client, "Usage Calc Org", "owner@usage-calc.test")

    db_enterprise.upsert_tenant_limits(
        tenant_id=tenant_id,
        daily_requests_limit=40,
        rpm_limit=15,
        enabled=True,
    )
    db_enterprise.increment_tenant_usage_daily(
        tenant_id=tenant_id,
        request_delta=55,
        token_delta=5,
    )

    resp = client.get("/tenant/admin/usage-summary", headers=_auth_headers(token, tenant_id))
    assert resp.status_code == 200
    body = resp.json()

    assert int(body["today_request_count"]) == 55
    assert int(body["daily_requests_remaining"]) == 0
    assert float(body["daily_percent_used"]) == 100.0


def test_usage_summary_zero_usage_case(app_ctx):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    tenant_id, token = _signup_company_tenant_admin(client, "Usage Zero Org", "owner@usage-zero.test")

    db_enterprise.upsert_tenant_limits(
        tenant_id=tenant_id,
        daily_requests_limit=80,
        rpm_limit=20,
        enabled=True,
    )

    resp = client.get("/tenant/admin/usage-summary", headers=_auth_headers(token, tenant_id))
    assert resp.status_code == 200
    body = resp.json()

    assert int(body["today_request_count"]) == 0
    assert int(body["today_token_count"]) == 0
    assert int(body["daily_requests_remaining"]) == 80
    assert float(body["daily_percent_used"]) == 0.0
