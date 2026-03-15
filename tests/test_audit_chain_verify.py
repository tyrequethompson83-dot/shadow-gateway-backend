def test_audit_chain_verify_passes(app_ctx):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]

    user_id = db_enterprise.ensure_user("platform-admin-user")
    db_enterprise.upsert_membership(tenant_id=1, user_id=user_id, role="platform_admin")

    # Generate at least one audited request.
    ping = client.get("/health", headers={"X-User": "platform-admin-user", "X-Tenant-Id": "1"})
    assert ping.status_code == 200

    resp = client.get("/admin/audit/verify", headers={"X-User": "platform-admin-user", "X-Tenant-Id": "1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
