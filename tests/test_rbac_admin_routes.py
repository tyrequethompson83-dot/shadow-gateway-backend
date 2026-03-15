def test_non_admin_cannot_grant_role(app_ctx):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]

    user_id = db_enterprise.ensure_user("non-admin-user")
    db_enterprise.upsert_membership(tenant_id=1, user_id=user_id, role="user")

    resp = client.post(
        "/admin/grant-role",
        params={"external_user": "target-user", "role": "auditor"},
        headers={"X-User": "non-admin-user", "X-Tenant-Id": "1"},
    )
    assert resp.status_code == 403
