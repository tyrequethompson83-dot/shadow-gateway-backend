import sqlite3


def _auth_headers(token: str, tenant_id: int) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": str(int(tenant_id)),
    }


def _item_by_provider(items: list[dict], provider: str) -> dict:
    for item in items:
        if str(item.get("provider") or "").strip().lower() == provider:
            return item
    return {}


def test_tenant_admin_can_put_get_delete_keys_with_persistence(app_ctx):
    client = app_ctx["client"]
    db_path = app_ctx["db_path"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Keys Org",
            "admin_email": "admin@keys-org.test",
            "password": "StrongPass123!",
        },
    )
    assert signup.status_code == 200
    body = signup.json()
    tenant_id = int(body["tenant_id"])
    admin_token = str(body["access_token"])

    plain_key = "sk-test-openai-1234567890abcdef"
    put_resp = client.put(
        "/tenant/keys",
        json={"provider": "openai", "api_key": plain_key},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["ok"] is True

    get_resp = client.get("/tenant/keys", headers=_auth_headers(admin_token, tenant_id))
    assert get_resp.status_code == 200
    get_body = get_resp.json()
    assert int(get_body["tenant_id"]) == tenant_id
    providers = [str(item.get("provider") or "").strip().lower() for item in get_body.get("items", [])]
    assert "mock" not in providers
    assert "groq" in providers
    openai_item = _item_by_provider(get_body.get("items", []), "openai")
    assert openai_item
    assert openai_item["has_key"] is True
    assert openai_item["api_key_tail"] == plain_key[-4:]

    with sqlite3.connect(str(db_path)) as con:
        row = con.execute(
            """
            SELECT api_key_enc, api_key_tail
            FROM tenant_provider_keys
            WHERE tenant_id = ? AND provider = 'openai'
            """,
            (tenant_id,),
        ).fetchone()
    assert row is not None
    assert str(row[0]).startswith("enc:v2:")
    assert plain_key not in str(row[0])
    assert str(row[1]) == plain_key[-4:]

    delete_resp = client.delete(
        "/tenant/keys/openai",
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert delete_resp.status_code == 200
    assert delete_resp.json()["ok"] is True

    get_after = client.get("/tenant/keys", headers=_auth_headers(admin_token, tenant_id))
    assert get_after.status_code == 200
    providers_after = [str(item.get("provider") or "").strip().lower() for item in get_after.json().get("items", [])]
    assert "mock" not in providers_after
    openai_after = _item_by_provider(get_after.json().get("items", []), "openai")
    assert openai_after
    assert openai_after["has_key"] is False
    assert openai_after["api_key_tail"] in (None, "")

    with sqlite3.connect(str(db_path)) as con:
        row_after = con.execute(
            """
            SELECT api_key_enc
            FROM tenant_provider_keys
            WHERE tenant_id = ? AND provider = 'openai'
            """,
            (tenant_id,),
        ).fetchone()
    assert row_after is None


def test_employee_forbidden_for_tenant_keys_endpoints(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Forbidden Keys Org",
            "admin_email": "admin@forbidden-keys.test",
            "password": "StrongPass123!",
        },
    )
    assert signup.status_code == 200
    tenant_id = int(signup.json()["tenant_id"])
    admin_token = str(signup.json()["access_token"])

    invite = client.post(
        "/tenant/admin/invite",
        json={"email": "employee@forbidden-keys.test", "role": "employee", "expires_hours": 24},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert invite.status_code == 200
    invite_token = str(invite.json()["token"])

    employee_signup = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "employee@forbidden-keys.test",
            "password": "EmployeePass123!",
        },
    )
    assert employee_signup.status_code == 200
    employee_token = str(employee_signup.json()["access_token"])

    get_resp = client.get("/tenant/keys", headers=_auth_headers(employee_token, tenant_id))
    assert get_resp.status_code == 403

    put_resp = client.put(
        "/tenant/keys",
        json={"provider": "openai", "api_key": "sk-test-openai-employee-attempt"},
        headers=_auth_headers(employee_token, tenant_id),
    )
    assert put_resp.status_code == 403

    delete_resp = client.delete("/tenant/keys/openai", headers=_auth_headers(employee_token, tenant_id))
    assert delete_resp.status_code == 403


def test_tenant_admin_can_read_active_provider_configuration(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Provider Read Org",
            "admin_email": "admin@provider-read.test",
            "password": "StrongPass123!",
        },
    )
    assert signup.status_code == 200
    tenant_id = int(signup.json()["tenant_id"])
    admin_token = str(signup.json()["access_token"])

    set_resp = client.put(
        "/tenant/keys",
        json={"provider": "groq", "api_key": "gsk_test_1234567890abcdef"},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert set_resp.status_code == 200

    cfg_resp = client.get("/tenant/provider", headers=_auth_headers(admin_token, tenant_id))
    assert cfg_resp.status_code == 200
    body = cfg_resp.json()
    assert int(body["tenant_id"]) == tenant_id
    assert body["provider"] == "groq"
    assert body["model"] == "llama-3.1-8b-instant"
    assert body["base_url"] == "https://api.groq.com/openai/v1"
