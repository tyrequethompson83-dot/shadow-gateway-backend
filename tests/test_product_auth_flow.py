def _auth_headers(token: str, tenant_id: int) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": str(int(tenant_id)),
    }


def test_company_signup_invite_employee_login_chat(app_ctx, monkeypatch):
    client = app_ctx["client"]

    class _ProductAuthProvider:
        async def generate_text(self, _prompt: str):
            from provider_layer import ProviderCallResult

            return ProviderCallResult(
                text="Hello from provider",
                provider="gemini",
                model="models/gemini-2.0-flash",
                latency_ms=1,
                retry_info={
                    "attempts": 1,
                    "max_retries": 3,
                    "retries_used": 0,
                    "retried": False,
                    "retry_after_seconds": None,
                    "last_status_code": 200,
                    "retryable_status_codes": [429, 500, 503],
                },
            )

    monkeypatch.setattr(
        "main.build_tenant_provider",
        lambda *_args, **_kwargs: _ProductAuthProvider(),
    )

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Acme Security",
            "admin_email": "admin@acme.test",
            "password": "StrongPass123!",
        },
    )
    assert signup.status_code == 200
    signup_body = signup.json()
    assert signup_body["role"] == "tenant_admin"
    company_tenant_id = int(signup_body["tenant_id"])
    admin_token = str(signup_body["access_token"])
    admin_me = client.get("/me", headers=_auth_headers(admin_token, company_tenant_id))
    assert admin_me.status_code == 200
    assert admin_me.json()["is_personal"] is False

    invite = client.post(
        "/tenant/admin/invite",
        json={"email": "employee@acme.test", "role": "employee", "expires_hours": 48},
        headers=_auth_headers(admin_token, company_tenant_id),
    )
    assert invite.status_code == 200
    invite_body = invite.json()
    assert invite_body["ok"] is True
    assert invite_body["role"] == "employee"
    invite_token = str(invite_body["token"])

    provider_cfg = client.put(
        "/tenant/keys",
        json={"provider": "gemini", "api_key": "AIza_auth_flow_test_value_12345678901234567890"},
        headers=_auth_headers(admin_token, company_tenant_id),
    )
    assert provider_cfg.status_code == 200

    employee_signup = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "employee@acme.test",
            "password": "EmployeePass123!",
        },
    )
    assert employee_signup.status_code == 200
    employee_signup_body = employee_signup.json()
    assert employee_signup_body["role"] == "employee"

    employee_login = client.post(
        "/auth/login",
        json={
            "email": "employee@acme.test",
            "password": "EmployeePass123!",
            "tenant_id": company_tenant_id,
        },
    )
    assert employee_login.status_code == 200
    employee_login_body = employee_login.json()
    assert employee_login_body["role"] == "employee"
    employee_token = str(employee_login_body["access_token"])

    chat = client.post(
        "/chat",
        json={"prompt": "Hello from employee", "purpose": "test"},
        headers=_auth_headers(employee_token, company_tenant_id),
    )
    assert chat.status_code == 200
    chat_body = chat.json()
    assert "ai_response_clean" in chat_body


def test_individual_signup_and_employee_blocked_from_tenant_admin(app_ctx):
    client = app_ctx["client"]

    personal_signup = client.post(
        "/auth/signup/individual",
        json={
            "name_or_label": "Solo Builder",
            "email": "solo@example.test",
            "password": "SoloPass123!",
        },
    )
    assert personal_signup.status_code == 200
    personal_body = personal_signup.json()
    assert personal_body["role"] == "tenant_admin"
    personal_tenant_id = int(personal_body["tenant_id"])
    personal_token = str(personal_body["access_token"])

    personal_me = client.get("/me", headers=_auth_headers(personal_token, personal_tenant_id))
    assert personal_me.status_code == 200
    personal_me_body = personal_me.json()
    assert personal_me_body["is_personal"] is True
    assert personal_me_body["role"] == "tenant_admin"

    personal_invite_forbidden = client.post(
        "/tenant/admin/invite",
        json={"email": "blocked@personal.test", "role": "employee"},
        headers=_auth_headers(personal_token, personal_tenant_id),
    )
    assert personal_invite_forbidden.status_code == 403

    personal_members_forbidden = client.get(
        "/tenant/admin/members",
        headers=_auth_headers(personal_token, personal_tenant_id),
    )
    assert personal_members_forbidden.status_code == 403

    personal_policy_forbidden = client.get(
        "/tenant/admin/policy",
        headers=_auth_headers(personal_token, personal_tenant_id),
    )
    assert personal_policy_forbidden.status_code == 403

    company_signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Shielded Ops",
            "admin_email": "owner@shielded.test",
            "password": "OwnerPass123!",
        },
    )
    assert company_signup.status_code == 200
    company_body = company_signup.json()
    company_tenant_id = int(company_body["tenant_id"])
    admin_token = str(company_body["access_token"])

    invite = client.post(
        "/tenant/admin/invite",
        json={"email": "staff@shielded.test", "role": "employee"},
        headers=_auth_headers(admin_token, company_tenant_id),
    )
    assert invite.status_code == 200
    invite_token = str(invite.json()["token"])

    employee_signup = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "staff@shielded.test",
            "password": "StaffPass123!",
        },
    )
    assert employee_signup.status_code == 200
    employee_token = str(employee_signup.json()["access_token"])

    forbidden = client.post(
        "/tenant/admin/invite",
        json={"email": "blocked@shielded.test", "role": "employee"},
        headers=_auth_headers(employee_token, company_tenant_id),
    )
    assert forbidden.status_code == 403


def test_single_use_invite_rejects_second_redemption(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Single Use Org",
            "admin_email": "owner@singleuse.test",
            "password": "OwnerPass123!",
        },
    )
    assert signup.status_code == 200
    tenant_id = int(signup.json()["tenant_id"])
    admin_token = str(signup.json()["access_token"])

    invite = client.post(
        "/tenant/admin/invite",
        json={"role": "employee", "expires_hours": 24},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert invite.status_code == 200
    invite_token = str(invite.json()["token"])

    first = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "first@singleuse.test",
            "password": "FirstPass123!",
        },
    )
    assert first.status_code == 200

    second = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "second@singleuse.test",
            "password": "SecondPass123!",
        },
    )
    assert second.status_code == 400
    assert "already used" in str(second.json().get("detail", "")).lower()


def test_multi_use_invite_respects_max_uses(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Multi Use Org",
            "admin_email": "owner@multiuse.test",
            "password": "OwnerPass123!",
        },
    )
    assert signup.status_code == 200
    tenant_id = int(signup.json()["tenant_id"])
    admin_token = str(signup.json()["access_token"])

    invite = client.post(
        "/tenant/admin/invite",
        json={"role": "employee", "expires_hours": 24, "max_uses": 2},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert invite.status_code == 200
    invite_body = invite.json()
    assert int(invite_body["max_uses"]) == 2
    invite_token = str(invite_body["token"])

    first = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "first@multiuse.test",
            "password": "FirstPass123!",
        },
    )
    assert first.status_code == 200

    second = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "second@multiuse.test",
            "password": "SecondPass123!",
        },
    )
    assert second.status_code == 200

    third = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "third@multiuse.test",
            "password": "ThirdPass123!",
        },
    )
    assert third.status_code == 400
    assert "max uses reached" in str(third.json().get("detail", "")).lower()


def test_tenant_admin_members_lists_users_and_roles(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Members View Org",
            "admin_email": "owner@membersview.test",
            "password": "OwnerPass123!",
        },
    )
    assert signup.status_code == 200
    tenant_id = int(signup.json()["tenant_id"])
    admin_token = str(signup.json()["access_token"])

    invite = client.post(
        "/tenant/admin/invite",
        json={"email": "employee@membersview.test", "role": "employee", "expires_hours": 24},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert invite.status_code == 200
    invite_token = str(invite.json()["token"])

    employee_signup = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "employee@membersview.test",
            "password": "EmployeePass123!",
        },
    )
    assert employee_signup.status_code == 200

    members = client.get(
        "/tenant/admin/members",
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert members.status_code == 200
    body = members.json()
    assert int(body["tenant_id"]) == tenant_id
    assert int(body["count"]) >= 2

    items = body.get("items", [])
    role_by_email = {str(item.get("email") or "").lower(): str(item.get("role") or "") for item in items}
    assert role_by_email.get("owner@membersview.test") == "tenant_admin"
    assert role_by_email.get("employee@membersview.test") == "employee"
