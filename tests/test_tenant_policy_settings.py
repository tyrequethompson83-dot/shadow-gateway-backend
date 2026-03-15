import sqlite3


def _auth_headers(token: str, tenant_id: int) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "X-Tenant-Id": str(int(tenant_id)),
    }


class _CaptureProvider:
    def __init__(self):
        self.calls = []

    async def generate_text(self, prompt: str):
        from provider_layer import ProviderCallResult

        self.calls.append(str(prompt))
        return ProviderCallResult(
            text="ok",
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


def test_default_policy_redacts_pii_fin_and_allows(app_ctx, monkeypatch):
    client = app_ctx["client"]
    provider = _CaptureProvider()
    monkeypatch.setattr("main.build_tenant_provider", lambda *_args, **_kwargs: provider)

    prompt = "Contact me at user@example.com. Card: 4111111111111111"
    resp = client.post(
        "/chat",
        headers={"X-User": "policy-redact-user", "X-Tenant-Id": "1"},
        json={"prompt": prompt},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "REDACT"
    assert len(provider.calls) == 1
    assert "Do not modify placeholder tokens like [PERSON_1], [EMAIL_1], etc." in provider.calls[0]
    assert body["cleaned_prompt"] in provider.calls[0]
    assert provider.calls[0] != prompt


def test_public_location_prompt_defaults_to_allow_without_redaction(app_ctx, monkeypatch):
    client = app_ctx["client"]
    provider = _CaptureProvider()
    monkeypatch.setattr("main.build_tenant_provider", lambda *_args, **_kwargs: provider)

    prompt = "What is the birth rate in Jamaica currently?"
    location = "Jamaica"
    location_start = prompt.index(location)
    monkeypatch.setattr(
        "main.scrub_prompt",
        lambda text: {
            "cleaned_prompt": str(text),
            "placeholders": {},
            "detections": [
                {
                    "entity_type": "LOCATION",
                    "start": location_start,
                    "end": location_start + len(location),
                    "score": 0.99,
                    "redacted": False,
                }
            ],
            "technical_mode": False,
        },
    )

    resp = client.post(
        "/chat",
        headers={"X-User": "policy-public-location-user", "X-Tenant-Id": "1"},
        json={"prompt": prompt},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOW"
    assert body["redactions_applied"] == 0
    assert body["cleaned_prompt"] == prompt
    assert int(body["entity_counts"].get("LOCATION", 0)) == 1
    assert int(body["risk_categories"].get("PUBLIC", 0)) == 1
    assert len(provider.calls) == 1
    assert prompt in provider.calls[0]
    assert "[LOCATION_" not in provider.calls[0]


def test_default_policy_blocks_secrets_without_upstream_call(app_ctx, monkeypatch):
    client = app_ctx["client"]
    provider = _CaptureProvider()
    monkeypatch.setattr("main.build_tenant_provider", lambda *_args, **_kwargs: provider)

    prompt = "my key is sk-abcdefghijklmnopqrstuvwxyz123456"
    resp = client.post(
        "/chat",
        headers={"X-User": "policy-block-user", "X-Tenant-Id": "1"},
        json={"prompt": prompt},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["decision"] == "BLOCK"
    assert "tenant policy" in str(detail["message"]).lower()
    assert len(provider.calls) == 0


def test_policy_change_pii_to_block_changes_chat_outcome(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    provider = _CaptureProvider()
    monkeypatch.setattr("main.build_tenant_provider", lambda *_args, **_kwargs: provider)

    db_enterprise.upsert_tenant_policy_settings(
        1,
        pii_action="block",
        block_threshold="high",
    )
    prompt = "SSN 123-45-6789 passport: A1234567 email: person@example.com"
    resp = client.post(
        "/chat",
        headers={"X-User": "policy-change-user", "X-Tenant-Id": "1"},
        json={"prompt": prompt},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["decision"] == "BLOCK"
    assert len(provider.calls) == 0


def test_request_row_stores_original_and_sent_prompt_previews(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_path = app_ctx["db_path"]
    provider = _CaptureProvider()
    monkeypatch.setattr("main.build_tenant_provider", lambda *_args, **_kwargs: provider)

    prompt = "Email me at audit@example.com and use card 4111111111111111"
    resp = client.post(
        "/chat",
        headers={"X-User": "policy-audit-user", "X-Tenant-Id": "1"},
        json={"prompt": prompt},
    )
    assert resp.status_code == 200

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT prompt_original_preview, prompt_sent_to_ai_preview, cleaned_prompt_preview
            FROM requests
            WHERE tenant_id = 1
            ORDER BY ts DESC
            LIMIT 1
            """
        ).fetchone()
    assert row is not None
    assert str(row["prompt_original_preview"] or "") != ""
    assert str(row["prompt_sent_to_ai_preview"] or "") != ""
    assert str(row["cleaned_prompt_preview"] or "") == str(row["prompt_sent_to_ai_preview"] or "")


def test_chat_restores_redacted_values_in_user_response_only_by_default(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_path = app_ctx["db_path"]

    class _PlaceholderProvider:
        def __init__(self):
            self.calls = []

        async def generate_text(self, prompt: str):
            from provider_layer import ProviderCallResult

            self.calls.append(str(prompt))
            return ProviderCallResult(
                text="We will contact [EMAIL_ADDRESS_1] shortly.",
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

    provider = _PlaceholderProvider()
    monkeypatch.setattr("main.build_tenant_provider", lambda *_args, **_kwargs: provider)
    monkeypatch.setattr("main.RESTORE_REDACTED_VALUES", True)

    email = "jane.doe@example.com"
    prompt = f"Please send the onboarding packet to {email}."
    resp = client.post(
        "/chat",
        headers={"X-User": "restore-default-user", "X-Tenant-Id": "1"},
        json={"prompt": prompt},
    )
    assert resp.status_code == 200
    body = resp.json()

    assert len(provider.calls) == 1
    assert "Do not modify placeholder tokens like [PERSON_1], [EMAIL_1], etc." in provider.calls[0]
    assert email not in provider.calls[0]
    assert "[EMAIL_ADDRESS_1]" in provider.calls[0]

    assert body["ai_response_clean"] == "We will contact [EMAIL_ADDRESS_1] shortly."
    assert body["assistant_response"] == f"We will contact {email} shortly."
    assert body["ai_response_rehydrated"] == f"We will contact {email} shortly."
    assert email not in str(body["cleaned_prompt"])
    assert "[EMAIL_ADDRESS_1]" in str(body["cleaned_prompt"])

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT prompt_sent_to_ai_preview, cleaned_prompt_preview
            FROM requests
            WHERE tenant_id = 1
            ORDER BY ts DESC
            LIMIT 1
            """
        ).fetchone()
    assert row is not None
    assert email not in str(row["prompt_sent_to_ai_preview"] or "")
    assert email not in str(row["cleaned_prompt_preview"] or "")


def test_chat_does_not_restore_when_restore_flag_is_disabled(app_ctx, monkeypatch):
    client = app_ctx["client"]

    class _PlaceholderProvider:
        async def generate_text(self, _prompt: str):
            from provider_layer import ProviderCallResult

            return ProviderCallResult(
                text="Response for [EMAIL_ADDRESS_1]",
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

    monkeypatch.setattr("main.build_tenant_provider", lambda *_args, **_kwargs: _PlaceholderProvider())
    monkeypatch.setattr("main.RESTORE_REDACTED_VALUES", False)

    resp = client.post(
        "/chat",
        headers={"X-User": "restore-disabled-user", "X-Tenant-Id": "1"},
        json={"prompt": "Email jane.doe@example.com please."},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["assistant_response"] == "Response for [EMAIL_ADDRESS_1]"
    assert body["ai_response_clean"] == "Response for [EMAIL_ADDRESS_1]"
    assert body["ai_response_rehydrated"] is None


def test_tenant_admin_can_get_and_put_policy_and_employee_is_forbidden(app_ctx):
    client = app_ctx["client"]

    signup = client.post(
        "/auth/signup/company",
        json={
            "company_name": "Policy Org",
            "admin_email": "owner@policyorg.test",
            "password": "OwnerPass123!",
        },
    )
    assert signup.status_code == 200
    tenant_id = int(signup.json()["tenant_id"])
    admin_token = str(signup.json()["access_token"])

    get_resp = client.get("/tenant/admin/policy", headers=_auth_headers(admin_token, tenant_id))
    assert get_resp.status_code == 200
    get_body = get_resp.json()
    assert get_body["pii_action"] == "redact"
    assert get_body["secrets_action"] == "block"

    put_resp = client.put(
        "/tenant/admin/policy",
        headers=_auth_headers(admin_token, tenant_id),
        json={
            "pii_action": "block",
            "financial_action": "redact",
            "secrets_action": "block",
            "health_action": "redact",
            "ip_action": "allow",
            "block_threshold": "high",
            "store_original_prompt": False,
            "show_sanitized_prompt_admin": False,
        },
    )
    assert put_resp.status_code == 200
    put_body = put_resp.json()
    assert put_body["pii_action"] == "block"
    assert put_body["block_threshold"] == "high"
    assert put_body["store_original_prompt"] is False
    assert put_body["show_sanitized_prompt_admin"] is False

    invite = client.post(
        "/tenant/admin/invite",
        json={"email": "employee@policyorg.test", "role": "employee"},
        headers=_auth_headers(admin_token, tenant_id),
    )
    assert invite.status_code == 200
    invite_token = str(invite.json()["token"])

    employee_signup = client.post(
        "/auth/signup/invite",
        json={
            "token": invite_token,
            "email": "employee@policyorg.test",
            "password": "EmployeePass123!",
        },
    )
    assert employee_signup.status_code == 200
    employee_token = str(employee_signup.json()["access_token"])

    emp_get = client.get("/tenant/admin/policy", headers=_auth_headers(employee_token, tenant_id))
    assert emp_get.status_code == 403
    emp_put = client.put(
        "/tenant/admin/policy",
        headers=_auth_headers(employee_token, tenant_id),
        json={"pii_action": "allow"},
    )
    assert emp_put.status_code == 403
