from provider_layer import ProviderCallError


def _grant_platform_admin(db_enterprise, external_user: str, tenant_id: int = 1) -> None:
    user_id = db_enterprise.ensure_user(external_user)
    db_enterprise.upsert_membership(tenant_id=tenant_id, user_id=user_id, role="platform_admin")


def test_llm_smoke_success_shape(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    _grant_platform_admin(db_enterprise, "admin-smoke-ok")

    class _SuccessProvider:
        async def generate_text(self, _prompt: str):
            from provider_layer import ProviderCallResult

            return ProviderCallResult(
                text="pong",
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
        "routes.admin.build_tenant_provider",
        lambda *_args, **_kwargs: _SuccessProvider(),
    )

    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="gemini",
        model="models/gemini-2.0-flash",
        api_key="AIza_smoke_test_value_12345678901234567890",
    )

    resp = client.get(
        "/admin/llm-smoke",
        headers={"X-User": "admin-smoke-ok", "X-Tenant-Id": "1"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["provider"] == "gemini"
    assert body["model"] == "models/gemini-2.0-flash"
    assert body["has_api_key"] is True
    assert body["api_key_tail"] == "7890"
    assert isinstance(body["latency_ms"], int)
    assert body["status_code"] == 200
    assert body["message"] == "ok"
    assert body["retry_info"]["attempts"] == 1


def test_llm_smoke_error_shape_and_retry_info(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    _grant_platform_admin(db_enterprise, "admin-smoke-fail")

    class _FailingProvider:
        async def generate_text(self, _prompt: str):
            raise ProviderCallError(
                provider="gemini",
                model="models/gemini-2.0-flash",
                status_code=429,
                message="Quota exceeded",
                retry_info={
                    "attempts": 3,
                    "max_retries": 3,
                    "retries_used": 2,
                    "retried": True,
                    "retry_after_seconds": 2.0,
                    "last_status_code": 429,
                    "retryable_status_codes": [429, 500, 503],
                },
                raw_error_json={"error": {"message": "Quota exceeded"}},
            )

    monkeypatch.setattr(
        "routes.admin.build_tenant_provider",
        lambda *_args, **_kwargs: _FailingProvider(),
    )

    resp = client.get(
        "/admin/llm-smoke",
        headers={"X-User": "admin-smoke-fail", "X-Tenant-Id": "1"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is False
    assert body["provider"] == "gemini"
    assert body["model"] == "models/gemini-2.0-flash"
    assert isinstance(body["latency_ms"], int)
    assert body["status_code"] == 429
    assert body["message"] == "Quota exceeded"
    assert body["retry_info"]["retried"] is True
    assert body["retry_info"]["retry_after_seconds"] == 2.0
    assert "raw_error_json" not in body
