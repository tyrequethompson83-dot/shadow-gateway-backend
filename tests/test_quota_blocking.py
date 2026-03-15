def _patch_quota_provider(monkeypatch):
    class _ProviderForQuota:
        async def generate_text(self, _prompt: str):
            from provider_layer import ProviderCallResult

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

    monkeypatch.setattr(
        "main.build_tenant_provider",
        lambda *_args, **_kwargs: _ProviderForQuota(),
    )


def test_chat_rpm_limit_blocks_with_structured_429(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    limits = app_ctx["limits"]

    _patch_quota_provider(monkeypatch)
    limits.reset_rate_limit_state()
    db_enterprise.upsert_tenant_limits(
        tenant_id=1,
        daily_requests_limit=100,
        rpm_limit=1,
        enabled=True,
    )

    headers = {"X-User": "quota-user", "X-Tenant-Id": "1"}
    first = client.post("/chat", headers=headers, json={"prompt": "hello"})
    second = client.post("/chat", headers=headers, json={"prompt": "hello again"})

    assert first.status_code == 200
    assert second.status_code == 429
    payload = second.json()
    assert "detail" in payload
    detail = payload["detail"]
    assert detail["message"] == "Tenant limit exceeded"
    assert detail["limit"] == "rpm"
    assert int(detail["retry_after_seconds"]) >= 1


def test_chat_rpd_limit_blocks_with_structured_429(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]
    limits = app_ctx["limits"]

    _patch_quota_provider(monkeypatch)
    limits.reset_rate_limit_state()
    db_enterprise.upsert_tenant_limits(
        tenant_id=1,
        daily_requests_limit=1,
        rpm_limit=100,
        enabled=True,
    )

    headers = {"X-User": "quota-day-user", "X-Tenant-Id": "1"}
    first = client.post("/chat", headers=headers, json={"prompt": "hello"})
    second = client.post("/chat", headers=headers, json={"prompt": "hello again"})

    assert first.status_code == 200
    assert second.status_code == 429
    payload = second.json()
    assert "detail" in payload
    detail = payload["detail"]
    assert detail["message"] == "Tenant limit exceeded"
    assert detail["limit"] == "rpd"
    assert int(detail["retry_after_seconds"]) >= 1
