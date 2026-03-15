def test_metrics_endpoint_emits_basic_counters(app_ctx, monkeypatch):
    client = app_ctx["client"]
    db_enterprise = app_ctx["db_enterprise"]

    class _ProviderForMetrics:
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
        lambda *_args, **_kwargs: _ProviderForMetrics(),
    )

    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="gemini",
        model="models/gemini-2.0-flash",
        api_key="AIza_metrics_test_value_12345678901234567890",
    )
    db_enterprise.create_policy_rule(
        tenant_id=1,
        rule_type="category",
        match="PII",
        action="REDACT",
        enabled=True,
    )

    resp = client.post(
        "/chat",
        headers={"X-User": "metrics-user", "X-Tenant-Id": "1"},
        json={"prompt": "Email me at user@example.com"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "gemini"
    assert body["model"] == "models/gemini-2.0-flash"
    assert body["decision"] == "REDACT"
    assert body["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert body["redactions_applied"] >= 1
    assert isinstance(str(body["cleaned_prompt"]), str)
    assert body["cleaned_prompt"] != ""

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    text = metrics.text

    assert 'requests_total{tenant="1",action="REDACT",provider="gemini"}' in text
    assert 'redactions_total{category="PII"}' in text
    assert 'upstream_latency_ms_count{provider="gemini"}' in text
