import pytest

import tenant_llm
from provider_layer import AnthropicProvider, GeminiProvider, OpenAIProvider


def test_chat_returns_503_when_tenant_has_no_provider_keys(app_ctx):
    client = app_ctx["client"]

    resp = client.post(
        "/chat",
        headers={"X-User": "no-keys-user", "X-Tenant-Id": "1"},
        json={"prompt": "hello"},
    )

    assert resp.status_code == 503
    payload = resp.json()
    detail = payload["detail"]
    assert detail["provider"] == "none"
    assert detail["model"] == ""
    assert detail["status_code"] == 503
    assert "No AI provider key configured" in detail["message"]


def test_build_tenant_provider_selects_gemini(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="gemini",
        model="models/gemini-2.0-flash",
        api_key="AIza_test_value_12345678901234567890123456",
    )
    provider = tenant_llm.build_tenant_provider(1)
    assert isinstance(provider, GeminiProvider)


def test_build_tenant_provider_selects_openai(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="openai",
        model="gpt-4.1-mini",
        api_key="sk-test-openai-1234567890abcdef",
    )
    provider = tenant_llm.build_tenant_provider(1)
    assert isinstance(provider, OpenAIProvider)


def test_build_tenant_provider_selects_groq_with_openai_adapter(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="groq",
        model="llama-3.1-8b-instant",
        api_key="gsk_test_1234567890abcdef",
    )
    provider = tenant_llm.build_tenant_provider(1)
    assert isinstance(provider, OpenAIProvider)
    assert provider.provider_name == "groq"
    assert provider._client.base_url == "https://api.groq.com/openai/v1"


def test_build_tenant_provider_rejects_unsupported_groq_model(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    with pytest.raises(ValueError) as exc_info:
        db_enterprise.upsert_tenant_provider_config(
            tenant_id=1,
            provider="groq",
            model="gpt-4.1-mini",
            api_key="gsk_test_1234567890abcdef",
        )
    assert "Unsupported Groq model" in str(exc_info.value)


def test_runtime_config_auto_fixes_legacy_invalid_groq_model(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_enterprise.upsert_tenant_key(
        tenant_id=1,
        provider="groq",
        api_key_plain="gsk_test_1234567890abcdef",
    )
    with db_enterprise.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_provider_configs
              (tenant_id, provider, model, api_key, api_key_tail, base_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id) DO UPDATE SET
              provider = excluded.provider,
              model = excluded.model,
              api_key = excluded.api_key,
              api_key_tail = excluded.api_key_tail,
              base_url = excluded.base_url,
              updated_at = excluded.updated_at
            """,
            (1, "groq", "gpt-4.1-mini", "", None, "https://api.groq.com/openai/v1"),
        )

    runtime = db_enterprise.get_tenant_provider_runtime_config(1)
    assert runtime["provider"] == "groq"
    assert runtime["model"] == "llama-3.1-8b-instant"

    with db_enterprise.get_conn() as conn:
        row = conn.execute(
            "SELECT model FROM tenant_provider_configs WHERE tenant_id = 1",
        ).fetchone()
    assert row is not None
    assert str(row["model"]) == "llama-3.1-8b-instant"


def test_runtime_config_repairs_invalid_groq_model_even_when_fallback_provider_is_used(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_enterprise.upsert_tenant_key(
        tenant_id=1,
        provider="anthropic",
        api_key_plain="sk-ant-test-fallback-1234567890",
    )
    with db_enterprise.get_conn() as conn:
        conn.execute(
            """
            INSERT INTO tenant_provider_configs
              (tenant_id, provider, model, api_key, api_key_tail, base_url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id) DO UPDATE SET
              provider = excluded.provider,
              model = excluded.model,
              api_key = excluded.api_key,
              api_key_tail = excluded.api_key_tail,
              base_url = excluded.base_url,
              updated_at = excluded.updated_at
            """,
            (1, "groq", "gpt-4.1-mini", "", None, "https://api.groq.com/openai/v1"),
        )

    runtime = db_enterprise.get_tenant_provider_runtime_config(1)
    assert runtime["provider"] == "anthropic"

    with db_enterprise.get_conn() as conn:
        row = conn.execute(
            "SELECT model FROM tenant_provider_configs WHERE tenant_id = 1",
        ).fetchone()
    assert row is not None
    assert str(row["model"]) == "llama-3.1-8b-instant"


def test_build_tenant_provider_selects_anthropic(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="anthropic",
        model="claude-3-5-haiku-latest",
        api_key="sk-ant-test-1234567890abcdef",
    )
    provider = tenant_llm.build_tenant_provider(1)
    assert isinstance(provider, AnthropicProvider)


def test_build_tenant_provider_falls_back_to_first_available_provider_key(app_ctx):
    db_enterprise = app_ctx["db_enterprise"]
    db_enterprise.upsert_tenant_provider_config(
        tenant_id=1,
        provider="anthropic",
        model="claude-3-5-haiku-latest",
        api_key=None,
    )
    db_enterprise.upsert_tenant_key(
        tenant_id=1,
        provider="openai",
        api_key_plain="sk-test-openai-fallback-1234567890",
    )
    provider = tenant_llm.build_tenant_provider(1)
    assert isinstance(provider, OpenAIProvider)
