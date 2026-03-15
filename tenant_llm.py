from typing import Any, Dict

from enterprise.db_enterprise import get_tenant_provider_config, get_tenant_provider_runtime_config
from gemini_client import GeminiClient, normalize_gemini_model
from provider_layer import ProviderCallError, default_model_for_provider, GeminiProvider, build_provider


NO_PROVIDER_MESSAGE = (
    "No AI provider key configured for this tenant. Ask an admin to add a Gemini/OpenAI/Groq/Anthropic key in Tenant Admin."
)


def build_tenant_provider(
    tenant_id: int,
    *,
    default_gemini_client: GeminiClient | None = None,
    default_gemini_api_key: str | None = None,
) -> Any:
    cfg = get_tenant_provider_runtime_config(tenant_id)
    provider = cfg["provider"]
    model = cfg["model"]
    base_url = cfg.get("base_url")
    api_key = (cfg.get("api_key") or "").strip()
    source = str(cfg.get("source") or "")
    used_default_gemini_fallback = False

    if provider == "none":
        fallback_key = (default_gemini_api_key or "").strip()
        if fallback_key:
            provider = "gemini"
            model = default_model_for_provider(provider)
            api_key = fallback_key
            source = "env"
            used_default_gemini_fallback = True
        else:
            raise ProviderCallError(
                provider="none",
                model="",
                status_code=503,
                message=NO_PROVIDER_MESSAGE,
                retry_info={
                    "attempts": 1,
                    "max_retries": 0,
                    "retries_used": 0,
                    "retried": False,
                    "retry_after_seconds": None,
                    "last_status_code": 503,
                    "retryable_status_codes": [],
                },
            )

    if provider == "gemini":
        if not api_key and default_gemini_api_key:
            api_key = default_gemini_api_key.strip()
        if (
            (source == "env" or used_default_gemini_fallback)
            and default_gemini_client is not None
            and normalize_gemini_model(model) == normalize_gemini_model(default_gemini_client.model)
        ):
            return GeminiProvider(
                api_key=api_key,
                model=model,
                client=default_gemini_client,
            )

    if not api_key:
        raise ProviderCallError(
            provider="none",
            model="",
            status_code=503,
            message=NO_PROVIDER_MESSAGE,
            retry_info={
                "attempts": 1,
                "max_retries": 0,
                "retries_used": 0,
                "retried": False,
                "retry_after_seconds": None,
                "last_status_code": 503,
                "retryable_status_codes": [],
            },
        )

    return build_provider(
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url,
    )


def provider_health_snapshot(tenant_id: int) -> Dict[str, Any]:
    cfg = get_tenant_provider_config(tenant_id)
    return {
        "tenant_id": int(cfg["tenant_id"]),
        "provider": cfg["provider"],
        "model": cfg["model"],
        "base_url": cfg.get("base_url"),
        "source": cfg["source"],
        "has_key": bool(cfg["has_api_key"]),
        "api_key_tail": cfg["api_key_tail"],
    }
