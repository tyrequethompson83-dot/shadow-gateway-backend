import os
from dataclasses import dataclass, field
from typing import Any, Dict

from anthropic_client import (
    AnthropicClient,
    AnthropicClientError,
    AnthropicChatResult,
    AnthropicTextResult,
    DEFAULT_ANTHROPIC_MODEL,
)
from gemini_client import (
    DEFAULT_GEMINI_MODEL,
    GeminiClient,
    GeminiClientError,
    GeminiTextResult,
    normalize_gemini_model,
)
from openai_client import (
    DEFAULT_OPENAI_MODEL,
    OpenAIClient,
    OpenAIClientError,
    OpenAIChatResult,
    OpenAITextResult,
)


DEFAULT_GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_ALLOWED_MODELS = (
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
)
DEFAULT_GROQ_MODEL = os.getenv("GROQ_MODEL", GROQ_ALLOWED_MODELS[0]).strip() or GROQ_ALLOWED_MODELS[0]
OPENAI_COMPATIBLE_PROVIDERS = {"openai", "groq"}
ALLOWED_PROVIDERS = {"gemini", "openai", "groq", "anthropic"}


def normalize_optional_base_url(base_url: str | None) -> str | None:
    value = (base_url or "").strip().rstrip("/")
    return value or None


def default_base_url_for_provider(provider: str) -> str | None:
    name = normalize_provider_name(provider)
    if name == "openai":
        return normalize_optional_base_url(os.getenv("OPENAI_BASE_URL", ""))
    if name == "groq":
        return normalize_optional_base_url(os.getenv("GROQ_BASE_URL", DEFAULT_GROQ_BASE_URL)) or DEFAULT_GROQ_BASE_URL
    return None


def normalize_provider_name(provider: str | None) -> str:
    value = (provider or "").strip().lower()
    if not value:
        env_value = os.getenv("LLM_PROVIDER", "gemini").strip().lower() or "gemini"
        value = env_value if env_value in ALLOWED_PROVIDERS else "gemini"
    if value not in ALLOWED_PROVIDERS:
        raise ValueError(f"Unsupported provider: {provider}")
    return value


def validate_model_for_provider(provider: str, model: str | None) -> str:
    provider_name = normalize_provider_name(provider)
    normalized_model = str(model or "").strip()
    if not normalized_model:
        normalized_model = default_model_for_provider(provider_name)

    if provider_name == "groq" and normalized_model not in GROQ_ALLOWED_MODELS:
        supported = ", ".join(GROQ_ALLOWED_MODELS)
        raise ValueError(f"Unsupported Groq model: {normalized_model}. Allowed models: {supported}")

    return normalized_model


def default_model_for_provider(provider: str) -> str:
    name = normalize_provider_name(provider)
    if name == "gemini":
        return normalize_gemini_model(os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip())
    if name == "openai":
        return os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL
    if name == "groq":
        candidate = os.getenv("GROQ_MODEL", DEFAULT_GROQ_MODEL).strip() or DEFAULT_GROQ_MODEL
        return validate_model_for_provider("groq", candidate)
    if name == "anthropic":
        return os.getenv("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL).strip() or DEFAULT_ANTHROPIC_MODEL
    raise ValueError(f"Unsupported provider: {provider}")


def mask_key_tail(api_key: str | None, visible: int = 4) -> str | None:
    value = (api_key or "").strip()
    if not value:
        return None
    return value[-max(1, int(visible)) :]


@dataclass
class ProviderCallResult:
    text: str
    provider: str
    model: str
    latency_ms: int
    retry_info: Dict[str, Any] = field(default_factory=dict)


class ProviderCallError(Exception):
    def __init__(
        self,
        *,
        provider: str,
        model: str,
        status_code: int,
        message: str,
        retry_info: Dict[str, Any] | None = None,
        raw_error_json: Any = None,
    ):
        super().__init__(message)
        self.provider = str(provider)
        self.model = str(model)
        self.status_code = int(status_code)
        self.message = str(message)
        self.retry_info = dict(retry_info or {})
        self.raw_error_json = raw_error_json

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "status_code": self.status_code,
            "message": self.message,
            "retry_info": self.retry_info,
            "raw_error_json": self.raw_error_json,
        }


class BaseProvider:
    provider_name = "unknown"

    @property
    def model(self) -> str:
        raise NotImplementedError

    async def generate_text(self, prompt: str) -> ProviderCallResult:
        raise NotImplementedError


class GeminiProvider(BaseProvider):
    provider_name = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        retry_base_seconds: float = 0.5,
        client: GeminiClient | None = None,
    ):
        self._client = client or GeminiClient(
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )

    @property
    def model(self) -> str:
        return self._client.model

    async def generate_text(self, prompt: str, *, google_search: bool = False) -> ProviderCallResult:
        try:
            result: GeminiTextResult = await self._client.generate_text(prompt, google_search=google_search)
        except GeminiClientError as exc:
            raise ProviderCallError(
                provider=self.provider_name,
                model=self.model,
                status_code=exc.status_code,
                message=exc.message,
                retry_info=exc.retry_info,
                raw_error_json=exc.raw_error_json,
            )
        return ProviderCallResult(
            text=result.text,
            provider=self.provider_name,
            model=result.model,
            latency_ms=result.latency_ms,
            retry_info=result.retry_info,
        )


class OpenAIProvider(BaseProvider):
    provider_name = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        provider_label: str = "openai",
        base_url: str | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        retry_base_seconds: float = 0.5,
        client: OpenAIClient | None = None,
    ):
        normalized_label = normalize_provider_name(provider_label)
        if normalized_label not in OPENAI_COMPATIBLE_PROVIDERS:
            raise ValueError(f"Unsupported OpenAI-compatible provider label: {provider_label}")
        self.provider_name = normalized_label
        self._client = client or OpenAIClient(
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )

    @property
    def model(self) -> str:
        return self._client.model

    async def generate_text(self, prompt: str) -> ProviderCallResult:
        try:
            result: OpenAITextResult = await self._client.generate_text(prompt)
        except OpenAIClientError as exc:
            raise ProviderCallError(
                provider=self.provider_name,
                model=self.model,
                status_code=exc.status_code,
                message=exc.message,
                retry_info=exc.retry_info,
                raw_error_json=exc.raw_error_json,
            )
        return ProviderCallResult(
            text=result.text,
            provider=self.provider_name,
            model=result.model,
            latency_ms=result.latency_ms,
            retry_info=result.retry_info,
        )


class AnthropicProvider(BaseProvider):
    provider_name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        retry_base_seconds: float = 0.5,
        client: AnthropicClient | None = None,
    ):
        self._client = client or AnthropicClient(
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )

    @property
    def model(self) -> str:
        return self._client.model

    async def generate_text(self, prompt: str) -> ProviderCallResult:
        try:
            result: AnthropicTextResult = await self._client.generate_text(prompt)
        except AnthropicClientError as exc:
            raise ProviderCallError(
                provider=self.provider_name,
                model=self.model,
                status_code=exc.status_code,
                message=exc.message,
                retry_info=exc.retry_info,
                raw_error_json=exc.raw_error_json,
            )
        return ProviderCallResult(
            text=result.text,
            provider=self.provider_name,
            model=result.model,
            latency_ms=result.latency_ms,
            retry_info=result.retry_info,
        )


def build_provider(
    *,
    provider: str,
    model: str,
    api_key: str,
    base_url: str | None = None,
    timeout_seconds: float = 60.0,
    max_retries: int = 3,
    retry_base_seconds: float = 0.5,
) -> BaseProvider:
    name = normalize_provider_name(provider)
    normalized_model = validate_model_for_provider(name, model)
    if name == "gemini":
        return GeminiProvider(
            api_key=api_key,
            model=normalized_model,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )
    if name in OPENAI_COMPATIBLE_PROVIDERS:
        resolved_base_url = normalize_optional_base_url(base_url)
        if not resolved_base_url:
            resolved_base_url = default_base_url_for_provider(name)
        return OpenAIProvider(
            api_key=api_key,
            model=normalized_model,
            provider_label=name,
            base_url=resolved_base_url,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )
    if name == "anthropic":
        return AnthropicProvider(
            api_key=api_key,
            model=normalized_model,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
            retry_base_seconds=retry_base_seconds,
        )
    raise ValueError(f"Unsupported provider: {provider}")
