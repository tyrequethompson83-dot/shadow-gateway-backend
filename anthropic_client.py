import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

import httpx


ANTHROPIC_API_BASE = "https://api.anthropic.com/v1"
DEFAULT_ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest").strip() or "claude-3-5-haiku-latest"
DEFAULT_ANTHROPIC_VERSION = os.getenv("ANTHROPIC_VERSION", "2023-06-01").strip() or "2023-06-01"
DEFAULT_ANTHROPIC_MAX_TOKENS = int(os.getenv("ANTHROPIC_MAX_TOKENS", "512"))
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
LOGGER = logging.getLogger("shadow.anthropic")
LOG_PREVIEW_LIMIT = 4000


def _preview_for_log(value: Any, limit: int = LOG_PREVIEW_LIMIT) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        return value if len(value) <= limit else f"{value[:limit]}...<truncated>"
    try:
        text = json.dumps(value, ensure_ascii=True, default=str, sort_keys=True)
    except Exception:
        text = str(value)
    return text if len(text) <= limit else f"{text[:limit]}...<truncated>"


def _log_anthropic_event(level: int, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    LOGGER.log(level, json.dumps(payload, ensure_ascii=True, default=str, sort_keys=True))


def _get_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _get_float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


def build_anthropic_messages_payload(prompt: str, model: str, max_tokens: int) -> Dict[str, Any]:
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    return {
        "model": (model or DEFAULT_ANTHROPIC_MODEL).strip() or DEFAULT_ANTHROPIC_MODEL,
        "max_tokens": max(1, int(max_tokens)),
        "temperature": 0,
        "messages": [{"role": "user", "content": prompt}],
    }


@dataclass
class AnthropicTextResult:
    text: str
    model: str
    latency_ms: int
    retry_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnthropicChatResult:
    text: Optional[str]
    tool_calls: List[Dict[str, Any]]
    model: str
    latency_ms: int
    retry_info: Dict[str, Any] = field(default_factory=dict)


class AnthropicClientError(Exception):
    def __init__(
        self,
        status_code: int,
        message: str,
        raw_error_json: Any = None,
        retry_info: Dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status_code = int(status_code)
        self.message = str(message)
        self.raw_error_json = raw_error_json
        self.retry_info = dict(retry_info or {})


class AnthropicClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        anthropic_version: str = DEFAULT_ANTHROPIC_VERSION,
        max_tokens: int = DEFAULT_ANTHROPIC_MAX_TOKENS,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        retry_base_seconds: float = 0.5,
    ):
        self.api_key = (api_key or "").strip()
        self.model = (model or DEFAULT_ANTHROPIC_MODEL).strip() or DEFAULT_ANTHROPIC_MODEL
        self.anthropic_version = (anthropic_version or DEFAULT_ANTHROPIC_VERSION).strip() or DEFAULT_ANTHROPIC_VERSION
        self.max_tokens = max(1, int(max_tokens))
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.max_retries = max(0, int(max_retries))
        self.retry_base_seconds = max(0.0, float(retry_base_seconds))

    @property
    def url(self) -> str:
        return f"{ANTHROPIC_API_BASE}/messages"

    def _backoff_seconds(self, attempt: int) -> float:
        return min(self.retry_base_seconds * (2 ** attempt), 8.0)

    @staticmethod
    def _parse_retry_after_seconds(response: httpx.Response) -> float | None:
        raw = response.headers.get("Retry-After")
        if raw is None:
            return None
        val = raw.strip()
        if not val:
            return None
        try:
            return max(0.0, float(val))
        except ValueError:
            pass
        try:
            dt = parsedate_to_datetime(val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
        except Exception:
            return None

    def _build_retry_info(
        self,
        *,
        attempts: int,
        retried: bool,
        last_status_code: int | None,
        retry_after_seconds: float | None,
    ) -> Dict[str, Any]:
        retries_used = max(0, attempts - 1)
        return {
            "attempts": int(attempts),
            "max_retries": int(self.max_retries),
            "retries_used": int(retries_used),
            "retried": bool(retried),
            "retry_after_seconds": retry_after_seconds,
            "last_status_code": last_status_code,
            "retryable_status_codes": sorted(RETRYABLE_STATUS_CODES),
        }

    @staticmethod
    def _parse_error_body(response: httpx.Response) -> Any:
        try:
            return response.json()
        except ValueError:
            text = response.text.strip()
            return {"raw_text": text[:4000]} if text else None

    @staticmethod
    def _extract_error_message(status_code: int, payload: Any) -> str:
        fallback = f"Anthropic HTTP {status_code}"
        if isinstance(payload, dict):
            err = payload.get("error")
            if isinstance(err, dict):
                msg = err.get("message")
                if isinstance(msg, str) and msg.strip():
                    return msg.strip()
            msg = payload.get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()
        return fallback

    @staticmethod
    def _extract_text(payload: Dict[str, Any]) -> str:
        content = payload.get("content")
        if not isinstance(content, list):
            raise AnthropicClientError(502, "Anthropic response missing content", raw_error_json=payload)
        parts: list[str] = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text":
                text = item.get("text")
                if isinstance(text, str):
                    parts.append(text)
        text = "".join(parts).strip()
        if not text:
            raise AnthropicClientError(502, "Anthropic response contained no text", raw_error_json=payload)
        return text

    async def generate_text(self, prompt: str) -> AnthropicTextResult:
        if not self.api_key:
            _log_anthropic_event(
                logging.ERROR,
                "anthropic.request.error",
                model=self.model,
                message="ANTHROPIC_API_KEY is not configured",
            )
            raise AnthropicClientError(
                500,
                "ANTHROPIC_API_KEY is not configured",
                retry_info=self._build_retry_info(
                    attempts=0,
                    retried=False,
                    last_status_code=None,
                    retry_after_seconds=None,
                ),
            )
        payload = build_anthropic_messages_payload(prompt, self.model, self.max_tokens)
        _log_anthropic_event(
            logging.INFO,
            "anthropic.request.payload",
            model=self.model,
            url=self.url,
            payload=_preview_for_log(payload),
        )
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "content-type": "application/json",
        }
        started = asyncio.get_running_loop().time()
        attempts = 0
        retried = False
        last_status_code: int | None = None
        last_retry_after: float | None = None

        async with httpx.AsyncClient(timeout=self.timeout_seconds, http2=False) as client:
            for attempt in range(self.max_retries + 1):
                attempts = attempt + 1
                try:
                    response = await client.post(self.url, headers=headers, json=payload)
                    _log_anthropic_event(
                        logging.INFO,
                        "anthropic.response",
                        model=self.model,
                        url=self.url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                except httpx.TimeoutException as exc:
                    _log_anthropic_event(
                        logging.ERROR,
                        "anthropic.exception",
                        model=self.model,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise AnthropicClientError(
                        504,
                        f"Anthropic timeout: {type(exc).__name__}: {exc}",
                        raw_error_json={"exception": str(exc), "type": type(exc).__name__},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=None,
                            retry_after_seconds=None,
                        ),
                    )
                except httpx.TransportError as exc:
                    _log_anthropic_event(
                        logging.ERROR,
                        "anthropic.exception",
                        model=self.model,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise AnthropicClientError(
                        502,
                        f"Anthropic network error: {type(exc).__name__}: {exc}",
                        raw_error_json={"exception": str(exc), "type": type(exc).__name__},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=None,
                            retry_after_seconds=None,
                        ),
                    )

                last_status_code = int(response.status_code)
                retry_after = self._parse_retry_after_seconds(response)
                if retry_after is not None:
                    last_retry_after = retry_after

                if response.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    retried = True
                    await asyncio.sleep(retry_after if retry_after is not None else self._backoff_seconds(attempt))
                    continue

                if response.status_code >= 400:
                    raw = self._parse_error_body(response)
                    raise AnthropicClientError(
                        response.status_code,
                        self._extract_error_message(response.status_code, raw),
                        raw_error_json=raw,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                try:
                    body = response.json()
                except ValueError:
                    raise AnthropicClientError(
                        502,
                        "Anthropic response was not JSON",
                        raw_error_json={"raw_text": response.text[:4000]},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                text = self._extract_text(body if isinstance(body, dict) else {"raw": body})
                latency_ms = int((asyncio.get_running_loop().time() - started) * 1000)
                return AnthropicTextResult(
                    text=text,
                    model=self.model,
                    latency_ms=latency_ms,
                    retry_info=self._build_retry_info(
                        attempts=attempts,
                        retried=retried,
                        last_status_code=last_status_code,
                        retry_after_seconds=last_retry_after,
                    ),
                )

        raise AnthropicClientError(
            502,
            "Anthropic request failed after retries",
            retry_info=self._build_retry_info(
                attempts=attempts,
                retried=retried,
                last_status_code=last_status_code,
                retry_after_seconds=last_retry_after,
            ),
        )

    async def chat_with_tools(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> AnthropicChatResult:
        if not self.api_key:
            _log_anthropic_event(
                logging.ERROR,
                "anthropic.request.error",
                model=self.model,
                message="ANTHROPIC_API_KEY is not configured",
            )
            raise AnthropicClientError(
                500,
                "ANTHROPIC_API_KEY is not configured",
                retry_info=self._build_retry_info(
                    attempts=0,
                    retried=False,
                    last_status_code=None,
                    retry_after_seconds=None,
                ),
            )

        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "messages": messages,
            "tools": tools or [],
            "tool_choice": "auto",
        }

        _log_anthropic_event(
            logging.INFO,
            "anthropic.request.payload",
            model=self.model,
            url=self.url,
            payload=_preview_for_log(payload),
        )

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": self.anthropic_version,
            "content-type": "application/json",
        }
        started = asyncio.get_running_loop().time()
        attempts = 0
        retried = False
        last_status_code: int | None = None
        last_retry_after: float | None = None

        async with httpx.AsyncClient(timeout=self.timeout_seconds, http2=False) as client:
            for attempt in range(self.max_retries + 1):
                attempts = attempt + 1
                try:
                    response = await client.post(self.url, headers=headers, json=payload)
                    _log_anthropic_event(
                        logging.INFO,
                        "anthropic.response",
                        model=self.model,
                        url=self.url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                except httpx.TimeoutException as exc:
                    _log_anthropic_event(
                        logging.ERROR,
                        "anthropic.exception",
                        model=self.model,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise AnthropicClientError(
                        504,
                        f"Anthropic timeout: {type(exc).__name__}: {exc}",
                        raw_error_json={"exception": str(exc), "type": type(exc).__name__},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=None,
                            retry_after_seconds=None,
                        ),
                    )
                except httpx.TransportError as exc:
                    _log_anthropic_event(
                        logging.ERROR,
                        "anthropic.exception",
                        model=self.model,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise AnthropicClientError(
                        502,
                        f"Anthropic network error: {type(exc).__name__}: {exc}",
                        raw_error_json={"exception": str(exc), "type": type(exc).__name__},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=None,
                            retry_after_seconds=None,
                        ),
                    )

                last_status_code = int(response.status_code)
                retry_after_seconds = self._parse_retry_after_seconds(response)
                if retry_after_seconds is not None:
                    last_retry_after = retry_after_seconds

                if response.status_code in RETRYABLE_STATUS_CODES and attempt < self.max_retries:
                    retried = True
                    if retry_after_seconds is not None:
                        await asyncio.sleep(retry_after_seconds)
                    else:
                        await asyncio.sleep(self._backoff_seconds(attempt))
                    continue

                if response.status_code >= 400:
                    payload_err = self._parse_error_body(response)
                    message = self._extract_error_message(response.status_code, payload_err)
                    _log_anthropic_event(
                        logging.WARNING,
                        "anthropic.response.error",
                        model=self.model,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(payload_err),
                    )
                    raise AnthropicClientError(
                        status_code=response.status_code,
                        message=message,
                        raw_error_json=payload_err,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                try:
                    data = response.json()
                except ValueError:
                    _log_anthropic_event(
                        logging.ERROR,
                        "anthropic.response.bad_json",
                        model=self.model,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                    raise AnthropicClientError(
                        502,
                        "Anthropic response was not JSON",
                        raw_error_json={"raw_text": response.text[:4000]},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                content = data.get("content")
                if not isinstance(content, list):
                    raise AnthropicClientError(
                        502,
                        "Anthropic response missing content",
                        raw_error_json=data,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                tool_calls: List[Dict[str, Any]] = []
                text_parts: List[str] = []
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    if item.get("type") == "tool_use":
                        tool_calls.append(item)
                    elif item.get("type") == "text" and isinstance(item.get("text"), str):
                        text_parts.append(item["text"])

                text = "".join(text_parts).strip() if text_parts else None
                latency_ms = int((asyncio.get_running_loop().time() - started) * 1000)
                return AnthropicChatResult(
                    text=text,
                    tool_calls=tool_calls,
                    model=self.model,
                    latency_ms=latency_ms,
                    retry_info=self._build_retry_info(
                        attempts=attempts,
                        retried=retried,
                        last_status_code=last_status_code,
                        retry_after_seconds=last_retry_after,
                    ),
                )

        raise AnthropicClientError(
            502,
            "Anthropic request failed after retries",
            retry_info=self._build_retry_info(
                attempts=attempts,
                retried=retried,
                last_status_code=last_status_code,
                retry_after_seconds=last_retry_after,
            ),
        )


def build_anthropic_client_from_env() -> AnthropicClient:
    return AnthropicClient(
        api_key=os.getenv("ANTHROPIC_API_KEY", "").strip(),
        model=os.getenv("ANTHROPIC_MODEL", DEFAULT_ANTHROPIC_MODEL).strip(),
        anthropic_version=os.getenv("ANTHROPIC_VERSION", DEFAULT_ANTHROPIC_VERSION).strip(),
        max_tokens=_get_int_env("ANTHROPIC_MAX_TOKENS", DEFAULT_ANTHROPIC_MAX_TOKENS),
        timeout_seconds=_get_float_env("ANTHROPIC_TIMEOUT_SECONDS", 60.0),
        max_retries=_get_int_env("ANTHROPIC_MAX_RETRIES", 3),
        retry_base_seconds=_get_float_env("ANTHROPIC_RETRY_BASE_SECONDS", 0.5),
    )
