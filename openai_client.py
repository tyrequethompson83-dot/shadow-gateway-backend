import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

import httpx


OPENAI_API_BASE = "https://api.openai.com/v1"
DEFAULT_OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip() or "gpt-4.1-mini"
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
LOGGER = logging.getLogger("shadow.openai")
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


def _log_openai_event(level: int, event: str, **fields: Any) -> None:
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


def build_openai_responses_payload(prompt: str, model: str) -> Dict[str, Any]:
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    return {
        "model": (model or DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL,
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": prompt,
                    }
                ],
            }
        ],
        "temperature": 0,
        "top_p": 1,
    }


def build_openai_chat_completions_payload(prompt: str, model: str) -> Dict[str, Any]:
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    return {
        "model": (model or DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "temperature": 0,
        "top_p": 1,
    }


@dataclass
class OpenAITextResult:
    text: str
    model: str
    latency_ms: int
    retry_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OpenAIChatResult:
    text: Optional[str]
    tool_calls: List[Dict[str, Any]]
    model: str
    latency_ms: int
    retry_info: Dict[str, Any] = field(default_factory=dict)


class OpenAIClientError(Exception):
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


class OpenAIClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        base_url: str | None = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        retry_base_seconds: float = 0.5,
    ):
        self.api_key = (api_key or "").strip()
        self.model = (model or DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL
        normalized_base_url = (base_url or "").strip().rstrip("/")
        self.base_url = normalized_base_url or OPENAI_API_BASE
        self.timeout_seconds = max(1.0, float(timeout_seconds))
        self.max_retries = max(0, int(max_retries))
        self.retry_base_seconds = max(0.0, float(retry_base_seconds))

    @property
    def url(self) -> str:
        return f"{self.base_url}/chat/completions"

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
        fallback = f"OpenAI HTTP {status_code}"
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
    def _is_unsupported_model_error(payload: Any, message: str) -> bool:
        if not isinstance(message, str):
            return False
        haystack = message.lower()
        model_hints = ("model", "unsupported", "not found", "does not exist", "invalid")
        if any(h in haystack for h in model_hints):
            return True
        if isinstance(payload, dict):
            err = payload.get("error")
            if isinstance(err, dict):
                code = str(err.get("code") or "").strip().lower()
                if code in {"model_not_found", "invalid_model"}:
                    return True
        return False

    @staticmethod
    def _extract_text(payload: Dict[str, Any]) -> str:
        choices = payload.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                message = choice.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, str) and content.strip():
                        return content.strip()
                    if isinstance(content, list):
                        parts: list[str] = []
                        for part in content:
                            if isinstance(part, dict):
                                text_part = part.get("text")
                                if isinstance(text_part, str):
                                    parts.append(text_part)
                        merged = "".join(parts).strip()
                        if merged:
                            return merged
                text = choice.get("text")
                if isinstance(text, str) and text.strip():
                    return text.strip()

        output_text = payload.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()

        output = payload.get("output")
        if isinstance(output, list):
            parts: list[str] = []
            for item in output:
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if not isinstance(content, list):
                    continue
                for c in content:
                    if isinstance(c, dict):
                        t = c.get("text")
                        if isinstance(t, str):
                            parts.append(t)
            text = "".join(parts).strip()
            if text:
                return text
        raise OpenAIClientError(502, "OpenAI response contained no text", raw_error_json=payload)

    async def generate_text(self, prompt: str) -> OpenAITextResult:
        if not self.api_key:
            _log_openai_event(
                logging.ERROR,
                "openai.request.error",
                model=self.model,
                base_url=self.base_url,
                message="OPENAI_API_KEY is not configured",
            )
            raise OpenAIClientError(
                500,
                "OPENAI_API_KEY is not configured",
                retry_info=self._build_retry_info(
                    attempts=0,
                    retried=False,
                    last_status_code=None,
                    retry_after_seconds=None,
                ),
            )
        payload = build_openai_chat_completions_payload(prompt, self.model)
        _log_openai_event(
            logging.INFO,
            "openai.request.payload",
            model=self.model,
            base_url=self.base_url,
            url=self.url,
            payload=_preview_for_log(payload),
        )
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
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
                    _log_openai_event(
                        logging.INFO,
                        "openai.response",
                        model=self.model,
                        base_url=self.base_url,
                        url=self.url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                except httpx.TimeoutException as exc:
                    _log_openai_event(
                        logging.ERROR,
                        "openai.exception",
                        model=self.model,
                        base_url=self.base_url,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise OpenAIClientError(
                        504,
                        f"OpenAI timeout: {type(exc).__name__}: {exc}",
                        raw_error_json={"exception": str(exc), "type": type(exc).__name__},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=None,
                            retry_after_seconds=None,
                        ),
                    )
                except httpx.TransportError as exc:
                    _log_openai_event(
                        logging.ERROR,
                        "openai.exception",
                        model=self.model,
                        base_url=self.base_url,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise OpenAIClientError(
                        502,
                        f"OpenAI network error: {type(exc).__name__}: {exc}",
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
                    message = self._extract_error_message(response.status_code, raw)
                    if response.status_code in (400, 404) and self._is_unsupported_model_error(raw, message):
                        message = (
                            f"{message} "
                            f"(model '{self.model}' may not be supported by backend '{self.base_url}')"
                        )
                    raise OpenAIClientError(
                        response.status_code,
                        message,
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
                    _log_openai_event(
                        logging.ERROR,
                        "openai.response.invalid_json",
                        model=self.model,
                        base_url=self.base_url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                    raise OpenAIClientError(
                        502,
                        "OpenAI response was not JSON",
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
                return OpenAITextResult(
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

        raise OpenAIClientError(
            502,
            "OpenAI request failed after retries",
            retry_info=self._build_retry_info(
                attempts=attempts,
                retried=retried,
                last_status_code=last_status_code,
                retry_after_seconds=last_retry_after,
            ),
        )

    async def chat_with_tools(self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> OpenAIChatResult:
        if not self.api_key:
            _log_openai_event(
                logging.ERROR,
                "openai.request.error",
                model=self.model,
                base_url=self.base_url,
                message="OPENAI_API_KEY is not configured",
            )
            raise OpenAIClientError(
                500,
                "OPENAI_API_KEY is not configured",
                retry_info=self._build_retry_info(
                    attempts=0,
                    retried=False,
                    last_status_code=None,
                    retry_after_seconds=None,
                ),
            )

        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools or [],
            "tool_choice": "auto",
            "temperature": 0,
            "top_p": 1,
        }

        _log_openai_event(
            logging.INFO,
            "openai.request.payload",
            model=self.model,
            base_url=self.base_url,
            url=self.url,
            payload=_preview_for_log(payload),
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
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
                    _log_openai_event(
                        logging.INFO,
                        "openai.response",
                        model=self.model,
                        base_url=self.base_url,
                        url=self.url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                except httpx.TimeoutException as exc:
                    _log_openai_event(
                        logging.ERROR,
                        "openai.exception",
                        model=self.model,
                        base_url=self.base_url,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise OpenAIClientError(
                        504,
                        f"OpenAI timeout: {type(exc).__name__}: {exc}",
                        raw_error_json={"exception": str(exc), "type": type(exc).__name__},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=None,
                            retry_after_seconds=None,
                        ),
                    )
                except httpx.TransportError as exc:
                    _log_openai_event(
                        logging.ERROR,
                        "openai.exception",
                        model=self.model,
                        base_url=self.base_url,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    raise OpenAIClientError(
                        502,
                        f"OpenAI network error: {type(exc).__name__}: {exc}",
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
                    _log_openai_event(
                        logging.WARNING,
                        "openai.response.error",
                        model=self.model,
                        base_url=self.base_url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(payload_err),
                    )
                    raise OpenAIClientError(
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
                    _log_openai_event(
                        logging.ERROR,
                        "openai.response.bad_json",
                        model=self.model,
                        base_url=self.base_url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                    raise OpenAIClientError(
                        502,
                        "OpenAI response was not JSON",
                        raw_error_json={"raw_text": response.text[:4000]},
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                choices = data.get("choices")
                if not isinstance(choices, list) or not choices:
                    raise OpenAIClientError(
                        502,
                        "OpenAI response missing choices",
                        raw_error_json=data,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                message = choices[0].get("message") if isinstance(choices[0], dict) else None
                if not isinstance(message, dict):
                    raise OpenAIClientError(
                        502,
                        "OpenAI response missing message",
                        raw_error_json=data,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            retried=retried,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                        ),
                    )

                tool_calls = message.get("tool_calls") if isinstance(message, dict) else None
                if not isinstance(tool_calls, list):
                    tool_calls = []

                content = message.get("content")
                text_parts: list[str] = []
                if isinstance(content, str) and content.strip():
                    text_parts.append(content.strip())
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict):
                            if part.get("type") == "text" and isinstance(part.get("text"), str):
                                text_parts.append(part["text"])
                text = "".join(text_parts).strip() if text_parts else None

                latency_ms = int((asyncio.get_running_loop().time() - started) * 1000)
                return OpenAIChatResult(
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

        raise OpenAIClientError(
            502,
            "OpenAI request failed after retries",
            retry_info=self._build_retry_info(
                attempts=attempts,
                retried=retried,
                last_status_code=last_status_code,
                retry_after_seconds=last_retry_after,
            ),
        )


def build_openai_client_from_env() -> OpenAIClient:
    return OpenAIClient(
        api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        model=os.getenv("OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip(),
        base_url=(os.getenv("OPENAI_BASE_URL", "") or "").strip() or None,
        timeout_seconds=_get_float_env("OPENAI_TIMEOUT_SECONDS", 60.0),
        max_retries=_get_int_env("OPENAI_MAX_RETRIES", 3),
        retry_base_seconds=_get_float_env("OPENAI_RETRY_BASE_SECONDS", 0.5),
    )
