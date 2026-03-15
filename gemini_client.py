import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict

import httpx


DEFAULT_GEMINI_MODEL = "models/gemini-2.0-flash"
GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
LOGGER = logging.getLogger("shadow.gemini")
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


def _log_gemini_event(level: int, event: str, **fields: Any) -> None:
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


def normalize_gemini_model(model: str) -> str:
    value = (model or "").strip().strip("/")
    if not value:
        value = DEFAULT_GEMINI_MODEL
    if ":generateContent" in value:
        value = value.split(":generateContent", 1)[0]
    if value.startswith("v1beta/"):
        value = value[len("v1beta/") :]
    while value.startswith("models/"):
        value = value[len("models/") :]
    return f"models/{value}"


def build_generate_content_payload(prompt: str, *, google_search: bool = False) -> Dict[str, Any]:
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    # Keep strict Gemini shape: contents -> parts -> text.
    payload: Dict[str, Any] = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
    if google_search:
        payload["tools"] = [{"google_search": {}}]
    return payload


@dataclass
class GeminiTextResult:
    text: str
    model: str
    latency_ms: int
    retry_info: Dict[str, Any] = field(default_factory=dict)


class GeminiClientError(Exception):
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "message": self.message,
            "raw_error_json": self.raw_error_json,
            "retry_info": self.retry_info,
        }


class GeminiClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        *,
        timeout_seconds: float = 60.0,
        max_retries: int = 3,
        retry_base_seconds: float = 0.5,
    ):
        self.api_key = (api_key or "").strip()
        self.model = normalize_gemini_model(model)
        self.timeout_seconds = max(float(timeout_seconds), 1.0)
        self.max_retries = max(int(max_retries), 0)
        self.retry_base_seconds = max(float(retry_base_seconds), 0.0)

    @property
    def url(self) -> str:
        # Ensure URL always has exactly one `models/` segment.
        model_id = self.model[len("models/") :] if self.model.startswith("models/") else self.model
        return f"{GEMINI_API_BASE}/models/{model_id}:generateContent"

    def _backoff_seconds(self, attempt: int) -> float:
        return min(self.retry_base_seconds * (2 ** attempt), 8.0)

    @staticmethod
    def _parse_retry_after_seconds(response: httpx.Response) -> float | None:
        raw = response.headers.get("Retry-After")
        if raw is None:
            return None

        value = raw.strip()
        if not value:
            return None

        try:
            return max(0.0, float(value))
        except ValueError:
            pass

        try:
            dt = parsedate_to_datetime(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            delta = (dt - datetime.now(timezone.utc)).total_seconds()
            return max(0.0, delta)
        except Exception:
            return None

    def _build_retry_info(
        self,
        *,
        attempts: int,
        last_status_code: int | None,
        retry_after_seconds: float | None,
        retried: bool,
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
            if not text:
                return None
            return {"raw_text": text[:4000]}

    @staticmethod
    def _extract_error_message(status_code: int, payload: Any) -> str:
        fallback = f"Gemini HTTP {status_code}"
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict):
                msg = error.get("message")
                if isinstance(msg, str) and msg.strip():
                    return msg.strip()
            msg = payload.get("message")
            if isinstance(msg, str) and msg.strip():
                return msg.strip()
        return fallback

    @staticmethod
    def _structured_error(
        *,
        status_code: int,
        payload: Any = None,
        message: str | None = None,
        code: Any = None,
        status: str | None = None,
    ) -> Dict[str, Any]:
        payload_error = payload.get("error") if isinstance(payload, dict) else None
        parsed_code = code
        parsed_status = status
        parsed_message = message
        if isinstance(payload_error, dict):
            if parsed_code is None:
                parsed_code = payload_error.get("code")
            if not parsed_status:
                raw_status = payload_error.get("status")
                parsed_status = str(raw_status).strip() if raw_status else ""
            if not parsed_message:
                raw_message = payload_error.get("message")
                parsed_message = str(raw_message).strip() if raw_message else ""
        if parsed_code in (None, ""):
            parsed_code = int(status_code)
        if not parsed_status:
            parsed_status = f"HTTP_{int(status_code)}"
        if not parsed_message:
            parsed_message = f"Gemini HTTP {int(status_code)}"
        return {
            "error": {
                "provider": "gemini",
                "code": parsed_code,
                "status": str(parsed_status),
                "message": str(parsed_message),
            }
        }

    @staticmethod
    def _extract_text(payload: Dict[str, Any]) -> str:
        candidates = payload.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise GeminiClientError(
                status_code=502,
                message="Gemini response missing candidates",
                raw_error_json=payload,
            )

        first = candidates[0]
        if not isinstance(first, dict):
            raise GeminiClientError(
                status_code=502,
                message="Gemini response candidate shape is invalid",
                raw_error_json=payload,
            )

        content = first.get("content")
        if not isinstance(content, dict):
            raise GeminiClientError(
                status_code=502,
                message="Gemini response missing content",
                raw_error_json=payload,
            )

        parts = content.get("parts")
        if not isinstance(parts, list):
            raise GeminiClientError(
                status_code=502,
                message="Gemini response missing parts",
                raw_error_json=payload,
            )

        text = "".join(
            p.get("text", "")
            for p in parts
            if isinstance(p, dict) and isinstance(p.get("text"), str)
        ).strip()

        if not text:
            raise GeminiClientError(
                status_code=502,
                message="Gemini response contained no text",
                raw_error_json=payload,
            )
        return text

    async def generate_text(self, prompt: str, *, google_search: bool = False) -> GeminiTextResult:
        if not self.api_key:
            structured = self._structured_error(
                status_code=500,
                code="MISSING_API_KEY",
                status="MISSING_API_KEY",
                message="GEMINI_API_KEY is not configured",
            )
            LOGGER.warning(
                "Gemini config error provider=gemini model=%s status=%s",
                self.model,
                structured["error"]["status"],
            )
            raise GeminiClientError(
                status_code=500,
                message="GEMINI_API_KEY is not configured",
                raw_error_json=structured,
                retry_info=self._build_retry_info(
                    attempts=0,
                    last_status_code=None,
                    retry_after_seconds=None,
                    retried=False,
                ),
            )

        payload = build_generate_content_payload(prompt, google_search=google_search)
        _log_gemini_event(
            logging.INFO,
            "gemini.request.payload",
            model=self.model,
            url=self.url,
            payload=_preview_for_log(payload),
        )
        headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}

        start = asyncio.get_running_loop().time()
        last_status_code: int | None = None
        last_retry_after: float | None = None
        attempts = 0
        retried = False

        async with httpx.AsyncClient(timeout=self.timeout_seconds, http2=False) as client:
            for attempt in range(self.max_retries + 1):
                attempts = attempt + 1
                try:
                    response = await client.post(self.url, headers=headers, json=payload)
                    _log_gemini_event(
                        logging.INFO,
                        "gemini.response",
                        model=self.model,
                        url=self.url,
                        attempt=attempts,
                        status_code=int(response.status_code),
                        body=_preview_for_log(response.text),
                    )
                except httpx.TimeoutException as exc:
                    _log_gemini_event(
                        logging.ERROR,
                        "gemini.exception",
                        model=self.model,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    structured = self._structured_error(
                        status_code=504,
                        code="TIMEOUT",
                        status="TIMEOUT",
                        message=f"Gemini timeout: {type(exc).__name__}: {exc}",
                    )
                    LOGGER.warning(
                        "Gemini timeout provider=gemini model=%s status=%s",
                        self.model,
                        structured["error"]["status"],
                    )
                    raise GeminiClientError(
                        status_code=504,
                        message=f"Gemini timeout: {type(exc).__name__}: {exc}",
                        raw_error_json=structured,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            last_status_code=None,
                            retry_after_seconds=None,
                            retried=retried,
                        ),
                    )
                except httpx.TransportError as exc:
                    _log_gemini_event(
                        logging.ERROR,
                        "gemini.exception",
                        model=self.model,
                        attempt=attempts,
                        exception_type=type(exc).__name__,
                        message=str(exc),
                    )
                    if attempt < self.max_retries:
                        retried = True
                        await asyncio.sleep(self._backoff_seconds(attempt))
                        continue
                    structured = self._structured_error(
                        status_code=502,
                        code="NETWORK_ERROR",
                        status="NETWORK_ERROR",
                        message=f"Gemini network error: {type(exc).__name__}: {exc}",
                    )
                    LOGGER.warning(
                        "Gemini network error provider=gemini model=%s status=%s",
                        self.model,
                        structured["error"]["status"],
                    )
                    raise GeminiClientError(
                        status_code=502,
                        message=f"Gemini network error: {type(exc).__name__}: {exc}",
                        raw_error_json=structured,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            last_status_code=None,
                            retry_after_seconds=None,
                            retried=retried,
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
                    raw_error = self._parse_error_body(response)
                    message = self._extract_error_message(response.status_code, raw_error)
                    structured = self._structured_error(
                        status_code=int(response.status_code),
                        payload=raw_error,
                        message=message,
                    )
                    LOGGER.warning(
                        "Gemini HTTP error provider=gemini model=%s status_code=%s code=%s status=%s message=%s",
                        self.model,
                        int(response.status_code),
                        structured["error"]["code"],
                        structured["error"]["status"],
                        structured["error"]["message"],
                    )
                    raise GeminiClientError(
                        status_code=response.status_code,
                        message=message,
                        raw_error_json=structured,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                            retried=retried,
                        ),
                    )

                try:
                    data = response.json()
                except ValueError:
                    structured = self._structured_error(
                        status_code=502,
                        code="BAD_JSON",
                        status="BAD_JSON",
                        message="Gemini response was not JSON",
                    )
                    LOGGER.warning(
                        "Gemini bad JSON provider=gemini model=%s",
                        self.model,
                    )
                    raise GeminiClientError(
                        status_code=502,
                        message="Gemini response was not JSON",
                        raw_error_json=structured,
                        retry_info=self._build_retry_info(
                            attempts=attempts,
                            last_status_code=last_status_code,
                            retry_after_seconds=last_retry_after,
                            retried=retried,
                        ),
                    )

                text = self._extract_text(data if isinstance(data, dict) else {"raw": data})
                latency_ms = int((asyncio.get_running_loop().time() - start) * 1000)
                return GeminiTextResult(
                    text=text,
                    model=self.model,
                    latency_ms=latency_ms,
                    retry_info=self._build_retry_info(
                        attempts=attempts,
                        last_status_code=last_status_code,
                        retry_after_seconds=last_retry_after,
                        retried=retried,
                    ),
                )

        raise GeminiClientError(
            status_code=502,
            message="Gemini request failed after retries",
            raw_error_json=None,
            retry_info=self._build_retry_info(
                attempts=attempts,
                last_status_code=last_status_code,
                retry_after_seconds=last_retry_after,
                retried=retried,
            ),
        )


def build_gemini_client_from_env() -> GeminiClient:
    return GeminiClient(
        api_key=os.getenv("GEMINI_API_KEY", "").strip(),
        model=os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip(),
        timeout_seconds=_get_float_env("GEMINI_TIMEOUT_SECONDS", 60.0),
        max_retries=_get_int_env("GEMINI_MAX_RETRIES", 3),
        retry_base_seconds=_get_float_env("GEMINI_RETRY_BASE_SECONDS", 0.5),
    )
