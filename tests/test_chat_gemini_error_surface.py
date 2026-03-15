import asyncio

from gemini_client import GeminiClientError
import gemini_client
import main


def test_chat_returns_structured_gemini_error(app_ctx, monkeypatch):
    client = app_ctx["client"]

    async def _fake_generate(_prompt: str):
        raise GeminiClientError(
            status_code=503,
            message="Upstream unavailable",
            raw_error_json={"error": {"message": "backend down"}},
        )

    monkeypatch.setattr(main, "GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(main.GEMINI_CLIENT, "generate_text", _fake_generate)

    resp = client.post(
        "/chat",
        headers={"X-User": "gemini-error-user", "X-Tenant-Id": "1"},
        json={"prompt": "hello world"},
    )
    assert resp.status_code == 502
    payload = resp.json()

    assert "detail" in payload
    detail = payload["detail"]
    assert detail["provider"] == "gemini"
    assert str(detail["model"]).startswith("models/gemini")
    assert detail["status_code"] == 503
    assert detail["message"] == "Upstream unavailable"
    assert detail["raw_error_json"] == {"error": {"message": "backend down"}}


def test_chat_parses_mocked_gemini_success_response(app_ctx, monkeypatch):
    client = app_ctx["client"]

    class _FakeResponse:
        status_code = 200
        headers = {}
        text = '{"candidates":[{"content":{"parts":[{"text":"Hello "},{"text":"Gemini"}]}}]}'

        def json(self):
            return {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": "Hello "},
                                {"text": "Gemini"},
                            ]
                        }
                    }
                ]
            }

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *_args, **_kwargs):
            await asyncio.sleep(0)
            return _FakeResponse()

    monkeypatch.setattr(main, "GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(main.GEMINI_CLIENT, "api_key", "test-key")
    monkeypatch.setattr(gemini_client.httpx, "AsyncClient", _FakeAsyncClient)

    resp = client.post(
        "/chat",
        headers={"X-User": "gemini-success-user", "X-Tenant-Id": "1"},
        json={"prompt": "hello world"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ai_response_clean"] == "Hello Gemini"
    assert payload["provider"] == "gemini"
    assert payload["model"].startswith("models/gemini")
    assert payload["decision"] == "ALLOW"
    assert payload["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert isinstance(float(payload["risk_score"]), float)
    assert payload["redactions_applied"] == 0
    assert payload["cleaned_prompt"] == "hello world"


def test_chat_surfaces_retry_after_seconds_for_upstream_429(app_ctx, monkeypatch):
    client = app_ctx["client"]

    async def _fake_generate(_prompt: str):
        raise GeminiClientError(
            status_code=429,
            message="Quota exceeded",
            raw_error_json={"error": {"message": "quota hit"}},
            retry_info={"retry_after_seconds": 3.0},
        )

    monkeypatch.setattr(main, "GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(main.GEMINI_CLIENT, "generate_text", _fake_generate)

    resp = client.post(
        "/chat",
        headers={"X-User": "gemini-429-user", "X-Tenant-Id": "1"},
        json={"prompt": "hello world"},
    )
    assert resp.status_code == 502
    payload = resp.json()
    detail = payload["detail"]
    assert detail["provider"] == "gemini"
    assert detail["status_code"] == 429
    assert detail["retry_after_seconds"] == 3
