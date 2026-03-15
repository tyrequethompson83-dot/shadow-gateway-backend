import asyncio

import pytest

from openai_client import OpenAIClient, OpenAIClientError


def test_openai_client_surfaces_backend_for_unsupported_model(monkeypatch):
    class _FakeResponse:
        status_code = 400
        headers = {}
        text = '{"error":{"message":"The model `gpt-4.1-mini` does not exist","code":"model_not_found"}}'

        @staticmethod
        def json():
            return {
                "error": {
                    "message": "The model `gpt-4.1-mini` does not exist",
                    "code": "model_not_found",
                }
            }

    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *_args, **_kwargs):
            return _FakeResponse()

    monkeypatch.setattr("openai_client.httpx.AsyncClient", _FakeAsyncClient)

    client = OpenAIClient(
        api_key="gsk_test_1234567890abcdef",
        model="gpt-4.1-mini",
        base_url="https://api.groq.com/openai/v1",
        max_retries=0,
    )
    with pytest.raises(OpenAIClientError) as exc_info:
        asyncio.run(client.generate_text("hello"))

    message = str(exc_info.value.message)
    assert "gpt-4.1-mini" in message
    assert "https://api.groq.com/openai/v1" in message
    assert "may not be supported by backend" in message


def test_openai_client_parses_chat_completions_choices(monkeypatch):
    class _FakeResponse:
        status_code = 200
        headers = {}
        text = '{"choices":[{"message":{"role":"assistant","content":"Hello from Groq"}}]}'

        @staticmethod
        def json():
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "Hello from Groq",
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
            return _FakeResponse()

    monkeypatch.setattr("openai_client.httpx.AsyncClient", _FakeAsyncClient)

    client = OpenAIClient(
        api_key="gsk_test_1234567890abcdef",
        model="llama-3.1-8b-instant",
        base_url="https://api.groq.com/openai/v1",
        max_retries=0,
    )
    result = asyncio.run(client.generate_text("hello"))
    assert result.text == "Hello from Groq"
