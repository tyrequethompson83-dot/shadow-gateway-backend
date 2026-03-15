from anthropic_client import build_anthropic_messages_payload
from openai_client import build_openai_chat_completions_payload
from openai_client import build_openai_responses_payload


def test_openai_payload_format():
    payload = build_openai_responses_payload("hello world", "gpt-4.1-mini")
    assert payload["model"] == "gpt-4.1-mini"
    assert payload["temperature"] == 0
    assert payload["top_p"] == 1
    assert payload["input"][0]["role"] == "user"
    assert payload["input"][0]["content"][0]["type"] == "input_text"
    assert payload["input"][0]["content"][0]["text"] == "hello world"


def test_openai_chat_completions_payload_format():
    payload = build_openai_chat_completions_payload("hello world", "gpt-4.1-mini")
    assert payload["model"] == "gpt-4.1-mini"
    assert payload["temperature"] == 0
    assert payload["top_p"] == 1
    assert payload["messages"] == [{"role": "user", "content": "hello world"}]


def test_anthropic_payload_format():
    payload = build_anthropic_messages_payload("hello world", "claude-3-5-haiku-latest", 256)
    assert payload["model"] == "claude-3-5-haiku-latest"
    assert payload["temperature"] == 0
    assert payload["max_tokens"] == 256
    assert payload["messages"] == [{"role": "user", "content": "hello world"}]
