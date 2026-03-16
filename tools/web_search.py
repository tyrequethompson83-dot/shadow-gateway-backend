import logging
import os
from typing import Any, Dict, List, Optional

import httpx


LOGGER = logging.getLogger("shadow.tools.web_search")
TAVILY_API_URL = "https://api.tavily.com/search"


_WEB_SEARCH_INPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": "The search query to run. Use natural language, include entities and key facts.",
        },
        "max_results": {
            "type": "integer",
            "description": "Maximum number of results to return (1-10).",
            "minimum": 1,
            "maximum": 10,
            "default": 5,
        },
    },
    "required": ["query"],
}

# Provider-specific tool schemas (OpenAI != Anthropic).
WEB_SEARCH_TOOL_OPENAI: Dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "Search the web for up-to-date information and return relevant results.",
        "parameters": _WEB_SEARCH_INPUT_SCHEMA,
    },
}

WEB_SEARCH_TOOL_ANTHROPIC: Dict[str, Any] = {
    "name": "web_search",
    "description": "Search the web for up-to-date information and return relevant results.",
    "input_schema": _WEB_SEARCH_INPUT_SCHEMA,
}

# Default schema used for introspection/listing.
WEB_SEARCH_TOOL: Dict[str, Any] = WEB_SEARCH_TOOL_OPENAI


class WebSearchError(Exception):
    pass


def _resolve_key(user_key: Optional[str]) -> str:
    key = (user_key or "").strip()
    if not key:
        key = os.getenv("TAVILY_API_KEY", "").strip()
    if not key:
        raise WebSearchError("Tavily API key is not configured")
    return key


async def web_search(query: str, max_results: int = 5, api_key: Optional[str] = None) -> List[Dict[str, str]]:
    key = _resolve_key(api_key)

    q = (query or "").strip()
    if not q:
        raise WebSearchError("query must be provided")

    limit = max(1, min(int(max_results or 5), 10))

    payload = {
        "api_key": key,
        "query": q,
        "max_results": limit,
        "search_depth": "basic",
    }

    LOGGER.info("web_search.request %s", {"query": _preview(q), "max_results": limit})

    async with httpx.AsyncClient(timeout=30.0, http2=False) as client:
        response = await client.post(TAVILY_API_URL, json=payload)
        try:
            data = response.json()
        except ValueError:
            data = {}

        if response.status_code >= 400:
            LOGGER.warning(
                "web_search.error %s",
                {
                    "status": response.status_code,
                    "body": _preview(response.text),
                },
            )
            raise WebSearchError(f"Tavily error {response.status_code}: {response.text[:200]}")

    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        LOGGER.warning("web_search.empty_results %s", {"body": _preview(data)})
        return []

    formatted: List[Dict[str, str]] = []
    for item in results[:limit]:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("name") or "").strip()
        url = str(item.get("url") or "").strip()
        content = str(item.get("content") or item.get("snippet") or "").strip()
        if not url:
            continue
        formatted.append(
            {
                "title": title or url,
                "url": url,
                "content": content,
            }
        )

    LOGGER.info("web_search.results %s", {"count": len(formatted)})
    return formatted


def _preview(value: Any, limit: int = 500) -> Any:
    try:
        text = str(value)
    except Exception:
        return "<unserializable>"
    return text if len(text) <= limit else f"{text[:limit]}...<truncated>"
