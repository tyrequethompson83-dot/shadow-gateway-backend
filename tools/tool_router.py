import logging
from typing import Any, Awaitable, Callable, Dict, Optional

from tools.web_search import WEB_SEARCH_TOOL, WebSearchError, web_search


LOGGER = logging.getLogger("shadow.tools.router")

ToolFunc = Callable[..., Awaitable[Any]]

TOOL_REGISTRY: Dict[str, ToolFunc] = {
    "web_search": web_search,
}


def list_tools() -> Dict[str, Any]:
    return {"web_search": WEB_SEARCH_TOOL}


async def execute_tool_call(name: str, arguments: Dict[str, Any], *, tavily_api_key: Optional[str] = None) -> Any:
    func = TOOL_REGISTRY.get(name)
    if func is None:
        raise WebSearchError(f"Unsupported tool: {name}")

    args = dict(arguments or {})
    LOGGER.info("tool.call %s", {"name": name, "args": _preview(args)})

    try:
        if name == "web_search":
            return await func(api_key=tavily_api_key, **args)
        return await func(**args)
    except WebSearchError:
        raise
    except TypeError as exc:
        raise WebSearchError(f"Invalid arguments for tool {name}: {exc}") from exc
    except Exception as exc:
        LOGGER.exception("tool.call.error %s", {"name": name, "error": str(exc)})
        raise WebSearchError(f"Tool {name} failed: {exc}") from exc


def _preview(value: Any, limit: int = 500) -> Any:
    try:
        text = str(value)
    except Exception:
        return "<unserializable>"
    return text if len(text) <= limit else f"{text[:limit]}...<truncated>"
