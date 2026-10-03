"""Strict adapter for a model that writes a tool call as plain JSON text.

Parsing an envelope is not permission to execute arbitrary content. The same
AgentTools.dispatch validates the tool name, arguments, paths, identity and
request budget used for native Ollama tool calls.
"""

from __future__ import annotations

import json
from typing import Any


MAX_TEXT_BYTES = 8192


def parse_text_tool_call(content: Any) -> tuple[str, dict] | None:
    """Accept one whole {name, arguments} JSON object, with no surrounding text."""
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_TEXT_BYTES:
        return None
    try:
        payload = json.loads(content)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict) or set(payload) != {"name", "arguments"}:
        return None
    name, arguments = payload["name"], payload["arguments"]
    if not isinstance(name, str) or not isinstance(arguments, dict):
        return None
    return name, arguments
