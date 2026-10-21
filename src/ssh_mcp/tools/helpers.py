"""Helpers shared by every tool handler."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from mcp.types import CallToolResult, TextContent

from ssh_mcp.errors import ToolFailure

MAX_TEXT_BYTES = 512 * 1024

_RESULT_TOO_LARGE = {
    "error": "result_too_large",
    "hint": "结果过大，请缩小范围（如减小 max_output_bytes 或分页读取）。",
}


def _result(payload: dict[str, Any], *, is_error: bool = False) -> CallToolResult:
    """Serialize once; ``structured_content`` is the payload itself.

    The SDK serializes ``structured_content`` for its own wire format, so
    re-parsing our JSON text into a dict was a third full pass over up to
    512 KiB per call.
    """
    body = json.dumps(payload, ensure_ascii=False, default=str)
    return CallToolResult(
        content=[TextContent(type="text", text=body)],
        structured_content=payload,
        is_error=is_error,
    )


def tool_ok(payload: dict[str, Any]) -> CallToolResult:
    """Return a successful structured result."""
    body = json.dumps(payload, ensure_ascii=False, default=str)
    if len(body) > MAX_TEXT_BYTES or len(body.encode("utf-8")) > MAX_TEXT_BYTES:
        # ``len(body)`` is a cheap lower bound on the UTF-8 size; the exact
        # encode only runs when the text could actually be too large.
        return _result(_RESULT_TOO_LARGE, is_error=True)
    return CallToolResult(content=[TextContent(type="text", text=body)], structured_content=payload)


# Set by :func:`ssh_mcp.server.create_server`; None when tools run standalone.
_error_sink: "Callable[[str], None] | None" = None


def set_error_sink(sink: "Callable[[str], None] | None") -> None:
    """Install a callback that counts failures by error code."""
    global _error_sink
    _error_sink = sink


def tool_err(failure: ToolFailure) -> CallToolResult:
    """Return a structured error result (``is_error=True``)."""
    if _error_sink is not None:
        try:
            _error_sink(failure.error)
        except Exception:  # noqa: BLE001 - counting must never break a response
            pass
    return _result(failure.to_dict(), is_error=True)


def tool_err_dict(payload: dict[str, Any]) -> CallToolResult:
    return _result(payload, is_error=True)
