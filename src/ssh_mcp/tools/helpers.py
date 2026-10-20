"""Helpers shared by every tool handler."""

from __future__ import annotations

import json
from typing import Any

from mcp.types import CallToolResult, TextContent

from ssh_mcp.errors import ToolFailure

MAX_TEXT_BYTES = 512 * 1024


def tool_ok(payload: dict[str, Any]) -> CallToolResult:
    """Return a successful structured result."""
    body = json.dumps(payload, ensure_ascii=False, default=str)
    if len(body.encode("utf-8")) > MAX_TEXT_BYTES:
        body = json.dumps(
            {"error": "result_too_large", "hint": "结果过大，请缩小范围（如减小 max_output_bytes 或分页读取）。"},
            ensure_ascii=False,
        )
        return CallToolResult(content=[TextContent(type="text", text=body)], structured_content=json.loads(body), is_error=True)
    return CallToolResult(content=[TextContent(type="text", text=body)], structured_content=json.loads(body))


def tool_err(failure: ToolFailure) -> CallToolResult:
    """Return a structured error result (``is_error=True``)."""
    body = json.dumps(failure.to_dict(), ensure_ascii=False, default=str)
    return CallToolResult(content=[TextContent(type="text", text=body)], structured_content=failure.to_dict(), is_error=True)


def tool_err_dict(payload: dict[str, Any]) -> CallToolResult:
    body = json.dumps(payload, ensure_ascii=False, default=str)
    return CallToolResult(content=[TextContent(type="text", text=body)], structured_content=payload, is_error=True)
