"""Result envelope contract: text and structured content must agree."""

from __future__ import annotations

import json

from ssh_mcp.errors import ToolFailure
from ssh_mcp.tools.helpers import MAX_TEXT_BYTES, tool_err, tool_ok


def test_text_is_the_serialized_structured_content():
    """The two fields are one payload; a client may read either.

    MCP requires a text content block, so the JSON text is duplicated into
    ``structuredContent``. The duplication is unavoidable; disagreeing is not,
    and an empty text block while structured content is populated is what a
    client sees as "no output".
    """
    result = tool_ok({"a": 1, "文件": "值", "nested": {"ok": True}})
    assert result.is_error is False
    assert json.loads(result.content[0].text) == result.structured_content


def test_error_payload_is_consistent_too():
    failure = ToolFailure("connection_lost", stage="execute", hint="重试", retryable=True)
    result = tool_err(failure)
    assert result.is_error is True
    text_payload = json.loads(result.content[0].text)
    assert text_payload == result.structured_content
    assert text_payload["error"] == "connection_lost"
    assert text_payload["retryable"] is True


def test_oversized_payload_becomes_a_clear_error():
    result = tool_ok({"blob": "x" * (MAX_TEXT_BYTES + 1)})
    assert result.is_error is True
    assert json.loads(result.content[0].text)["error"] == "result_too_large"
