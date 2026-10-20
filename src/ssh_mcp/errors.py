"""Structured error contract shared by every tool.

Tools never raise an MCP protocol error for an expected failure: they return
``CallToolResult(is_error=True)`` whose JSON body carries at least ``error``,
``stage``, ``hint`` and ``retryable``. The AI client can therefore branch on a
stable code instead of parsing prose, and a stack trace never reaches the wire.
"""

from __future__ import annotations

from typing import Any


class ToolFailure(Exception):
    """An anticipated, structured tool failure."""

    def __init__(
        self,
        error: str,
        *,
        stage: str,
        hint: str,
        retryable: bool = False,
        **details: Any,
    ) -> None:
        super().__init__(hint)
        self.error = error
        self.stage = stage
        self.hint = hint
        self.retryable = retryable
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": self.error,
            "stage": self.stage,
            "hint": self.hint,
            "retryable": self.retryable,
        }
        for key, value in self.details.items():
            if value is not None:
                payload[key] = value
        return payload


class ConfirmationRequired(ToolFailure):
    """A destructive action was requested without ``confirm: true``."""

    def __init__(self, action: str, consequence: str, **details: Any) -> None:
        super().__init__(
            "confirmation_required",
            stage="validate",
            hint=f"请先向用户确认：{consequence}。确认后在参数中传 confirm=true 再次调用。",
            retryable=False,
            action=action,
            **details,
        )


class ConnectionMissing(ToolFailure):
    """The supplied handle is unknown, stale, or belongs to a closed connection."""

    def __init__(self, handle: str | None = None) -> None:
        super().__init__(
            "connection_not_found",
            stage="lookup",
            hint="连接句柄已失效或不存在，请先调用 connect 重建连接。",
            retryable=True,
            connection_handle=handle,
        )


def validate_remote_path(path: str, field: str = "path") -> str:
    """Reject an unusable remote path before it reaches SFTP.

    One owner for the rule: ``tools/files.py``, the transfer engine, and command
    execution all funnel through here so the wording and ordering cannot drift.
    """
    if not path or not path.strip():
        raise ToolFailure("invalid_argument", stage="validate", hint=f"{field} 不能为空。", retryable=False)
    if "\x00" in path:
        raise ToolFailure("invalid_argument", stage="validate", hint=f"{field} 不能包含 NUL 字符。", retryable=False)
    return path
