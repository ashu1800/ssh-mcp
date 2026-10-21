"""Structured error contract shared by every tool.

Tools never raise an MCP protocol error for an expected failure: they return
``CallToolResult(is_error=True)`` whose JSON body carries at least ``error``,
``stage``, ``hint`` and ``retryable``. The AI client can therefore branch on a
stable code instead of parsing prose, and a stack trace never reaches the wire.
"""

from __future__ import annotations

from typing import Any

# Machine-readable next steps, so a client can branch without parsing ``hint``.
# Values are a small closed vocabulary rather than free text.
NextAction = str

NEXT_ACTION_HINTS: dict[str, NextAction] = {
    "invalid_argument": "fix_arguments",
    "confirmation_required": "ask_user_then_retry_with_confirm",
    "connection_not_found": "call_connect",
    "connection_lost": "reconnect",
    "server_not_found": "call_list_servers",
    "path_not_allowed": "fix_arguments_or_change_config",
    "interactive_command_rejected": "rewrite_as_batch_command",
    "command_timeout": "narrow_the_command_or_raise_timeout",
    "auth_failed": "check_credentials_in_management_console",
    "auth_failed_publickey": "retry_with_password",
    "host_key_mismatch": "verify_host_then_clear_known_hosts",
    "credentials_unavailable": "retry_later",
    "mcp_key_invalid": "reissue_mcp_key",
    "mcp_key_forbidden": "reissue_mcp_key_with_scopes",
    "service_not_found": "call_list_services",
    "log_unavailable": "fix_arguments",
}
# Any retryable failure without a specific entry can always be retried.
DEFAULT_RETRYABLE_ACTION = "retry"


class ToolFailure(Exception):
    """An anticipated, structured tool failure."""

    def __init__(
        self,
        error: str,
        *,
        stage: str,
        hint: str,
        retryable: bool = False,
        next_actions: list[str] | None = None,
        **details: Any,
    ) -> None:
        super().__init__(hint)
        self.error = error
        self.stage = stage
        self.hint = hint
        self.retryable = retryable
        self.details = details
        if next_actions is not None:
            self.next_actions = list(next_actions)
        else:
            suggested = NEXT_ACTION_HINTS.get(error)
            if suggested is not None:
                self.next_actions = [suggested]
            elif retryable:
                self.next_actions = [DEFAULT_RETRYABLE_ACTION]
            else:
                self.next_actions = []

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error": self.error,
            "stage": self.stage,
            "hint": self.hint,
            "retryable": self.retryable,
            "next_actions": self.next_actions,
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
        hint = (
            "还没有建立过连接，请先调用 connect（之后可省略 connection_handle）。"
            if handle is None
            else "连接句柄已失效或不存在，请先调用 connect 重建连接。"
        )
        super().__init__(
            "connection_not_found",
            stage="lookup",
            hint=hint,
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
