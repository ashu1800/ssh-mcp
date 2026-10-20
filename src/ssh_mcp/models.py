"""Data models shared across the server.

:class:`CredentialPayload` holds the decrypted connection details and is the one
object that must never be logged, echoed, or serialised. Its ``repr`` and
``str`` are overridden so an accidental ``log.info("%s", payload)`` prints no
secret, and the secret fields are excluded from ``model_dump`` output by
default.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ServerSummary(BaseModel):
    """One row of ``list_servers`` -- no connection details."""

    server_id: str
    alias: str
    encrypted_blob_ref: str
    auth_type: str | None = None
    group_name: str | None = None


class AuthInfo(BaseModel):
    model_config = ConfigDict(extra="allow")

    type: Literal["password", "private_key"] = "password"
    private_key: str | None = Field(default=None, repr=False, exclude=True)
    passphrase: str | None = Field(default=None, repr=False, exclude=True)


class CredentialPayload(BaseModel):
    """Decrypted connection information for one server.

    ``password`` and ``auth``'s key material are excluded from serialisation;
    everything else is safe to show in a redacted summary.
    """

    model_config = ConfigDict(extra="ignore")

    version: int = 1
    server_id: int | str
    alias: str | None = None
    host: str
    port: int = 22
    username: str
    auth: AuthInfo = Field(default_factory=AuthInfo)
    password: str | None = Field(default=None, repr=False, exclude=True)
    mcp_key_id: str | None = Field(default=None, exclude=True)

    def __repr__(self) -> str:
        return (
            f"CredentialPayload(server_id={self.server_id!r}, host={self.host!r}, "
            f"port={self.port!r}, username={self.username!r}, auth_type={self.auth.type!r})"
        )

    __str__ = __repr__

    @property
    def key(self) -> tuple[str, int, str]:
        """Connection-pool identity: (host, port, username)."""
        return (self.host, self.port, self.username)

    @property
    def auth_method(self) -> str:
        return "private_key" if self.auth.type == "private_key" else "password"

    def redacted_summary(self) -> dict[str, Any]:
        """Fields safe to return to an AI client."""
        summary: dict[str, Any] = {
            "server_id": self.server_id,
            "alias": self.alias,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "auth_type": self.auth.type,
        }
        if self.mcp_key_id:
            summary["mcp_key_id"] = self.mcp_key_id
        return summary
