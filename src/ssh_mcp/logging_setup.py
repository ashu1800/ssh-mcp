"""Logging that can never write to stdout and never echoes a secret.

stdio MCP transport owns stdout; a stray ``print`` or a naive log handler would
corrupt the JSON-RPC stream. Everything here goes to stderr, and every record
passes through :class:`RedactionFilter` before it is formatted.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Iterable

REDACTED = "[REDACTED]"

_SECRET_PATTERNS = (
    # MCP tokens issued by the credential service.
    re.compile(r"mcp_[A-Za-z0-9_\-]{16,}"),
    # PEM private key bodies, including OpenSSH's format.
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    # JSON-ish field echoes: "password": "...", "ciphertext": "...", "nonce": "..."
    re.compile(r'"(password|passphrase|ciphertext|nonce|private_key)"\s*:\s*"[^"]*"', re.IGNORECASE),
    # An ssh-ed25519 / ssh-rsa private key blob in base64 form.
    re.compile(r"b3BlbnNzaC1rZXktdjEAAAAA[A-Za-z0-9+/=]+"),
)

_NOISY_LOGGERS = {
    "asyncio": logging.WARNING,
    "asyncssh": logging.INFO,
    "httpx2": logging.WARNING,
    "httpcore2": logging.WARNING,
    "mcp": logging.INFO,
    "uvicorn": logging.WARNING,
    "uvicorn.error": logging.INFO,
    "uvicorn.access": logging.WARNING,
}


def redact(text: str) -> str:
    """Return ``text`` with anything that looks like a secret replaced."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


class RedactionFilter(logging.Filter):
    """Scrub secrets from the message and its arguments before formatting."""

    def __init__(self, extra_secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self._extra = tuple(s for s in extra_secrets if s and len(s) >= 8)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - a broken format string must not kill logging
            message = str(record.msg)
        for secret in self._extra:
            if secret in message:
                message = message.replace(secret, REDACTED)
        record.msg = redact(message)
        record.args = ()
        if record.exc_info:
            # Traceback text can embed locals when ``show_locals`` is on; rebuild
            # the exception summary from its type and message instead.
            exc_type, exc_value, _ = record.exc_info
            if exc_value is not None:
                record.exc_text = redact(f"{exc_type.__name__}: {exc_value}")
                record.exc_info = None
        return True


def configure_logging(level: str = "INFO", *, extra_secrets: Iterable[str] = (), force: bool = False) -> None:
    """Attach a stderr handler to the root logger.

    The MCP SDK installs its own stderr handler for the ``mcp`` logger; we do not
    remove or reconfigure it, only keep our own handler on the root logger so
    application records land on stderr too.
    """
    root = logging.getLogger()
    marker = "_ssh_mcp_handler"
    if not force and any(getattr(h, marker, False) for h in root.handlers):
        return
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactionFilter(extra_secrets))
    setattr(handler, marker, True)
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    for name, forced in _NOISY_LOGGERS.items():
        logging.getLogger(name).setLevel(max(forced, root.level))
