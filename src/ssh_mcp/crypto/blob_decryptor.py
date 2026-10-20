"""Credential blob decryption.

Implements the contract in ``credential-api.md`` §3 exactly:

    key = HKDF-SHA256(IKM=token, salt=b"basic-server-ops/credential-blob/v1",
                      info=f"server/{server_id}", length=32)
    pt  = AES-256-GCM(key).decrypt(nonce, ciphertext,
                                   aad=f"basic-server-ops/credential/v1|server={server_id}")

The payload is bound to ``server_id`` by both the HKDF ``info`` and the GCM
``AAD``, so a blob cannot be replayed for another server. Any failure is
reported as ``decrypt_failed`` with no fallback, no partial plaintext, and no
echo of the blob or the token.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import ValidationError

from ssh_mcp.models import CredentialPayload

logger = logging.getLogger(__name__)

HKDF_SALT = b"basic-server-ops/credential-blob/v1"
AAD_TEMPLATE = "basic-server-ops/credential/v1|server={server_id}"
KEY_LENGTH = 32


class DecryptFailed(Exception):
    """The blob could not be decrypted or did not contain a usable payload."""

    def __init__(self, server_id: str) -> None:
        super().__init__("decrypt_failed")
        self.server_id = server_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": "decrypt_failed",
            "stage": "decrypt",
            "server_id": self.server_id,
            "hint": "加密负载无法解密，请检查 MCP 密钥是否有效或联系服务器管理服务重新签发",
            "retryable": False,
        }


def derive_key(token: str, server_id: str) -> bytes:
    """Derive the 32-byte AES key for one server from the MCP token."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=HKDF_SALT,
        info=f"server/{server_id}".encode(),
    ).derive(token.encode("utf-8"))


def _b64url_decode(value: str, field: str) -> bytes:
    """Decode unpadded base64url.

    The reference implementation appends ``"=="`` unconditionally; that happens
    to work because Python ignores excess padding, but a length that is already
    a multiple of four needs none. Padding is computed from the actual length
    here so both spellings decode.
    """
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    cleaned = value.strip()
    remainder = len(cleaned) % 4
    if remainder == 1:
        raise ValueError(f"{field} has an invalid base64url length")
    padded = cleaned + "=" * ((4 - remainder) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} is not valid base64url") from exc


def decrypt_blob(token: str, blob: dict[str, Any]) -> CredentialPayload:
    """Decrypt one ``blob`` object from the credential service.

    Raises :class:`DecryptFailed` for every failure mode. Callers translate that
    into the structured ``decrypt_failed`` tool result.
    """
    server_id = str(blob.get("server_id", ""))
    try:
        if not token:
            raise ValueError("missing token")
        if not server_id:
            raise ValueError("blob has no server_id")
        alg = str(blob.get("alg", "AES-256-GCM"))
        if alg != "AES-256-GCM":
            raise ValueError(f"unsupported cipher {alg}")
        kdf = str(blob.get("kdf", "HKDF-SHA256"))
        if kdf != "HKDF-SHA256":
            raise ValueError(f"unsupported kdf {kdf}")

        key = derive_key(token, server_id)
        nonce = _b64url_decode(blob["nonce"], "nonce")
        ciphertext = _b64url_decode(blob["ciphertext"], "ciphertext")
        aad = AAD_TEMPLATE.format(server_id=server_id).encode("utf-8")
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        data = json.loads(plaintext)
        if not isinstance(data, dict):
            raise ValueError("payload is not a JSON object")
        # The AAD already binds the blob to this server, but a payload whose
        # server_id disagrees means the service produced something inconsistent.
        if str(data.get("server_id", server_id)) != server_id:
            raise ValueError("payload server_id mismatch")
        payload = CredentialPayload.model_validate(data)
        payload.mcp_key_id = token_id(token)
        return payload
    except InvalidTag:
        # Wrong token, tampered ciphertext, or mismatched AAD: indistinguishable
        # by design, and deliberately reported without detail.
        logger.warning("credential blob for server %s failed authentication", server_id)
        raise DecryptFailed(server_id) from None
    except (KeyError, TypeError, ValueError, ValidationError, json.JSONDecodeError):
        logger.warning("credential blob for server %s could not be decoded", server_id)
        raise DecryptFailed(server_id) from None


def token_id(token: str) -> str:
    """Return a stable, non-reversible identifier for a token (for logs and keys)."""
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]
