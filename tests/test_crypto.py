"""Credential decryption contract tests."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ssh_mcp.crypto.blob_decryptor import DecryptFailed, decrypt_blob, derive_key
from tests.conftest import TOKEN
from tests.conftest import build_credential_blob

PAYLOAD = {
    "version": 1,
    "server_id": 7,
    "alias": "prod",
    "host": "10.0.0.7",
    "port": 2222,
    "username": "root",
    "auth": {"type": "password"},
    "password": "s3cr3t-password",
}


def test_decrypts_documented_payload():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    payload = decrypt_blob(TOKEN, blob)
    assert payload.host == "10.0.0.7"
    assert payload.port == 2222
    assert payload.username == "root"
    assert payload.password == "s3cr3t-password"
    assert payload.key == ("10.0.0.7", 2222, "root")


def test_key_derivation_matches_reference_implementation():
    server_id = "7"
    expected = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"basic-server-ops/credential-blob/v1", info=b"server/7"
    ).derive(TOKEN.encode())
    assert derive_key(TOKEN, server_id) == expected


def test_repr_never_contains_secrets():
    payload = decrypt_blob(TOKEN, build_credential_blob(TOKEN, PAYLOAD))
    text = repr(payload)
    assert "s3cr3t-password" not in text
    assert "10.0.0.7" in text
    assert payload.password not in json.dumps(payload.redacted_summary())


def test_tampered_ciphertext_is_rejected():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    raw = bytearray(base64.urlsafe_b64decode(blob["ciphertext"] + "=="))
    raw[3] ^= 0x01
    blob["ciphertext"] = base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")
    with pytest.raises(DecryptFailed) as excinfo:
        decrypt_blob(TOKEN, blob)
    assert excinfo.value.to_dict()["error"] == "decrypt_failed"


def test_blob_for_another_server_is_rejected():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    blob["server_id"] = 8  # AAD and HKDF info now disagree with the ciphertext
    with pytest.raises(DecryptFailed):
        decrypt_blob(TOKEN, blob)


def test_wrong_token_is_rejected():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    with pytest.raises(DecryptFailed):
        decrypt_blob("mcp_othertoken_0123456789abcdefgh", blob)


def test_missing_token_is_rejected():
    with pytest.raises(DecryptFailed):
        decrypt_blob("", build_credential_blob(TOKEN, PAYLOAD))


def test_unsupported_algorithm_is_rejected():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    blob["alg"] = "AES-128-CBC"
    with pytest.raises(DecryptFailed):
        decrypt_blob(TOKEN, blob)


def test_non_json_plaintext_is_rejected():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    key = derive_key(TOKEN, "7")
    nonce = base64.urlsafe_b64decode(blob["nonce"] + "==")
    aad = b"basic-server-ops/credential/v1|server=7"
    blob["ciphertext"] = (
        base64.urlsafe_b64encode(AESGCM(key).encrypt(nonce, b"not json", aad)).decode().rstrip("=")
    )
    with pytest.raises(DecryptFailed):
        decrypt_blob(TOKEN, blob)


def test_error_body_carries_no_blob_material():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    blob["ciphertext"] = blob["ciphertext"][:-4] + "AAAA"
    with pytest.raises(DecryptFailed) as excinfo:
        decrypt_blob(TOKEN, blob)
    rendered = json.dumps(excinfo.value.to_dict())
    assert blob["ciphertext"] not in rendered
    assert TOKEN not in rendered
    assert str(excinfo.value) == "decrypt_failed"


def test_unpadded_and_padded_base64_both_decode():
    blob = build_credential_blob(TOKEN, PAYLOAD)
    padded = dict(blob)
    padded["nonce"] = blob["nonce"] + "=" * ((4 - len(blob["nonce"]) % 4) % 4)
    payload = decrypt_blob(TOKEN, padded)
    assert payload.server_id == 7
