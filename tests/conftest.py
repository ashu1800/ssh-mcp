"""Shared fixtures: temp state, a local SSH server, and a fake credential service."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import asyncssh
import httpx2
import pytest
import pytest_asyncio

from ssh_mcp.config import Settings
from ssh_mcp.credentials.client import CredentialClient
from ssh_mcp.ssh.auth_state import AuthStateStore
from ssh_mcp.ssh.connector import Connector
from ssh_mcp.ssh.keys import KeyStore
from ssh_mcp.ssh.known_hosts import KnownHostsStore
from ssh_mcp.ssh.pool import ConnectionPool
from ssh_mcp.ssh.transfer import SftpTransferEngine

from tests import fake_ssh_server

TOKEN = "mcp_testtoken_0123456789abcdefghij"
PASSWORD = "test-password"
USERNAME = "testuser"


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    path = tmp_path / "state"
    path.mkdir()
    return path


@pytest.fixture
def settings(state_dir: Path, tmp_path: Path) -> Settings:
    roots = tmp_path / "local"
    roots.mkdir()
    return Settings(
        mcp_key=TOKEN,
        state_dir=state_dir,
        allowed_local_roots=[roots],
        connect_timeout=5.0,
        login_timeout=5.0,
        keepalive_interval=0.0,
        pool_idle_timeout=60.0,
        pool_reaper_interval=3600.0,
        sftp_block_size=64 * 1024,
        sftp_max_requests=8,
        sftp_buffer_size=128 * 1024,
        sftp_idle_timeout=10.0,
        sftp_concurrency=2,
        command_timeout_default=10.0,
    )


@pytest_asyncio.fixture
async def ssh_server(tmp_path: Path):
    handle = await fake_ssh_server.start_server(tmp_path)
    try:
        yield handle
    finally:
        await handle.close()


@pytest.fixture
def credential_payload(ssh_server):
    from ssh_mcp.models import CredentialPayload

    return CredentialPayload(
        server_id="1",
        alias="fake",
        host="127.0.0.1",
        port=ssh_server.port,
        username=USERNAME,
        password=PASSWORD,
    )


@pytest_asyncio.fixture
async def connector(settings: Settings):
    known_hosts = KnownHostsStore(settings.known_hosts_path)
    auth_state = AuthStateStore(settings.auth_state_path)
    key_store = KeyStore(settings.keys_dir)
    return Connector(settings, known_hosts, auth_state, key_store)


@pytest_asyncio.fixture
async def pool(settings: Settings):
    known_hosts = KnownHostsStore(settings.known_hosts_path)
    auth_state = AuthStateStore(settings.auth_state_path)
    key_store = KeyStore(settings.keys_dir)
    connector = Connector(settings, known_hosts, auth_state, key_store)
    instance = ConnectionPool(settings, connector)
    instance.start_reaper()
    try:
        yield instance
    finally:
        await instance.aclose()


@pytest.fixture
def engine(settings: Settings) -> SftpTransferEngine:
    return SftpTransferEngine(settings)


# -- fake credential service --------------------------------------------------


def build_credential_blob(token: str, payload: dict) -> dict:
    """Encrypt ``payload`` the way the real service does (for tests)."""
    import base64
    import json as _json

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    server_id = payload["server_id"]
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"basic-server-ops/credential-blob/v1",
        info=f"server/{server_id}".encode(),
    ).derive(token.encode())
    nonce = b"0123456789ab"
    aad = f"basic-server-ops/credential/v1|server={server_id}".encode()
    ciphertext = AESGCM(key).encrypt(nonce, _json.dumps(payload).encode(), aad)

    def enc(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    return {
        "version": 1,
        "server_id": server_id,
        "ref": f"cred-{server_id}-v1",
        "alg": "AES-256-GCM",
        "kdf": "HKDF-SHA256",
        "nonce": enc(nonce),
        "ciphertext": enc(ciphertext),
        "issued_at": 0,
    }


class FakeCredentialService:
    """In-process HTTP handler that mimics ``GET /api/mcp/credentials``."""

    def __init__(self, servers: list[dict], token: str = TOKEN) -> None:
        self._servers = servers
        self._token = token
        self.requests = 0
        self.fail_next = 0
        self.status_override: int | None = None

    def handler(self, request: httpx2.Request) -> httpx2.Response:
        self.requests += 1
        if self.fail_next > 0:
            self.fail_next -= 1
            return httpx2.Response(503, text="<html>unavailable</html>")
        if self.status_override is not None:
            code = self.status_override
            if code == 401:
                return httpx2.Response(401, text="no bearer token")
            if code == 403:
                return httpx2.Response(403, json={"code": 403, "message": "missing scope", "data": None})
            return httpx2.Response(code, json={"code": code, "message": "error", "data": None})
        auth = request.headers.get("authorization", "")
        if auth != f"Bearer {self._token}":
            return httpx2.Response(401, text="no bearer token")
        body = {
            "code": 200,
            "message": "success",
            "data": {"servers": self._servers, "total": len(self._servers), "crypto": {"version": 1}},
        }
        return httpx2.Response(200, json=body)


@pytest.fixture
def fake_service(ssh_server):
    servers = [
        {
            "server_id": 1,
            "alias": "fake-1",
            "encrypted_blob_ref": "cred-1-v1",
            "auth_type": "password",
            "group_name": "tests",
            "blob": build_credential_blob(
                TOKEN,
                {
                    "version": 1,
                    "server_id": 1,
                    "alias": "fake-1",
                    "host": "127.0.0.1",
                    "port": ssh_server.port,
                    "username": USERNAME,
                    "auth": {"type": "password"},
                    "password": PASSWORD,
                },
            ),
        }
    ]
    return FakeCredentialService(servers)


@pytest.fixture
def credential_client(settings: Settings, fake_service: FakeCredentialService):
    transport = httpx2.MockTransport(fake_service.handler)
    client = CredentialClient(settings, transport=transport)
    yield client


@pytest.fixture
def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
