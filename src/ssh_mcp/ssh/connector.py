"""Connection establishment: host-key pinning plus the authentication state machine.

For each ``(host, port, username)`` target:

* ``KEY_READY``        -> publickey only; a successful connect reports ``publickey``.
* ``UNKNOWN`` / ``PASSWORD_FALLBACK`` -> password auth. On success a local
  Ed25519 key is generated (if absent) and its public half is installed into the
  remote ``authorized_keys``, then a *separate* connection proves that the key
  works. Only then does the target become ``KEY_READY``.
* A key refusal (``Permission denied (publickey)``) marks the key invalid -- it is
  kept on disk for audit -- and falls back to password with an explicit warning.

Host keys are checked against the pin store before authentication; an unknown
host is pinned after a successful connect (TOFU), a changed key is refused.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import asyncssh

from ssh_mcp.config import Settings
from ssh_mcp.errors import ToolFailure
from ssh_mcp.models import CredentialPayload
from ssh_mcp.ssh.auth_state import AuthState, AuthStateStore
from ssh_mcp.ssh.keys import KeyStore, public_key_line
from ssh_mcp.ssh.sftp_ops import replace_file
from ssh_mcp.ssh.known_hosts import HostKeyStoreError, KnownHostsStore

logger = logging.getLogger(__name__)


class ConnectFailure(ToolFailure):
    """Structured connection failure; already a tool error, so the pool re-raises it as-is."""

    def __init__(self, error: str, hint: str, *, stage: str, retryable: bool = False, **details) -> None:
        super().__init__(error, stage=stage, hint=hint, retryable=retryable, **details)


@dataclass
class ConnectResult:
    conn: asyncssh.SSHClientConnection
    auth_method: str
    warning: str | None = None
    compression: str = "none"


class Connector:
    """Builds authenticated connections for one target at a time."""

    def __init__(
        self,
        settings: Settings,
        known_hosts: KnownHostsStore,
        auth_state: AuthStateStore,
        key_store: KeyStore,
    ) -> None:
        self._settings = settings
        self._known_hosts = known_hosts
        self._auth_state = auth_state
        self._keys = key_store

    # -- public ---------------------------------------------------------------

    async def connect(self, payload: CredentialPayload, *, timeout: float | None = None) -> ConnectResult:
        record = self._auth_state.get(*payload.key)
        compression_choice = self._compression()
        warning: str | None = None
        key_rejected = False

        if payload.auth.type == "private_key":
            return await self._connect_with_service_key(payload, compression_choice, timeout)

        local_key = self._keys.load(*payload.key)
        if record.state is AuthState.KEY_READY and local_key is not None:
            try:
                conn = await self._open(
                    payload,
                    client_keys=[local_key],
                    preferred_auth="publickey",
                    compression=compression_choice,
                    timeout=timeout,
                )
                await self._auth_state.set_state(*payload.key, AuthState.KEY_READY, auth_method="publickey")
                return ConnectResult(conn=conn, auth_method="publickey", compression=compression_choice)
            except ConnectFailure as exc:
                if exc.error != "auth_failed_publickey":
                    raise
                key_rejected = True
                await self._auth_state.mark_key_invalid(*payload.key)
                logger.warning(
                    "public key refused by %s@%s:%s; falling back to password", payload.username, payload.host, payload.port
                )

        # Password phase (UNKNOWN, PASSWORD_FALLBACK, just-rejected, or key file missing).
        password = payload.password
        if payload.auth.type == "password" and not password:
            raise ConnectFailure(
                "credential_incomplete",
                "该服务器未下发密码，无法建立连接；请联系服务器管理服务补充凭据。",
                stage="auth",
                server_id=str(payload.server_id),
            )
        conn = await self._open(
            payload, client_keys=None, preferred_auth="password", compression=compression_choice, timeout=timeout
        )

        # --- key provisioning -------------------------------------------------
        key = local_key or self._keys.create(
            payload.host, payload.port, payload.username, comment=f"ssh-mcp@{self._hostname()}"
        )
        install_note: str | None = None
        try:
            install_note = await self._install_public_key(conn, key)
        except Exception as exc:  # noqa: BLE001 - provisioning must never fail the connect
            logger.warning("could not install the local public key on %s: %s", payload.host, type(exc).__name__)
            install_note = f"写入远端 authorized_keys 失败：{type(exc).__name__}"

        verified, verify_error = await self._verify_key_login(payload, key, compression_choice, timeout)
        if verified:
            await self._auth_state.set_state(*payload.key, AuthState.KEY_READY, auth_method="password")
            auth_method = "password"
            if key_rejected:
                warning = (
                    "原公钥已被远端拒绝，已标记失效并改用密码登录；新公钥写入验证成功，下次连接将使用公钥。"
                )
            return ConnectResult(
                conn=conn,
                auth_method=auth_method,
                warning=warning or install_note,
                compression=compression_choice,
            )

        if verify_error == "auth_failed_publickey":
            # The key itself was refused: stop offering it.
            await self._auth_state.mark_key_invalid(*payload.key)
            warning = (
                "密码登录成功，但新生成的公钥未能通过验证，已保持 PASSWORD_FALLBACK；"
                "后续连接仍会使用密码。"
            )
        else:
            # A network/host-key failure says nothing about the key. Keep the
            # state as it was so the next attempt can still try the key, and
            # surface the real reason instead of blaming the key.
            warning = (
                f"密码登录成功，但用于验证新公钥的独立连接失败（{verify_error}）；"
                "未改动密钥状态，下次连接会继续尝试。"
            )
        if install_note:
            warning += f" （{install_note}）"
        return ConnectResult(
            conn=conn,
            auth_method="password",
            warning=warning,
            compression=compression_choice,
        )

    # -- internals ------------------------------------------------------------

    def _compression(self) -> str:
        """Compression is negotiated per connection, and the connection is
        established before any file is known, so this is purely the setting.
        ``auto`` therefore means ``on`` (zlib), matching the README."""
        return "none" if self._settings.compression_mode == "off" else "zlib"

    def _base_kwargs(self, payload: CredentialPayload, compression: str, timeout: float | None = None) -> dict:
        try:
            pinned = self._known_hosts.pinned_store(payload.host, None, payload.port)
        except HostKeyStoreError as exc:
            raise ConnectFailure(
                "known_hosts_unreadable", str(exc), stage="host_key", retryable=False, host=payload.host
            ) from None

        kwargs: dict = {
            "host": payload.host,
            "port": payload.port,
            "username": payload.username,
            "connect_timeout": timeout or self._settings.connect_timeout,
            "login_timeout": timeout or self._settings.login_timeout,
            "keepalive_interval": self._settings.keepalive_interval,
            "keepalive_count_max": self._settings.keepalive_count_max,
            # Never consult ~/.ssh/config: IdentityFile/ProxyJump there would
            # change authentication semantics behind the user's back.
            "config": None,
            # An explicit ssh-agent would let unrelated keys try first.
            "agent_path": None,
        }
        if compression == "none":
            kwargs["compression_algs"] = None
        # ``known_hosts`` must be passed explicitly either way: leaving it out
        # makes AsyncSSH fall back to ``~/.ssh/known_hosts`` (an empty string
        # when absent), which turns its strict check on and rejects every key.
        #  - pinned   -> hand AsyncSSH the expected keys (it enforces the match)
        #  - unpinned -> None disables that check; the TOFU pin in ``trust`` is
        #                recorded right after the handshake and enforced from
        #                the next connection on.
        kwargs["known_hosts"] = pinned or None
        return kwargs

    async def _open(
        self,
        payload: CredentialPayload,
        *,
        client_keys: list[asyncssh.SSHKey] | None,
        preferred_auth: str,
        compression: str,
        timeout: float | None = None,
    ) -> asyncssh.SSHClientConnection:
        kwargs = self._base_kwargs(payload, compression, timeout)
        kwargs["client_keys"] = client_keys
        kwargs["preferred_auth"] = preferred_auth
        if preferred_auth == "password":
            password = payload.password
            if not password:
                raise ConnectFailure(
                    "credential_incomplete",
                    "该服务器下发的凭据中没有密码，无法进行密码认证。",
                    stage="auth",
                    retryable=False,
                )
            kwargs["password"] = password
        try:
            conn = await asyncssh.connect(**kwargs)
        except asyncssh.HostKeyNotVerifiable as exc:
            raise ConnectFailure(
                "host_key_mismatch",
                "服务器主机密钥与本地记录的指纹不一致，已拒绝连接。请确认服务器是否被重装或存在中间人攻击；"
                "确认可信后可删除 known_hosts 中对应条目重新信任。",
                stage="host_key",
                retryable=False,
                host=payload.host,
                port=payload.port,
                detail=str(exc),
            ) from None
        except asyncssh.PermissionDenied as exc:
            if preferred_auth == "publickey":
                raise ConnectFailure(
                    "auth_failed_publickey",
                    "公钥认证被拒绝",
                    stage="publickey",
                    retryable=False,
                    host=payload.host,
                ) from None
            raise ConnectFailure(
                "auth_failed",
                "密码认证失败，请确认服务器管理服务中的账号密码是否正确。",
                stage="password",
                retryable=False,
                host=payload.host,
                detail=str(exc),
            ) from None
        except (TimeoutError, OSError) as exc:
            raise ConnectFailure(
                "connect_timeout",
                f"连接 {payload.host}:{payload.port} 超时或网络不可达。",
                stage="tcp",
                retryable=True,
                host=payload.host,
                port=payload.port,
                detail=type(exc).__name__,
            ) from None
        except asyncssh.Error as exc:
            raise ConnectFailure(
                "connect_failed",
                f"建立 SSH 连接失败：{type(exc).__name__}。",
                stage="handshake",
                retryable=True,
                host=payload.host,
                detail=str(exc),
            ) from None

        # TOFU: record the host key now that the peer proved possession of it.
        host_key = conn.get_server_host_key()
        if host_key is not None:
            try:
                await self._known_hosts.trust(payload.host, payload.port, host_key)
            except Exception as exc:  # noqa: BLE001
                logger.warning("could not pin host key for %s: %s", payload.host, type(exc).__name__)
        return conn

    async def _connect_with_service_key(
        self, payload: CredentialPayload, compression: str, timeout: float | None = None
    ) -> ConnectResult:
        try:
            key = asyncssh.import_private_key(payload.auth.private_key, passphrase=payload.auth.passphrase or None)
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise ConnectFailure(
                "private_key_invalid",
                "服务器管理服务下发的私钥无法导入（可能口令错误或格式不受支持）。",
                stage="auth",
                retryable=False,
                detail=type(exc).__name__,
            ) from None
        try:
            conn = await self._open(
                payload, client_keys=[key], preferred_auth="publickey", compression=compression, timeout=timeout
            )
        except ConnectFailure as exc:
            if exc.error == "auth_failed_publickey":
                raise ConnectFailure(
                    "auth_failed",
                    "服务器拒绝了下发的私钥，且该服务器没有可回退的密码。" ,
                    stage="publickey",
                    retryable=False,
                    host=payload.host,
                ) from None
            raise
        await self._auth_state.set_state(*payload.key, AuthState.KEY_READY, auth_method="publickey")
        return ConnectResult(conn=conn, auth_method="publickey", compression=compression)

    async def _install_public_key(self, conn: asyncssh.SSHClientConnection, key: asyncssh.SSHKey) -> str:
        """Append the public key to the remote authorized_keys over SFTP.

        Writing through SFTP keeps the install independent of the remote login
        shell, quoting rules, and whether a home directory shortcut exists.
        Returns a short human-readable note for the connect result.
        """
        line = public_key_line(key)
        sftp = await conn.start_sftp_client()
        try:
            home = await sftp.realpath(".")
            if isinstance(home, bytes):
                home = home.decode("utf-8")
            ssh_dir = f"{home.rstrip('/')}/.ssh"
            auth_path = f"{ssh_dir}/authorized_keys"
            try:
                await sftp.makedirs(ssh_dir, exist_ok=True)
            except asyncssh.SFTPError:
                pass
            await sftp.chmod(ssh_dir, 0o700)

            existing = ""
            try:
                attrs = await sftp.stat(auth_path)
                if attrs.size and attrs.size > 4 * 1024 * 1024:
                    raise asyncssh.SFTPFailure("authorized_keys is unexpectedly large")
                async with sftp.open(auth_path, "rb") as handle:
                    existing = (await handle.read()).decode("utf-8", "replace")
            except asyncssh.SFTPNoSuchFile:
                existing = ""

            if line in existing:
                return "公钥已存在于远端 authorized_keys"

            updated = existing
            if updated and not updated.endswith("\n"):
                updated += "\n"
            updated += line + "\n"

            tmp_path = f"{auth_path}.ssh-mcp.tmp"
            async with sftp.open(tmp_path, "wb") as handle:
                await handle.write(updated.encode("utf-8"))
            await sftp.chmod(tmp_path, 0o600)
            await replace_file(sftp, tmp_path, auth_path)
            await sftp.chmod(auth_path, 0o600)
            logger.info("installed local public key into %s", auth_path)
            return "已将新公钥写入远端 authorized_keys"
        finally:
            sftp.exit()
            await sftp.wait_closed()

    async def _verify_key_login(
        self, payload: CredentialPayload, key: asyncssh.SSHKey, compression: str, timeout: float | None = None
    ) -> tuple[bool, str]:
        """Prove the newly installed key works on a fresh connection.

        Returns ``(verified, error)`` where ``error`` names why verification
        failed: only ``auth_failed_publickey`` means the key itself was refused;
        host-key and connectivity failures must not be read as a bad key.
        """
        try:
            conn = await self._open(
                payload, client_keys=[key], preferred_auth="publickey", compression=compression, timeout=timeout
            )
        except ConnectFailure as exc:
            logger.warning("public key verification failed for %s: %s", payload.host, exc.error)
            return False, exc.error
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "public key verification failed for %s: %s: %s", payload.host, type(exc).__name__, exc, exc_info=True
            )
            return False, type(exc).__name__
        conn.close()
        return True, ""

    @staticmethod
    def _hostname() -> str:
        import socket

        try:
            return socket.gethostname() or "ssh-mcp"
        except OSError:  # pragma: no cover
            return "ssh-mcp"
