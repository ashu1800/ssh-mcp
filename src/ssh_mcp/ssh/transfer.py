"""SFTP transfer engine.

Both directions stream through a fixed-size buffer with baked-in resumability,
atomic commit, throttled progress, idle timeout, and size/hash verification.

Upload:

    local file --(1 MiB chunks)--> <remote>.part --(posix rename)--> <remote>

Download:

    <remote> --(1 MiB chunks)--> <local>.part --(os.replace)--> <local>

Failure keeps the ``.part`` file so a retry resumes; a *verification* failure
deletes it because the partial data is known to be wrong.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import shlex
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from ssh_mcp.config import PathNotAllowed, Settings
from ssh_mcp.errors import ToolFailure

logger = logging.getLogger(__name__)

ProgressFn = Callable[[int, int | None], Awaitable[None]]

HASH_CHUNK = 1024 * 1024


@dataclass
class TransferResult:
    direction: str
    local_path: str
    remote_path: str
    bytes_transferred: int
    resumed_from: int
    total_bytes: int
    verified: str
    duration_seconds: float
    hash_seconds: float | None = None
    remote_hash: str | None = None
    local_hash: str | None = None
    block_size: int = 0
    atomic: bool = True

    def to_dict(self) -> dict:
        payload = {
            "bytes_transferred": self.bytes_transferred,
            "resumed_from": self.resumed_from,
            "total_bytes": self.total_bytes,
            "local_path": self.local_path,
            "remote_path": self.remote_path,
            "verified": self.verified,
            "duration_seconds": round(self.duration_seconds, 3),
            "block_size": self.block_size,
            "atomic": self.atomic,
        }
        if self.hash_seconds is not None:
            payload["hash_seconds"] = round(self.hash_seconds, 3)
        if self.remote_hash:
            payload["remote_sha256"] = self.remote_hash
        if self.local_hash:
            payload["local_sha256"] = self.local_hash
        return payload


class _ProgressReporter:
    """Reports progress at most every 1% or 5 seconds, whichever comes first."""

    def __init__(self, callback: ProgressFn | None, total: int | None) -> None:
        self._callback = callback
        self._total = total
        self._last_bytes = 0
        self._last_report_at = 0.0
        self._last_pct = -1
        self._started = time.monotonic()
        self._last_sent = 0

    async def update(self, transferred: int) -> None:
        if self._callback is None:
            return
        now = time.monotonic()
        pct = int(transferred * 100 / self._total) if self._total else -1
        by_percent = self._total is not None and pct != self._last_pct
        by_time = (now - self._last_report_at) >= 5.0
        if not (by_percent or by_time):
            return
        if transferred <= self._last_sent:
            return
        elapsed = max(now - self._started, 1e-6)
        rate = transferred / elapsed
        message = f"{pct}% · {_human_bytes(transferred)}" if pct >= 0 else _human_bytes(transferred)
        message += f" · {_human_bytes(int(rate))}/s"
        try:
            await self._callback(transferred, self._total)
        except Exception:  # noqa: BLE001 - progress must never break a transfer
            logger.debug("progress callback failed", exc_info=True)
            self._callback = None
            return
        self._last_report_at = now
        self._last_pct = pct
        self._last_sent = transferred
        logger.debug("progress %s", message)

    async def finish(self, transferred: int) -> None:
        if self._callback is None or transferred <= self._last_sent:
            return
        try:
            await self._callback(transferred, self._total)
        except Exception:  # noqa: BLE001
            logger.debug("final progress callback failed", exc_info=True)


def _human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{value} B"


class SftpTransferEngine:
    """Streaming upload/download with resume, atomic commit, and verification."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    # -- upload ---------------------------------------------------------------

    async def upload(
        self,
        sftp: asyncssh.SFTPClient,
        local_path: Path,
        remote_path: str,
        *,
        overwrite: bool = False,
        resume: bool = True,
        verify: str = "size",
        create_parent_dirs: bool = False,
        progress: ProgressFn | None = None,
        conn: asyncssh.SSHClientConnection | None = None,
    ) -> TransferResult:
        started = time.monotonic()
        remote_path = _validate_remote_path(remote_path)
        if not local_path.is_file():
            raise ToolFailure(
                "local_file_missing",
                stage="prepare",
                hint=f"本地文件不存在：{local_path}",
                retryable=False,
                local_path=str(local_path),
            )
        source_size = local_path.stat().st_size
        part_path = remote_path + ".part"

        if not overwrite:
            exists = await _stat_exists(sftp, remote_path)
            if exists:
                raise ToolFailure(
                    "remote_exists",
                    stage="prepare",
                    hint=f"远端文件已存在：{remote_path}。如确认覆盖，请传 overwrite=true 与 confirm=true。",
                    retryable=False,
                    remote_path=remote_path,
                )
        if create_parent_dirs:
            parent = remote_path.rsplit("/", 1)[0] if "/" in remote_path else None
            if parent:
                await sftp.makedirs(parent, exist_ok=True)

        resumed_from, truncated_existing = await self._plan_resume(sftp, part_path, source_size, resume=resume)
        if truncated_existing:
            logger.info("discarding oversized partial upload %s", part_path)

        block_size = self._block_size(sftp)
        deadline = self._deadline()
        reporter = _ProgressReporter(progress, source_size)
        transferred = resumed_from
        await reporter.update(transferred)

        remote_handle = None
        local_handle = None
        try:
            mode = "r+b" if resumed_from else "wb"
            remote_handle = await self._open_with_fallback(sftp, part_path, mode, block_size)
            if resumed_from:
                await remote_handle.seek(resumed_from)
            local_handle = await asyncio.to_thread(open, local_path, "rb")
            if resumed_from:
                await asyncio.to_thread(local_handle.seek, resumed_from)

            while True:
                chunk = await asyncio.to_thread(local_handle.read, self._settings.sftp_buffer_size)
                if not chunk:
                    break
                await self._step(remote_handle.write(chunk), deadline)
                transferred += len(chunk)
                await reporter.update(transferred)
        except asyncio.CancelledError:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)
            logger.warning("upload of %s cancelled after %d bytes; .part kept for resume", remote_path, transferred)
            raise
        except ToolFailure:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)
            await self._delete_quietly(sftp, part_path)
            raise
        except BaseException as exc:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)
            raise self._transfer_error("upload", str(local_path), remote_path, transferred, source_size, exc) from None
        else:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)

        await reporter.finish(transferred)
        hash_seconds = None
        remote_hash = local_hash = None
        try:
            verified_ok = True
            if verify == "sha256":
                hash_started = time.monotonic()
                local_hash = await asyncio.to_thread(_sha256_file, local_path)
                remote_hash = await _sha256_remote(sftp, part_path, conn)
                hash_seconds = time.monotonic() - hash_started
                verified_ok = local_hash == remote_hash
            elif verify == "size":
                attrs = await sftp.stat(part_path)
                verified_ok = int(attrs.size or 0) == source_size
        except asyncssh.SFTPError as exc:
            await self._delete_quietly(sftp, part_path)
            raise self._transfer_error("upload", str(local_path), remote_path, transferred, source_size, exc) from None

        if not verified_ok:
            await self._delete_quietly(sftp, part_path)
            raise ToolFailure(
                "verification_failed",
                stage="verify",
                hint=f"上传校验失败（{verify} 不一致），已删除临时文件 {part_path}。",
                retryable=True,
                remote_path=remote_path,
                bytes_transferred=transferred,
                total_bytes=source_size,
                local_sha256=local_hash,
                remote_sha256=remote_hash,
            )

        atomic = await self._commit(sftp, part_path, remote_path, overwrite=overwrite)
        return TransferResult(
            direction="upload",
            local_path=str(local_path),
            remote_path=remote_path,
            bytes_transferred=transferred,
            resumed_from=resumed_from,
            total_bytes=source_size,
            verified=verify,
            duration_seconds=time.monotonic() - started,
            hash_seconds=hash_seconds,
            remote_hash=remote_hash,
            local_hash=local_hash,
            block_size=block_size,
            atomic=atomic,
        )

    # -- download -------------------------------------------------------------

    async def download(
        self,
        sftp: asyncssh.SFTPClient,
        remote_path: str,
        local_path: Path,
        *,
        overwrite: bool = False,
        resume: bool = True,
        verify: str = "size",
        progress: ProgressFn | None = None,
        conn: asyncssh.SSHClientConnection | None = None,
    ) -> TransferResult:
        started = time.monotonic()
        remote_path = _validate_remote_path(remote_path)
        if local_path.exists() and not overwrite:
            raise ToolFailure(
                "local_exists",
                stage="prepare",
                hint=f"本地文件已存在：{local_path}。如确认覆盖，请传 overwrite=true 与 confirm=true。",
                retryable=False,
                local_path=str(local_path),
            )
        await asyncio.to_thread(local_path.parent.mkdir, parents=True, exist_ok=True)
        try:
            attrs = await sftp.stat(remote_path)
        except asyncssh.SFTPNoSuchFile:
            raise ToolFailure(
                "remote_not_found",
                stage="prepare",
                hint=f"远端文件不存在：{remote_path}",
                retryable=False,
                remote_path=remote_path,
            ) from None
        if attrs.permissions is not None and attrs.type == asyncssh.FILEXFER_TYPE_DIRECTORY:
            raise ToolFailure(
                "remote_is_directory",
                stage="prepare",
                hint=f"远端路径是目录，不能用 download_file 下载：{remote_path}",
                retryable=False,
                remote_path=remote_path,
            )
        source_size = int(attrs.size or 0)
        part_path = local_path.with_name(local_path.name + ".part")

        resumed_from, truncated_existing = await self._plan_resume_local(part_path, source_size, resume=resume)
        if truncated_existing:
            logger.info("discarding oversized partial download %s", part_path)

        block_size = self._block_size(sftp)
        deadline = self._deadline()
        reporter = _ProgressReporter(progress, source_size)
        transferred = resumed_from

        remote_handle = None
        local_handle = None
        try:
            remote_handle = await self._open_with_fallback(sftp, remote_path, "rb", block_size)
            if resumed_from:
                await remote_handle.seek(resumed_from)
            local_handle = await asyncio.to_thread(open, part_path, "r+b" if resumed_from else "wb")
            if resumed_from:
                await asyncio.to_thread(local_handle.seek, resumed_from)
            await reporter.update(transferred)

            while True:
                chunk = await self._step(remote_handle.read(self._settings.sftp_buffer_size), deadline)
                if not chunk:
                    break
                await asyncio.to_thread(local_handle.write, chunk)
                transferred += len(chunk)
                await reporter.update(transferred)
        except asyncio.CancelledError:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)
            logger.warning("download of %s cancelled after %d bytes; .part kept for resume", remote_path, transferred)
            raise
        except ToolFailure:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)
            await self._delete_local_quietly(part_path)
            raise
        except BaseException as exc:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)
            raise self._transfer_error("download", str(local_path), remote_path, transferred, source_size, exc) from None
        else:
            await self._close_quietly(remote_handle)
            await self._close_local(local_handle)

        await reporter.finish(transferred)
        hash_seconds = None
        remote_hash = local_hash = None
        if verify == "sha256":
            hash_started = time.monotonic()
            local_hash = await asyncio.to_thread(_sha256_file, part_path)
            remote_hash = await _sha256_remote(sftp, remote_path, conn)
            hash_seconds = time.monotonic() - hash_started
            verified_ok = local_hash == remote_hash
        elif verify == "size":
            size = await asyncio.to_thread(lambda: part_path.stat().st_size)
            verified_ok = size == source_size and transferred == source_size
        else:
            verified_ok = True

        if not verified_ok:
            await self._delete_local_quietly(part_path)
            raise ToolFailure(
                "verification_failed",
                stage="verify",
                hint=f"下载校验失败（{verify} 不一致），已删除临时文件 {part_path}。",
                retryable=True,
                remote_path=remote_path,
                bytes_transferred=transferred,
                total_bytes=source_size,
                local_sha256=local_hash,
                remote_sha256=remote_hash,
            )

        await self._commit_local(part_path, local_path)
        return TransferResult(
            direction="download",
            local_path=str(local_path),
            remote_path=remote_path,
            bytes_transferred=transferred,
            resumed_from=resumed_from,
            total_bytes=source_size,
            verified=verify,
            duration_seconds=time.monotonic() - started,
            hash_seconds=hash_seconds,
            remote_hash=remote_hash,
            local_hash=local_hash,
            block_size=block_size,
            atomic=True,
        )

    # -- helpers --------------------------------------------------------------

    def _block_size(self, sftp: asyncssh.SFTPClient) -> int:
        configured = self._settings.sftp_block_size
        limits = getattr(sftp, "limits", None)
        if limits is None:
            return min(configured, self._settings.sftp_intolerant_block_size)
        server_max = min(limits.max_read_len or configured, limits.max_write_len or configured)
        return max(16 * 1024, min(configured, server_max))

    def _deadline(self) -> float | None:
        total = self._settings.sftp_total_timeout
        return None if not total else time.monotonic() + total

    async def _open_with_fallback(
        self, sftp: asyncssh.SFTPClient, path: str, mode: str, block_size: int
    ) -> asyncssh.SFTPClientFile:
        """Open a remote file, shrinking the block size if the server refuses large packets.

        ``block_size`` only sizes the request pipeline; the retry repeats the
        same ``mode`` on the same path, so nothing is opened twice concurrently.
        """
        attempt = block_size
        last_error: Exception | None = None
        while attempt >= 16 * 1024:
            try:
                return await sftp.open(
                    path, mode, encoding=None, block_size=attempt, max_requests=self._settings.sftp_max_requests
                )
            except (asyncssh.SFTPFailure, asyncssh.SFTPError) as exc:
                last_error = exc
                logger.info("SFTP open with block_size=%d failed (%s); retrying smaller", attempt, type(exc).__name__)
                attempt //= 2
        assert last_error is not None
        raise last_error

    async def _step(self, awaitable, deadline: float | None = None):
        """Await one I/O step under the idle timeout, and an optional total deadline."""
        allowed = self._settings.sftp_idle_timeout
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _TotalTimeout
            allowed = min(allowed, remaining)
        try:
            async with asyncio.timeout(allowed):
                return await awaitable
        except TimeoutError:
            if deadline is not None and time.monotonic() >= deadline:
                raise _TotalTimeout from None
            raise

    async def _plan_resume(self, sftp: asyncssh.SFTPClient, part_path: str, source_size: int, *, resume: bool) -> tuple[int, bool]:
        exists, size = await _stat_size(sftp, part_path)
        if not exists:
            return 0, False
        if not resume or size <= 0:
            await sftp.remove(part_path)
            return 0, False
        if size > source_size:
            await sftp.remove(part_path)
            return 0, True
        if size == source_size:
            # A complete .part from an interrupted commit: verify and promote.
            return size, False
        return size, False

    async def _plan_resume_local(self, part_path: Path, source_size: int, *, resume: bool) -> tuple[int, bool]:
        if not part_path.is_file():
            return 0, False
        size = await asyncio.to_thread(lambda: part_path.stat().st_size)
        if not resume or size <= 0:
            await asyncio.to_thread(part_path.unlink, True)
            return 0, False
        if size > source_size:
            await asyncio.to_thread(part_path.unlink, True)
            return 0, True
        return size, False

    async def _commit(self, sftp: asyncssh.SFTPClient, part_path: str, target: str, *, overwrite: bool) -> bool:
        """Atomically promote ``.part`` to its final name. Returns whether it was atomic."""
        try:
            await sftp.posix_rename(part_path, target)
            return True
        except asyncssh.SFTPError as exc:
            if not overwrite:
                await self._delete_quietly(sftp, part_path)
                raise ToolFailure(
                    "remote_exists",
                    stage="commit",
                    hint=f"目标文件在传输期间出现：{target}；已保留未覆盖。",
                    retryable=False,
                    remote_path=target,
                    detail=type(exc).__name__,
                ) from None
            logger.warning("posix-rename unavailable for %s; falling back to remove+rename", target)
            with contextlib.suppress(asyncssh.SFTPNoSuchFile):
                await sftp.remove(target)
            await sftp.rename(part_path, target)
            return False

    async def _commit_local(self, part_path: Path, target: Path) -> None:
        await asyncio.to_thread(os.replace, part_path, target)

    async def _delete_quietly(self, sftp: asyncssh.SFTPClient, path: str) -> None:
        with contextlib.suppress(Exception):
            await sftp.remove(path)

    async def _delete_local_quietly(self, path: Path) -> None:
        with contextlib.suppress(OSError):
            await asyncio.to_thread(path.unlink, True)

    @staticmethod
    async def _close_quietly(handle) -> None:
        if handle is None:
            return
        with contextlib.suppress(Exception):
            await handle.close()

    @staticmethod
    async def _close_local(handle) -> None:
        if handle is None:
            return
        with contextlib.suppress(Exception):
            await asyncio.to_thread(handle.close)

    def _transfer_error(
        self,
        direction: str,
        local_path: str,
        remote_path: str,
        transferred: int,
        total: int,
        exc: BaseException,
    ) -> ToolFailure:
        if isinstance(exc, _TotalTimeout):
            return ToolFailure(
                "transfer_total_timeout",
                stage=direction,
                hint=(
                    f"传输超过配置的总时长上限（{self._settings.sftp_total_timeout:.0f} 秒），已中止；"
                    "临时文件已保留，可使用 resume=true 续传或调大 SSH_MCP_SFTP_TOTAL_TIMEOUT。"
                ),
                retryable=True,
                local_path=local_path,
                remote_path=remote_path,
                bytes_transferred=transferred,
                total_bytes=total,
                resumable=True,
            )
        if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
            return ToolFailure(
                "transfer_idle_timeout",
                stage=direction,
                hint=(
                    f"连续 {self._settings.sftp_idle_timeout:.0f} 秒没有收到数据，已中止传输；"
                    "临时文件已保留，可使用 resume=true 续传。"
                ),
                retryable=True,
                local_path=local_path,
                remote_path=remote_path,
                bytes_transferred=transferred,
                total_bytes=total,
                resumable=True,
            )
        logger.warning("%s failed after %d bytes: %s", direction, transferred, type(exc).__name__)
        return ToolFailure(
            "transfer_failed",
            stage=direction,
            hint=f"传输过程中断（{type(exc).__name__}）；临时文件已保留，可使用 resume=true 续传。",
            retryable=True,
            local_path=local_path,
            remote_path=remote_path,
            bytes_transferred=transferred,
            total_bytes=total,
            resumable=True,
        )


class _TotalTimeout(Exception):
    """The configured total transfer budget was exhausted."""


# -- module helpers -----------------------------------------------------------


def _validate_remote_path(path: str) -> str:
    if not path or not path.strip():
        raise ToolFailure("invalid_argument", stage="validate", hint="远端路径不能为空。", retryable=False)
    if "\x00" in path:
        raise ToolFailure("invalid_argument", stage="validate", hint="远端路径不能包含 NUL 字符。", retryable=False)
    return path


async def _stat_exists(sftp: asyncssh.SFTPClient, path: str) -> bool:
    try:
        await sftp.stat(path)
        return True
    except asyncssh.SFTPNoSuchFile:
        return False
    except asyncssh.SFTPError:
        return False


async def _stat_size(sftp: asyncssh.SFTPClient, path: str) -> tuple[bool, int]:
    try:
        attrs = await sftp.stat(path)
        return True, int(attrs.size or 0)
    except asyncssh.SFTPNoSuchFile:
        return False, 0
    except asyncssh.SFTPError:
        return False, 0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


async def _sha256_remote(
    sftp: asyncssh.SFTPClient, path: str, conn: asyncssh.SSHClientConnection | None = None
) -> str:
    """Hash a remote file.

    Prefers the server's own ``sha256sum`` (one round trip, no payload transfer);
    falls back to reading the file over SFTP when the command is unavailable.
    """
    if conn is not None:
        digest = await _sha256_remote_command(conn, path)
        if digest is not None:
            return digest
    return await _sha256_remote_sftp(sftp, path)


async def _sha256_remote_command(conn: asyncssh.SSHClientConnection, path: str) -> str | None:
    """Run ``sha256sum`` (or ``shasum -a 256`` on BSD/macOS) on the remote."""
    quoted = shlex.quote(path)
    for command in (f"sha256sum -- {quoted}", f"shasum -a 256 -- {quoted}"):
        try:
            async with asyncio.timeout(300):
                result = await conn.run(command, check=False)
        except (asyncssh.Error, OSError, TimeoutError):
            continue
        if result.exit_status == 0 and result.stdout:
            digest = str(result.stdout).strip().split()[0].lower()
            if len(digest) == 64 and all(c in "0123456789abcdef" for c in digest):
                return digest
    return None


async def _sha256_remote_sftp(sftp: asyncssh.SFTPClient, path: str) -> str:
    digest = hashlib.sha256()
    # A dedicated handle with a large block size keeps the fallback from being
    # slower than the transfer it is verifying.
    async with sftp.open(path, "rb", encoding=None, block_size=1024 * 1024, max_requests=32) as handle:
        while True:
            chunk = await handle.read(HASH_CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def resolve_local_target(settings: Settings, raw: str) -> Path:
    """Allowlist-checked local path for a transfer target."""
    try:
        return settings.resolve_local_path(raw)
    except PathNotAllowed as exc:
        raise ToolFailure(
            "path_not_allowed",
            stage="validate",
            hint=exc.reason,
            retryable=False,
            local_path=raw,
            allowed_roots=[str(p) for p in settings.allowed_local_roots],
        ) from None
