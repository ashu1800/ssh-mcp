"""SFTP transfer tools (single file and batch)."""

from __future__ import annotations

import logging
from typing import Annotated, Literal

import anyio
from mcp.server.mcpserver import Context
from mcp.types import CallToolResult
from pydantic import BaseModel, Field

from ssh_mcp.errors import ConfirmationRequired, ToolFailure
from ssh_mcp.ssh.pool import ConnectionPool, borrow
from ssh_mcp.ssh.transfer import SftpTransferEngine, resolve_local_target
from ssh_mcp.tools.helpers import tool_err, tool_ok

logger = logging.getLogger(__name__)


class FilePair(BaseModel):
    local_path: str = Field(description="本地文件路径（MCP 所在机器）。若服务端配置了允许根目录，则必须位于其内。")
    remote_path: str = Field(description="远端文件路径（POSIX 风格绝对路径）。")


class TransferTools:
    """Registers ``upload_file`` / ``download_file`` / ``upload_files`` / ``download_files``."""

    def __init__(self, app, pool: ConnectionPool, engine: SftpTransferEngine, settings) -> None:
        self._pool = pool
        self._engine = engine
        self._settings = settings

        @app.tool(
            name="upload_file",
            title="上传文件到远端",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def upload_file(
            ctx: Context,
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            local_path: Annotated[
                str,
                Field(description="本地文件路径（MCP 所在机器）。若设置了 SSH_MCP_ALLOWED_LOCAL_ROOTS，则必须位于其根目录内。"),
            ],
            remote_path: Annotated[str, Field(description="远端目标文件路径，如 /home/app/release.tar.gz。")],
            overwrite: Annotated[bool, Field(description="目标已存在时是否覆盖。默认 false，会在传输前直接拒绝。")] = False,
            confirm: Annotated[
                bool, Field(description="覆盖写入属于破坏性操作，overwrite=true 时必须同时传 confirm=true。")
            ] = False,
            resume: Annotated[bool, Field(description="为 true 时从 <remote>.part 的断点继续传输。默认 true。")] = True,
            verify: Annotated[
                Literal["size", "sha256", "none"],
                Field(description="完整性校验方式：size（默认，比对字节数）、sha256（逐字节哈希，大文件较慢）、none。"),
            ] = "size",
            create_parent_dirs: Annotated[bool, Field(description="为 true 时递归创建远端父目录。默认 false。")] = False,
            progress: Annotated[bool, Field(description="为 true 时按 1% 或 5 秒的节流频率上报传输进度。")] = True,
        ) -> CallToolResult:
            """把本地文件通过 SFTP 流式上传到远端，支持断点续传、原子落盘与完整性校验。
            返回 {bytes_transferred, resumed_from, total_bytes, verified, remote_path, local_path, duration_seconds}。
            数据先写入 <remote_path>.part，校验通过后原子重命名为目标文件；中断时 .part 会保留以便续传。
            Use when 需要把构建产物、配置或日志等本地文件送到服务器；大文件优先使用本工具而不是 execute_command + base64。
            """
            if overwrite and not confirm:
                return tool_err(
                    ConfirmationRequired(
                        "upload_file(overwrite)", f"将会覆盖远端已有文件 {remote_path}", remote_path=remote_path
                    )
                )
            try:
                local = resolve_local_target(self._settings, local_path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    result = await self._engine.upload(
                        sftp,
                        local,
                        remote_path,
                        overwrite=overwrite,
                        resume=resume,
                        verify=verify,
                        create_parent_dirs=create_parent_dirs,
                        progress=self._progress_fn(ctx, progress),
                        conn=acquired.conn,
                    )
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok(result.to_dict())

        @app.tool(
            name="download_file",
            title="从远端下载文件",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def download_file(
            ctx: Context,
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            remote_path: Annotated[str, Field(description="远端文件路径，如 /var/log/app.log。")],
            local_path: Annotated[
                str,
                Field(description="本地目标路径（MCP 所在机器）。若设置了 SSH_MCP_ALLOWED_LOCAL_ROOTS，则必须位于其根目录内。"),
            ],
            overwrite: Annotated[bool, Field(description="本地文件已存在时是否覆盖。默认 false，会在传输前直接拒绝。")] = False,
            confirm: Annotated[
                bool, Field(description="覆盖本地文件属于破坏性操作，overwrite=true 时必须同时传 confirm=true。")
            ] = False,
            resume: Annotated[bool, Field(description="为 true 时从 <local>.part 的断点继续传输。默认 true。")] = True,
            verify: Annotated[
                Literal["size", "sha256", "none"],
                Field(description="完整性校验方式：size（默认）、sha256（大文件较慢）、none。"),
            ] = "size",
            progress: Annotated[bool, Field(description="为 true 时按 1% 或 5 秒的节流频率上报传输进度。")] = True,
        ) -> CallToolResult:
            """通过 SFTP 把远端文件流式下载到本地，支持断点续传、原子落盘与完整性校验。
            返回 {bytes_transferred, resumed_from, total_bytes, verified, remote_path, local_path, duration_seconds}。
            数据先写入 <local_path>.part，校验通过后原子重命名为目标文件；中断时 .part 会保留以便续传。
            Use when 需要取回远端日志、备份或产物到本机；本地父目录不存在时会自动创建（仍受白名单约束）。
            """
            if overwrite and not confirm:
                return tool_err(
                    ConfirmationRequired(
                        "download_file(overwrite)", f"将会覆盖本地已有文件 {local_path}", local_path=local_path
                    )
                )
            try:
                local = resolve_local_target(self._settings, local_path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    result = await self._engine.download(
                        sftp,
                        remote_path,
                        local,
                        overwrite=overwrite,
                        resume=resume,
                        verify=verify,
                        progress=self._progress_fn(ctx, progress),
                        conn=acquired.conn,
                    )
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok(result.to_dict())

        @app.tool(
            name="upload_files",
            title="批量上传文件",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def upload_files(
            ctx: Context,
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            files: Annotated[list[FilePair], Field(description="待上传文件列表，每项包含 local_path 与 remote_path。")],
            overwrite: Annotated[bool, Field(description="目标已存在时是否覆盖。默认 false，会在传输前对每个文件单独拒绝。")] = False,
            confirm: Annotated[bool, Field(description="overwrite=true 时必须同时传 confirm=true。")] = False,
            resume: Annotated[bool, Field(description="为 true 时从各自的 .part 断点继续传输。默认 true。")] = True,
            verify: Annotated[
                Literal["size", "sha256", "none"], Field(description="完整性校验方式，默认 size。")
            ] = "size",
            create_parent_dirs: Annotated[bool, Field(description="为 true 时递归创建每个远端父目录。默认 false。")] = False,
        ) -> CallToolResult:
            """并发上传多个文件，按配置的并发上限（默认 4）限流，每个文件独立续传、校验与原子落盘。
            返回 {results: [{local_path, remote_path, ok, ...}], succeeded, failed}；单个文件失败不影响其余文件。
            Use when 一次需要上传多个文件（如整个发布包或多个配置），比逐个调用 upload_file 更高效且不会打满服务器。
            """
            if overwrite and not confirm:
                return tool_err(
                    ConfirmationRequired("upload_files(overwrite)", "将会覆盖多个远端已有文件", file_count=len(files))
                )
            return await self._run_batch(
                ctx,
                connection_handle,
                files,
                direction="upload",
                overwrite=overwrite,
                resume=resume,
                verify=verify,
                create_parent_dirs=create_parent_dirs,
            )

        @app.tool(
            name="download_files",
            title="批量下载文件",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def download_files(
            ctx: Context,
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            files: Annotated[list[FilePair], Field(description="待下载文件列表，每项包含 remote_path 与 local_path。")],
            overwrite: Annotated[bool, Field(description="本地文件已存在时是否覆盖。默认 false。")] = False,
            confirm: Annotated[bool, Field(description="overwrite=true 时必须同时传 confirm=true。")] = False,
            resume: Annotated[bool, Field(description="为 true 时从各自的 .part 断点继续传输。默认 true。")] = True,
            verify: Annotated[
                Literal["size", "sha256", "none"], Field(description="完整性校验方式，默认 size。")
            ] = "size",
        ) -> CallToolResult:
            """并发下载多个文件，按配置的并发上限限流，每个文件独立续传、校验与原子落盘。
            返回 {results: [{local_path, remote_path, ok, ...}], succeeded, failed}；单个文件失败不影响其余文件。
            Use when 一次需要取回多个远端文件（如一批日志或产物），比逐个调用 download_file 更高效。
            """
            if overwrite and not confirm:
                return tool_err(
                    ConfirmationRequired("download_files(overwrite)", "将会覆盖多个本地已有文件", file_count=len(files))
                )
            return await self._run_batch(
                ctx,
                connection_handle,
                files,
                direction="download",
                overwrite=overwrite,
                resume=resume,
                verify=verify,
                create_parent_dirs=False,
            )

    # -- helpers --------------------------------------------------------------

    def _progress_fn(self, ctx: Context, enabled: bool):
        if not enabled:
            return None

        async def report(done: int, total: int | None) -> None:
            try:
                await ctx.report_progress(done, total)
            except Exception:  # noqa: BLE001 - progress is best effort
                logger.debug("progress notification failed", exc_info=True)

        return report

    async def _run_batch(
        self,
        ctx: Context,
        handle: str,
        files: list[FilePair],
        *,
        direction: str,
        overwrite: bool,
        resume: bool,
        verify: str,
        create_parent_dirs: bool,
    ) -> CallToolResult:
        if not files:
            return tool_err(
                ToolFailure("invalid_argument", stage="validate", hint="files 不能为空。", retryable=False)
            )
        if len(files) > 200:
            return tool_err(
                ToolFailure(
                    "invalid_argument",
                    stage="validate",
                    hint="单次批量传输最多 200 个文件，请分批调用。",
                    retryable=False,
                )
            )
        try:
            acquired = await self._pool.acquire(handle)
        except ToolFailure as exc:
            return tool_err(exc)
        semaphore = anyio.Semaphore(self._settings.sftp_concurrency)
        results: list[dict] = [{} for _ in files]

        async def one(index: int, pair: FilePair) -> None:
            async with semaphore:
                try:
                    local = resolve_local_target(self._settings, pair.local_path)
                    sftp = await acquired.sftp_client()
                    # Both engine methods take (sftp, local, remote) opposite
                    # ways; normalise once so the branch cannot swap them.
                    if direction == "upload":
                        result = await self._engine.upload(
                            sftp,
                            local,
                            pair.remote_path,
                            overwrite=overwrite,
                            resume=resume,
                            verify=verify,
                            create_parent_dirs=create_parent_dirs,
                            progress=None,
                            conn=acquired.conn,
                        )
                    else:
                        result = await self._engine.download(
                            sftp,
                            pair.remote_path,
                            local,
                            overwrite=overwrite,
                            resume=resume,
                            verify=verify,
                            progress=None,
                            conn=acquired.conn,
                        )
                    results[index] = {"ok": True, **pair.model_dump(), **result.to_dict()}
                except ToolFailure as exc:
                    results[index] = {"ok": False, **pair.model_dump(), **exc.to_dict()}
                except Exception as exc:  # noqa: BLE001
                    logger.warning("batch %s item failed: %s", direction, type(exc).__name__)
                    results[index] = {
                        "ok": False,
                        **pair.model_dump(),
                        "error": "transfer_failed",
                        "stage": direction,
                        "hint": f"传输失败（{type(exc).__name__}）。",
                        "retryable": True,
                    }

        try:
            async with anyio.create_task_group() as tg:
                for index, pair in enumerate(files):
                    tg.start_soon(one, index, pair)
        finally:
            self._pool.release(acquired.entry)

        succeeded = sum(1 for item in results if item.get("ok"))
        failed = len(results) - succeeded
        payload = {
            "direction": direction,
            "results": results,
            "succeeded": succeeded,
            "failed": failed,
            "concurrency": self._settings.sftp_concurrency,
        }
        if failed:
            from ssh_mcp.tools.helpers import tool_err_dict

            payload["error"] = "batch_partial_failure"
            payload["stage"] = direction
            payload["hint"] = f"{failed} 个文件传输失败，逐个查看 results 中的 error/hint；失败项的 .part 已保留可续传。"
            payload["retryable"] = True
            return tool_err_dict(payload)
        return tool_ok(payload)
