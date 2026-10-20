"""Remote file-system inspection and management tools."""

from __future__ import annotations

import logging
import posixpath
from typing import Annotated

import asyncssh
from mcp.server.mcpserver import Context
from mcp.types import CallToolResult
from pydantic import Field

from ssh_mcp.errors import ConfirmationRequired, ToolFailure
from ssh_mcp.ssh.pool import ConnectionPool, borrow
from ssh_mcp.tools.helpers import tool_err, tool_ok

logger = logging.getLogger(__name__)


def _validate_remote(path: str, field: str = "path") -> str:
    if not path or not path.strip():
        raise ToolFailure("invalid_argument", stage="validate", hint=f"{field} 不能为空。", retryable=False)
    if "\x00" in path:
        raise ToolFailure("invalid_argument", stage="validate", hint=f"{field} 不能包含 NUL 字符。", retryable=False)
    return path


def _mode_string(permissions: int | None, file_type: str) -> str:
    perms = (permissions or 0) & 0o777
    return f"{file_type}{perms:04o}"


def _entry_type(attrs: asyncssh.SFTPAttrs) -> str:
    kind = attrs.type
    if kind == asyncssh.FILEXFER_TYPE_DIRECTORY:
        return "dir"
    if kind == asyncssh.FILEXFER_TYPE_SYMLINK:
        return "link"
    if kind == asyncssh.FILEXFER_TYPE_REGULAR:
        return "file"
    if kind == asyncssh.FILEXFER_TYPE_SPECIAL:
        return "special"
    return "unknown"


def _attrs_to_dict(path: str, attrs: asyncssh.SFTPAttrs) -> dict:
    kind = _entry_type(attrs)
    perms = (attrs.permissions or 0) & 0o777
    return {
        "name": posixpath.basename(path.rstrip("/")) or path,
        "path": path,
        "type": kind,
        "size": int(attrs.size or 0),
        "permissions": f"{perms:04o}",
        "mode": _mode_string(attrs.permissions, "d" if kind == "dir" else "l" if kind == "link" else "-"),
        "uid": attrs.uid,
        "gid": attrs.gid,
        "owner": attrs.owner,
        "group": attrs.group,
        "modified_at": int(attrs.mtime) if attrs.mtime else None,
    }


class FileTools:
    """Registers list_directory / stat_file / make_directory / remove_path / rename_path / change_permissions."""

    def __init__(self, app, pool: ConnectionPool, settings) -> None:
        self._pool = pool
        self._settings = settings

        @app.tool(
            name="list_directory",
            title="列出远端目录内容",
            annotations={"readOnlyHint": True, "openWorldHint": True},
        )
        async def list_directory(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            path: Annotated[str, Field(description="远端目录路径，默认当前用户主目录。")] = ".",
            max_entries: Annotated[
                int, Field(description="返回的最大条目数，默认取服务配置（500），超出部分通过 truncated 标记。")
            ] = 0,
            include_hidden: Annotated[bool, Field(description="为 false 时跳过以 . 开头的隐藏条目。默认 true。")] = True,
        ) -> CallToolResult:
            """列出远端目录下的条目及其类型、大小、权限与修改时间，不递归、不返回文件内容。
            返回 {path, entries: [{name, type, size, mode, modified_at}], total, truncated}。
            Use when 需要了解远端目录结构、确认文件是否存在或查找目标文件路径时。
            """
            limit = max_entries or self._settings.directory_page_limit
            limit = max(1, min(limit, 10_000))
            try:
                _validate_remote(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    entries: list[dict] = []
                    total = 0
                    base = path.rstrip("/") or "/"
                    async for entry in sftp.scandir(path):
                        name = entry.filename
                        if isinstance(name, bytes):
                            name = name.decode("utf-8", "replace")
                        # AsyncSSH reports the server's raw directory entries,
                        # which typically include "." and "..".
                        if name in (".", ".."):
                            continue
                        if not include_hidden and name.startswith("."):
                            continue
                        total += 1
                        if len(entries) >= limit:
                            continue
                        child = posixpath.join(base, name) if base != "/" else f"/{name}"
                        entries.append(_attrs_to_dict(child, entry.attrs))
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure(
                        "remote_not_found", stage="list", hint=f"远端目录不存在：{path}", retryable=False, path=path
                    )
                )
            except asyncssh.SFTPNotADirectory:
                return tool_err(
                    ToolFailure(
                        "remote_not_a_directory",
                        stage="list",
                        hint=f"远端路径不是目录：{path}",
                        retryable=False,
                        path=path,
                    )
                )
            except ToolFailure as exc:
                return tool_err(exc)
            entries.sort(key=lambda item: (item["type"] != "dir", item["name"].lower()))
            return tool_ok({"path": path, "entries": entries, "total": total, "truncated": total > len(entries)})

        @app.tool(
            name="stat_file",
            title="查询远端文件元信息",
            annotations={"readOnlyHint": True, "openWorldHint": True},
        )
        async def stat_file(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            path: Annotated[str, Field(description="远端文件或目录路径。")],
            follow_symlinks: Annotated[bool, Field(description="为 false 时查询符号链接本身的属性。默认 true。")] = True,
        ) -> CallToolResult:
            """查询远端单个路径的属性：类型、大小、权限、属主与修改时间，不读取文件内容。
            返回 {path, type, size, permissions, mode, owner, group, modified_at}。
            Use when 需要确认文件是否存在、大小或权限是否符合预期，或在传输前核对目标状态时。
            """
            try:
                _validate_remote(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    attrs = await sftp.stat(path, follow_symlinks=follow_symlinks)
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure("remote_not_found", stage="stat", hint=f"远端路径不存在：{path}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok(_attrs_to_dict(path, attrs))

        @app.tool(
            name="make_directory",
            title="创建远端目录",
            annotations={"readOnlyHint": False, "destructiveHint": False, "openWorldHint": True},
        )
        async def make_directory(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            path: Annotated[str, Field(description="要创建的远端目录路径。")],
            parents: Annotated[bool, Field(description="为 true 时递归创建缺失的父目录。默认 false。")] = False,
        ) -> CallToolResult:
            """在远端创建一个目录，可选递归创建父目录；已存在的目录视为成功。
            返回 {path, created, created_parents}。
            Use when 需要为上传、日志或发布产物准备远端目录时。
            """
            try:
                _validate_remote(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    try:
                        existing = await sftp.stat(path)
                        if _entry_type(existing) == "dir":
                            return tool_ok({"path": path, "created": False, "already_existed": True})
                    except asyncssh.SFTPNoSuchFile:
                        pass
                    if parents:
                        await sftp.makedirs(path, exist_ok=True)
                        return tool_ok({"path": path, "created": True, "created_parents": True})
                    await sftp.mkdir(path)
                    return tool_ok({"path": path, "created": True, "created_parents": False})
            except asyncssh.SFTPPermissionDenied:
                return tool_err(
                    ToolFailure(
                        "permission_denied",
                        stage="mkdir",
                        hint=f"没有权限在远端创建目录：{path}",
                        retryable=False,
                        path=path,
                    )
                )
            except asyncssh.SFTPFileAlreadyExists:
                return tool_ok({"path": path, "created": False, "already_existed": True})
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="remove_path",
            title="删除远端文件或目录",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def remove_path(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            path: Annotated[str, Field(description="要删除的远端文件或目录路径。")],
            recursive: Annotated[bool, Field(description="为 true 时递归删除目录及其全部内容。默认 false，仅删除空目录。")] = False,
            confirm: Annotated[bool, Field(description="破坏性操作，必须为 true 才会执行。")] = False,
        ) -> CallToolResult:
            """删除远端文件、符号链接或目录（默认仅限空目录），返回删除的类型与路径。
            递归删除会连同子目录中的全部内容一起永久删除，且无法恢复。
            Use when 需要清理远端临时文件或目录；必须先向用户确认删除范围，尤其是 recursive=true 时。
            """
            consequence = (
                f"将递归删除 {path} 及其全部子内容（不可恢复）" if recursive else f"将删除远端 {path}（空目录或文件）"
            )
            if not confirm:
                return tool_err(ConfirmationRequired("remove_path", consequence, path=path, recursive=recursive))
            try:
                _validate_remote(path)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    attrs = await sftp.stat(path, follow_symlinks=False)
                    kind = _entry_type(attrs)
                    if kind == "dir":
                        if recursive:
                            await sftp.rmtree(path)
                            return tool_ok({"path": path, "removed": "dir", "recursive": True})
                        await sftp.rmdir(path)
                        return tool_ok({"path": path, "removed": "dir", "recursive": False})
                    await sftp.remove(path)
                    return tool_ok({"path": path, "removed": kind, "recursive": False})
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure("remote_not_found", stage="remove", hint=f"远端路径不存在：{path}", retryable=False, path=path)
                )
            except asyncssh.SFTPFailure as exc:
                if not recursive:
                    return tool_err(
                        ToolFailure(
                            "directory_not_empty",
                            stage="remove",
                            hint=f"目录非空：{path}。确认要递归删除时传 recursive=true 与 confirm=true。",
                            retryable=False,
                            path=path,
                            detail=str(exc),
                        )
                    )
                return tool_err(
                    ToolFailure("remove_failed", stage="remove", hint=f"删除失败：{exc}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)

        @app.tool(
            name="rename_path",
            title="重命名或移动远端路径",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def rename_path(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            old_path: Annotated[str, Field(description="远端原路径。")],
            new_path: Annotated[str, Field(description="远端新路径（可跨目录移动）。")],
            overwrite: Annotated[bool, Field(description="目标已存在时是否覆盖。默认 false，会直接拒绝。")] = False,
            confirm: Annotated[bool, Field(description="覆盖目标或移动目录属于破坏性操作，必须为 true 才会执行。")] = False,
        ) -> CallToolResult:
            """在远端重命名或移动文件/目录，目标已存在时默认拒绝，除非 overwrite=true。
            返回 {old_path, new_path, overwritten}。
            Use when 需要调整远端文件布局、归档日志或替换配置；必须先向用户确认目标路径。
            """
            if not confirm:
                return tool_err(
                    ConfirmationRequired(
                        "rename_path",
                        f"将把远端 {old_path} 移动/重命名为 {new_path}" + ("，并覆盖已存在的目标" if overwrite else ""),
                        old_path=old_path,
                        new_path=new_path,
                    )
                )
            try:
                _validate_remote(old_path, "old_path")
                _validate_remote(new_path, "new_path")
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    target_exists = False
                    try:
                        await sftp.stat(new_path, follow_symlinks=False)
                        target_exists = True
                    except asyncssh.SFTPNoSuchFile:
                        target_exists = False
                    if target_exists and not overwrite:
                        return tool_err(
                            ToolFailure(
                                "remote_exists",
                                stage="rename",
                                hint=f"目标路径已存在：{new_path}。确认覆盖请传 overwrite=true。",
                                retryable=False,
                                new_path=new_path,
                            )
                        )
                    if target_exists:
                        try:
                            await sftp.posix_rename(old_path, new_path)
                        except asyncssh.SFTPError:
                            await sftp.remove(new_path)
                            await sftp.rename(old_path, new_path)
                    else:
                        await sftp.rename(old_path, new_path)
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure(
                        "remote_not_found", stage="rename", hint=f"原路径不存在：{old_path}", retryable=False, old_path=old_path
                    )
                )
            except asyncssh.SFTPError as exc:
                return tool_err(
                    ToolFailure(
                        "rename_failed", stage="rename", hint=f"重命名失败：{exc}", retryable=False, old_path=old_path
                    )
                )
            except ToolFailure as exc:
                return tool_err(exc)
            return tool_ok({"old_path": old_path, "new_path": new_path, "overwritten": target_exists})

        @app.tool(
            name="change_permissions",
            title="修改远端文件权限",
            annotations={"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
        )
        async def change_permissions(
            connection_handle: Annotated[str, Field(description="connect 返回的 connection_handle。")],
            path: Annotated[str, Field(description="远端文件或目录路径。")],
            mode: Annotated[str, Field(description="八进制权限字符串，如 \"644\"、\"755\"、\"600\"。")],
            recursive: Annotated[bool, Field(description="为 true 时递归应用到目录下的所有条目。默认 false。")] = False,
            confirm: Annotated[bool, Field(description="破坏性操作，必须为 true 才会执行。")] = False,
        ) -> CallToolResult:
            """修改远端文件或目录的 POSIX 权限位，返回新权限与受影响的条目数。
            权限设置错误可能导致服务无法访问文件或暴露敏感数据。
            Use when 需要为脚本添加可执行位、收紧配置文件权限或修复上传后的权限问题时；执行前必须先向用户确认。
            """
            if not confirm:
                return tool_err(
                    ConfirmationRequired(
                        "change_permissions", f"将把远端 {path} 的权限改为 {mode}", path=path, mode=mode
                    )
                )
            try:
                _validate_remote(path)
                numeric = _parse_mode(mode)
                async with borrow(self._pool, connection_handle) as acquired:
                    sftp = await acquired.sftp_client()
                    attrs = await sftp.stat(path)
                    if _entry_type(attrs) == "dir" and recursive:
                        affected = await _chmod_tree(sftp, path, numeric)
                    else:
                        await sftp.chmod(path, numeric)
                        affected = 1
                    return tool_ok({"path": path, "mode": f"{numeric:04o}", "recursive": recursive, "affected": affected})
            except asyncssh.SFTPNoSuchFile:
                return tool_err(
                    ToolFailure("remote_not_found", stage="chmod", hint=f"远端路径不存在：{path}", retryable=False, path=path)
                )
            except asyncssh.SFTPError as exc:
                return tool_err(
                    ToolFailure("chmod_failed", stage="chmod", hint=f"修改权限失败：{exc}", retryable=False, path=path)
                )
            except ToolFailure as exc:
                return tool_err(exc)


async def _chmod_tree(sftp: asyncssh.SFTPClient, root: str, numeric: int) -> int:
    """Apply ``numeric`` to ``root`` and everything below it; returns the count."""
    count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        await sftp.chmod(current, numeric)
        count += 1
        async for entry in sftp.scandir(current):
            name = entry.filename
            if isinstance(name, bytes):
                name = name.decode("utf-8", "replace")
            child = posixpath.join(current, name)
            if _entry_type(entry.attrs) == "dir":
                stack.append(child)
            else:
                await sftp.chmod(child, numeric)
                count += 1
    return count


def _parse_mode(mode: str) -> int:
    text = str(mode).strip().lower()
    if text.startswith("0o"):
        text = text[2:]
    if not text or any(ch not in "01234567" for ch in text) or len(text) > 4:
        raise ToolFailure(
            "invalid_argument",
            stage="validate",
            hint=f"mode 必须是八进制权限字符串，例如 \"644\" 或 \"0755\"，收到 {mode!r}。",
            retryable=False,
        )
    return int(text, 8)
