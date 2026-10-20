"""Small SFTP helpers shared by the pool, the transfer engine, and the tools."""

from __future__ import annotations

import contextlib
import logging

import asyncssh

logger = logging.getLogger(__name__)


async def replace_file(sftp: asyncssh.SFTPClient, source: str, target: str) -> bool:
    """Move ``source`` onto ``target``, replacing it if present.

    Returns whether the move was atomic. ``posix_rename`` is the atomic path;
    when the server lacks the extension (``SFTPOpUnsupported``) the move
    degrades to remove-then-rename. Any other error propagates untouched: it is
    not a signal that the extension is missing, and deleting the target before
    a rename that may itself fail would destroy data.
    """
    try:
        await sftp.posix_rename(source, target)
        return True
    except asyncssh.SFTPOpUnsupported:
        logger.warning("posix-rename unavailable for %s; falling back to remove+rename", target)
        with contextlib.suppress(asyncssh.SFTPNoSuchFile):
            await sftp.remove(target)
        await sftp.rename(source, target)
        return False
