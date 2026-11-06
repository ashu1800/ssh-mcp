"""Small filesystem helpers whose behaviour is not uniform across platforms."""

from __future__ import annotations

import contextlib
import logging
import os
import time
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)


def replace_with_retry(
    tmp: Path,
    target: Path,
    *,
    attempts: int = 5,
    fallback: Callable[[], None] | None = None,
) -> None:
    """``os.replace`` that survives a momentarily-open target on Windows.

    Windows refuses to rename onto a file another process holds open, even for
    reading: a folder-sync client, an antivirus scan or the previous process
    turns a correct write into ``PermissionError`` (WinError 32). Retry briefly;
    if the handle never goes away, run ``fallback`` (a caller-supplied in-place
    write) instead of failing the operation that triggered the write.
    """
    for attempt in range(attempts):
        try:
            os.replace(tmp, target)
            return
        except PermissionError:
            if attempt == attempts - 1:
                if fallback is None:
                    raise
                logger.debug("rename onto %s stayed blocked; writing in place", target.name)
                fallback()
                with contextlib.suppress(OSError):
                    tmp.unlink()
                return
            time.sleep(0.02 * (attempt + 1))


def remove_quietly(path: Path) -> None:
    """Delete a temporary file without caring whether it was ever created."""
    with contextlib.suppress(OSError):
        path.unlink()
