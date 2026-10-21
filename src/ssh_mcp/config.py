"""Runtime configuration.

Every setting comes from an environment variable (see ``.env.example``); a TOML
file may be pointed at with ``SSH_MCP_CONFIG`` to supply the same keys in a
flatter spelling. Validation happens once at startup so a misconfigured process
fails before it accepts a single tool call.
"""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_CREDENTIALS_URL = "https://ssh.ashu180.cn/api/mcp/credentials"
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8765

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class ConfigError(RuntimeError):
    """Raised when the environment does not describe a usable server."""


class PathNotAllowed(ValueError):
    """Raised when a local path falls outside ``allowed_local_roots``."""

    def __init__(self, path: str, reason: str) -> None:
        super().__init__(reason)
        self.path = path
        self.reason = reason


class _Source:
    """Environment variables with an optional TOML fallback."""

    def __init__(self, env: Mapping[str, str], toml_flat: dict) -> None:
        self._env = env
        self._toml = toml_flat

    def env(self, name: str) -> str | None:
        value = self._env.get(name)
        if value is None:
            return None
        value = value.strip()
        return value or None

    def toml(self, key: str, default=None):
        for candidate in (key, key.replace("_", "-"), key.lower()):
            if candidate in self._toml:
                return self._toml[candidate]
        return default

    def pick(self, env_name: str, toml_key: str, default):
        raw = self.env(env_name)
        if raw is not None:
            return raw
        return self.toml(toml_key, default)

    def integer(self, env_name: str, toml_key: str, default: int, *, minimum=None, maximum=None) -> int:
        raw = self.pick(env_name, toml_key, default)
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{env_name} must be an integer, got {raw!r}") from exc
        return _check_range(env_name, value, minimum, maximum)

    def number(self, env_name: str, toml_key: str, default: float, *, minimum=None, maximum=None) -> float:
        raw = self.pick(env_name, toml_key, default)
        try:
            value = float(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigError(f"{env_name} must be a number, got {raw!r}") from exc
        return _check_range(env_name, value, minimum, maximum)


def _check_range(name: str, value, minimum, maximum):
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}, got {value}")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name} must be <= {maximum}, got {value}")
    return value


def _split_paths(raw: str) -> list[Path]:
    parts = [p.strip() for p in raw.replace(";", os.pathsep).split(os.pathsep)]
    return [Path(p).expanduser() for p in parts if p]


def _load_toml(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except OSError as exc:
        raise ConfigError(f"cannot read SSH_MCP_CONFIG at {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in SSH_MCP_CONFIG at {path}: {exc}") from exc
    # Accept a nested [server] / [sftp] layout by flattening one level.
    flat: dict = {}
    for key, value in data.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


@dataclass(slots=True)
class Settings:
    """Validated runtime settings."""

    # --- credentials service -------------------------------------------------
    mcp_key: str
    credentials_url: str = DEFAULT_CREDENTIALS_URL
    credentials_timeout: float = 15.0
    credentials_cache_ttl: float = 45.0
    credentials_max_retries: int = 3

    # --- local state ---------------------------------------------------------
    state_dir: Path = field(default_factory=lambda: Path.home() / ".ssh-mcp")
    known_hosts_path: Path | None = None
    auth_state_path: Path | None = None
    keys_dir: Path | None = None
    allowed_local_roots: list[Path] = field(default_factory=list)
    resolved_local_roots: list[Path] = field(default_factory=list)
    # Writes only; lets reads stay open while download targets are confined.
    write_local_roots: list[Path] = field(default_factory=list)
    resolved_write_roots: list[Path] = field(default_factory=list)
    # --- ssh -----------------------------------------------------------------
    connect_timeout: float = 10.0
    login_timeout: float = 20.0
    keepalive_interval: float = 30.0
    keepalive_count_max: int = 3
    pool_idle_timeout: float = 300.0
    pool_reaper_interval: float = 60.0
    pool_max_entries: int = 64
    compression_mode: str = "auto"  # auto | on | off

    # --- commands ------------------------------------------------------------
    command_timeout_default: float = 30.0
    command_timeout_max: float = 600.0
    # Per-stream cap for captured output. Kept below the tool result text
    # budget (512 KiB in tools/helpers.py) so a command that fills the cap is
    # still delivered; otherwise every large `cat`/`journalctl` turns into a
    # result_too_large error instead of truncated output.
    command_max_output_bytes: int = 256 * 1024

    # --- sftp ----------------------------------------------------------------
    sftp_block_size: int = 256 * 1024
    sftp_max_requests: int = 16
    sftp_buffer_size: int = 1024 * 1024
    sftp_idle_timeout: float = 60.0
    sftp_total_timeout: float | None = None
    sftp_concurrency: int = 4
    sftp_intolerant_block_size: int = 64 * 1024
    directory_page_limit: int = 500

    # --- transports ----------------------------------------------------------
    http_host: str = DEFAULT_HTTP_HOST
    http_port: int = DEFAULT_HTTP_PORT
    http_bearer_token: str | None = None
    http_allowed_origins: list[str] = field(default_factory=list)
    log_level: str = "INFO"

    def __post_init__(self) -> None:
        self.state_dir = self.state_dir.expanduser()
        if self.known_hosts_path is None:
            self.known_hosts_path = self.state_dir / "known_hosts"
        if self.auth_state_path is None:
            self.auth_state_path = self.state_dir / "auth_state.json"
        if self.keys_dir is None:
            self.keys_dir = self.state_dir / "keys"
        self.known_hosts_path = self.known_hosts_path.expanduser()
        self.auth_state_path = self.auth_state_path.expanduser()
        self.keys_dir = self.keys_dir.expanduser()
        # An empty allowlist means "not restricted": local transfers may touch
        # any path the user running the server can reach. Roots are only
        # enforced when at least one is configured, so the restriction is
        # opt-in rather than silently truncating the AI to one directory.
        self.allowed_local_roots = [p.expanduser() for p in self.allowed_local_roots]
        # Resolved lazily and once: each ``Path.resolve`` stats every component,
        # and a 200-file batch would otherwise re-walk every root 200 times.
        self.resolved_local_roots = [p.resolve(strict=False) for p in self.allowed_local_roots]
        self.write_local_roots = [p.expanduser() for p in self.write_local_roots]
        self.resolved_write_roots = [p.resolve(strict=False) for p in self.write_local_roots]

    @property
    def http_is_loopback(self) -> bool:
        return self.http_host.lower() in {"127.0.0.1", "localhost", "::1"}

    @property
    def local_paths_restricted(self) -> bool:
        """Whether local transfers are confined to :attr:`allowed_local_roots`."""
        return bool(self.resolved_local_roots)

    @property
    def local_writes_restricted(self) -> bool:
        """Whether local *writes* are confined to :attr:`write_local_roots`."""
        return bool(self.resolved_write_roots)

    def resolve_local_path(self, raw: str, *, write: bool = False) -> Path:
        """Return the realpath for ``raw``, rejecting anything outside the allowlist.

        Two independent lists, checked in order:

        * ``SSH_MCP_ALLOWED_LOCAL_ROOTS`` -- caps *both* reads and writes.
        * ``SSH_MCP_WRITE_LOCAL_ROOTS`` -- caps writes only, so an upload can
          read from anywhere while a download cannot land in, say, ``~/.ssh``.

        Symlinks are resolved before the containment check, so a link inside an
        allowed root that points outside it is rejected. With neither list set
        the path is returned unrestricted.
        """
        if "\x00" in raw:
            raise PathNotAllowed(raw, "路径包含 NUL 字符")
        if not raw or not raw.strip():
            raise PathNotAllowed(raw, "本地路径不能为空")
        candidate = Path(raw).expanduser()
        # ``resolve()`` follows symlinks where they exist and normalises the
        # rest, which is what the containment check must see.
        resolved = candidate.resolve(strict=False)

        if write and self.resolved_write_roots:
            if any(resolved == root or resolved.is_relative_to(root) for root in self.resolved_write_roots):
                return resolved
            allowed = ", ".join(str(r) for r in self.write_local_roots)
            raise PathNotAllowed(raw, f"路径不在允许写入的本地目录内：{allowed}")

        if not self.resolved_local_roots:
            return resolved
        for root_resolved in self.resolved_local_roots:
            if resolved == root_resolved or resolved.is_relative_to(root_resolved):
                return resolved
        allowed = ", ".join(str(r) for r in self.allowed_local_roots)
        raise PathNotAllowed(raw, f"路径不在允许的本地根目录内：{allowed}")


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """Build :class:`Settings` from the environment (and optional TOML overlay).

    ``env`` defaults to ``os.environ``; tests pass a mapping to avoid touching
    the real process environment.
    """
    source_env = os.environ if env is None else env
    src = _Source(source_env, {})

    config_path = src.env("SSH_MCP_CONFIG")
    if config_path:
        src = _Source(source_env, _load_toml(Path(config_path).expanduser()))

    mcp_key = src.env("MCP_KEY") or src.env("SSH_MCP_MCP_KEY") or src.toml("mcp_key")
    if not mcp_key or not isinstance(mcp_key, str):
        raise ConfigError("MCP_KEY is required: set it to the MCP token issued by the credential service")
    if not mcp_key.startswith("mcp_"):
        raise ConfigError("MCP_KEY does not look like an MCP token (expected a 'mcp_' prefix)")

    state_dir_raw = src.env("SSH_MCP_STATE_DIR") or src.toml("state_dir")
    state_dir = Path(str(state_dir_raw)).expanduser() if state_dir_raw else Path.home() / ".ssh-mcp"

    roots_raw = src.env("SSH_MCP_ALLOWED_LOCAL_ROOTS")
    if roots_raw is not None:
        # Explicitly set -- including an empty value, which means "no limit".
        allowed_roots = _split_paths(roots_raw)
    else:
        toml_roots = src.toml("allowed_local_roots")
        if isinstance(toml_roots, list):
            allowed_roots = [Path(str(p)).expanduser() for p in toml_roots]
        elif isinstance(toml_roots, str):
            allowed_roots = _split_paths(toml_roots)
        else:
            # Unset: local transfers are unrestricted. Confining the AI to one
            # directory is opt-in, because the useful default is "let it read
            # the build output it was asked to upload".
            allowed_roots = []

    write_roots_raw = src.env("SSH_MCP_WRITE_LOCAL_ROOTS")
    if write_roots_raw is not None:
        write_roots = _split_paths(write_roots_raw)
    else:
        toml_write = src.toml("write_local_roots")
        if isinstance(toml_write, list):
            write_roots = [Path(str(p)).expanduser() for p in toml_write]
        elif isinstance(toml_write, str):
            write_roots = _split_paths(toml_write)
        else:
            write_roots = []

    total_raw = src.env("SSH_MCP_SFTP_TOTAL_TIMEOUT")
    if total_raw is None:
        toml_total = src.toml("sftp_total_timeout")
        sftp_total_timeout = float(toml_total) if toml_total not in (None, "", 0, "0") else None
    else:
        sftp_total_timeout = float(total_raw) or None

    origins_raw = src.env("SSH_MCP_HTTP_ALLOWED_ORIGINS")
    if origins_raw:
        allowed_origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
    else:
        toml_origins = src.toml("http_allowed_origins")
        allowed_origins = [str(o) for o in toml_origins] if isinstance(toml_origins, list) else []

    http_token = src.env("SSH_MCP_HTTP_TOKEN")
    if http_token is None:
        toml_token = src.toml("http_bearer_token")
        http_token = toml_token if isinstance(toml_token, str) and toml_token.strip() else None

    compression_raw = src.pick("SSH_MCP_COMPRESSION", "compression", "auto")
    compression_mode = _compression_mode(compression_raw)

    settings = Settings(
        mcp_key=mcp_key,
        credentials_url=str(src.pick("SSH_MCP_CREDENTIALS_URL", "credentials_url", DEFAULT_CREDENTIALS_URL)),
        credentials_timeout=src.number("SSH_MCP_CREDENTIALS_TIMEOUT", "credentials_timeout", 15.0, minimum=1.0),
        credentials_cache_ttl=src.number("SSH_MCP_CREDENTIALS_CACHE_TTL", "credentials_cache_ttl", 45.0, minimum=0.0),
        credentials_max_retries=src.integer(
            "SSH_MCP_CREDENTIALS_MAX_RETRIES", "credentials_max_retries", 3, minimum=0, maximum=10
        ),
        state_dir=state_dir,
        known_hosts_path=_optional_path(src.env("SSH_MCP_KNOWN_HOSTS")),
        auth_state_path=_optional_path(src.env("SSH_MCP_AUTH_STATE")),
        keys_dir=_optional_path(src.env("SSH_MCP_KEYS_DIR")),
        allowed_local_roots=allowed_roots,
        write_local_roots=write_roots,
        connect_timeout=src.number("SSH_MCP_CONNECT_TIMEOUT", "connect_timeout", 10.0, minimum=1.0),
        login_timeout=src.number("SSH_MCP_LOGIN_TIMEOUT", "login_timeout", 20.0, minimum=1.0),
        keepalive_interval=src.number("SSH_MCP_KEEPALIVE_INTERVAL", "keepalive_interval", 30.0, minimum=0.0),
        keepalive_count_max=src.integer("SSH_MCP_KEEPALIVE_COUNT_MAX", "keepalive_count_max", 3, minimum=1),
        pool_idle_timeout=src.number("SSH_MCP_POOL_IDLE_TIMEOUT", "pool_idle_timeout", 300.0, minimum=0.0),
        pool_reaper_interval=src.number("SSH_MCP_POOL_REAPER_INTERVAL", "pool_reaper_interval", 60.0, minimum=1.0),
        # Ceiling on live SSH connections; idle LRU entries are evicted first.
        pool_max_entries=src.integer("SSH_MCP_POOL_MAX_ENTRIES", "pool_max_entries", 64, minimum=1),
        compression_mode=compression_mode,
        command_timeout_default=src.number("SSH_MCP_COMMAND_TIMEOUT_DEFAULT", "command_timeout_default", 30.0, minimum=1.0),
        command_timeout_max=src.number("SSH_MCP_COMMAND_TIMEOUT_MAX", "command_timeout_max", 600.0, minimum=1.0),
        command_max_output_bytes=src.integer(
            "SSH_MCP_COMMAND_MAX_OUTPUT_BYTES", "command_max_output_bytes", 256 * 1024, minimum=1024
        ),
        sftp_block_size=src.integer(
            "SSH_MCP_SFTP_BLOCK_SIZE", "sftp_block_size", 256 * 1024, minimum=16 * 1024, maximum=4 * 1024 * 1024
        ),
        sftp_max_requests=src.integer("SSH_MCP_SFTP_MAX_REQUESTS", "sftp_max_requests", 16, minimum=1, maximum=128),
        sftp_buffer_size=src.integer(
            "SSH_MCP_SFTP_BUFFER_SIZE", "sftp_buffer_size", 1024 * 1024, minimum=64 * 1024, maximum=8 * 1024 * 1024
        ),
        sftp_idle_timeout=src.number("SSH_MCP_SFTP_IDLE_TIMEOUT", "sftp_idle_timeout", 60.0, minimum=1.0),
        sftp_total_timeout=sftp_total_timeout,
        sftp_concurrency=src.integer("SSH_MCP_SFTP_CONCURRENCY", "sftp_concurrency", 4, minimum=1, maximum=16),
        sftp_intolerant_block_size=src.integer(
            "SSH_MCP_SFTP_FALLBACK_BLOCK_SIZE", "sftp_intolerant_block_size", 64 * 1024, minimum=16 * 1024
        ),
        directory_page_limit=src.integer(
            "SSH_MCP_DIRECTORY_ENTRY_LIMIT", "directory_page_limit", 500, minimum=1, maximum=10000
        ),
        http_host=str(src.pick("SSH_MCP_HTTP_HOST", "http_host", DEFAULT_HTTP_HOST)),
        http_port=src.integer("SSH_MCP_HTTP_PORT", "http_port", DEFAULT_HTTP_PORT, minimum=1, maximum=65535),
        http_bearer_token=http_token,
        http_allowed_origins=allowed_origins,
        log_level=str(src.pick("SSH_MCP_LOG_LEVEL", "log_level", "INFO")).upper(),
    )
    if settings.command_timeout_default > settings.command_timeout_max:
        raise ConfigError("SSH_MCP_COMMAND_TIMEOUT_DEFAULT must not exceed SSH_MCP_COMMAND_TIMEOUT_MAX")
    if settings.log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigError(f"SSH_MCP_LOG_LEVEL must be a standard level, got {settings.log_level!r}")
    if not settings.http_is_loopback and not settings.http_bearer_token:
        raise ConfigError(
            "Refusing to bind HTTP transport to "
            f"{settings.http_host}: set SSH_MCP_HTTP_TOKEN before exposing the server"
        )
    return settings


def _optional_path(raw: str | None) -> Path | None:
    return Path(raw).expanduser() if raw else None


def _compression_mode(raw) -> str:
    value = str(raw).lower()
    if value in {"auto", "on", "off"}:
        return value
    if value in _TRUE:
        return "on"
    if value in _FALSE:
        return "off"
    raise ConfigError(f"SSH_MCP_COMPRESSION must be auto|on|off, got {raw!r}")
