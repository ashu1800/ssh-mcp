# ssh-mcp

本地运行的 MCP Server，把 **SSH 远程命令执行**与 **SFTP 文件传输**提供给 AI 客户端（Claude Code、Cursor、通义灵码等）。

服务器清单与连接凭据不手工录入：MCP 调用服务器管理服务的 `GET /api/mcp/credentials`，取得**加密 blob**，用持有的 MCP 密钥经 HKDF-SHA256 派生密钥、AES-256-GCM 解密后，在本进程内完成全部 SSH/SFTP 操作。

- 传输：**stdio**（默认）与 **Streamable HTTP**（无状态，协议版本 `2026-07-28`）
- 认证：首次密码登录 → 本地生成 Ed25519 密钥 → 写入远端 `authorized_keys` → 后续公钥登录
- 主机密钥：TOFU 固定指纹，指纹变化直接拒绝
- 传输引擎：流式、断点续传、原子落盘、进度上报、空闲超时、size/sha256 校验

## 安装

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"     # Windows
# .venv/bin/python -m pip install -e ".[dev]"       # Linux/macOS
```

要求 Python ≥ 3.11。

## 配置

复制 `.env.example`，至少填写 `MCP_KEY`（由服务器管理端签发）。程序只读环境变量，不自动加载 `.env` 文件——由客户端配置注入。

关键项：

| 变量 | 默认 | 说明 |
|---|---|---|
| `MCP_KEY` | 必填 | 调接口与派生解密密钥 |
| `SSH_MCP_ALLOWED_LOCAL_ROOTS` | `~/ssh-mcp-files` | 允许读写的本机目录（realpath 校验，symlink 解析后判断） |
| `SSH_MCP_STATE_DIR` | `~/.ssh-mcp` | known_hosts、Ed25519 私钥、认证状态 |
| `SSH_MCP_SFTP_BLOCK_SIZE` | 256 KiB | SFTP 请求流水线块大小 |
| `SSH_MCP_SFTP_IDLE_TIMEOUT` | 60 s | 连续无数据即中止（大文件主超时） |
| `SSH_MCP_SFTP_TOTAL_TIMEOUT` | 0（关闭） | 可选的总时长上限 |
| `SSH_MCP_HTTP_TOKEN` | 空 | HTTP 入站 Bearer；绑定非回环地址时必填 |
| `SSH_MCP_LOG_LEVEL` | INFO | 日志只写 stderr，敏感串自动脱敏 |

全部变量见 `.env.example`。

## 客户端配置

### Claude Code / Claude Desktop

stdio（推荐本地使用）：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "D:/Sync/AICoding/ssh-mcp/.venv/Scripts/python.exe",
      "args": ["-m", "ssh_mcp", "--transport", "stdio"],
      "env": {
        "MCP_KEY": "mcp_xxx",
        "SSH_MCP_ALLOWED_LOCAL_ROOTS": "D:/Sync/ssh-files"
      }
    }
  }
}
```

```bash
claude mcp add ssh -- /path/to/.venv/bin/python -m ssh_mcp --transport stdio
```

HTTP（多客户端共享）：

```json
{
  "mcpServers": {
    "ssh": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer <SSH_MCP_HTTP_TOKEN>" }
    }
  }
}
```

### Cursor

`~/.cursor/mcp.json` 与上面的 stdio 形态一致：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "python",
      "args": ["-m", "ssh_mcp"],
      "env": { "MCP_KEY": "mcp_xxx" }
    }
  }
}
```

Cursor 目前走 `initialize` 握手（协议 `2025-11-25`），由同一个 SDK 处理，工具行为一致。

### 通义灵码

在其 MCP 配置中加入本地命令（stdio）：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "python",
      "args": ["-m", "ssh_mcp"],
      "env": { "MCP_KEY": "mcp_xxx" }
    }
  }
}
```

> 三种客户端的协议版本不同（握手式 `2025-11-25` 与无状态 `2026-07-28`），它们共用同一套工具实现；**没有**哪一种传输模式能通吃所有客户端，所以 stdio 作为默认兜底。

## 运行

```bash
# stdio
python -m ssh_mcp

# HTTP（默认 127.0.0.1:8765，无状态）
SSH_MCP_HTTP_TOKEN=change-me python -m ssh_mcp --transport http
```

## 工具

| 工具 | 用途 | 需 confirm |
|---|---|---|
| `list_servers` | 列出可访问服务器（无凭据） | – |
| `resolve_server` | 返回脱敏连接摘要 | – |
| `connect` | 建立/复用连接，返回 `connection_handle` | – |
| `disconnect` | 关闭连接 | ✓ |
| `execute_command` | 执行非交互命令，超时终止远端进程 | – |
| `upload_file` / `download_file` | 单文件传输 | 覆盖时 ✓ |
| `upload_files` / `download_files` | 批量传输（并发限流） | 覆盖时 ✓ |
| `list_directory` / `stat_file` | 目录与元信息 | – |
| `make_directory` | 建目录（可递归） | – |
| `remove_path` | 删除文件/空目录（递归需显式） | ✓ |
| `rename_path` | 重命名/移动 | ✓ |
| `change_permissions` | 改权限（八进制） | ✓ |

所有工具返回结构化 JSON；失败时 `is_error=true`，字段含 `error`、`stage`、`hint`、`retryable`。

## 传输语义

- 数据先写 `<目标>.part`，校验通过后原子重命名；中断保留 `.part` 以便续传。
- 续传前校验 `.part` 不超过源大小，超出则丢弃重传。
- `verify=size` 默认；`sha256` 会分别计算源/目标哈希（返回 `hash_seconds`）。
- 进度按 **每 1% 或每 5 秒** 节流，通过 MCP progress notification 上报。

## 安全

- 密码/私钥只在内存；日志过滤器会脱敏 `mcp_` 令牌、PEM 私钥与 `password` 字段。
- 本地路径经 `realpath` 后必须落在允许根目录内，symlink 逃逸同样拒绝。
- `known_hosts` 位于 `~/.ssh-mcp/known_hosts`；首次信任后指纹变化会拒绝连接。
- HTTP 默认绑定 `127.0.0.1`，校验 `Origin`，可要求 Bearer；绑定非回环地址而未设置 Token 时拒绝启动。
- 私钥文件 600、目录 700（Windows 上权限位语义有限，依赖文件系统 ACL）。

## 测试

```bash
pytest -q                                        # 离线套件（本地假 SSH/SFTP 服务）
SSH_MCP_RUN_LARGE=1 pytest -m large -q           # 1 GB 内存基线
```

## 已知取舍

1. SSH 压缩在连接级协商，因此只能按连接配置：`auto` 与 `on` 等价（协商 zlib），`off` 关闭压缩。连接在 `connect` 时建立，此时还没有目标文件，池 key `(host, port, username)` 也不含压缩维度，所以不做按文件扩展名的判断；需要为大批已压缩文件关压缩时，把 `SSH_MCP_COMPRESSION=off` 并重新 `connect`。
2. HTTP 无状态模式下，客户端断开会触发请求取消；`json_response=False`（默认 SSE）是保证进度与取消可用的前提。
3. Windows 上无法设置 POSIX 权限位，`chmod` 作用于远端不受影响，本地密钥文件权限依赖 ACL。
