# ssh-mcp

本地运行的 MCP Server，把 **SSH 远程命令执行**与 **SFTP 文件传输**提供给 AI 客户端（Claude Code、Cursor、通义灵码等）。

服务器清单与连接凭据不手工录入：MCP 调用服务器管理服务的 `GET /api/mcp/credentials`，取得**加密 blob**，用持有的 MCP 密钥经 HKDF-SHA256 派生密钥、AES-256-GCM 解密后，在本进程内完成全部 SSH/SFTP 操作。

- 传输：**stdio**（默认）与 **Streamable HTTP**（无状态，协议版本 `2026-07-28`）
- 认证：首次密码登录 → 本地生成 Ed25519 密钥 → 写入远端 `authorized_keys` → 后续公钥登录
- 主机密钥：TOFU 固定指纹，指纹变化直接拒绝
- 传输引擎：流式、断点续传、原子落盘、进度上报、空闲超时、size/sha256 校验

## 安装

要求 Python ≥ 3.11。

### 方式一：从源码安装（开发 / 当前机器）

```bash
git clone https://github.com/ashu1800/ssh-mcp.git && cd ssh-mcp
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"     # Windows
# .venv/bin/python -m pip install -e ".[dev]"       # Linux/macOS
```

### 方式二：装成一个普通命令（换机器时推荐）

在任意一台已装好 Python 的机器上执行（仓库为私有，需要本机已配置 GitHub 凭据，
例如 `gh auth setup-git`）：

```bash
python -m pip install --user "git+https://github.com/ashu1800/ssh-mcp.git"
```

目标机器不能访问 GitHub 时，先在本机构建 wheel 再拷过去离线安装：

```bash
python -m pip wheel --no-deps -w dist .
# 把 dist/ssh_mcp-0.1.0-py3-none-any.whl 拷到目标机
python -m pip install dist/ssh_mcp-0.1.0-py3-none-any.whl
```

安装后会得到 `ssh-mcp` 命令（Windows 为 `ssh-mcp.exe`）。客户端配置里就可以直接写这个命令，
不必再关心仓库路径与虚拟环境位置：

```json
{
  "mcpServers": {
    "ssh": {
      "command": "ssh-mcp",
      "args": ["--transport", "stdio"],
      "env": { "MCP_KEY": "mcp_xxx" }
    }
  }
}
```

用 `ssh-mcp --help` 可确认命令可用；`python -m ssh_mcp` 在没有把 Scripts 目录加入 PATH 时是等价写法。

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

## 一键安装并接入客户端

先取得代码（仓库为私有，需要已配置 GitHub 凭据，例如 `gh auth setup-git`）：

```bash
git clone https://github.com/ashu1800/ssh-mcp.git && cd ssh-mcp
```

然后一条命令安装并接入本机所有已安装的 MCP 客户端：

```bash
python scripts/install.py --mcp-key mcp_xxx
```

已经 clone 过的机器上不用重复拉取，直接在仓库目录里跑第二条即可。脚本会安装本仓库、把 `ssh-mcp` 写进客户端，并验证命令能启动：

- **Claude Code**：优先调用 `claude mcp add -s user`，没有 CLI 时改 `~/.claude.json`
- **Claude Desktop**：标准版 `%APPDATA%\Claude`，3p 版 `%LOCALAPPDATA%\Claude-3p`
- **Cursor**：`~/.cursor/mcp.json`
- **VS Code / 通义灵码**：`%APPDATA%\Code\User\mcp.json`（`servers` 键）

`--dry-run` 只报告会改哪些文件；`--skip-install` 只写配置；`--clients claude,cursor` 限定目标；
`--from-wheel dist/xxx.whl` 在离线机器上安装。改动前会留 `.bak`，检测不到客户端的配置不会被创建。

### 不 clone 仓库的安装方式

私有仓库匿名拉不到原始文件，所以用 pip 直接装（需要本机有 GitHub 凭据，如 `gh auth setup-git`）：

```bash
pip install --user "git+https://github.com/ashu1800/ssh-mcp.git"
```

装完后再把密钥写进客户端配置，两种办法任选：

**用仓库里的脚本**（需要 checkout，见上一节）：

```bash
python scripts/install.py --mcp-key mcp_xxx --skip-install
```

**用 `claude mcp add`**（只接 Claude Code，不用 checkout）：

```bash
claude mcp add -s user ssh -e MCP_KEY=mcp_xxx -e SSH_MCP_ALLOWED_LOCAL_ROOTS=~/ssh-mcp-files -- ssh-mcp --transport stdio
```

## 更新已安装的机器

包版本号在两次提交之间不变，所以普通 `pip install` 会把现有安装视为已满足并**跳过**。更新必须显式强制：

```bash
python scripts/install.py --mcp-key mcp_xxx --update
```

`--update` 会 `--force-reinstall --no-deps` 重装当前提交的代码，然后照常重写客户端配置。只想重装包、不动配置时：

```bash
pip install --force-reinstall --no-deps "git+https://github.com/ashu1800/ssh-mcp.git"
```

已用 venv 安装的机器（`install.py` 默认），更新也会装回同一个 venv；用 `pip install --user` 装的机器用上面的 pip 命令即可。
更新后需要重启客户端（Desktop/Cursor 重启应用，Claude Code 新开会话）才会加载新进程。

## 客户端配置

`command` 必须是**绝对路径或 PATH 中的可执行文件名**——MCP 客户端不会继承你终端里的虚拟环境激活状态。
源码安装写 venv 里解释器的绝对路径，pip 安装则直接写 `ssh-mcp`。

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
