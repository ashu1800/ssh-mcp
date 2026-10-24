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

在任意一台已装好 Python 的机器上执行：

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
| `SSH_MCP_ALLOWED_LOCAL_ROOTS` | 空（不限制） | 可选。设置后本地**读写**都只允许这些目录（`os.pathsep` 分隔，realpath 校验，symlink 解析后判断） |
| `SSH_MCP_WRITE_LOCAL_ROOTS` | 空（不限制） | 可选。只限制**写入**（下载落盘）的目录，读取不受影响 —— 推荐用它代替上面那条，既能读构建产物又不会污染其它目录 |
| `SSH_MCP_POOL_MAX_ENTRIES` | 64 | 同时保持的 SSH 连接上限，超限时淘汰最久未用的空闲连接 |
| `SSH_MCP_POOL_IDLE_TIMEOUT` | 300 | 空闲多少秒后关闭 socket（**handle 仍然有效**，下次调用自动重连） |
| `SSH_MCP_POOL_HANDLE_TTL` | 3600 | 连接关闭后 handle 再保留多久；超时才彻底失效 |
| `SSH_MCP_MAX_CONCURRENT_CONNECTS` | 4 | 同时进行的 SSH 握手上限；防止对卡住的主机堆积半开连接 |
| `SSH_MCP_STATE_DIR` | `~/.ssh-mcp` | known_hosts、Ed25519 私钥、认证状态 |
| `SSH_MCP_SFTP_BLOCK_SIZE` | 256 KiB | SFTP 请求流水线块大小 |
| `SSH_MCP_SFTP_IDLE_TIMEOUT` | 180 s | 完全无进展多少秒才中止。这是**下限**：链路慢时按上一次分块耗时自动放宽（见「传输语义」） |
| `SSH_MCP_SFTP_TOTAL_TIMEOUT` | 0（关闭） | 可选的总时长上限 |
| `SSH_MCP_SFTP_RETRY_ATTEMPTS` | 3 | 断线/停滞后的自动续传次数，0 关闭 |
| `SSH_MCP_SFTP_RETRY_DELAY` | 3 s | 首次重试前等待，之后每次翻倍（上限 60 s） |
| `SSH_MCP_HTTP_TOKEN` | 空 | HTTP 入站 Bearer；绑定非回环地址时必填 |
| `SSH_MCP_LOG_LEVEL` | INFO | 日志只写 stderr，敏感串自动脱敏 |

全部变量见 `.env.example`。

## 一键安装并接入客户端

先取得代码：

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
- **Windsurf**：`~/.codeium/windsurf/mcp_config.json`
- **Trae / Qoder**：`%APPDATA%\<App>\User\mcp.json`
- **WorkBuddy**：`~/.workbuddy/mcp.json`
- **ZCode（智谱）**：`~/.zcode/cli/config.json`（`mcp.servers` 键，桌面端与 CLI 共用）
- **DSH 桌面端 / Web 端**：各自 profile 的 `~/.dsh/profiles/{desktop,web}/cordis.patch.yml`

客户端按「已安装才写」处理：配置文件、应用数据目录或可执行文件任一存在即视为已安装，否则跳过。

### DSH 的两个端

DSH 的桌面端与 Web 端是两套独立的 profile 根，各自从 `profiles/<name>/cordis.patch.yml` 读 MCP 服务器，
所以两边都要写才会同时生效。脚本只动面板管的那一段：

```yaml
# >>> dsh-skill-mcp-panel:mcp:begin
- insert:
    - id: panel-mcp-ssh
      name: "@deepseek-ai/dsh-mcp-client"
      config:
        serverName: ssh
        transport: stdio
        command: C:\...\ssh-mcp.exe
        args:
          - --transport
          - stdio
        env:
          MCP_KEY: mcp_xxx
# <<< dsh-skill-mcp-panel:mcp:end
```

同一文件里的其它插件配置、模型 provider 和其他 MCP 服务器（含它们的凭据）逐字节保留；
重复运行只替换 `panel-mcp-ssh` 这一条。`~/.dsh/skill-mcp-manager/registry.json` 是面板根据这些行
生成的缓存，不需要单独写。DSH 的 HMR 会热加载改动，桌面端若没反应重启一次即可。

`--dry-run` 只报告会改哪些文件；`--skip-install` 只写配置；`--clients claude,cursor` 限定目标；
`--from-wheel dist/xxx.whl` 在离线机器上安装。改动前会留 `.bak`，检测不到客户端的配置不会被创建。

### 不 clone 仓库的安装方式

下载安装脚本并运行即可，脚本发现不在仓库目录时会自动从 GitHub 安装：

```bash
curl -fsSL https://raw.githubusercontent.com/ashu1800/ssh-mcp/main/scripts/install.py -o ssh-mcp-install.py
```

```bash
python ssh-mcp-install.py --mcp-key mcp_xxx
```

也可以只装包、不改客户端配置（之后用 `claude mcp add` 手动接）：

```bash
pip install --user "git+https://github.com/ashu1800/ssh-mcp.git"
```

```bash
claude mcp add -s user ssh -e MCP_KEY=mcp_xxx -- ssh-mcp --transport stdio
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

### 客户端正在运行时更新

Windows 不允许替换正在运行的 `ssh-mcp.exe`，而 MCP 客户端会把它一直启动着，所以更新时 pip 必然报
`[WinError 32] 另一个程序正在使用此文件`。这**不是**安装失败：脚本会自动重新装好包本体，只把
启动器换成 `python -m ssh_mcp` 写进客户端配置，功能完全等价，不关客户端也能完成更新。

要彻底刷新启动器本身，先退出启动了 ssh-mcp 的客户端（或在其 MCP 设置里停用该服务器）再跑一次即可。

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
        "MCP_KEY": "mcp_xxx"
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

### ZCode

ZCode 的桌面端与自带 CLI 读同一份 `~/.zcode/cli/config.json`，服务器放在 `mcp.servers` 下，
条目形态与 VS Code 一致（多一个 `type`）：

```json
{
  "mcp": {
    "servers": {
      "ssh": {
        "type": "stdio",
        "command": "python",
        "args": ["-m", "ssh_mcp"],
        "env": { "MCP_KEY": "mcp_xxx" }
      }
    }
  }
}
```

这份文件同时是 ZCode agent 自己的配置（主题、provider、其它 MCP 服务器都在里面），
`install.py` 只增删 `mcp.servers.ssh` 一项，其余键原样保留，写前留 `.bak`。
改完在 ZCode 的「设置 → MCP 服务器」里能看到该条目；若列表没刷新，重启一次应用。

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
| `disconnect` | 关闭连接（handle 随之失效） | ✓ |
| `execute_command` | 执行非交互命令，超时终止远端进程 | – |
| `upload_file` / `download_file` | 单文件传输 | 覆盖时 ✓ |
| `upload_files` / `download_files` | 批量传输（并发限流） | 覆盖时 ✓ |
| `list_directory` / `stat_file` | 目录与元信息 | – |
| `make_directory` | 建目录（可递归） | – |
| `remove_path` | 删除文件/空目录（递归需显式） | ✓ |
| `rename_path` | 重命名/移动 | ✓ |
| `change_permissions` | 改权限（八进制） | ✓ |
| `get_connection_stats` | 连接池与运行计数 | – |

### 语义化运维工具

下面这些不是"多几个工具"，而是**把容易写错的 shell 拼装固化下来**。AI 直接说"nginx 在跑吗"即可，
不必自己拼 `systemctl | grep`，也就不会踩到分页器、`-f` 跟随、引号里带 `|` 这类坑。

| 工具 | 用途 |
|---|---|
| `get_service_status` | 单个 systemd 服务的状态、自启、PID、重启次数、最近 20 行日志 |
| `list_services` | 按 running / failed 列出服务 |
| `tail_log` | 日志尾部，支持 `journalctl -u` 或文件 `tail -n`，**永不跟随** |
| `get_disk_usage` | 各挂载点使用率，≥85% 时给出 warning |
| `get_system_overview` | 主机名、内核、发行版、uptime、负载、内存、CPU 数 |
| `list_processes` | 按 CPU/内存排序的进程列表（批处理版 top） |
| `list_listening_ports` | 监听端口及占用进程 |

### 握手并发上限

`SSH_MCP_MAX_CONCURRENT_CONNECTS`（默认 4）限制**同时进行的 SSH 握手数**。这不是性能参数，是保护措施：

一台接受了 TCP 却不回应握手的机器，每次连接尝试都会在客户端留下一条半开 socket（`FIN_WAIT2`，
内核持有，用户态关不掉），要等系统超时才回收。客户端在 `retryable: true` 上重试时，这个数量会成倍累积——
表现就是服务端 `sshd` 进程数暴涨、`who` 显示大量未完成登录。

闸门把并发压在 4，重试再多也只会排队。`get_connection_stats` 的 `counters.connect_failures`
能看到失败次数，`errors` 里能看出是哪类失败占主导。

### connection_handle 的生命周期

handle 只在两种情况下失效：**显式 `disconnect`**，或关闭后超过 `SSH_MCP_POOL_HANDLE_TTL`（默认 1 小时）。

中途的空闲回收、网络抖动、服务器重启都**不会**让它失效：池子关掉 socket 但保留 handle，
下次用同一个 handle 调用时会自动重新取凭据并重连（`get_connection_stats` 里的
`connections_reestablished` 计数会 +1）。重连时凭据会重新拉取，所以改过密码也能恢复。

早先的版本会在回收时连 handle 一起删掉，导致"闲置几分钟后再操作"必定报
`connection_not_found` —— 那是个缺陷，已修正。

### 省略 connection_handle

`connect` 之后，后续工具可以**不传** `connection_handle`，默认用最近一次使用的连接。
适合"一连上就连续操作同一台机器"的场景，省掉每次复制 handle。多台机器交替操作时仍应显式传。

> 该默认值只在 stdio（单用户）下有意义；HTTP 传输是无状态的，多个调用方共用一个进程，
> 省略 handle 会串号，因此 HTTP 场景请始终显式传。

所有工具返回结构化 JSON；失败时 `is_error=true`，字段含 `error`、`stage`、`hint`、`retryable` 与
`next_actions`（机器可读的下一步，如 `call_connect`、`ask_user_then_retry_with_confirm`）。
工具同时带 MCP 注解：`readOnlyHint`（只读）、`destructiveHint`（破坏性）、`idempotentHint`（重复执行结果一致）。

## 传输语义

- 数据先写 `<目标>.part`，校验通过后原子重命名；中断保留 `.part` 以便续传。
- 续传前校验 `.part` 不超过源大小，超出则丢弃重传。
- `verify=size` 默认；`sha256` 会分别计算源/目标哈希（返回 `hash_seconds`）。
- 进度按 **每 1% 或每 5 秒** 节流，通过 MCP progress notification 上报。

### 超时与自动续传

传输的超时不是一个固定秒数，而是一个**会随实际速度放宽的下限**：

```
单步允许时长 = max(SSH_MCP_SFTP_IDLE_TIMEOUT, 4 × 上一次分块耗时)
```

固定的 60 秒在局域网上很宽松，但在丢包的移动网络或跨境链路上，1 MiB 分块本身就可能传上一分钟——
传输明明在走，却被判成超时。改成自适应后，**慢但活着**永远不会触发超时，**完全没动静**仍会在
`SSH_MCP_SFTP_IDLE_TIMEOUT`（默认 180 秒）后放弃。

超时或断链后不再直接把错误抛给调用方：引擎会换一条新的 SFTP 通道（必要时经由连接池重连，
`connection_handle` 不变），从 `.part` 里**实际落盘的字节数**继续传，最多 `SSH_MCP_SFTP_RETRY_ATTEMPTS`
次，间隔按 `SSH_MCP_SFTP_RETRY_DELAY` 指数退避。

只重试确实可能自愈的错误（连接丢失、SFTP 会话中断、停滞）。权限拒绝、文件不存在这类服务端明确答复
不会重试——它们每次都一样，重试只是把同一个结果延迟几分钟。重试预算用尽后仍返回
`transfer_idle_timeout` / `transfer_failed`，`.part` 保留，可再次调用续传。

## 安全

- 密码/私钥只在内存；日志过滤器会脱敏 `mcp_` 令牌、PEM 私钥与 `password` 字段。
- 本地传输默认**不限制路径**（AI 可以直接上传构建产物）；`SSH_MCP_WRITE_LOCAL_ROOTS` 只约束写入，
  `SSH_MCP_ALLOWED_LOCAL_ROOTS` 同时约束读写，两者都经 `realpath` 校验且拒绝 symlink 逃逸。见「已知取舍」第 4 条。
- `known_hosts` 位于 `~/.ssh-mcp/known_hosts`；首次信任后指纹变化会拒绝连接。
- HTTP 默认绑定 `127.0.0.1`，校验 `Origin`，可要求 Bearer；绑定非回环地址而未设置 Token 时拒绝启动。
- 私钥文件 600、目录 700（Windows 上权限位语义有限，依赖文件系统 ACL）。

## 开发

**所有开发操作都走这一个入口**，不要手动 `pip install -e .`：

```bash
make dev          # 首次：建 venv、装依赖、把 src/ 放到 import 路径
make test         # 跑测试（自动校验真的在跑 src/，否则直接拒绝）
make doctor       # 体检：当前 import 到哪份代码、有没有残留、有没有进程占用
make install      # 拉了新代码后刷新依赖
make serve        # 用 src/ 起服务
make clean        # 清 build/缓存/pip 残留
```

Windows 上没有 GNU make 时，用等价命令：`python scripts/dev.py setup|test|doctor|install|serve|clean`。

### 为什么不用 `pip install -e .`

两个坑，都踩过：

1. **Windows 不允许替换正在运行的 exe。** MCP 客户端把 `Scripts/ssh-mcp.exe` 一直开着，pip 重建它时
   `[WinError 32]` 失败。更糟的是 pip 在失败**之前**已经把旧的包目录改名为 `~ssh_mcp`，于是环境变成
   "没有可导入的 `ssh_mcp`" —— 原本能用的命令反而坏了。
2. **非 editable 安装会遮蔽 `src/`。** `site-packages/ssh_mcp` 在 `sys.path` 里优先于 `.pth`，
   测试会在你毫无察觉的情况下对着旧代码通过。

`scripts/dev.py` 的做法是**不生成 console script**：往 venv 写一个 `_ssh_mcp_dev.pth` 指向 `src/`，
直接用 `python -m ssh_mcp` 运行。没有 exe 就没有锁，改完代码即时生效。`doctor` 和 `test`
都会在不注入 `PYTHONPATH` 的前提下检查 `import ssh_mcp` 落在哪里，确保校验的是真实状态。

### 测试

```bash
make test                                  # 等价于 python scripts/dev.py test
python scripts/dev.py test -q -k sftp      # 透传 pytest 参数
SSH_MCP_RUN_LARGE=1 python scripts/dev.py test -m large -q   # 1 GB 内存基线
```

## 已知取舍

1. SSH 压缩在连接级协商，因此只能按连接配置：`auto` 与 `on` 等价（协商 zlib），`off` 关闭压缩。连接在 `connect` 时建立，此时还没有目标文件，池 key `(host, port, username)` 也不含压缩维度，所以不做按文件扩展名的判断；需要为大批已压缩文件关压缩时，把 `SSH_MCP_COMPRESSION=off` 并重新 `connect`。
2. HTTP 无状态模式下，客户端断开会触发请求取消；`json_response=False`（默认 SSE）是保证进度与取消可用的前提。
3. Windows 上无法设置 POSIX 权限位，`chmod` 作用于远端不受影响，本地密钥文件权限依赖 ACL。
4. 本地路径默认不限制，是因为 AI 常需要上传源码树里的构建产物，强制单一目录会让每次上传都先失败一次。
   代价是这个 MCP 进程能读到你账号可达的任何本地文件，包括 `~/.ssh` 下的私钥。如果要收紧，设置
   `SSH_MCP_ALLOWED_LOCAL_ROOTS`（多个根用系统路径分隔符隔开），或用安装脚本的 `--allowed-roots`。
   注意这是**进程级权限**，不是按会话隔离：同一实例的所有客户端共用同一份限制。
