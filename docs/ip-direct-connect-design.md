# MCP 架构改造：AI 直传 IP / IP:port 连接

## 需求

1. AI 拿到 `IP` 或 `IP:port` 后**直接调用 connect**，不再走 list_servers → 匹配 server_id → connect 三步。
2. 解析、匹配全部在 MCP 工具内部完成；AI 只管传"它想连的地址"。
3. 同一 IP 存在多台服务器（不同端口）且 AI 只给了 IP 时，返回候选清单让 AI/用户**选择端口**后重试。

## 现状与根因（已核对源码）

| 组件 | 现状 | 缺口 |
|---|---|---|
| 后端 `GET /api/mcp/credentials` | 明文只返回 `server_id / alias / encrypted_blob_ref / auth_type / group_name` + 加密 blob（`credential.go:205-212`） | **host/port 只存在于密文 blob 内**，客户端不解密就不认 IP |
| 客户端 `CredentialClient._resolve`（`client.py:127-160`） | 三级：server_id 精确 → alias 精确 → id/alias 唯一子串 | 无任何 IP/端口解析分支；`"1.2.3.4:2222"` 必然 `server_not_found` |
| 客户端错误回包（`client.py:103-107`） | candidates 仅 `{server_id, alias}` | 无 host:port，AI 拿着 IP 也无法从候选里选 |
| 连接池（`pool.py:3`） | key 为 `(host, port, username)`，同 IP 多端口天然是多条连接 | 无缺口，只卡解析 |
| 本地历史（`history.py:30`） | 只记 alias + last_used | 帮不上 IP 匹配（本方案不依赖它） |

后端 `/mcp`（Go 服务端代连工具）**不受影响**：它按 `server_id` 寻址、自己建连，AI 从不传地址。

## 方案选型

- **A. 客户端拉全列表后逐 blob 解密建 host 索引** —— 不改后端，但要把用户名下所有机器的密码/私钥同时解出驻留内存，扩大敏感面，否决。
- **B. 凭证列表明文随附 host/port，客户端只做字符串匹配** —— 采纳。blob 本来就含 host/port 且客户端可解（token 在手），明文化**不降低机密性**；密码/私钥仍只存在于密文；列表接口从「故意不返回 host」改为「返回寻址所需的 host/port，继续不返回凭据」。
- **C. 再加一个服务端 resolve REST 端点**（`GET /api/mcp/credentials/resolve?q=IP[:port]`）—— 采纳，但定位是**给未来服务端组件复用**（后端 `server/service.go:259-352` 已有同语义的 IP→唯一性判定逻辑可复用），本地客户端直接用 B 的清单匹配即可，不多一次往返。

## 协议契约变更（版本 1 → 2，只增不改）

`GET /api/mcp/credentials` 出参每个 item 增加两字段：

```json
{
  "server_id": 12,
  "alias": "web-prod",
  "encrypted_blob_ref": "cred-12-v1",
  "auth_type": "password",
  "group_name": "生产",
  "host": "10.0.0.7",
  "port": 22,
  "blob": { "…原样不变…" }
}
```

- `crypto.version` **保持 1**：blob 的密码学信封（KDF/AEAD/AAD/字段）完全不变，明文寻址字段加在列表 item 层，不是 blob 层，无需版本协商。
- 老客户端：多余字段被忽略，行为不变 → 向后兼容，可先部署后端。✅ 已实现（后端 + 客户端，2026-11-05）。

## 后端改动

### 1. `internal/service/mcp/credential.go`

- `CredentialServerItem` 增加：

```go
Host string `json:"host" jsonschema:"主机地址，供调用方按 IP 直连寻址"`
Port int    `json:"port" jsonschema:"SSH 端口"`
```

- `listCredentialServers` 填 `item.IP` / `item.Port`。
- 更新 `credentialAlias` 注释：列表承诺从「不含 host」改为「不含凭据」；alias 兜底仍是 `服务器 #id`。

### 2. `credential_handler.go` 新增 `Resolve`（REST，供服务端组件）

```
GET /api/mcp/credentials/resolve?q=<ip|ip:port|id|alias>
→ 200 { data: { matches: [{server_id, alias, host, port, auth_type, group_name}] } }
```

- 命中 1 条返回 1 条；命中 0 条 `matches: []`；**绝不返回 blob/凭据**。
- 匹配顺序与客户端一致（见下），复用 `listCredentialServers` 的 owner 隔离 + ssh_ready 过滤。
- 路由挂 `middleware.MCPAuth` 之后（与 List 同组），鉴权/审计口径不变。
- 若暂无服务端消费方，此端点可后置到第二期——第一期纯客户端匹配已满足需求。

### 3. 文档

- 根 README（远程桌面管理）：契约表补 `host/port` 两行与 resolve 端点；「known_hosts/指纹」章节不受影响。
- 审计不变：`ServerIP` 字段已有记录（`credential_handler.go:129`）。

## 客户端（ssh-mcp）改动

### 1. `models.py`

`ServerSummary` 增加 `host: str | None`、`port: int | None`。`list_servers` 输出自然带上（含 host:port），原「不含任何明文连接信息」的 docstring 改为「不含凭据」。

### 2. `credentials/client.py` — `_resolve` 增加地址解析层

匹配顺序（每一步都在同一份缓存清单上）：

1. `server_id` 精确；
2. `alias` 精确（大小写不敏感）；
3. **`parse_target` 新函数**：输入含 `:` 且冒号右侧为纯数字 → `(host, port)`；纯 IPv4 / 域名（含 `[v6]`）→ `(host, None)`；解析失败返回 None，落到第 4 步；
4. `(host, port)`：清单里 host 不敏感相等 + port 相等 → 唯一命中即返回 blob；命中 0 继续；
5. `(host, None)`：host 相等 → 恰 1 条返回；**≥2 条返回 `ambiguous_ports`**；
6. 唯一子串（id/alias，保留现状兜底）。

### 3. 错误回包升级

- 新错误码 `ambiguous_ports`：

```json
{
  "error": "ambiguous_ports",
  "hint": "10.0.0.7 存在 2 个 SSH 端口，请从 candidates 选择后重试 connect",
  "candidates": [
    {"server_id": "12", "alias": "web-prod", "host": "10.0.0.7", "port": 22, "group_name": "生产"},
    {"server_id": "18", "alias": "web-prod-bt", "host": "10.0.0.7", "port": "2222", "group_name": "生产"}
  ],
  "next_actions": ["ask_user_then_retry_connect_with_port"]
}
```

- 现有 `server_not_found` 的 candidates 也带上 `host:port`（信息已明文可回，直接喂给 AI 纠正）。

### 4. `tools/servers.py` — connect 的 `server` 参数描述

改为：「用户给的 IP、`IP:port`、server_id 或别名均可（如 `10.0.0.7:2222` / `web-prod`）；同 IP 多端口且未指定端口时返回 `ambiguous_ports` 候选供选择；省略则重连最近一台。」其余逻辑不动。

## 安全边界（明确说出去）

- 列表仍不含密码/私钥；凭据只在 blob 密文里，按「token × server_id」HKDF 派生，模型密钥换即换。
- host/port/alias/group 视为**寻址元数据**：调用方（本地 MCP 进程 + 持 token 的 AI 会话）本就有能力解密获得，明文化不扩大泄露面；对外 HTTP 传输仍全程 TLS + Bearer 校验 + `no-store`。
- TOFU 主机密钥、known_hosts、指纹校验全在 connect 之后的 SSH 层，与本改动无关，不受影响。
- 审计与 owner 隔离不变。

## 实施顺序（先后有依赖）

1. **后端先行**：`CredentialServerItem` 加字段 + `go build ./... && go test ./...` + 契约 README。旧客户端无感。
2. **客户端跟进**：`_resolve` 解析层 + `ambiguous_ports` + 参数/文档措辞 + 跑 `make dev` 等价测试。后端未升时 host 缺失 → 第 4/5 步跳过，行为完全等同现状，无需探测版本。
3. 部署后升级 DSH 里连接的 MCP（旧 schema 还要求先 list → 连的是老版）。

## 验收清单

- [ ] `connect(server="10.0.0.7")` 唯一命中 → 直连成功。
- [ ] 同 IP 两台不同端口，`connect(server="10.0.0.7")` → `ambiguous_ports` + 带端口候选；`connect(server="10.0.0.7:2222")` → 直连 2222。
- [ ] `connect(server="web-prod")`、`connect(server="12")`、省略参数重连最近一台 —— 全部保持原行为。
- [ ] 后端未升级时客户端不报错（host 字段缺失走原子串兜底）。
- [ ] `list_servers` 输出含 host/port；`go test ./internal/...`、客户端 `pytest`、新格式 blob 解密往返全绿。
- [ ] 多账号同 IP 不同端口（用户场景）端到端验证一台 22 / 一台 2222。

## 测试要点

- 后端：`credential_test.go` 断言列表含 host/port、无凭据字段；`credential_http_test.go` 加 Resolve 端点用例。
- 客户端：`_resolve` 参数化单测（含 `[::1]:22`、`host` 无端口、大小写、IPv6）；`ambiguous_ports` 错误码回包形状；e2e mock 服务按新契约出参。
