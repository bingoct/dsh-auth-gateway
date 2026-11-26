# dsh-auth-gateway

dsh 的 Web 网关：**进程管理 + 健康检查 + cookie 维护 + 认证门禁 + 流量转发**。

单二进制、单配置文件，按需拉起 dsh 并替它持有、注入随进程变化的 v1 cookie。
HTTP / SSE / WebSocket 全协议转发，零外部依赖（Go 标准库）。

可执行文件名为 `dsh-auth-proxy`。

## 特色

- **认证门禁**：密码 + TOTP 双因子，单页一次 POST 全验完；登录带一次性挑战因子，
  重放的登录请求到不了因子校验。
- **会话时效只有一处真相：服务端台账**。票本身不含 `exp`，闲置滑动续期
  （`session_days` / `temp_hours`）与绝对硬顶（`session_abs_max_days`）分开判定，
  再活跃也绕不过硬顶；代数轮换把 cookie 被动泄露后的可用窗口压到轮换周期。
- **设备管理**：`device list` / `alias` / `revoke`，单设备撤销会立刻断开它的
  WebSocket / SSE 隧道（4401 Close 帧），不需要改密码。
- **来源门禁**：Origin / Sec-Fetch 校验先于一切转发，跨站 WebSocket 握手在进门时
  被挡（403）；`X-Forwarded-For` 只采信可信反代网段，从右往左跳过可信跳。
- **进程管理**：从 dsh 启动输出解析端口与 token，换取 v1 cookie；崩溃自动重建，
  启动失败进入退避，失败页直接显示 dsh 的 stderr 尾部。
- **审计**：认证事件（登录 / 登出 / 撤销 / 隧道开关）追加写 JSONL，
  不记凭据、票原文、动态码。

## 安装

```powershell
go install github.com/bingoct/dsh-auth-gateway/cmd/dsh-auth-proxy@latest
```

或从源码构建：

```powershell
git clone https://github.com/bingoct/dsh-auth-gateway.git
cd dsh-auth-gateway
go build -o dsh-auth-proxy.exe .\cmd\dsh-auth-proxy
```

要求 Go ≥ 1.27，无 CGO 要求（`-race` 需要 cgo 工具链）。

## 快速开始

```powershell
.\dsh-auth-proxy.exe config init      # 生成带注释的 gateway.toml（默认 ~/.dsh/gateway.toml）
# 编辑 gateway.toml：auth.public_origin 必填（https:// 你的对外地址）
.\dsh-auth-proxy.exe init             # 创建凭据：设置密码 + 生成 TOTP，打印二维码与 otpauth 链接
.\dsh-auth-proxy.exe                  # 启动网关，浏览器打开 public_origin
```

首次登录后浏览器拿到会话 cookie `dsh_dev`；勾选"长期设备"签发持久票，
不勾选则为浏览器会话级票。全部配置项与环境变量见
[docs/config-reference.md](docs/config-reference.md)。

## 命令

```
dsh-auth-proxy                      启动网关（等价于 serve，服务包装器用这个）
dsh-auth-proxy serve                同上，显式写出
dsh-auth-proxy init                 创建或轮换凭据，打印 otpauth 链接与终端二维码
dsh-auth-proxy init --password-only 只改密码，保留 TOTP（认证器不用重绑）
dsh-auth-proxy init --force         全量重置（密码 + TOTP，认证器要重绑）
dsh-auth-proxy config init          写出带注释的 gateway.toml 模板
dsh-auth-proxy device list          列已登录设备（别名 ls）
dsh-auth-proxy device alias --family <id> --name <名字>
                                    给设备起别名（只影响展示；空串清除）
dsh-auth-proxy device revoke        撤销单台设备（--family）或全部（--all）
dsh-auth-proxy version              打印版本
```

## 请求路径

```
client → 来源校验(Origin/Sec-Fetch) → 会话校验 → Ensure(dsh) → ReverseProxy → dsh
                                                                            ↑
                                    Host 改写 + 注入 v1 cookie + 剥离 Origin
```

- 上游 `Set-Cookie` 一律剥掉：v1 cookie 不出网关。
- `Origin`、`Referer`、`Sec-Fetch-*` 在转发前剥离；dsh 对缺失 Origin 的请求直接放行，
  保留反而会与改写后的 Host 冲突。

## 状态与观测

内部端点的路径每天轮换：`/_g/<12位HMAC片段>/<操作>`，片段由凭据派生的密钥按 UTC
日期计算，跨天自动切换。旧片段一律 404，不会落到 dsh 转发。

| 端点 | 内容 |
|---|---|
| `…/h` | `{"ok","totp","temp","dsh","state"}`，不触发拉起 |
| `…/s` | `{"state","pid","port","uptime_sec","idle_sec","active","last_error"}`，非本机需登录 |
| `…/r` | `POST` 终止当前 dsh，下一请求重新拉起。**只认 `local_cidrs`，非本机一律 404** |

dsh 状态四态：`stopped` / `starting` / `running` / `failed`。拉起期间返回 503 +
自动刷新；失败页显示 dsh 的 stderr 尾部。

`auth.enabled = false` 时登录端点一律 404——公网上留一张能回答"密码对不对"的
死登录页就是攻击者的探针。

## 空闲回收（默认关闭）

dsh 可能在跑定时任务或长任务，这类活动网关无法可靠观测，自动杀进程省下的内存
远不值任务中断的代价，所以 `[dsh] idle_reap = false` 是默认值。显式打开后，
三条同时满足才终止 dsh：无在途请求（`active == 0`）、距最后一次请求超过
`idle_min` 分钟、最近 5 分钟没有会话文件写入（扫 `~/.dsh/sessions/**/session.*.jsonl.zstd`
的 mtime）。

## 测试

```powershell
go test ./...                     # 109 个用例（含子测试）
go test -race ./...               # 数据竞争检测，需要 cgo 工具链
go test -tags integration ./...   # 额外跑真实 dsh 拉起的集成用例，要求本机能启动 dsh
```

覆盖：进程生命周期（拉起/超时/崩溃重建/停止/空闲回收）、转发（101 双向、chunked、
20MB 上传、逐块 flush、50 并发、HEAD、上游挂掉、客户端中断）、cookie（注入/重建/
隔离/不泄漏）、认证算法（scrypt 向量、RFC 6238 TOTP 向量、重放）、台账（滑动/硬顶/
轮换/撤销/重载）、配置（三层合并、默认值、非法配置拒绝）、CLI（命令树、别名、模板一致性）。

## 文档

| 文件 | 内容 |
|---|---|
| [docs/session-model.md](docs/session-model.md) | 设备票 + 服务端台账的时效模型；每个数值都有实测或代码依据 |
| [docs/auth-coverage.md](docs/auth-coverage.md) | 威胁模型与逐条防线，每条对应哪几行代码与哪个测试 |
| [docs/config-reference.md](docs/config-reference.md) | 全部配置项、环境变量、默认值与 CLI 命令 |
| [docs/deployment.md](docs/deployment.md) | 部署形态：直接运行、Scoop、计划任务、前置 gost + Traefik 的拓扑 |

## 许可

[MIT](LICENSE)。可商用、可闭源二次分发，保留版权声明即可。
