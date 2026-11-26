# 部署

网关本身是一个不写盘的静态二进制：配置、凭据、台账、审计全在 `~/.dsh` 下，进程只读。
这决定了它能用任何方式托管——前台、计划任务、systemd、容器都行，区别只在"谁负责拉起和重启"。

下面按复杂度分三种形态。前两种是通用做法，第三种是本机（Windows 宿主 + WSL 里的
Traefik）正在跑的公网拓扑，用来解释清楚每一跳为什么存在。

## 形态一：前台直接运行

```powershell
go build -trimpath -o dsh-auth-proxy.exe ./cmd/dsh-auth-proxy
.\dsh-auth-proxy.exe config init     # 生成 ~/.dsh/gateway.toml
# 改 auth.public_origin 与 server.listen_host
.\dsh-auth-proxy.exe init            # 建凭据，扫二维码绑认证器
.\dsh-auth-proxy.exe                 # 启动
```

要求：

- `auth.public_origin` 必填，且必须与浏览器地址栏一致（它决定 cookie 的 `Secure` 与来源校验基准）。
- `server.listen_host` 不是回环时，`public_origin` 必须是 `https://`，否则启动直接拒绝——
  明文 HTTP 上传口令等于把密码写在链路上。
- `dsh.bin` / `dsh.cwd` 留空时用默认值（`<用户目录>/scoop/apps/dsh/current/lib/bin.js` 与
  `<用户目录>/WorkBuddy/dsh`）。非 Scoop 安装必须显式指定。

## 形态二：Scoop + 计划任务（本机生产形态）

### 为什么不是 Windows 服务

先试过 WinSW 2.12 把网关注册成服务，失败：**同一个 XML，LocalSystem 能起，本地用户令牌在
会话 0 下直接以 1067 退出**，连日志通道都没建立。问题在 WinSW 与用户令牌的组合，不在配置。

网关又必须以用户身份跑：它要写 `~/.dsh`（台账、审计），要 spawn dsh，要继承用户的
PATH / USERPROFILE。用 LocalSystem 会把 `~/.dsh` 写成 SYSTEM 属主，后面 dsh 自己反而读不了。

所以网关改由**计划任务**托管：

- `LogonType=Interactive` + `RunLevel=Highest`，只在用户登录时跑，不存密码；
- `AtLogOn` 触发，延迟 30 秒——WSL 的 `vEthernet` 网卡要等 session 起来才存在，
  而配置里 `listen_host = "127.0.0.1,if:vEthernet (WSL)"` 解析不到会直接退出（fail-fast，不降级）；
- 动作是 `wscript.exe run-hidden.vbs`，不是直接跑 exe。Interactive 任务直接跑控制台程序
  会弹一个终端窗口；`wscript` 是 GUI 子系统程序，用
  `sh.Run("cmd /c ... >> log 2>&1", 0, True)` 隐藏窗口并把输出落盘，退出码经 `WScript.Quit`
  回传，Task Scheduler 才能判定失败并触发重启。

gost 那边相反，无状态、不碰用户目录，所以用 WinSW 跑 LocalSystem 服务（`gost-8443`）。

### 安装顺序

1. `deploy.ps1`：`go build` → 打包 → 以 Scoop 应用 `dsh-auth-proxy` 安装（应用名与 exe 名不变，
   PATH shim 与既有快捷方式不用改）。
2. `install-services.ps1 install`：只装 gost-8443；顺带把历史遗留的同名 Windows 服务卸掉。
3. `install-task.ps1`：注册计划任务（需要管理员）。它会先停掉同名服务与残留进程，
   避免两个实例抢 33080。

### 升级与回滚

`deploy.ps1` 检测到网关进程在跑会直接拒绝（`dsh-auth-proxy is running`）。正确顺序：

```powershell
Stop-ScheduledTask -TaskName dsh-auth-proxy
pwsh -File scripts\deploy.ps1
Start-ScheduledTask -TaskName dsh-auth-proxy
```

回滚就是把 manifest 的 `version` / `url` / `hash` 指回上一版 zip，重跑 `install`。
Scoop 对"同一版本"的 install 是 no-op，所以每次构建都用带时间戳的版本号。

## 形态三：前置 L4 转发 + HTTPS 反代（本机公网拓扑）

```
外网 (IPv6)
  │  AAAA → 宿主公网 IPv6
  ▼
gost  [::]:8443  ── 注入 PROXY protocol v2 头
  │  tcp → 127.0.0.1:443
  ▼
Windows wslrelay  127.0.0.1:443 → WSL
  ▼
Traefik (WSL 容器, 443)  ── 采信 PROXY 头、TLS、Host 路由
  │  http → win.local:33080
  ▼
dsh-auth-proxy  127.0.0.1:33080 + <vEthernet 地址>:33080
  │  spawn / 转发
  ▼
dsh（端口由系统分配，网关从启动输出里解析）
```

各跳职责与它解决的问题：

| 跳 | 组件 | 职责 | 端口 |
|---|---|---|---|
| 1 | gost | IPv6 接入；在 TLS 之前写入 PROXY v2 头 | `[::]:8443` |
| 2 | wslrelay | Windows 回环 → WSL 的端口转发（系统组件） | `127.0.0.1:443` |
| 3 | Traefik | 证书、Host 路由、采信 PROXY 头拿真实来源 | WSL 内 443 |
| 4 | 网关 | 认证、设备台账、cookie 注入、转发 | `127.0.0.1:33080` + vNIC 地址 |
| 5 | dsh | Web UI / API / WebSocket | 系统分配 |

三条硬约束，违反任何一条都会静默拿错来源地址或直接断 TLS：

1. **PROXY 头必须在 TLS 之前**。它是一段裸字节前导（v1 是文本行，v2 是 12 字节签名 + 地址），
   由 L4 代理写、由第一个终止 TLS 的组件读。写在 TLS 之后就没有意义了。
2. **Traefik 必须显式信任写入方**。`proxyProtocol.trustedIPs` 只列 WSL 网关与回环；
   不配这项 Traefik 会把 PROXY 头当成 TLS 记录解析，握手直接失败；配成 `0.0.0.0/0`
   则任何人都能伪造来源 IP。
3. **端口转发会换源**。Windows 的 `netsh portproxy` 转发后，容器看到的来源是转发器自己
   （端口也会变），所以这里不用 portproxy，改由 gost 注入 PROXY 头；实测直连 WSL 网卡时
   来源是宿主在 WSL 网段的地址（`172.x.x.1`），属于宿主发起的连接，同样不是真实客户端。

若整条链上没有 gost 这一跳（比如只在本机访问），Traefik 的 `trustedIPs` 必须去掉，
否则没有 PROXY 头的连接会被拒绝。

## 配置要点

```toml
[server]
# 回环 + 一块会变的网卡：保留本机调试，同时让 WSL 里的 Traefik 能连进来
listen_host = "127.0.0.1,if:vEthernet (WSL)"
listen_port = 33080

[auth]
public_origin = "https://dsh.example.com"   # 必填，与浏览器地址一致
session_days = 14
session_abs_max_days = 30

[network]
# 真实来源由 Traefik 通过 X-Forwarded-For 传进来，它落在私有网段里，
# 所以这里必须信任；若链路里没有反代，改回 false，否则客户端可以自带 XFF 伪造来源。
trust_proxy = true
proxy_trusted = "172.16.0.0/12,10.0.0.0/8,192.168.0.0/16"
local_cidrs = "127.0.0.0/8,::1/128"
```

`if:<网卡名>` 在启动时解析一次并打日志，解析失败直接退出——这是有意的：
监听地址错了却继续跑，表现是"服务活着但外面连不上"，比启动失败难查得多。

真实 IP 的传递路径只有一条：

```
客户端 IPv6 → PROXY v2 头（gost 写）→ Traefik 采信、写 XFF → 网关从右往左跳过可信跳
```

网关不直接读 PROXY 头；它只认 XFF，并且只在来源属于 `proxy_trusted` 时才认。
台账把完整地址折成网段存（IPv4 折 /24，IPv6 折 /56），既避免运营商换地址就掉线，
也避免把精确位置长期留在磁盘上。

## 数据与日志

| 路径 | 内容 |
|---|---|
| `~/.dsh/gateway.toml` | 配置与 `[credentials]`（init 写入，运行时只读） |
| `~/.dsh/sessions.json` | 设备台账：family / 别名 / 模式 / IP 段 / UA 哈希 / 首次登录 / 最近活动 |
| `~/.dsh/audit.jsonl` | 审计：登录成败、隧道开关、撤销、旧代数被拒 |
| `~/.dsh/logs/gateway/stdout.log` | 计划任务下网关的 stdout + stderr（追加） |
| `~/.dsh/logs/gost/` | gost 的 WinSW 轮转日志 |

## 排障顺序

按链路从外往里，每一步都能独立判定：

1. `netstat -ano | findstr :8443` —— gost 是否在听（双栈时 TCPv4 与 TCPv6 两张表都会出现）。
2. 外部拨测 `https://<域名>/` —— 证书是否正常。证书错说明 PROXY 头没被正确采信或没写。
3. 看 Traefik 日志里的来源地址 —— 是真实公网 IP 还是 `172.x.x.1`。后者说明 PROXY 头没到。
4. `curl -s http://127.0.0.1:33080/` —— 网关自身是否活着（本机来源免认证）。
5. `dsh-auth-proxy device list` —— 登录是否落到台账、IP 段是否符合预期。
6. 网关日志里的 `[gateway] listening on ...` —— 实际绑定了哪些地址。
