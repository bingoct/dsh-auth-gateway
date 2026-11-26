# 会话模型设计（v1 设备票 + v2 隧道凭据）

> 状态：**已实现**（见 §12）。取代此前的 `dsh_sid`(10min) + `dsh_rt`(30d) 双票方案。
> 本文的每个数值都来自实测或代码，不来自推断；推断处会标注「推断」并给出验证方式。

## 0. 事实基础

### 0.1 dsh 自带 WS 心跳（已核实）

本机 dsh 0.2.2-rc.1，`@deepseek-ai/dsh-api-gateway/lib/index.js`：

```js
startHeartbeat() {                                   // :376
  this.heartbeatTimer = setInterval(() => {
    for (const socket of this.server.clients) {
      if (socket.readyState !== WebSocket.OPEN) continue
      const missed = this.missedHeartbeats.get(socket)
      if (missed >= MAX_MISSED_HEARTBEATS) { ... socket.terminate(); continue }
      this.missedHeartbeats.set(socket, missed + 1)
      socket.ping()
    }
  }, this.heartbeatIntervalMs)
}
```

默认 `DEFAULT_WEBSOCKET_HEARTBEAT_INTERVAL_MS = 2e3`（`:717`），本机配置未覆盖。

**推论（这条决定了隧道能不能做读超时）**：
- 服务端每 2s 发 Ping（下行）
- 浏览器收到 Ping 自动回 Pong（上行，JS 无法拦截也无法伪造）
- 所以 WS 连接**两个方向都每 2s 至少有 2 字节流动**

因此读超时阈值只要显著大于 2s（取 60s，容忍 30 次心跳丢失），活跃连接不会被误断；真正的死连接（半开 TCP）会在 60s 内被发现。

### 0.2 SSE 没有周期保活（已核实）

`api-gateway` 里只有 `text/event-stream` 的类型判断（`:205`）与 `flushHeaders()`（`:265`），没有周期性注释帧写入。所以 SSE 的**上行方向长期无数据**，不能设短读超时。

处理方式见 §5.4。

## 1. 两层凭证

| | v1 设备票 | v2 隧道凭据 |
|---|---|---|
| 存在哪 | 浏览器 cookie `dsh_dev` | **只在网关内存**，不下发 |
| 客户端能看到 | 是（HttpOnly，JS 读不到） | 否，客户端根本不知道它存在 |
| 形态 | 自包含签名票（HMAC） | 随机 16 字节 + 服务端结构体 |
| 寿命 | 由服务端台账判定（idle + abs） | 与那条 conn 同生共死 |
| 谁能失效 | 删台账记录（CLI/同进程） | conn 关闭 / 撤销 / 空闲超时 |
| 回答什么问题 | 你是谁、这台设备还能不能用 | 这条管道属于谁、该不该继续 |

v2 不下发 cookie 是刻意的。官方需要 v2 cookie，是因为它的 HTTP API 请求要拿 v2 去引用一个 API Peer；我们的所有 HTTP 请求都走 v1，没有任何场景需要客户端持有 v2。少一枚可被复制的凭据，少一类泄露面。

## 2. v1：设备票

### 2.1 cookie 内容

```
dsh_dev = v1.<b64u(payload)>.<b64u(HMAC-SHA256(key, "v1."+b64u(payload)))>

payload = {
  "v": 1,
  "fam": "<family id，128 位随机，base64url 22 字符>",
  "mode": "temp" | "persist",
  "iat": <首次登录 unix 秒>,
  "ip": "<绑定值，见下方粒度表>",
  "ua": "<UA 的 sha256 前 16 位 hex>",
  "gen": <轮换代数，登录时为 1，之后按周期递增>
}
```

**绑定粒度按档位分**（`auth.BindIP`）：

| 模式 | IPv4 | IPv6 | 理由 |
|---|---|---|---|
| `temp` | 完整地址 `/32` | 完整地址 `/128` | 非信任设备，换地址即失效；temp 只活 6h，隐私地址轮换影响不到它 |
| `persist` | `/24` | `/56` | 信任设备，容忍家宽重新拨号换 IPv6 前缀；`/56` 是运营商给家庭的整块，`/64` 会随重拨变化 |

- 签名密钥：`sha256("dsh-session-v3:" + password_hash)`，与现有 HMAC 票同源派生，改密码即全量失效。
- 属性：`HttpOnly; SameSite=Strict; Path=/`，HTTPS 时加 `Secure`。
- `Max-Age` **按档位不同**：
  - `persist` → 30 天（写进磁盘，关浏览器仍在）
  - `temp` → **不写 Max-Age**（会话 cookie，浏览器进程结束即丢弃）

  cookie 生命周期只决定"浏览器还带不带这张票"，不是安全边界。服务端判活始终看台账的 idle/abs，所以关浏览器丢掉 temp 票，并不会让台账里那条记录提前失效（它要等空闲 2h 才被回收）。

**payload 里不带 exp**。原因：如果 cookie 自己带 exp，就产生「cookie 说没过期、服务端说过期」两套真相。时效完全交给服务端台账，只保留一个判断点。

**已知边界**：payload 是 base64 而非加密，浏览器物理上存着明文（fam/iat/ip 段/ua 哈希）。JS 读不到（HttpOnly），但内存 dump 或 cookie 导出能读。加密（AES-GCM）列为待选项，不在本轮。

### 2.2 服务端台账（`~/.dsh/sessions.json`）

```json
{
  "version": 2,
  "sessions": [
    {
      "family": "9f3a7c2e8b1d4a6f",
      "device": "Edge/Windows",
      "mode": "persist",
      "ip": "1.2.3.0/24",
      "ua": "a7f3c9d1e0b24568",
      "created_at": 1732430000,
      "last_seen": 1732433600
    }
  ]
}
```

一条记录 = 一台设备 = 一条 family。相比现有 `RefreshRecord`：删掉 `hash`（没有 refresh 原文了）、`expires_at`（改由 idle/abs 算）、`used_at`（没有轮换）；`persist` 改为 `mode`。

### 2.3 时效模型：idle + abs

| 档 | idle（多久不用就失效） | abs（从登录起最长多久） | cookie Max-Age |
|---|---|---|---|
| 临时（不勾保持登录） | `temp_hours` = 2h | `temp_abs_hours` = 6h | 6h |
| 持久（勾保持登录） | `session_days` = 14d | `session_abs_max_days` = 30d | 30d |

判活函数（服务端唯一真相）：

```
active(s, now) = (now - s.last_seen < idle(s.mode))
              && (now - s.created_at < abs(s.mode))
```

四象限：

| 场景 | 结果 |
|---|---|
| 临时用户连续用 5 小时 | 一直可用（last_seen 每次请求刷新） |
| 临时用户用 10 分钟就走，2 小时后回来 | 失效（超 idle），需重新登录 |
| 临时用户连续用 6 小时 | 失效（abs 到点），必须重新登录 |
| 持久用户隔夜打开 | 可用（14d idle 内，30d abs 内） |
| 持久用户 15 天没开 | 失效（超 idle） |
| 持久用户连续用 31 天 | 失效（abs 到点） |

**关于滑动**：滑动在这里是「刷新 last_seen」，不是「重签 cookie」。收益拿到了（常用设备不掉线），代价是零——不需要 Set-Cookie 重签、没有 101 响应写 cookie 的兼容性问题、没有多标签页并发重签的竞态。

### 2.3.1 连接活跃也算活跃

`last_seen` 不只在 HTTP 请求时刷新。用户挂着 WS/SSE 干活时可能几小时不发一个新请求，
只看 HTTP 会让"连接还活着、人还在用"的会话被判定闲置。

所以隧道读到字节时调 `Ledger.Touch(family)`（节流落盘），语义是：
**HTTP 请求和隧道上的字节流动都是活跃证据。**

`Touch` 只刷新 `last_seen`，不判活、不建记录：
- 已撤销的 family 调 Touch 无效（不复活）
- 一直活跃的隧道也绕不过 `abs`（`TestLedgerTouchCannotBypassAbs` 锁这一条）

**为什么官方不滑动、我们可以**：官方撤销只能换签名密钥（全设备一起掉线），所以滑动等于让泄露的 cookie 无限续命。我们有台账，能删单条，滑动的风险被 `abs` 和「可撤销」双重框住。

### 2.4 last_seen 写盘策略

- 内存里每请求更新 `last_seen`
- 刷盘节流：某条记录的 `last_seen` 与磁盘值相差 ≥ 60s 才落盘；另有 60s 定时刷
- **写盘前必须 merge，不能 reload 覆盖**：
  - 磁盘有、内存没有的 family → 尊重磁盘（说明被 CLI 撤销了，删内存）
  - 内存有、磁盘没有的 family → 说明被撤销，**不写回**
  - 都存在 → 用内存的 `last_seen`，其余字段以磁盘为准

这条是防「网关刷盘把 CLI 的撤销覆盖回去」。现有实现是 reload 覆盖，必须改。

### 2.5 代数轮换：让被动泄露的 cookie 自动作废

`last_seen` 滑动有一个挡不住的场景：**cookie 被复制后攻击者只是持有、暂不使用**。他手里那枚和你手里的一模一样，服务端分不出谁是谁，只能靠 IP/UA 绑定或你去 `revoke`。

代数轮换补上这一层：

- 票里带 `gen`（代数）
- 台账带 `gen` / `prev_gen` / `gen_at`
- 每 `rotate` 周期（临时 30 min、持久 24 h）推进一代：`prev_gen = gen; gen++; gen_at = now`，并在响应里下发新 cookie
- 旧代数的票立即失效（`ErrSessionStale`）

**为什么不是"每次请求都换"**（标准 refresh token rotation）：

| | 每次请求换 | 定期换（本方案） |
|---|---|---|
| 要存"用过的票" | 要 | 不要，只存一个代数 |
| 多标签页 | 每次请求都可能撞 | 只在轮换那一刻撞一次 |
| 长连接 | 不重新握手就换不到 | 同样（见下方代价） |
| 复杂度 | 高（宽限 + 重用表） | 一个字段 + 一个分支 + 10 秒宽限 |

**多标签页为什么不是问题**：同域共享一个 cookie jar。标签页 A 收到新 cookie，B 下次请求自动带新的。只有 A、B **同时**发请求时，两个请求都带旧代数——第一个把代数 +1，第二个落在 10 秒宽限里，被接受并回当前代。

**代价（要认）**：

- 已建立的 WS/SSE 不重新握手，轮换不影响它们，它们也不触发轮换
- 纯 WS、一个 HTTP 请求都不发的用户不会轮换，泄露窗口回到 `abs`
- 每次轮换要写一次盘（代数变更必须立即持久化，否则重启后旧票复活）

**收益的准确表述**：轮换的主要价值不是"挡住"，是"暴露"。

| 顺序 | 结果 |
|---|---|
| 用户先用 | 攻击者手里的旧代数作废，用不了 |
| 攻击者先用 | 他触发轮换，用户下次被拒（`ErrSessionStale`），被迫重登 → **异常可见** |
| 两边交替 | 互相把对方踢掉，审计里一串 `stale` → 一眼看出被动过 |

泄露窗口从 `abs`（6h / 30d）压缩到 `rotate + 10s`（30min / 24h）。

## 3. v2：隧道凭据

```go
type Tunnel struct {
    ID        string    // 16 字节随机，日志与审计用，不对外
    Family    string    // 来自 v1 payload.fam
    Kind      string    // "ws" | "sse"
    Conn      net.Conn  // 浏览器侧
    Upstream  net.Conn  // dsh 侧
    CreatedAt time.Time
    LastRead  atomic.Int64 // 最近一次读到字节的 unix 秒（两方向都会刷新）
}
```

表结构：`map[string]map[*Tunnel]struct{}`，外层 key 是 family。一个 family 可以有多条 tunnel（多标签页），**不照抄官方的「一 peer 一 socket / 409」**——那条约束是给 API Peer 用的，我们允许多标签页。

生命周期：

| 事件 | 动作 |
|---|---|
| 握手通过 | 创建 Tunnel，登记进表 |
| conn 任一侧关闭 / 读写出错 | 注销 + `Close()` 另一侧 |
| 空闲超时（WS：60s 无字节） | 关闭两侧，注销，审计记 `tunnel_idle` |
| 寿命到期（WS/SSE：`tunnel_max_min`） | 关闭两侧，注销，审计记 `tunnel_max` |
| 撤销（CLI 经 reconcile / 同进程直接） | 关闭该 family 全部 tunnel |

**关闭方式按类型不同**：

- **WS**：先发 Close 帧（状态码 `4401`，reason `session revoked`），再关裸连接。不发帧直接砍 TCP 时浏览器只能本地生成 `1006`，前端无法区分"被撤销"和"网络抖动"，只会无脑重连。发帧后 `onclose` 能读到 `event.code === 4401`。发帧与转发线程共用一把写锁（`tunnel.wmu`），否则两处同时写同一个 socket 会把帧结构写坏。
- **SSE**：没有可关闭的 conn（连接藏在 `ReverseProxy` 内部），唯一入口是取消请求 context。tunnel 持有注册时创建的 `cancel`，`Close()` 先 cancel，`ReverseProxy` 中止上游请求并让 handler 返回。

⚠️ SSE 这条曾经漏过：早期实现注册 SSE 时 client/upstream 都是 nil，`Close()` 是空操作，撤销后事件流还在往旧浏览器推数据。`TestRevokeClosesActiveSSE` 锁住这个行为。

**v2 不持久化**。连接身份跟着 conn 走，写盘只会产生僵尸条目。进程重启时所有 conn 一起断，表清空，状态天然一致。

## 4. 交互流程

### 4.1 登录

```
浏览器                     网关                        台账
  │  GET /_g/<动态>/l         │                          │
  │──────────────────────────►│ 签挑战 → Set-Cookie dsh_ch │
  │◄── 登录页(密码+动态码) ────│                          │
  │  POST 同上 + ch/password/code/remember │             │
  │──────────────────────────►│ ① 来源校验                │
  │                           │ ② 挑战核销                │
  │                           │ ③ 密码 scrypt             │
  │                           │ ④ TOTP ±1 步 + 防重放     │
  │                           │ ⑤ 生成 family(128bit)     │
  │                           │────────────────────────►│ 写一条 session
  │                           │ 签 v1 cookie              │
  │◄── 303 / + Set-Cookie ────│                          │
```

字段：`ch`（挑战）、`password`、`code`、`remember`（"1" = persist）。
失败统一「认证失败」，不区分因子；审计记 `login ok=false`，不带因子名。

### 4.2 普通 HTTP 请求

```
  │ GET /any/path + Cookie: dsh_dev │
  │────────────────────────────────►│
  │                                 │ ① 来源校验（跨站 → 403）
  │                                 │ ② 验签（HMAC）
  │                                 │ ③ fam 在台账？（否 → 401）
  │                                 │ ④ payload.ip == 当前 IP 段？
  │                                 │ ⑤ payload.ua == 当前 UA 哈希？
  │                                 │ ⑥ active(s, now)？（否 → 401 + 删记录）
  │                                 │ ⑦ last_seen = now（内存，节流落盘）
  │◄──── 转发到 dsh 或 401 ─────────│
```

导航请求（`Accept: text/html`）失败 → 303 到动态登录路径；其余 → 401。

### 4.3 WS 握手（`Upgrade: websocket`）

网关自己接管，不再交给 `httputil.ReverseProxy` 内部 hijack。

```
  │ GET /api/remote.mux                    │
  │ Upgrade: websocket                     │
  │ Cookie: dsh_dev                        │
  │───────────────────────────────────────►│
  │                                        │ ①..⑦ 同 4.2
  │                                        │ ⑧ 自己连 dsh，转发握手（原样带 Cookie / Sec-WebSocket-*）
  │                                        │ ⑨ 收 dsh 的 101，回给浏览器
  │                                        │ ⑩ 建 Tunnel{Family, Kind:"ws", 两条 conn} 并登记
  │◄════════ 101 ══════════════════════════│
  │                                        │ ⑪ 双向 io.Copy，每次读到字节刷 Tunnel.LastRead
  │◄══════════════ 字节流 ═════════════════►│     （不解析帧，permessage-deflate 原样透传）
```

握手阶段**不写 Set-Cookie**（101 上写 cookie 的行为在各浏览器不一致，而 §2.3 的时效判断本来就不依赖重签）。

### 4.4 SSE（`Accept: text/event-stream`）

同 4.3，但：
- `Kind: "sse"`
- 只有下行是持续数据流，**不设读写空闲超时**（dsh 无保活，设了会误杀）
- 只受 `tunnel_max_min`（默认 30 分钟）约束，到点断开，浏览器 `EventSource` 自动重连

### 4.5 空闲检测与断开

```
每个 Tunnel 两个 reader goroutine：
  for {
      n, err := src.Read(buf)
      if n > 0 { tunnel.LastRead = now; dst.Write(buf[:n]) }
      if err != nil { closeBoth(); return }
  }

一条 watchdog（每 10s 扫一遍）：
  对 Kind=="ws" 且 now-LastRead > tunnel_idle_sec  → 关两侧
  对任意 kind 且 now-CreatedAt > tunnel_max_min    → 关两侧
```

读超时靠 `SetReadDeadline` 也可以，但统一用 watchdog 扫表更好调试（能打印每条连接的岁数与最后活动）。

### 4.6 撤销

```
终端                                网关
  │ dsh-auth-proxy revoke --family 9f3a │
  │── 从 sessions.json 删记录 ──────────│
  │                                     │ reconcile 每 2s：
  │                                     │   mtime 变 → 重载 → 得到活 family 集合
  │                                     │   遍历 tunnel 表，family 不在集合 → 关两侧
  │                                     │   审计记 revoke/tunnel_closed
```

同进程来源（重用检测、abs 到期）直接调用，不等 tick。

**顺序固定：先删台账记录，再关 conn。** 反了会留「记录已删、连接还活」的窗口。

### 4.7 登出

删当前 family 记录 → 关该 family 的 tunnel → 清 cookie（`Max-Age=0`）→ 审计 `logout`。

## 5. 安全控制点

| # | 控制点 | 谁执行 | 验什么 | 失败 |
|---|---|---|---|---|
| 1 | 来源门禁 | 网关 | `Origin` 比对 `public_origin`；`null` 时看 `Sec-Fetch-Site` | 403 |
| 2 | 挑战因子 | 网关 | 表单 `ch` 与 cookie `dsh_ch` 双持一致、签名、5 分钟内、未用过 | 重签挑战 + 「登录已过期」 |
| 3 | 口令 | 网关 | scrypt vs `password_hash` | 统一「认证失败」 |
| 4 | 动态码 | 网关 | RFC6238 ±1 步 + 已用步号表（防同码重放） | 统一「认证失败」 |
| 5 | v1 签名 | 网关 | HMAC-SHA256，常数时间比较 | 401 |
| 6 | 设备台账 | 网关 | `fam` 是否存在 | 401 |
| 7 | IP 绑定 | 网关 | 绑定值相等（temp 完整地址；persist IPv4 `/24`、IPv6 `/56`） | 401 |
| 8 | UA 绑定 | 网关 | `payload.ua` 与当前 UA 哈希相等 | 401 |
| 9 | 时效 | 网关 | `idle` + `abs`（§2.3） | 401 + 删记录 |
| 10 | 连接归属 | 网关 | tunnel 登记到 `fam`，撤销时按 family 关（WS 发 4401 帧 / SSE 取消 context） | 断连 |
| 11 | 空闲/寿命 | 网关 | §4.5 | 断连 + 客户端重连重新认证 |
| 12 | 审计 | 网关 | 登录成功/失败、撤销、登出、空闲/寿命断开、记录被外部删除 | 写 `audit.jsonl` |

### 5.1 逐帧鉴权为什么不做

WS 升级后是双向字节流，帧是应用协议。要做逐帧验证需实现 deflate 解压 + 分片重组 + 懂 dsh 的 JSON 语义，且绑死协议版本；一旦字段改名会静默放行，比不做更危险。

替代：撤销时主动关连接（控制点 10）+ 寿命上限（11）。这两条合起来的保证是「撤销 ≤2s 生效，最长 `tunnel_max_min` 必重认证」。这与官方是同一档（官方甚至不关已准入的 WS，见 `dsh-client-remote-connection` README 第 157 行）。

### 5.2 已知边界（不藏）

1. 隧道建立后不逐帧鉴权（协议固有，靠 10/11 缓解）
2. `isLocal` 来源完全豁免认证（本机直连不需要登录）
3. `dsh_dev` 的 payload 可解码（未加密），只防 JS 读取
4. 真实客户端 IP 未落地（Cloudflare → Traefik 链路，需另外处理）
5. 审计是本地文件，不轮转、不外发
6. 服务端台账丢失 = 所有设备失效（fail-closed，可接受）

## 6. 与现状的差异

| 项 | 现在 | 改后 |
|---|---|---|
| 浏览器 cookie | `dsh_sid` + `dsh_rt` | `dsh_dev`（一枚） |
| 票据形态 | access 自包含 + refresh opaque | 单枚自包含 |
| 时效 | access 10min / refresh 滑动 30d / abs 90d | idle 2h\|14d + abs 6h\|30d |
| 轮换 / 重用检测 / 宽限期 | 有（约 200 行） | **删除** |
| 连接管理 | 无（`tunnel_max_min` 固定超时） | tunnel 表 + 空闲检测 + 撤销即断 |
| 101 处理 | `httputil.ReverseProxy` 内部 hijack | 自己接，拿得到 conn |

删除：`CookieRefresh`、`MintPair`、`RotateAccess`、`NeedsRefresh`、`RefreshCookie`、`SessionStore.Rotate/Issue/Touch/LookupFamilyByToken`、`RefreshGraceSec`、`AccessTTLMin`、`dsh_rt` 相关测试。

新增：`internal/web/tunnel.go`（连接表 + 101 接管 + 双向拷贝 + watchdog）、`internal/web/reconcile.go`（mtime 轮询）、`SessionStore.ActiveFamilies/UpdateLastSeen/Merge`。

净效果：删约 350 行（双票 + 轮换 + 宽限 + 相关测试），加约 400 行（隧道 + 台账改造 + 测试）。逻辑上更简单：只有一套时效判断，不再有「access 过期但 refresh 有效」这类组合。

## 7. 测试矩阵

### 7.1 单元：v1 票与台账

| 测试 | 断言 |
|---|---|
| `TestDeviceCookieRoundTrip` | 签发→验签→payload 各字段一致 |
| `TestDeviceCookieTampered` | 改 payload / 改签名 → 拒绝 |
| `TestDeviceCookieWrongKey` | 换 password_hash → 旧票拒绝 |
| `TestSessionIdleExpires` | temp 档 last_seen 超 2h → 失效 |
| `TestSessionAbsCaps` | temp 档连续活跃到 6h → 失效（即使 last_seen 很新） |
| `TestPersistWindow` | 14d idle / 30d abs（每 10 天活跃一次，仍被 abs 拒绝） |
| `TestIPMismatchRejected` | 改变 IP 段 → 401 |
| `TestUAMismatchRejected` | 改变 UA → 401 |
| `TestRevokedFamilyRejected` | 删记录后旧票 → 401 |
| `TestLedgerRotatesAfterPeriod` | 到周期 → 代数 +1 并要求下发新票 |
| `TestLedgerRotationGraceForConcurrentTabs` | 两个标签页同时带旧代数 → 宽限内放行 |
| `TestLeakedCookieDiesAfterOwnerRotation` | 用户轮换后，泄露的旧票 `ErrSessionStale` |
| `TestLedgerRotationDoesNotExtendAbs` | 反复轮换也绕不过 6h |
| `TestLedgerGenPersistedAcrossRestart` | 重启后旧代数仍失效 |
| `TestLastSeenThrottled` | 60s 内多次请求只落盘一次 |
| `TestMergeDoesNotResurrect` | 磁盘删除 → 内存刷盘不写回（防覆盖撤销） |
| `TestBindIPGranularity` | temp 绑完整 IPv4/IPv6；persist 绑 `/24` 与 `/56` |
| `TestIPPrefixIPv6` | IPv6 前缀正确（锁住旧实现把 8 字节切片打印成 `?hex` 的 bug） |
| `TestDeviceCookieLifetimeByMode` | temp 无 `Max-Age`（会话 cookie）；persist 为 30 天 |

### 7.2 单元：tunnel 表

| 测试 | 断言 |
|---|---|
| `TestTunnelRegisterAndClose` | 登记后可查、关闭后消失 |
| `TestTunnelByFamilyMultiple` | 同 family 两条 tunnel 共存（多标签页） |
| `TestRevokeClosesAllTunnels` | 撤销 family → 全部 conn 关闭 |
| `TestIdleClosesWS` | 无字节 60s → 关闭 |
| `TestActiveWSNotClosed` | 每 2s 有字节 → 存活超过 60s |
| `TestSSENotIdleClosed` | 静默 SSE → 不被空闲检测误杀 |
| `TestTunnelMaxCuts` | 到 `tunnel_max_min` → 关闭 |

### 7.3 集成：真实 HTTP

| 测试 | 断言 |
|---|---|
| `TestLoginIssuesDeviceCookie` | 登录只下发一枚 `dsh_dev`，无 `dsh_rt` |
| `TestHTTPForwardAfterLogin` | 带 v1 访问任意路径 → 转发到后端 |
| `TestExpiredIdleBouncesToLogin` | 过期票 → 303 登录页 |
| `TestXHRGets401` | 非导航请求 → 401 |
| `TestWSProxyStillWorks` | 101 双向透传、echo 正确（含压缩协商） |
| `TestWSTunnelRegistered` | 握手后表里有这条，且 family 正确 |
| `TestRevokeDuringWSDrops` | 撤销后 1 个 tick 内 WS 被断 |
| `TestRevokeClosesActiveWS` | 撤销后收到 4401 Close 帧，且连接表归零 |
| `TestRevokeClosesActiveSSE` | 撤销后 SSE 流被取消（否则事件流会继续推给旧浏览器） |
| `TestSSEStreamsAndSurvives` | SSE 正常流式、跨过 60s 不被断 |
| `TestReconnectAfterRevokeDenied` | 撤销后重连 → 401 |

### 7.4 回归 / 并发

| 测试 | 断言 |
|---|---|
| `go test -race ./...` | 无数据竞争 |
| `TestConcurrentRequestsSingleSession` | 20 并发请求不互相影响 last_seen 落盘 |
| `TestReconcileSeesCLIRevoke` | 外部改文件 → ≤2 tick 内连接被关 |

## 8. 实现顺序

1. `auth`: 新 `DeviceCookie` 签发/验签；`SessionStore` 改结构 + `ActiveFamilies` / `UpdateLastSeen` / merge
2. `web`: 认证门改单票；`tunnel.go` 接管 101；`reconcile.go`
3. `config`: 删 `access_ttl_min` / `refresh_grace_sec`，加 `temp_abs_hours` / `tunnel_idle_sec`
4. 测试：先单元（7.1、7.2），再集成（7.3），最后 race（7.4）
5. 文档：`config-reference.md`、`auth-coverage.md`、README 同步

## 9. 安全分析

### 9.1 cookie 不带 exp，会不会变成永久票

不会。三个独立约束，任一到点即失效：

| 约束 | 判定依据 | 谁能绕过 |
|---|---|---|
| idle | `last_seen` | 持续使用可以绕过（这就是"滑动"的定义） |
| abs | `created_at` | **没有人能绕过**，它只在登录时写一次 |
| Max-Age | 浏览器 | 浏览器到期丢弃，服务端判活不依赖它 |

关键性质：**被盗 cookie 的有效期上限 = rotate 周期 + 宽限**（临时 30min+10s / 持久 24h+10s），紧兜底是 `abs`（6h / 30d）。攻击者可以靠持续使用刷新 `last_seen`，但绕不过 `created_at`。

这和"cookie 自带 exp"的方案等价——那种方案里攻击者只要在 exp 前一直用也一直有效。差别只在一个地方：**到期基准**。自带 exp 是"每次签发后 N 天"，我们的 abs 是"首次登录后 N 天"。后者更严：续签次数再多也不会把基准往后推。这正是之前"90 天绝对上限失效"那个 bug 的根因（用 access 的 iat 而不是 family 的 created_at 判上限）。

### 9.2 相对现有双票是变强还是变弱

| 攻击/场景 | 双票（现状） | 单票 + 台账 |
|---|---|---|
| cookie 被复制到别处 | IP 段 + UA 绑定挡 | 同 |
| 被撤销后继续用 | access 最多再活 10 分钟 | 立即失效（下次请求查表） |
| 被撤销后已建立的 WS | 最长活到 `tunnel_max_min` | ≤2 秒被关 |
| 被盗后被动持有（不用） | 有效到 90 天 | **下一次用户活跃即作废**（≤rotate） |
| 被盗且持续使用 | 最长 90 天 | 最长 30 天（abs） |
| XSS 读 cookie | HttpOnly 挡 | 同 |
| 台账文件丢失 | refresh 全废，access 还能撑 10 分钟 | **全部失效**，必须重登 |
| 每请求开销 | HMAC + 查 family | HMAC + 查表（同量级，见 §11） |

三处变强（撤销即时、abs 真正生效、上限更短），一处变弱（状态丢失时更脆）。

最后一行的取舍是刻意的：**宁可全员重登，也不放行未知状态**。反过来（台账丢了就放行）等于把状态做成可绕过的装饰。

### 9.3 时钟

时效全部用服务端时钟算，客户端时钟不参与，所以用户改本机时间没有影响。

防御了一条：如果 `last_seen` 是未来值（时钟回拨、或文件被手工改），`now - last_seen` 会是负的，idle 判定永远通过。`Check` 里把未来时间夹到 `now`，宁可多算一次活跃。

### 9.4 多实例

台账是单文件、单进程写。两台网关共用一个文件会互相覆盖 `last_seen`。当前是单实例部署，列入已知边界（§5.2）。

## 10. v2 为什么不需要密码学

官方的 v2 是 HMAC 签名 cookie，因为它要走两个不可信跳：`服务端 → 浏览器 → 服务端`。签名解决的是"我怎么确认这枚 id 是我签的，而不是攻击者编的"。

我们的 v2 不走任何不可信跳：

| | 官方 v2 | 我们的 v2 |
|---|---|---|
| 存在哪 | 浏览器 cookie | 网关进程内存 |
| 客户端能否引用 | 能（每次 HTTP 请求都带） | **不能**，客户端不知道它存在 |
| 服务端需要验证吗 | 需要（验签 + 查表） | 不需要，是它自己创建的对象 |
| 加签名的收益 | 防伪造 | **零**，等于自己签给自己验 |

真正需要密码学的只有 v1（跨不可信通道），已经用 HMAC-SHA256。

v2 的 ID 用 16 字节随机，目的不是安全，是日志和审计里可区分、且不可预测（避免日志泄露暴露内部结构）。

## 11. 性能（实测，非估算）

`go test -bench` 实测，本机 AMD EPYC 7413，300000 次迭代：

| 基准 | 耗时 | 分配 |
|---|---|---|
| `BenchmarkDeviceCookieVerify`（验签 + 解 payload） | **2284 ns/op** | 1217 B / 13 allocs |
| `BenchmarkLedgerCheckMemory`（纯内存判定，含代数） | **58.3 ns/op** | 0 B / 0 allocs |
| `BenchmarkLedgerCheckWithFile`（台账挂文件，请求路径） | **59.2 ns/op** | 0 B / 0 allocs |

每请求合计约 **2.3 µs**（验签 2284 ns + 台账 59 ns）。单核理论上限约 43 万 QPS，实际由 HTTP 栈决定，这个开销不是瓶颈。

**一个被实测纠正的设计错误**：最初 `Check` 每个请求都 `os.Stat` 检查文件 mtime，测出 **26 µs/op**（慢 600 倍）。改为请求路径只读内存、文件同步交给后台 2 秒一次的 ticker，降到 40 ns。代价是撤销生效从"立即"变成"≤2 秒"，与 reconcile 的节奏一致。

内存：每设备约 200-300 字节（`DeviceSession` + map 开销）。100 台设备 ≈ 30 KB。

后台开销：reconcile 每 2 秒一次 `stat`（约 26 µs）+ 扫连接表；watchdog 每 10 秒扫一次 tunnel。都可忽略。

写盘：现状每次 refresh 轮换写全量 JSON；新方案最多 60 秒一次（`last_seen` 节流），**写盘频率下降**。

## 12. 实现进度

| 阶段 | 状态 |
|---|---|
| `internal/auth/device.go`（v1 签发/验签、Policy） | **已完成**，7 个单测 |
| `internal/auth/ledger.go`（台账、merge、节流、代数轮换、benchmark） | **已完成**，27 个单测 + 3 个 benchmark |
| `internal/web/tunnel.go`（101 接管、连接表、watchdog） | **已完成**，含撤销即断 / 拒绝不留表 / SSE 不误杀三个集成测试 |
| `internal/web/gateway.go`（认证门改单票、reconcile、WS/SSE 分流） | **已完成** |
| `internal/config/config.go`（加 temp_abs_hours / rotate_* / tunnel_idle_sec；旧字段保留但告警） | **已完成** |
| 删除双票旧代码（`dsh_rt`、refresh 轮换、重用检测、宽限期） | **已完成**，净删 ~700 行（含测试） |
