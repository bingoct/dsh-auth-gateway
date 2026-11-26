# 鉴权覆盖面与技术方案

> 目的：把「谁能进来、按什么条件进来、失败怎么办」逐条固定下来，每条都有对应测试。
> 本文只描述**已实现**的行为；未实现的单独列在最后一节，不混进来。

## 1. 威胁模型

### 防的

| 威胁 | 手段 |
|---|---|
| 陌生人猜到地址直接访问 | 登录路径按 UTC 日期轮换，旧路径一律 404；未认证导航 303 到当前登录路径 |
| 密码暴力破解 | 登录失败计数 + 冷却（`rate_window_min` / `rate_max_fails`）；失败文案统一为「认证失败」，不区分是密码错还是动态码错 |
| 重放已提交过的登录表单 | 挑战因子：表单隐藏字段 + cookie 双持，HMAC 签名 + 5 分钟有效 + 一次性核销 |
| 重放已用过的动态码 | TOTP 窗口 ±1 步，成功即记录 step，同一 step 二次提交失败 |
| 跨站伪造请求（CSRF / CSWSH） | `Origin` 必须等于 `public_origin`；`Origin: null` 时用 `Sec-Fetch-Site` 兜底，`cross-site` 拒绝；WebSocket 握手同样过这道门 |
| 票被拷到别的机器/浏览器 | 票内绑定 IP 前缀 + UA 哈希，不匹配即拒 |
| 票被篡改 | HMAC 签名（密钥由 `password_hash` 派生） |
| 长期票被盗用 | 服务端存 refresh 记录，支持轮换 + 重用检测 + 单设备撤销 |
| 事后无法追溯 | 审计 JSONL 追加文件：登录成功/失败、续签、登出、撤销、重用检测各一行，不含凭据 |
| 会话无限续期 | `session_abs_max_days` 按 family 首次签发时间强制截断 |
| 隧道跨过凭证有效期一直有效 | 隧道寿命上限 `tunnel_max_min`，到点主动断开逼重连 |

### 不防的（明确写出来，避免误以为覆盖了）

- 拿到**完整且有效**的 cookie 并能伪造同 UA、同 IP 段的攻击者：在 absMax 内可以正常使用，直到被撤销。
- 本机进程：`isLocal` 请求不过认证（见 §3 第 2 行）。
- dsh 自身应用层的漏洞：网关只保证「进来的人是谁经过验证」，不保证进来之后 dsh 做什么。

## 2. 凭证

| 名称 | cookie | 形态 | 寿命 | 存哪 |
|---|---|---|---|---|
| 会话票 | `dsh_sid` | `v1.<b64(payload)>.<b64(hmac)>`，payload = `{iat, exp, ip, ua, scope, family}` | `access_ttl_min`，默认 10 分钟 | 只在浏览器；服务端不存 |
| 刷新票 | `dsh_rt` | 32 字节随机串 | 持久 30 天 / 临时 2 小时 | 服务端存 sha256，浏览器存原文 |
| 挑战票 | `dsh_ch` | HMAC 签名串 | 5 分钟，一次性 | 浏览器 cookie + 表单隐藏字段 |

两枚 cookie 都是 `HttpOnly` + `SameSite=Strict`，`public_origin` 为 https 时加 `Secure`。

**关键设计**：会话票无状态，验证不查表（只做 HMAC + 字段比对 + family 存活检查）；刷新票有状态，是设备识别和撤销的唯一依据。

## 3. 覆盖面矩阵

按「请求进入网关后的实际分支」逐条列。表中「谁验」指判定发生在哪一步。

| # | 请求类型 | 谁验 | 验什么 | 失败行为 |
|---|---|---|---|---|
| 1 | 内部端点 `/_g/<token>/{h,s,r,l,o}` | 路径 token 与当天 HMAC 比对 | token 是否等于当日派生的片段 | 404（不落到转发层） |
| 2 | 本机请求（来源在 `local_cidrs` 内） | 不过认证 | — | 直接转发；`restart` 只允许本机 |
| 3 | `auth.enabled = false` | 不过认证 | — | 直接转发；启动打警告 |
| 4 | 任意来源 + 跨站特征 | 来源门禁 | `Origin` / `Sec-Fetch-Site` | 403 |
| 5 | 页面导航（`Accept: text/html` 或 `Sec-Fetch-Dest: document`） | 会话校验 | access 签名 + `exp` + `ip` + `ua` + family 存活 + family 未超 absMax | 303 到当前登录路径 |
| 6 | XHR / fetch / 静态资源 | 会话校验 | 同上 | 401 + `WWW-Authenticate` |
| 7 | SSE（`Accept: text/event-stream`） | 会话校验 | 同上，**在建立连接时验一次** | 401，客户端不会重连成功 |
| 8 | WebSocket 握手（`Upgrade: websocket`） | 会话校验 | 同上，**在握手时验一次** | 401，握手失败 |
| 9 | SSE / WS 建立之后的帧 | **不验** | — | 无；靠隧道寿命到点断开（见 §6） |
| 10 | access 失效但 refresh 有效 | 回落续签 | 读 `dsh_rt` → 查表 → 轮换 → 写回新一对票 | 换到就放行；换不到按 5/6 处理 |
| 11 | access 有效但剩余 < 1/3 | 顺带续签 | 同 10 | 续签失败也放行（access 本身仍有效） |

第 5/6 行的判定顺序（`internal/auth/auth.go` 的 `CheckSession`）：

1. HMAC 签名
2. `scope == full`
3. `exp > now`
4. `ip` 前缀匹配
5. `ua` 哈希匹配
6. family 仍在表中
7. `now - family.CreatedAt <= session_abs_max_days`

第 7 条依据是 **family 首次签发时间**，不是 access 自己的 `iat`。这一点曾是缺陷（access 每次续签都会刷新 `iat`，导致绝对上限永不触发），已修复并由 `TestAbsMaxSurvivesRotation` 锁住。

## 4. 续签状态机

```
                   ┌─ access 有效 ──┬─ 剩余 ≥ 1/3 ─→ 放行
请求 ─→ 取 cookie ─┤                └─ 剩余 < 1/3 ─→ 续签(尽力) → 放行
                   └─ access 失效 ──┬─ refresh 有效 ─→ 轮换 → 放行(200)
                                    └─ refresh 无效 ─→ 401 / 303 登录页
```

「access 失效」包含：cookie 缺失、签名不符、已过期、IP/UA 不匹配、family 被撤销、超过 absMax。

续签失败**不影响**「access 仍有效」的路径——`refreshSession` 返回 false 时只是不写新 cookie，请求照常转发。

## 5. 轮换与并发

- 持久档轮换：旧记录标记 `used_at`，签发新记录，继承同一个 `family_id` 和 `created_at`。
- 临时档（不勾「保持登录」）：不轮换，只更新 `last_seen`，`expires_at` 不变，2 小时后自然失效。
- 宽限期 `refresh_grace_sec`（默认 30 秒）：旧票在窗口内再次出现，允许再换一次，不撤销 family；超出窗口判定为重用攻击，撤销整个 family。
- 基准时间只记第一次使用，重放不会延长窗口。

## 6. 隧道（WS / SSE）

隧道升级成功后，网关只做双向字节流复制，**不再逐帧验证凭证**。这是 HTTP 升级的固有特性，不是可以靠改网关消除的。

因此必须限制隧道寿命：

- 判定：`Upgrade: websocket` 或 `Accept: text/event-stream`
- 处理：给转发用的 context 加 `tunnel_max_min`（默认 30 分钟）超时
- 到期：context 取消 → 已劫持的连接被关闭 → 客户端重连
- 重连时：浏览器带当前 cookie，走 §4 的状态机；若 access 已过期但 refresh 有效，自动换票后放行

**这条链是闭合的**：隧道断开 → 重连 → 重新认证。缺任一环都退化成「一条连接永久有效」。

残余风险：客户端若不实现自动重连，用户会看到「连接已断开」，需要手动刷新页面。

## 7. 测试矩阵

`go test ./...` 共 78 个用例。与本文档对应的关键用例：

| 矩阵行 | 测试 |
|---|---|
| 1 内部端点 / 旧路径 | `TestAuthDisabledPassthrough`、`TestLoginPageReachable` |
| 4 来源门禁 | `TestChallengePageIntegration`、`TestProxyStripsBrowserOrigin` |
| 5/6 会话校验 | `TestLoginFlowEndToEnd`、`TestOldSessionInvalid`、`TestRevokeFamilyKillsSession` |
| 7/8 隧道握手 | `TestProxyWebSocketEcho` |
| §6 隧道寿命 | `TestTunnelLifetimeCutsConnection`（把窗口压到 150ms，验证到点被掐断） |
| 10 access 失效回落 | `TestInvalidAccessFallsBackToRefresh`、`TestInvalidAccessWithoutRefreshIsRejected` |
| 11 顺带续签 | `TestRefreshRotatesPair` |
| §5 轮换 | `TestIssueAndRotate`、`TestRotateBindingMismatch`、`TestRotateExpired`、`TestTemporaryDoesNotRotate` |
| §5 重用检测 | `TestReuseRevokesFamily`、`TestReuseWithinGraceIsAllowed`、`TestGraceWindowDoesNotExtend` |
| §3 第 7 条 absMax | `TestSessionAbsoluteMax`、`TestAbsMaxSurvivesRotation` |
| 撤销与设备 | `TestRevokeAndDevices`、`TestExternalRevokeVisibleToGateway`、`TestDevicesExpiredHidden` |
| 审计 | `TestLogAppendsJSONLines`、`TestReopenAppends`、`TestLoginFlowEndToEnd`（断言成功/失败都落盘且不含凭据） |
| 持久化 | `TestStorePersistence` |

`TestExternalRevokeVisibleToGateway` 验证的是：CLI 在另一个进程里撤销后，运行中的网关下一次校验就能看到（按文件 mtime 重载），不需要重启。

## 8. 已知不覆盖

1. **隧道建立后的帧不逐帧鉴权**——靠寿命上限缓解，无法根除（协议层面决定）。
2. **`isLocal` 完全跳过认证**——本机任何进程都能直接访问。前提是网关只监听回环或前置反代。若 `listen_host` 改成 `0.0.0.0` 且 `local_cidrs` 配置过宽，这条会变成真实缺口。
3. **审计只有本地文件，没有集中收集**——JSONL 追加在 `~/.dsh/audit.jsonl`，不轮转、不外发。文件被删除或磁盘写满时会静默丢失，需要自己定期归档。
4. **`dsh_sid` 内容可解码**——签名但不加密，payload 里的 `iat/exp/ip/ua/family` 浏览器能读（JS 读不到，HttpOnly）。IETF 草案对这种形态有「SHOULD 加密 cookie 内容」的建议，未做。
5. **真实客户端 IP 未落地**——`trust_proxy` 依赖 `X-Forwarded-For`，当前链路最后一跳是 Cloudflare，取到的是边缘节点 IP 而非用户 IP。IP 绑定的实际约束力因此减弱，等反代/容器链路调整后再核验。
