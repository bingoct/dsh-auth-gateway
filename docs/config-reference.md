# dsh-auth-proxy 配置参数参考

配置文件默认路径：`~/.dsh/gateway.toml`（Windows: `%USERPROFILE%\.dsh\gateway.toml`）。
可用 `--config <path>` 或环境变量 `AUTH_CONFIG_FILE` 指定其他路径。

合并优先级（高 → 低）：**命令行 flag > 环境变量 > 配置文件 > 内置默认值**。
`[credentials]` 段由 `dsh-auth-proxy init` 写入，运行时只读，不要手工编辑。

模板：仓库根的 `config.example.toml`，或用 `dsh-auth-proxy config init` 自动生成。

## [server]

| 参数 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `listen_host` | `127.0.0.1` | `AUTH_PROXY_HOST` | 网关监听地址，可写多个（逗号分隔）。非回环监听必须配 `https://` 的 `public_origin`，否则启动拒绝（明文口令过网）。 |
| `listen_host` 的 `if:<网卡名>` | — | — | 启动时解析该网卡的 IPv4 并监听它，用来同时保留回环和一个会变的地址（如 WSL 的 `vEthernet (WSL)`），不必把地址写死。解析不到直接退出，不降级。例：`127.0.0.1,if:vEthernet (WSL)`。 |
| `listen_port` | `33080` | `AUTH_PROXY_PORT` | 网关监听端口。 |

## [dsh]

| 参数 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `host` | `127.0.0.1` | `AUTH_DSH_HOST` | dsh 进程监听地址，网关转发目标。 |
| `port` | `0` | `AUTH_DSH_PORT` | dsh 端口。`0` = 系统分配，网关从 dsh 打印的 URL 解析真实端口。 |
| `profile` | `web` | `AUTH_DSH_PROFILE` | 传给 dsh 的 `--profile`。 |
| `bin` | `<USERPROFILE>/scoop/apps/dsh/current/lib/bin.js` | `DSH_BIN` | dsh 入口脚本路径。留空走默认值。 |
| `cwd` | `<USERPROFILE>/WorkBuddy/dsh` | `DSH_CWD` | dsh 工作目录，决定它用哪个工作区。 |
| `node_bin` | `PATH` 上的 `node` | `AUTH_NODE_BIN` | node 可执行文件。也可设 `NODE` / `CODEBUDDY_NODE_BIN`。 |
| `extra_args` | `[]` | `AUTH_DSH_EXTRA_ARGS` | 追加给 dsh 的 flag（环境变量里用 `\|` 分隔）。 |
| `ready_ms` | `90000` | `AUTH_DSH_READY_MS` | 等 dsh 打印启动 token 的上限（毫秒）。 |
| `ensure_wait_ms` | `20000` | `AUTH_GATEWAY_ENSURE_WAIT_MS` | 单次请求最多等多久就绪，超时返回"正在启动"页（毫秒）。 |
| `idle_reap` | `false` | `AUTH_DSH_IDLE_REAP` | 空闲回收开关，默认关闭。dsh 可能跑长任务，自动回收收益小于中断代价。 |
| `idle_min` | `30` | `AUTH_DSH_IDLE_MIN` | 空闲分钟阈值，仅 `idle_reap = true` 时生效。`<= 0` 视为关闭，不是"立刻回收"。回收还需 `active == 0` 且最近 5 分钟无会话文件写入。 |
| `attach` | `false` | `AUTH_DSH_ATTACH` | `true` = 不拉起 dsh，从 `token_file` 读外部实例的 URL。attach 模式不拥有 dsh，restart 被拒。 |
| `token_file` | `~/.dsh/dsh-url.txt` | `AUTH_DSH_TOKEN_FILE` | attach 模式下外部 dsh 的 URL 文件。 |

## [auth]

| 参数 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `enabled` | `true` | `AUTH_GATEWAY_AUTH_ENABLED` | 认证总开关。`false` 时非本机来源直通、登录端点 404，仅限临时体验；公网暴露前必须开回。来源门禁（CSWSH）不受此开关影响。 |
| `session_days` | `14` | `AUTH_SESSION_DAYS` | 持久设备（勾"保持登录"）的闲置上限（天）：这么多天不用就失效。 |
| `session_abs_max_days` | `30` | `AUTH_SESSION_ABS_MAX_DAYS` | 持久设备的绝对上限（天）。按首次登录时间算，再活跃也绕不过；必须显著大于 `session_days`。 |
| `public_origin` | **无（必填）** | `AUTH_PUBLIC_ORIGIN` / CLI `--public-origin` | 对外 HTTPS 地址。决定 cookie 是否加 `Secure`、来源校验基准。配置文件、环境变量、CLI 都未指定时启动报错；不再有硬编码默认值。 |
| `temp_hours` | `2` | `AUTH_TEMP_HOURS` | 临时设备的闲置上限（小时）：这么久不用就失效。 |
| `temp_abs_hours` | `6` | `AUTH_TEMP_ABS_HOURS` | 临时设备的绝对上限（小时）。连续用满 6 小时必须重新登录；必须大于 `temp_hours`。 |
| `rotate_temp_min` | `30` | `AUTH_ROTATE_TEMP_MIN` | 临时档的代数轮换周期（分钟）。到期后下一次请求会换发新 cookie，旧代数立即作废。`0` 表示关闭轮换。 |
| `rotate_persist_hours` | `24` | `AUTH_ROTATE_PERSIST_HOURS` | 持久档的代数轮换周期（小时）。作用同上；它把"cookie 被动泄露后的可用窗口"从 `abs` 压到该周期。 |
| `tunnel_idle_sec` | `60` | `AUTH_TUNNEL_IDLE_SEC` | WebSocket 空闲超时（秒）。dsh 每 2 秒发 ping、浏览器回 pong，所以活跃连接不会被误断；死连接在 60 秒内被发现。`0` 表示不判空闲。 |
| `session_store_path` | `~/.dsh/sessions.json` | `AUTH_SESSION_STORE` | 设备台账文件路径。记录 family / 设备名 / 模式 / IP 段 / UA 哈希 / 首次登录 / 最近活动；`devices`、`revoke` 读写同一文件。 |
| `tunnel_max_min` | `30` | `AUTH_TUNNEL_MAX_MIN` | 隧道最长寿命（分钟）。WS 和 SSE 都受它约束；到点断开逼客户端重连并重新认证。`0` 表示不限（不建议）。 |
| ~~`access_ttl_min`~~ / ~~`refresh_grace_sec`~~ | — | — | **已废弃**：双票时代的字段。为了旧配置能继续启动仍然接受，但解析后忽略并打印告警，可从配置里删掉。 |
| `audit_log_path` | `~/.dsh/audit.jsonl` | `AUTH_AUDIT_LOG` | 审计事件追加文件（JSONL，每行一条）。记录登录成功/失败、隧道打开/关闭/超时、登出、撤销、旧代数被拒；不含密码、票原文、动态码。`"off"` 表示关闭。 |

## [network]

| 参数 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `trust_proxy` | `false` | `AUTH_TRUST_PROXY` | 是否采信 `X-Forwarded-For`。只有确实有可信反代时才开。 |
| `proxy_trusted` | `172.16.0.0/12,10.0.0.0/8,192.168.0.0/16` | `AUTH_PROXY_TRUSTED` | 可信反代网段列表（逗号分隔）。`trust_proxy=true` 时从右往左跳过这些跳数取真实 IP。 |
| `local_cidrs` | `127.0.0.0/8,::1/128` | `AUTH_LOCAL_CIDRS` | 本地来源网段，这些来源免认证；restart 端点只对这些来源开放。 |

## [rate]

登录失败计数与封禁，按来源 IP 计。窗口内失败达到 `max_fails` 就封 `ban_min` 分钟，
封禁期间登录 POST 返回 429；任一次登录成功即清零。计数在内存里，网关重启后归零。

| 参数 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `window_min` | `15` | `AUTH_RATE_WINDOW_MIN` | 失败计数窗口（分钟）。 |
| `max_fails` | `8` | `AUTH_RATE_MAX_FAILS` | 窗口内失败多少次触发封禁。 |
| `ban_min` | `15` | `AUTH_RATE_BAN_MIN` | 封禁时长（分钟）。 |

## [paths]

| 参数 | 默认值 | 环境变量 | 作用 |
|---|---|---|---|
| `home` | `~/.dsh` | `DSH_HOME` | dsh 数据根目录，决定从哪读 sessions/storages。 |
| ~~`data_dir`~~ | — | `AUTH_DATA_DIR` | **已废弃**：凭据已归到 `[credentials]`。仍接受但忽略，并在启动时告警。 |

## [credentials]（由 `init` 写入，只读）

| 参数 | 说明 |
|---|---|
| `version` | 凭据格式版本，当前 `2`。 |
| `created_at` | 凭据创建时间（UTC RFC3339）。 |
| `password_updated_at` | 最近一次 `--password-only` 改密码的时间。 |
| `password_hash` | scrypt 哈希（`scrypt$<salt>$<hash>`，N=2^14, r=8, p=1, 64 字节）。也是会话签名密钥的派生源——改密码即令旧会话失效。 |
| `totp_secret_b32` | TOTP 密钥（Base32）。认证器绑定用。 |
| `totp_digits` | 固定 `6`。 |
| `totp_period` | 固定 `30`（秒）。 |
| `totp_algorithm` | 固定 `SHA1`。 |

## CLI 命令速查

命令树按「名词用单数、动作做子命令」组织，顶层不放裸动词。未发布阶段不留旧命令别名。

| 命令 | 作用 |
|---|---|
| `dsh-auth-proxy`（无子命令） | 启动网关，等价于 `serve`。服务包装器用这个。 |
| `dsh-auth-proxy serve` | 同上，显式写出。 |
| `dsh-auth-proxy --config <p> --public-origin <url>` | 指定配置与对外地址启动（两者都是持久 flag，对子命令同样生效）。 |
| `dsh-auth-proxy init` | 首次创建凭据：交互读密码（隐藏回显）+ 二次确认 + 生成 TOTP + 打印二维码和链接。凭据已存在时拒绝。 |
| `dsh-auth-proxy init --password-stdin` | 从 stdin 读一行密码（不回显、不进 shell 历史、无二次确认），供脚本使用。 |
| `dsh-auth-proxy init --force` | 全量重置：新密码 + 新 TOTP，认证器要重绑。 |
| `dsh-auth-proxy init --password-only` | 只改密码、保留 TOTP，认证器不用动；旧会话全部失效。 |
| `dsh-auth-proxy config init` | 写出行内嵌的带注释模板；已存在则拒绝，`--force` 覆盖。 |
| `dsh-auth-proxy device list`（别名 `ls`） | 列出有效设备：family 短 ID / 别名或设备名 / IP 段 / 临时或持久 / 最近活动。 |
| `dsh-auth-proxy device alias --family <id> --name <名字>` | 给设备起别名，只影响展示。`--name ""` 清除。family 用前 10 位短 ID 即可。 |
| `dsh-auth-proxy device revoke --family <id>` | 踢掉单台设备（撤销整条 family）。 |
| `dsh-auth-proxy device revoke --all` | 所有设备下线，无需改密码。 |
| `dsh-auth-proxy version` / `--version` | 打印干净的 SemVer 版本号。 |
