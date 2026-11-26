package config

import (
	"encoding/base32"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Credentials 对应 gateway.toml 的 [credentials]，由 `dsh-auth-proxy init` 写入，运行时只读。
type Credentials struct {
	Version           int    `toml:"version"`
	CreatedAt         string `toml:"created_at"`
	PasswordUpdatedAt string `toml:"password_updated_at,omitempty"`
	PasswordHash      string `toml:"password_hash"`
	TOTPSecretB32     string `toml:"totp_secret_b32"`
	TOTPDigits        int    `toml:"totp_digits"`
	TOTPPeriod        int    `toml:"totp_period"`
	TOTPAlgorithm     string `toml:"totp_algorithm"`
}

// Config 是三层合并后的运行配置：环境变量 > gateway.toml > 内置默认。
type Config struct {
	ListenHost string
	// ListenAddrs 是 listen_host 展开后的监听地址列表。
	// 支持逗号分隔多个地址，以及 "if:<网卡名>" 形式（启动时解析该网卡的 IPv4）——
	// 后者用来同时保留回环和一个会变的地址（如 WSL 的 vNIC），不必把地址写死进配置。
	ListenAddrs []string
	ListenPort  int

	DshHost      string
	DshPort      int
	DshProfile   string
	DshCwd       string
	DshBin       string
	NodeBin      string
	DshExtraArgs []string
	DshReadyMS   int64
	EnsureWaitMS int64
	DshIdleReap  bool
	DshIdleMin   int
	DshAttach    bool
	DshTokenFile string

	SessionDays       int
	SessionAbsMaxDays int
	PublicOrigin      string
	TempHours         int
	// TempAbsHours 是临时档的绝对上限（小时）。必须大于 temp_hours，
	// 否则"滑动"没有空间：一到点就死，与是否活跃无关。
	TempAbsHours int
	// RotateTempMin / RotatePersistHours 是两档的代数轮换周期。
	// 必须显著小于对应的 idle，否则"旧代数作废"等不到触发点；0 表示关闭轮换。
	RotateTempMin      int
	RotatePersistHours int
	SessionStorePath   string
	// TunnelIdleSec 是 WebSocket 隧道的空闲超时（秒）：这么久没有任何字节就断开重连。
	// dsh 每 2 秒发一次 WS ping、浏览器自动回 pong，所以活跃连接不会被误判。
	TunnelIdleSec int
	// TunnelMaxMin 是 WebSocket / SSE 隧道的寿命上限（分钟）。
	// 隧道升级后只剩字节流，网关不再验证凭证，所以必须主动掐断逼客户端重连，
	// 否则一条连接可以跨过好几个 access 周期一直有效。0 表示不限。
	TunnelMaxMin int

	// AuditLogPath 是审计 JSONL 的追加路径。空或 "off" 表示不记。
	AuditLogPath string

	TrustProxy   bool
	ProxyTrusted []*net.IPNet
	AuthEnabled  bool
	LocalCIDRs   []*net.IPNet

	RateWindowMin int
	RateMaxFails  int
	RateBanMin    int

	Home        string
	ConfigPath  string
	Credentials *Credentials
}

// ---- 文件层：全部用指针接收，缺失即 nil，便于三层覆盖 ----

type fileConfig struct {
	Server      fileServer   `toml:"server"`
	Dsh         fileDsh      `toml:"dsh"`
	Auth        fileAuth     `toml:"auth"`
	Network     fileNetwork  `toml:"network"`
	Rate        fileRate     `toml:"rate"`
	Paths       filePaths    `toml:"paths"`
	Credentials *Credentials `toml:"credentials"`
}

type fileServer struct {
	ListenHost *string `toml:"listen_host"`
	ListenPort *int    `toml:"listen_port"`
}

type fileDsh struct {
	Host       *string  `toml:"host"`
	Port       *int     `toml:"port"`
	Profile    *string  `toml:"profile"`
	Cwd        *string  `toml:"cwd"`
	Bin        *string  `toml:"bin"`
	NodeBin    *string  `toml:"node_bin"`
	ExtraArgs  []string `toml:"extra_args"`
	ReadyMS    *int64   `toml:"ready_ms"`
	EnsureWait *int64   `toml:"ensure_wait_ms"`
	IdleReap   *bool    `toml:"idle_reap"`
	IdleMin    *int     `toml:"idle_min"`
	Attach     *bool    `toml:"attach"`
	TokenFile  *string  `toml:"token_file"`
}

type fileAuth struct {
	Enabled            *bool   `toml:"enabled"`
	SessionDays        *int    `toml:"session_days"`
	SessionAbsMaxDays  *int    `toml:"session_abs_max_days"`
	PublicOrigin       *string `toml:"public_origin"`
	TempHours          *int    `toml:"temp_hours"`
	TempAbsHours       *int    `toml:"temp_abs_hours"`
	RotateTempMin      *int    `toml:"rotate_temp_min"`
	RotatePersistHours *int    `toml:"rotate_persist_hours"`
	SessionStorePath   *string `toml:"session_store_path"`
	TunnelIdleSec      *int    `toml:"tunnel_idle_sec"`
	TunnelMaxMin       *int    `toml:"tunnel_max_min"`
	AuditLogPath       *string `toml:"audit_log_path"`
	// 已废弃：双票时代的字段。保留只为让旧配置能继续启动，解析后忽略并告警。
	LegacyAccessTTLMin *int `toml:"access_ttl_min"`
	LegacyRefreshGrace *int `toml:"refresh_grace_sec"`
}

type fileNetwork struct {
	TrustProxy   *bool   `toml:"trust_proxy"`
	ProxyTrusted *string `toml:"proxy_trusted"`
	LocalCIDRs   *string `toml:"local_cidrs"`
}

type fileRate struct {
	WindowMin *int `toml:"window_min"`
	MaxFails  *int `toml:"max_fails"`
	BanMin    *int `toml:"ban_min"`
}

type filePaths struct {
	Home *string `toml:"home"`
	// 已废弃；保留是为了旧配置不触发未知键报错。
	DataDir *string `toml:"data_dir"`
}

func userHome() string {
	if v := os.Getenv("USERPROFILE"); v != "" {
		return v
	}
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	return "."
}

func dshHome() string {
	if v := os.Getenv("DSH_HOME"); v != "" {
		return v
	}
	return filepath.Join(userHome(), ".dsh")
}

func DefaultConfigPath() string {
	return filepath.Join(dshHome(), "gateway.toml")
}

// locateConfig 定位配置：显式 flag > AUTH_CONFIG_FILE > $DSH_HOME/gateway.toml > exe 同目录 config.toml。
func locateConfig(explicit string) (string, error) {
	if explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("config not found: %s", explicit)
		}
		return explicit, nil
	}
	if p := os.Getenv("AUTH_CONFIG_FILE"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("AUTH_CONFIG_FILE not found: %s", p)
		}
		return p, nil
	}
	primary := DefaultConfigPath()
	if _, err := os.Stat(primary); err == nil {
		return primary, nil
	}
	if exe, err := os.Executable(); err == nil {
		legacy := filepath.Join(filepath.Dir(exe), "config.toml")
		if _, err := os.Stat(legacy); err == nil {
			fmt.Fprintf(os.Stderr, "[config] legacy config at %s; move it to %s\n", legacy, primary)
			return legacy, nil
		}
	}
	return "", nil
}

func envStr(key string) (string, bool) {
	v := os.Getenv(key)
	if v == "" {
		return "", false
	}
	return v, true
}

func pickStr(envKey string, file *string, def string) string {
	if v, ok := envStr(envKey); ok {
		return v
	}
	if file != nil && *file != "" {
		return *file
	}
	return def
}

func pickInt(envKey string, file *int, def int) int {
	if v, ok := envStr(envKey); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	if file != nil {
		return *file
	}
	return def
}

func pickInt64(envKey string, file *int64, def int64) int64 {
	if v, ok := envStr(envKey); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	if file != nil {
		return *file
	}
	return def
}

// pickBoolDefault 与 pickBool 同构，但允许缺省为 true（认证默认开启）。
func pickBoolDefault(envKey string, file *bool, def bool) bool {
	if v, ok := os.LookupEnv(envKey); ok {
		return v == "1" || v == "true" || v == "TRUE"
	}
	if file != nil {
		return *file
	}
	return def
}

func pickBool(envKey string, file *bool) bool {
	if v, ok := os.LookupEnv(envKey); ok {
		return v == "1" || v == "true" || v == "TRUE"
	}
	if file != nil {
		return *file
	}
	return false
}

func pickList(envKey string, file []string) []string {
	if v, ok := envStr(envKey); ok {
		out := make([]string, 0, 4)
		for _, s := range strings.Split(v, "|") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return file
}

func parseCIDRs(raw, source string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("%s: bad CIDR %q: %w", source, item, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// LoadConfig 读取并合并配置。credentials 缺失由调用方决定是否致命。
func LoadConfig(explicit string) (*Config, error) {
	return LoadConfigWithPublicOrigin(explicit, "")
}

// LoadConfigWithPublicOrigin 在 LoadConfig 基础上允许 CLI --public-origin 覆盖。
func LoadConfigWithPublicOrigin(explicit, cliPublicOrigin string) (*Config, error) {
	path, err := locateConfig(explicit)
	if err != nil {
		return nil, err
	}

	var fc fileConfig
	if path != "" {
		md, err := toml.DecodeFile(path, &fc)
		if err != nil {
			return nil, fmt.Errorf("parse config %s: %w", path, err)
		}
		if undecoded := md.Undecoded(); len(undecoded) > 0 {
			keys := make([]string, 0, len(undecoded))
			for _, k := range undecoded {
				keys = append(keys, k.String())
			}
			return nil, fmt.Errorf("config %s has unknown keys: %s", path, strings.Join(keys, ", "))
		}
	}
	if fc.Auth.LegacyAccessTTLMin != nil || fc.Auth.LegacyRefreshGrace != nil {
		fmt.Fprintln(os.Stderr, "[config] deprecated: access_ttl_min / refresh_grace_sec are ignored; sessions use idle + abs + generation rotation")
	}

	if fc.Paths.DataDir != nil || os.Getenv("AUTH_DATA_DIR") != "" {
		fmt.Fprintln(os.Stderr, "[config] deprecated: [paths] data_dir / AUTH_DATA_DIR ignored; credentials live in [credentials]")
	}

	up := userHome()
	cfg := &Config{
		ListenHost: pickStr("AUTH_PROXY_HOST", fc.Server.ListenHost, "127.0.0.1"),
		ListenPort: pickInt("AUTH_PROXY_PORT", fc.Server.ListenPort, 33080),

		DshHost:    pickStr("AUTH_DSH_HOST", fc.Dsh.Host, "127.0.0.1"),
		DshPort:    pickInt("AUTH_DSH_PORT", fc.Dsh.Port, 0),
		DshProfile: pickStr("AUTH_DSH_PROFILE", fc.Dsh.Profile, "web"),
		DshCwd: pickStr("DSH_CWD", fc.Dsh.Cwd,
			filepath.Join(up, "WorkBuddy", "dsh")),
		DshBin: pickStr("DSH_BIN", fc.Dsh.Bin,
			filepath.Join(up, "scoop", "apps", "dsh", "current", "lib", "bin.js")),
		NodeBin:      pickStr("AUTH_NODE_BIN", fc.Dsh.NodeBin, defaultNodeBin()),
		DshExtraArgs: pickList("AUTH_DSH_EXTRA_ARGS", fc.Dsh.ExtraArgs),
		DshReadyMS:   pickInt64("AUTH_DSH_READY_MS", fc.Dsh.ReadyMS, 90000),
		EnsureWaitMS: pickInt64("AUTH_GATEWAY_ENSURE_WAIT_MS", fc.Dsh.EnsureWait, 20000),
		DshIdleReap:  pickBool("AUTH_DSH_IDLE_REAP", fc.Dsh.IdleReap),
		DshIdleMin:   pickInt("AUTH_DSH_IDLE_MIN", fc.Dsh.IdleMin, 30),
		DshAttach:    pickBool("AUTH_DSH_ATTACH", fc.Dsh.Attach),
		DshTokenFile: pickStr("AUTH_DSH_TOKEN_FILE", fc.Dsh.TokenFile,
			filepath.Join(dshHome(), "dsh-url.txt")),

		SessionDays:        pickInt("AUTH_SESSION_DAYS", fc.Auth.SessionDays, 14),
		SessionAbsMaxDays:  pickInt("AUTH_SESSION_ABS_MAX_DAYS", fc.Auth.SessionAbsMaxDays, 30),
		PublicOrigin:       pickStr("AUTH_PUBLIC_ORIGIN", fc.Auth.PublicOrigin, ""),
		TempHours:          pickInt("AUTH_TEMP_HOURS", fc.Auth.TempHours, 2),
		TempAbsHours:       pickInt("AUTH_TEMP_ABS_HOURS", fc.Auth.TempAbsHours, 6),
		RotateTempMin:      pickInt("AUTH_ROTATE_TEMP_MIN", fc.Auth.RotateTempMin, 30),
		RotatePersistHours: pickInt("AUTH_ROTATE_PERSIST_HOURS", fc.Auth.RotatePersistHours, 24),
		SessionStorePath:   pickStr("AUTH_SESSION_STORE", fc.Auth.SessionStorePath, filepath.Join(dshHome(), "sessions.json")),
		TunnelIdleSec:      pickInt("AUTH_TUNNEL_IDLE_SEC", fc.Auth.TunnelIdleSec, 60),
		TunnelMaxMin:       pickInt("AUTH_TUNNEL_MAX_MIN", fc.Auth.TunnelMaxMin, 30),
		AuditLogPath:       pickStr("AUTH_AUDIT_LOG", fc.Auth.AuditLogPath, filepath.Join(dshHome(), "audit.jsonl")),
		AuthEnabled:        pickBoolDefault("AUTH_GATEWAY_AUTH_ENABLED", fc.Auth.Enabled, true),

		TrustProxy: pickBool("AUTH_TRUST_PROXY", fc.Network.TrustProxy),

		RateWindowMin: pickInt("AUTH_RATE_WINDOW_MIN", fc.Rate.WindowMin, 15),
		RateMaxFails:  pickInt("AUTH_RATE_MAX_FAILS", fc.Rate.MaxFails, 8),
		RateBanMin:    pickInt("AUTH_RATE_BAN_MIN", fc.Rate.BanMin, 15),

		Home:        pickStr("DSH_HOME", fc.Paths.Home, dshHome()),
		ConfigPath:  path,
		Credentials: fc.Credentials,
	}

	// 监听地址在启动时展开一次：接口名解析成具体地址，避免运行期反复查网卡。
	if cfg.ListenAddrs, err = parseListenAddrs(cfg.ListenHost); err != nil {
		return nil, err
	}

	trustedRaw := pickStr("AUTH_PROXY_TRUSTED", fc.Network.ProxyTrusted,
		"172.16.0.0/12,10.0.0.0/8,192.168.0.0/16")
	localRaw := pickStr("AUTH_LOCAL_CIDRS", fc.Network.LocalCIDRs, "127.0.0.0/8,::1/128")
	if cfg.ProxyTrusted, err = parseCIDRs(trustedRaw, "proxy_trusted"); err != nil {
		return nil, err
	}
	if cfg.LocalCIDRs, err = parseCIDRs(localRaw, "local_cidrs"); err != nil {
		return nil, err
	}

	if cfg.SessionAbsMaxDays < cfg.SessionDays {
		return nil, fmt.Errorf("auth.session_abs_max_days must be >= auth.session_days")
	}
	// CLI --public-origin 优先级最高，覆盖配置文件与环境变量。
	if cliPublicOrigin != "" {
		cfg.PublicOrigin = cliPublicOrigin
	}
	// public_origin 必须显式指定：把某个人的域名写死在二进制里，对其他部署者是无声的坑。
	if strings.TrimSpace(cfg.PublicOrigin) == "" {
		return nil, fmt.Errorf("auth.public_origin is required (set it in gateway.toml, --public-origin, or AUTH_PUBLIC_ORIGIN)")
	}
	// 明文口令过网禁止：没有 https 的外层，就必须只听回环。
	if !strings.HasPrefix(cfg.PublicOrigin, "https://") && !isLoopbackHost(cfg.ListenHost) {
		return nil, fmt.Errorf("refusing: non-https public_origin + non-loopback listen would send password in cleartext")
	}
	return cfg, nil
}

func defaultNodeBin() string {
	if v := os.Getenv("CODEBUDDY_NODE_BIN"); v != "" {
		return v
	}
	if v := os.Getenv("NODE"); v != "" {
		return v
	}
	return "node"
}

func isLoopbackHost(h string) bool {
	switch h {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// parseListenAddrs 展开 server.listen_host。语法：
//
//	127.0.0.1                     单个地址
//	127.0.0.1,if:vEthernet (WSL)  多个地址，逗号分隔
//	if:<网卡名>                    取该网卡上的第一个非回环 IPv4，启动时解析
//
// 接口名形式是为了"绑网卡而不是绑地址"：WSL 的 vNIC 地址会在重启后变化，
// 写死地址会在某次重启后静默失效（监听失败或绑到不存在的地址）。
func parseListenAddrs(raw string) ([]string, error) {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if name, ok := strings.CutPrefix(p, "if:"); ok {
			ip, err := interfaceIPv4(strings.TrimSpace(name))
			if err != nil {
				return nil, err
			}
			out = append(out, ip)
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("server.listen_host resolved to no address: %q", raw)
	}
	return out, nil
}

// interfaceIPv4 取指定网卡上的第一个非回环 IPv4。
func interfaceIPv4(name string) (string, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return "", fmt.Errorf("server.listen_host: interface %q not found: %w", name, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", fmt.Errorf("server.listen_host: read addresses of %q: %w", name, err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("server.listen_host: interface %q has no IPv4 address", name)
}

// CookieSecure 决定是否给 cookie 加 Secure；跟着对外 URL 走。
func (c *Config) CookieSecure() bool {
	return strings.HasPrefix(c.PublicOrigin, "https://")
}

// OriginAuthority 取出 URL 的 authority（host:port），非法输入返回空串。
func OriginAuthority(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return ""
	}
	rest := raw[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSuffix(rest, "/")
}

// decodeBase32 内联实现，避免 config -> auth 循环依赖。
func decodeBase32(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(strings.TrimSpace(s)))
	if clean == "" {
		return nil, fmt.Errorf("empty secret")
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
}

// Validate 校验凭据可用性，避免"配置在但永远登不上"。
func (c *Credentials) Validate() error {
	if c == nil {
		return fmt.Errorf("credentials missing")
	}
	if c.Version != 2 {
		return fmt.Errorf("credentials version %d unsupported (expected 2)", c.Version)
	}
	if !strings.HasPrefix(c.PasswordHash, "scrypt$") {
		return fmt.Errorf(`credentials.password_hash must start with "scrypt$"`)
	}
	if c.TOTPDigits != 6 {
		return fmt.Errorf("credentials.totp_digits must be 6")
	}
	if c.TOTPPeriod != 30 {
		return fmt.Errorf("credentials.totp_period must be 30")
	}
	if !strings.EqualFold(c.TOTPAlgorithm, "SHA1") {
		return fmt.Errorf("credentials.totp_algorithm must be SHA1")
	}
	raw, err := decodeBase32(c.TOTPSecretB32)
	if err != nil {
		return fmt.Errorf("credentials.totp_secret_b32: %w", err)
	}
	if len(raw) < 10 {
		return fmt.Errorf("credentials.totp_secret_b32 too short (%d bytes)", len(raw))
	}
	return nil
}
