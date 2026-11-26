package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// clearAuthEnv 去掉环境变量这一层的干扰：LoadConfig 是 env > file > default，
// 宿主里有 AUTH_* 时会把断言带偏。
func clearAuthEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"AUTH_PROXY_HOST", "AUTH_PROXY_PORT", "AUTH_DSH_HOST", "AUTH_DSH_PORT",
		"AUTH_DSH_PROFILE", "AUTH_DSH_IDLE_REAP", "AUTH_DSH_IDLE_MIN", "AUTH_DSH_READY_MS",
		"AUTH_DSH_ATTACH", "AUTH_SESSION_DAYS", "AUTH_SESSION_ABS_MAX_DAYS",
		"AUTH_PUBLIC_ORIGIN", "AUTH_TEMP_HOURS", "AUTH_TRUST_PROXY", "AUTH_PROXY_TRUSTED",
		"AUTH_LOCAL_CIDRS", "AUTH_RATE_WINDOW_MIN", "AUTH_RATE_MAX_FAILS", "AUTH_RATE_BAN_MIN",
		"AUTH_CONFIG_FILE", "AUTH_NODE_BIN", "AUTH_DSH_EXTRA_ARGS", "AUTH_DSH_TOKEN_FILE",
		"AUTH_DATA_DIR", "DSH_HOME", "DSH_BIN", "DSH_CWD", "NODE", "CODEBUDDY_NODE_BIN",
	}
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			k, v := k, v
			_ = os.Unsetenv(k)
			t.Cleanup(func() { _ = os.Setenv(k, v) })
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// public_origin 必填：配置文件、环境变量、CLI 都没给时拒绝启动。
func TestConfigRequiresPublicOrigin(t *testing.T) {
	clearAuthEnv(t)
	if _, err := LoadConfig(writeConfig(t, "")); err == nil || !strings.Contains(err.Error(), "public_origin is required") {
		t.Fatalf("err = %v, want public_origin-required error", err)
	}
}

// 环境变量可提供 public_origin；CLI --public-origin 再覆盖它。
func TestConfigPublicOriginSources(t *testing.T) {
	clearAuthEnv(t)
	path := writeConfig(t, "[auth]\npublic_origin = \"https://file.example\"\n")
	cfg, err := LoadConfig(path)
	if err != nil || cfg.PublicOrigin != "https://file.example" {
		t.Fatalf("file origin: cfg=%v err=%v", cfg, err)
	}
	t.Setenv("AUTH_PUBLIC_ORIGIN", "https://env.example")
	cfg, err = LoadConfig(path)
	if err != nil || cfg.PublicOrigin != "https://env.example" {
		t.Fatalf("env origin: cfg=%v err=%v", cfg, err)
	}
	cfg, err = LoadConfigWithPublicOrigin(path, "https://cli.example")
	if err != nil || cfg.PublicOrigin != "https://cli.example" {
		t.Fatalf("cli origin: cfg=%v err=%v", cfg, err)
	}
}

// 无配置文件时的内置默认值：本地回环、33080、空闲回收关闭。
func TestConfigDefaults(t *testing.T) {
	clearAuthEnv(t)
	cfg, err := LoadConfig(writeConfig(t, "[auth]\npublic_origin = \"https://dsh.example\"\n"))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenHost != "127.0.0.1" || cfg.ListenPort != 33080 {
		t.Fatalf("listen = %s:%d, want 127.0.0.1:33080", cfg.ListenHost, cfg.ListenPort)
	}
	if cfg.DshIdleReap {
		t.Fatal("idle_reap must default to false")
	}
	if cfg.DshIdleMin != 30 {
		t.Fatalf("idle_min = %d, want 30", cfg.DshIdleMin)
	}
	if cfg.DshPort != 0 {
		t.Fatalf("dsh port = %d, want 0 (OS assigned)", cfg.DshPort)
	}
	if cfg.DshProfile != "web" {
		t.Fatalf("profile = %q, want web", cfg.DshProfile)
	}
	if cfg.SessionDays != 14 || cfg.SessionAbsMaxDays != 30 {
		t.Fatalf("persist window = %d/%d, want 14/30", cfg.SessionDays, cfg.SessionAbsMaxDays)
	}
	if cfg.TempHours != 2 || cfg.TempAbsHours != 6 {
		t.Fatalf("temp window = %d/%d, want 2/6", cfg.TempHours, cfg.TempAbsHours)
	}
	if cfg.RotateTempMin != 30 || cfg.RotatePersistHours != 24 {
		t.Fatalf("rotate = %d min / %d h, want 30 / 24", cfg.RotateTempMin, cfg.RotatePersistHours)
	}
	if cfg.TunnelIdleSec != 60 || cfg.TunnelMaxMin != 30 {
		t.Fatalf("tunnel = %d s idle / %d min max, want 60 / 30", cfg.TunnelIdleSec, cfg.TunnelMaxMin)
	}
	if !cfg.CookieSecure() {
		t.Fatal("https public_origin must mark cookies Secure")
	}
}

// 文件层覆盖默认值。
func TestConfigFileOverrides(t *testing.T) {
	clearAuthEnv(t)
	path := writeConfig(t, `
[server]
listen_port = 8080

[dsh]
idle_reap = true
idle_min = 5
profile = "headless"

[auth]
public_origin = "https://dsh.example"
session_days = 7
session_abs_max_days = 14
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenPort != 8080 {
		t.Fatalf("listen_port = %d, want 8080", cfg.ListenPort)
	}
	if !cfg.DshIdleReap {
		t.Fatal("idle_reap from file must be honoured")
	}
	if cfg.DshIdleMin != 5 {
		t.Fatalf("idle_min = %d, want 5", cfg.DshIdleMin)
	}
	if cfg.DshProfile != "headless" {
		t.Fatalf("profile = %q", cfg.DshProfile)
	}
	if cfg.SessionDays != 7 || cfg.SessionAbsMaxDays != 14 {
		t.Fatalf("session = %d/%d", cfg.SessionDays, cfg.SessionAbsMaxDays)
	}
}

// 环境变量优先级最高。
func TestConfigEnvWins(t *testing.T) {
	clearAuthEnv(t)
	path := writeConfig(t, "[server]\nlisten_port = 8080\n[dsh]\nidle_reap = true\n[auth]\npublic_origin = \"https://dsh.example\"\n")
	t.Setenv("AUTH_PROXY_PORT", "9090")
	t.Setenv("AUTH_DSH_IDLE_REAP", "false")

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ListenPort != 9090 {
		t.Fatalf("env must win: port = %d, want 9090", cfg.ListenPort)
	}
	if cfg.DshIdleReap {
		t.Fatal("AUTH_DSH_IDLE_REAP=false must override the file")
	}
}

// 拼错的键必须报错，而不是静默忽略（否则用户以为开了回收其实没开）。
func TestConfigRejectsUnknownKeys(t *testing.T) {
	clearAuthEnv(t)
	path := writeConfig(t, "[dsh]\nidle_minutes = 5\n")
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("err = %v, want unknown-keys error", err)
	}
}

// 明文口令过网：非 https 对外地址 + 非回环监听必须拒绝启动。
func TestConfigRejectsCleartextWideListen(t *testing.T) {
	clearAuthEnv(t)
	path := writeConfig(t, `
[server]
listen_host = "0.0.0.0"
[auth]
public_origin = "http://example.com"
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "cleartext") {
		t.Fatalf("err = %v, want cleartext refusal", err)
	}
}

// 绝对上限小于常规有效期是自相矛盾的配置。
func TestConfigRejectsBadSessionWindow(t *testing.T) {
	clearAuthEnv(t)
	path := writeConfig(t, "[auth]\nsession_days = 30\nsession_abs_max_days = 7\n")
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "session_abs_max_days") {
		t.Fatalf("err = %v, want session window error", err)
	}
}

// 非法 CIDR 必须报错，而不是悄悄变成"永不匹配"。
func TestConfigRejectsBadCIDR(t *testing.T) {
	clearAuthEnv(t)
	path := writeConfig(t, "[network]\nlocal_cidrs = \"127.0.0.0/8,not-a-cidr\"\n")
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "not-a-cidr") {
		t.Fatalf("err = %v, want bad CIDR error", err)
	}
}

// listen_host 的展开规则：逗号分隔、空项忽略、接口名解析失败必须报错而不是静默降级。
func TestParseListenAddrs(t *testing.T) {
	got, err := parseListenAddrs("127.0.0.1, 0.0.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "127.0.0.1" || got[1] != "0.0.0.0" {
		t.Fatalf("got %v", got)
	}
	if _, err := parseListenAddrs("   "); err == nil {
		t.Fatal("empty listen_host must fail")
	}
	if _, err := parseListenAddrs("if:no-such-interface-xyz"); err == nil {
		t.Fatal("unknown interface must fail fast")
	}
}
