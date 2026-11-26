package supervisor

import (
	"context"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// spawnCfg 指向 testdata/fake-dsh.js，让 spawn 路径真跑一个子进程。
func spawnCfg(t *testing.T, readyMS int64) *config.Config {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fake-dsh.js"))
	if err != nil {
		t.Fatal(err)
	}
	return &config.Config{
		AuthEnabled: true,
		NodeBin:     "node", DshBin: abs, DshCwd: t.TempDir(),
		DshProfile: "web", DshHost: "127.0.0.1", DshPort: 0,
		DshReadyMS: readyMS, EnsureWaitMS: 20000, DshIdleMin: 30, Home: t.TempDir(),
		LocalCIDRs:   []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
		PublicOrigin: "https://x", SessionDays: 30, TempHours: 2,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		Credentials: &config.Credentials{Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
}

// waitPortClosed 轮询到端口拒绝连接为止：Kill 是异步的，进程退出需要时间。
func waitPortClosed(t *testing.T, port int, limit time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
		if err != nil {
			return true
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func ensureCtx(t *testing.T, sup *Supervisor, d time.Duration) (*Runtime, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return sup.Ensure(ctx)
}

// 拉起 → 就绪 → 停止：完整生命周期，且 cookie 必须是 exchange 拿到的那个。
func TestSpawnAndShutdown(t *testing.T) {
	cfg := spawnCfg(t, 5000)
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	rt, err := ensureCtx(t, sup, 8*time.Second)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if rt.Port <= 0 {
		t.Fatalf("port = %d, want > 0", rt.Port)
	}
	if !strings.HasPrefix(rt.Cookie, "dsh-auth-FAKE=v1-") {
		t.Fatalf("cookie = %q, want exchange result", rt.Cookie)
	}
	if got := sup.State(); got != StateRunning {
		t.Fatalf("state = %v, want running", got)
	}
	if st := sup.Status(0); st.PID <= 0 || st.Port != rt.Port {
		t.Fatalf("status = %+v, want pid and port", st)
	}

	sup.Shutdown()
	if got := sup.State(); got != StateStopped {
		t.Fatalf("state after shutdown = %v, want stopped", got)
	}
	// 端口必须真的关掉，而不是只把状态改成 stopped。
	if !waitPortClosed(t, rt.Port, 3*time.Second) {
		t.Fatalf("port %d still accepting after shutdown", rt.Port)
	}
}

// 运行期崩溃：状态回到 stopped，下次 Ensure 自动重建。
func TestSpawnCrashAndRebuild(t *testing.T) {
	t.Setenv("FAKE_DSH_MODE", "crash")
	cfg := spawnCfg(t, 5000)
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	first, err := ensureCtx(t, sup, 8*time.Second)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}

	// fake 就绪后 300ms 退出，等它退干净。
	deadline := time.Now().Add(3 * time.Second)
	for sup.State() == StateRunning && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := sup.State(); got != StateStopped {
		t.Fatalf("state after crash = %v, want stopped", got)
	}
	if sup.Runtime() != nil {
		t.Fatal("runtime must be cleared after crash")
	}

	second, err := ensureCtx(t, sup, 8*time.Second)
	if err != nil {
		t.Fatalf("second Ensure after crash: %v", err)
	}
	if second.Port <= 0 {
		t.Fatalf("rebuilt port = %d", second.Port)
	}
	if first.Cookie == second.Cookie {
		t.Fatalf("cookie should be re-exchanged after rebuild, both %q", first.Cookie)
	}
}

// 拉起超时：token 一直不来时必须快速失败，而不是挂到 ready_ms 之外。
func TestSpawnTimeout(t *testing.T) {
	t.Setenv("FAKE_DSH_MODE", "silent")
	cfg := spawnCfg(t, 400)
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	start := time.Now()
	_, err := ensureCtx(t, sup, 5*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Ensure should fail when no token appears")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("timeout took %v, want ~400ms", elapsed)
	}
	if got := sup.State(); got != StateFailed {
		t.Fatalf("state = %v, want failed", got)
	}
}

// 空闲回收：无活跃请求且超过阈值时真的杀进程。
func TestIdleReap(t *testing.T) {
	cfg := spawnCfg(t, 5000)
	cfg.DshIdleReap = true
	cfg.DshIdleMin = 1
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	rt, err := ensureCtx(t, sup, 8*time.Second)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	sup.ReapIfIdle(0) // 还没到阈值：不应回收
	if sup.State() != StateRunning {
		t.Fatal("reaped before the idle threshold")
	}

	// 把最后活跃时间拨到 2 分钟前，越过 1 分钟阈值。
	sup.lastActive.Store(time.Now().Add(-2 * time.Minute).UnixMilli())

	sup.ReapIfIdle(1) // 有活跃请求：不应回收
	if sup.State() != StateRunning {
		t.Fatal("must not reap while requests are active")
	}

	sup.ReapIfIdle(0)
	if got := sup.State(); got != StateStopped {
		t.Fatalf("state after reap = %v, want stopped", got)
	}
	if !waitPortClosed(t, rt.Port, 3*time.Second) {
		t.Fatalf("port %d still accepting after idle reap", rt.Port)
	}
}

// idle_min = 0 表示关闭自动回收，绝不能被理解成"0 分钟即立刻回收"。
func TestIdleDisabledByZero(t *testing.T) {
	cfg := spawnCfg(t, 5000)
	cfg.DshIdleReap = true
	cfg.DshIdleMin = 0
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	if _, err := ensureCtx(t, sup, 8*time.Second); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	sup.lastActive.Store(time.Now().Add(-24 * time.Hour).UnixMilli())
	sup.ReapIfIdle(0)
	if got := sup.State(); got != StateRunning {
		t.Fatalf("state = %v; idle_min=0 must disable auto-reap", got)
	}
}

// 页面关了但 agent 还在写会话文件时，不能被当成空闲杀掉。
func TestSessionsBusyBlocksReap(t *testing.T) {
	cfg := spawnCfg(t, 5000)
	cfg.DshIdleReap = true
	cfg.DshIdleMin = 1
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	if _, err := ensureCtx(t, sup, 8*time.Second); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	sessDir := filepath.Join(cfg.Home, "sessions", "--ws--", "session-x")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessDir, "session.v4.jsonl.zstd"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	sup.lastActive.Store(time.Now().Add(-2 * time.Minute).UnixMilli())
	sup.ReapIfIdle(0)

	if got := sup.State(); got != StateRunning {
		t.Fatalf("state = %v; must not reap while session files are being written", got)
	}
}

// 会话窗口外的旧文件不应阻止回收。
func TestStaleSessionsAllowReap(t *testing.T) {
	cfg := spawnCfg(t, 5000)
	cfg.DshIdleReap = true
	cfg.DshIdleMin = 1
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	rt, err := ensureCtx(t, sup, 8*time.Second)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	sessDir := filepath.Join(cfg.Home, "sessions", "--ws--", "session-old")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sessDir, "session.v4.jsonl.zstd")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-30 * time.Minute)
	if err := os.Chtimes(f, past, past); err != nil {
		t.Fatal(err)
	}

	sup.lastActive.Store(time.Now().Add(-2 * time.Minute).UnixMilli())
	sup.ReapIfIdle(0)

	if got := sup.State(); got != StateStopped {
		t.Fatalf("state = %v; stale session files must not block reap", got)
	}
	if !waitPortClosed(t, rt.Port, 3*time.Second) {
		t.Fatalf("port %d still accepting", rt.Port)
	}
}

// 开关默认关闭：即使空闲很久也不杀，定时任务场景下这是唯一安全的默认值。
func TestIdleReapOffByDefault(t *testing.T) {
	cfg := spawnCfg(t, 5000)
	if cfg.DshIdleReap {
		t.Fatal("idle reap must default to off")
	}
	cfg.DshIdleMin = 1
	sup := NewSupervisor(cfg, func(string, ...any) {})
	defer sup.Shutdown()

	if _, err := ensureCtx(t, sup, 8*time.Second); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	sup.lastActive.Store(time.Now().Add(-24 * time.Hour).UnixMilli())
	sup.ReapIfIdle(0)
	if got := sup.State(); got != StateRunning {
		t.Fatalf("state = %v; reap must stay off unless explicitly enabled", got)
	}
}

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad cidr %s: %v", s, err)
	}
	return n
}
