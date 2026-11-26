package supervisor

import (
	"context"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, p, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	fmt.Sscanf(p, "%d", &port)
	return port
}

// 并发请求必须共享同一次拉起：exchange 只应发生一次。
func TestEnsureConcurrentSingleStart(t *testing.T) {
	var exchanges atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			exchanges.Add(1)
			time.Sleep(120 * time.Millisecond) // 拉宽竞争窗口
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "url.txt")
	line := fmt.Sprintf("dsh web: http://127.0.0.1:%d/?token=testtoken\n", portOf(t, backend))
	if err := os.WriteFile(tokenFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AuthEnabled: true,
		DshHost:     "127.0.0.1", DshAttach: true, DshTokenFile: tokenFile, DshReadyMS: 5000,
		DshIdleMin: 30, PublicOrigin: "https://x", SessionDays: 30, TempHours: 2,
		LocalCIDRs:  []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
		Credentials: &config.Credentials{Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
	sup := NewSupervisor(cfg, func(string, ...any) {})

	var wg sync.WaitGroup
	errs := make([]error, 12)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, errs[i] = sup.Ensure(ctx)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("Ensure[%d] failed: %v", i, err)
		}
	}
	if n := exchanges.Load(); n != 1 {
		t.Fatalf("token exchange ran %d times, want 1", n)
	}
	if got := sup.State(); got != StateRunning {
		t.Fatalf("state = %v, want running", got)
	}
}

// 拉起失败后进入退避窗口，第二次调用不应再次触发拉起。
func TestEnsureBackoffAfterFailure(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "missing.txt")
	cfg := &config.Config{
		AuthEnabled: true,
		DshHost:     "127.0.0.1", DshAttach: true, DshTokenFile: tokenFile, DshReadyMS: 1000,
		DshIdleMin: 30, PublicOrigin: "https://x", SessionDays: 30, TempHours: 2,
		Credentials: &config.Credentials{Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
	sup := NewSupervisor(cfg, func(string, ...any) {})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := sup.Ensure(ctx); err == nil {
		t.Fatal("first Ensure should fail")
	}
	if got := sup.State(); got != StateFailed {
		t.Fatalf("state = %v, want failed", got)
	}

	// 退避窗口内再调一次：应立刻返回失败且不重新拉起（错误里带 retry 提示）。
	start := time.Now()
	_, err := sup.Ensure(ctx)
	if err == nil {
		t.Fatal("second Ensure should fail during backoff")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("backoff did not short-circuit: took %v", elapsed)
	}
	if st := sup.Status(0); st.LastError == "" {
		t.Fatal("status should carry last error")
	}
}
