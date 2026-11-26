package web

import (
	"bufio"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/bingoct/dsh-auth-gateway/internal/supervisor"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 拉起期间必须给等待页，而不是白屏或裸错误。
func TestStartingPageWhileBooting(t *testing.T) {
	t.Setenv("FAKE_DSH_MODE", "silent")
	cfg := spawnCfg(t, 60000)
	cfg.EnsureWaitMS = 300

	logf := func(string, ...any) {}
	sup := supervisor.NewSupervisor(cfg, logf)
	defer sup.Shutdown()
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), sup, logf)
	front := httptest.NewServer(gw)
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got != "2" {
		t.Fatalf("Retry-After = %q, want 2", got)
	}
	if !strings.Contains(string(body), "正在启动") {
		t.Fatalf("body = %q, want starting page", body)
	}
}

// 拉起失败页要带上 dsh 的 stderr，否则用户只能去翻日志。
func TestFailedPageShowsStderr(t *testing.T) {
	t.Setenv("FAKE_DSH_MODE", "error")
	cfg := spawnCfg(t, 5000)
	cfg.EnsureWaitMS = 5000

	logf := func(string, ...any) {}
	sup := supervisor.NewSupervisor(cfg, logf)
	defer sup.Shutdown()
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), sup, logf)
	front := httptest.NewServer(gw)
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", resp.StatusCode)
	}
	if !strings.Contains(string(body), "FAKE_BOOT_FAILURE") {
		t.Fatalf("body missing stderr tail:\n%s", body)
	}
	if st := sup.Status(0); st.LastError == "" {
		t.Fatal("status should carry the last error")
	}
}

// 客户端读到一半断开，不能拖垮网关，后续请求必须照常服务。
func TestClientAbortDoesNotBreakGateway(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("part1\n"))
		w.(http.Flusher).Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("part2\n"))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	// 预热，确保 attach + 探针已完成。
	warm, err := http.Get(front.URL + "/warm")
	if err == nil {
		_, _ = io.Copy(io.Discard, warm.Body)
		warm.Body.Close()
	}

	u, _ := url.Parse(front.URL)
	conn, err := net.DialTimeout("tcp", u.Host, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "GET /abort HTTP/1.1\r\nHost: %s\r\n\r\n", u.Host)
	br := bufio.NewReader(conn)
	if _, err := br.ReadString('\n'); err != nil { // 读状态行后立刻断开
		t.Fatalf("read status line: %v", err)
	}
	conn.Close()

	// 给上游一点时间感知断开。
	time.Sleep(400 * time.Millisecond)

	resp, err := http.Get(front.URL + "/after-abort")
	if err != nil {
		t.Fatalf("gateway stopped serving after client abort: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "part1") {
		t.Fatalf("after abort: code=%d body=%q", resp.StatusCode, body)
	}
}

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
