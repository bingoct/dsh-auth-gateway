package web

import (
	"bufio"
	"context"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/bingoct/dsh-auth-gateway/internal/supervisor"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad cidr %s: %v", s, err)
	}
	return n
}

// testGateway 起一个本地免认证网关，attach 到给定后端。
func testGateway(t *testing.T, backendPort int) *Gateway {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "url.txt")
	line := fmt.Sprintf("dsh web: http://127.0.0.1:%d/?token=testtoken\n", backendPort)
	if err := os.WriteFile(tokenFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AuthEnabled:   true,
		DshHost:       "127.0.0.1",
		DshPort:       backendPort,
		DshAttach:     true,
		DshTokenFile:  tokenFile,
		DshReadyMS:    5000,
		DshIdleMin:    30,
		PublicOrigin:  "https://dsh.example",
		LocalCIDRs:    []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
		SessionDays:   30,
		TempHours:     2,
		RateWindowMin: 15,
		RateMaxFails:  8,
		RateBanMin:    15,
		Credentials:   &config.Credentials{Version: 2, PasswordHash: "scrypt$AAAA$AAAA", TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
	logf := func(string, ...any) {}
	auth := auth.NewAuthenticator(cfg)
	sup := supervisor.NewSupervisor(cfg, logf)
	return NewGateway(cfg, auth, sup, logf)
}

func backendPort(t *testing.T, srv *httptest.Server) int {
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

// 101 升级后字节必须双向流动，且不能被网关截断。
func TestProxyWebSocketEcho(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "want upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("ECHO:" + line))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	u, _ := url.Parse(front.URL)
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "GET /api/remote.mux HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", u.Host)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("PING\n")); err != nil {
		t.Fatal(err)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if line != "ECHO:PING\n" {
		t.Fatalf("echo = %q, want %q", line, "ECHO:PING\n")
	}
}

// chunked 请求体必须完整到达上游：这是裸 TCP 版曾经丢掉已读字节的路径。
func TestProxyChunkedRequestBody(t *testing.T) {
	const payload = "chunked-body-0123456789"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		fmt.Fprintf(w, "%d:%s", len(body), body)
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte(payload))
		_ = pw.Close()
	}()
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/upload", pr)
	req.ContentLength = -1 // 触发 chunked

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	want := fmt.Sprintf("%d:%s", len(payload), payload)
	if string(got) != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// 上游 Set-Cookie 不能泄漏到浏览器：v1 cookie 只属于网关到 dsh 这一段。
func TestProxyStripsUpstreamSetCookie(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "dsh-auth-leak", Value: "secret", Path: "/"})
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if len(resp.Cookies()) != 0 {
		t.Fatalf("upstream set-cookie leaked: %v", resp.Cookies())
	}
}

// 隧道到点必须被网关掐断：否则一条 WS 连接能跨过好几个 access 周期一直有效，
// 凭证过期等于没生效。断开后客户端会重连，重连时重新走认证。
func TestTunnelLifetimeCutsConnection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "want upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		// 建立之后什么都不发，模拟一条挂着不动的心跳连接。
		time.Sleep(3 * time.Second)
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	gw.tunnelMax = 150 * time.Millisecond
	gw.reconcileEvery = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.Start(ctx)
	front := httptest.NewServer(gw)
	defer front.Close()

	u, _ := url.Parse(front.URL)
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "GET /api/remote.mux HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n", u.Host)
	br := bufio.NewReader(conn)
	if _, err := http.ReadResponse(br, nil); err != nil {
		t.Fatalf("read handshake: %v", err)
	}

	start := time.Now()
	if code := expectCloseFrame(t, br); code != closeCodeRevoked {
		t.Fatalf("close code = %d, want %d", code, closeCodeRevoked)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("tunnel took %v to cut, want roughly 150ms", elapsed)
	}
}
