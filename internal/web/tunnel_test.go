package web

import (
	"bufio"
	"context"
	"encoding/binary"
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
	"strconv"
	"strings"
	"testing"
	"time"
)

// tunnelGateway 起一个必须登录的网关，并把来源地址改写成 10.9.9.9。
func tunnelGateway(t *testing.T, backendPort int) (*Gateway, *auth.Authenticator, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "url.txt")
	line := "dsh web: http://127.0.0.1:" + strconv.Itoa(backendPort) + "/?token=t\n"
	if err := os.WriteFile(tokenFile, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AuthEnabled: true,
		DshHost:     "127.0.0.1", DshPort: backendPort, DshAttach: true, DshTokenFile: tokenFile,
		DshReadyMS: 5000, DshIdleMin: 30,
		PublicOrigin: "https://dsh.example",
		SessionDays:  14, SessionAbsMaxDays: 30,
		TempHours: 2, TempAbsHours: 6,
		RotateTempMin: 30, RotatePersistHours: 24,
		TunnelIdleSec: 0, // 关掉空闲判定，只测撤销
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		Credentials: &config.Credentials{Version: 2, PasswordHash: "scrypt$A$A",
			TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
	logf := func(string, ...any) {}
	authn := auth.NewAuthenticator(cfg)
	gw := NewGateway(cfg, authn, supervisor.NewSupervisor(cfg, logf), logf)
	gw.reconcileEvery = 20 * time.Millisecond
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "10.9.9.9:1234"
		gw.ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	return gw, authn, front
}

// upgradeBackend 是一个只接受 WS 升级并保持连接的后端。
func upgradeBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		time.Sleep(5 * time.Second) // 一直挂着，等对端断开
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialWS(t *testing.T, frontURL, cookie string) (net.Conn, *bufio.Reader) {
	t.Helper()
	u, err := url.Parse(frontURL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := fmt.Sprintf("GET /api/remote.mux HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\n"+
		"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"User-Agent: ws-agent\r\nCookie: %s\r\n\r\n", u.Host, cookie)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("ws handshake = %d, want 101", resp.StatusCode)
	}
	return conn, br
}

// expectCloseFrame 一直读到 Close 帧为止（跳过 ping/pong 等），返回状态码。
// 撤销路径现在会先发 Close 帧再断，所以"读到数据"不再等于"没断开"。
func expectCloseFrame(t *testing.T, br *bufio.Reader) uint16 {
	t.Helper()
	for {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(br, hdr); err != nil {
			t.Fatalf("read frame header: %v", err)
		}
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		n := int(hdr[1] & 0x7f)
		switch n {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(br, ext); err != nil {
				t.Fatalf("read extended length: %v", err)
			}
			n = int(binary.BigEndian.Uint16(ext))
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(br, ext); err != nil {
				t.Fatalf("read extended length: %v", err)
			}
			n = int(binary.BigEndian.Uint64(ext))
		}
		var mask []byte
		if masked {
			mask = make([]byte, 4)
			if _, err := io.ReadFull(br, mask); err != nil {
				t.Fatalf("read mask: %v", err)
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(br, payload); err != nil {
			t.Fatalf("read payload: %v", err)
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		if opcode != 0x8 {
			continue
		}
		if n < 2 {
			t.Fatalf("close frame carries no status code")
		}
		return binary.BigEndian.Uint16(payload[:2])
	}
}

// 撤销必须立刻断开已经建立的 WS：这是"连接表 + 主动关闭"的全部意义。
// 旧的实现只能等 tunnel_max_min 到点，撤销窗口等于隧道寿命。
func TestRevokeClosesActiveWS(t *testing.T) {
	backend := upgradeBackend(t)
	gw, authn, front := tunnelGateway(t, backendPort(t, backend))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.Start(ctx)

	const ua = "ws-agent"
	ip := net.ParseIP("10.9.9.9")
	payload, err := authn.NewSession(ip, ua, true)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := authn.Device().Mint(payload)
	if err != nil {
		t.Fatal(err)
	}

	conn, br := dialWS(t, front.URL, auth.CookieDevice+"="+tok)
	defer conn.Close()

	if n := gw.tunnels.count(); n != 1 {
		t.Fatalf("tunnel count after handshake = %d, want 1", n)
	}

	if !authn.Ledger().Revoke(payload.Fam) {
		t.Fatal("revoke must hit the active session")
	}

	// reconcile 每 20ms 一次，3 秒内必须断开；关闭时先发 4401 帧。
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if code := expectCloseFrame(t, br); code != closeCodeRevoked {
		t.Fatalf("close code = %d, want %d", code, closeCodeRevoked)
	}
	if n := gw.tunnels.count(); n != 0 {
		t.Fatalf("tunnel count after revoke = %d, want 0", n)
	}
}

// WS 握手被拒绝时不能留下隧道记录：未认证的握手不该占表。
func TestUnauthorizedWSLeavesNoTunnel(t *testing.T) {
	backend := upgradeBackend(t)
	gw, _, front := tunnelGateway(t, backendPort(t, backend))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.Start(ctx)

	// 没有 cookie：直接 401，且不登记
	u, _ := url.Parse(front.URL)
	conn, err := net.DialTimeout("tcp", u.Host, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /api/remote.mux HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\n"+
		"Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"User-Agent: ws-agent\r\n\r\n", u.Host)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ws without cookie = %d, want 401", resp.StatusCode)
	}
	if n := gw.tunnels.count(); n != 0 {
		t.Fatalf("rejected handshake must not register a tunnel, got %d", n)
	}
}

// SSE 没有周期保活：空闲判定只能用于 WS，否则一条正常的 SSE 流会被误杀。
func TestSSESurvivesIdleWindow(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			http.Error(w, "want sse", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		// 故意静默 1.5 秒（远超下面的 idle 窗口），再发一条事件。
		time.Sleep(1500 * time.Millisecond)
		_, _ = w.Write([]byte("data: late\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}))
	defer backend.Close()

	gw, authn, front := tunnelGateway(t, backendPort(t, backend))
	gw.tunnelIdle = 200 * time.Millisecond // 如果误用空闲判定，这条流会被杀掉
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.Start(ctx)

	const ua = "sse-agent"
	ip := net.ParseIP("10.9.9.9")
	payload, err := authn.NewSession(ip, ua, false)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := authn.Device().Mint(payload)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", ua)
	req.AddCookie(&http.Cookie{Name: auth.CookieDevice, Value: tok})
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sse status = %d, want 200", resp.StatusCode)
	}

	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("read first event: %v", err)
	}
	if !strings.Contains(line, "late") {
		t.Fatalf("expected the delayed event to survive the idle window, got %q", line)
	}
}

// 撤销必须同样中断 SSE。SSE 没有可关闭的 conn（它在 ReverseProxy 内部），
// 唯一入口是取消请求 context——漏了这条，撤销后事件流会继续往旧浏览器推数据。
func TestRevokeClosesActiveSSE(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			http.Error(w, "want sse", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
		tk := time.NewTicker(50 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-tk.C:
				if _, err := w.Write([]byte("data: tick\n\n")); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
			}
		}
	}))
	defer backend.Close()

	gw, authn, front := tunnelGateway(t, backendPort(t, backend))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.Start(ctx)

	const ua = "sse-agent"
	ip := net.ParseIP("10.9.9.9")
	payload, err := authn.NewSession(ip, ua, false)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := authn.Device().Mint(payload)
	if err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/stream", nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("User-Agent", ua)
	req.AddCookie(&http.Cookie{Name: auth.CookieDevice, Value: tok})
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sse status = %d, want 200", resp.StatusCode)
	}
	br := bufio.NewReader(resp.Body)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("read first event: %v", err)
	}
	if n := gw.tunnels.count(); n != 1 {
		t.Fatalf("sse tunnel count = %d, want 1", n)
	}

	if !authn.Ledger().Revoke(payload.Fam) {
		t.Fatal("revoke must hit the active session")
	}

	// 撤销后流必须自己结束：读完已在管道里的数据后应拿到 EOF。
	drained := make(chan struct{})
	go func() {
		for {
			if _, err := br.ReadString('\n'); err != nil {
				close(drained)
				return
			}
		}
	}()
	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("SSE stream must be cancelled after the session is revoked")
	}

	// handler 返回后隧道才从表里摘掉，给 defer 一点时间。
	deadline := time.Now().Add(2 * time.Second)
	for gw.tunnels.count() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := gw.tunnels.count(); n != 0 {
		t.Fatalf("sse tunnel count after revoke = %d, want 0", n)
	}
}
