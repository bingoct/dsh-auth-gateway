package web

import (
	"context"
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/bingoct/dsh-auth-gateway/internal/supervisor"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var challengeFieldRe = regexp.MustCompile(`name="ch" value="([^"]+)"`)

// 完整登录链路：未登录 → 单页双因子（密码+动态码一次 POST）→ 设备票 → 转发到后端。
// 这条测试证明认证链路是能用的；也锁住"两个因子错任一都不签发会话"。
func TestLoginFlowEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = w.Write([]byte("BACKEND path=" + r.URL.Path))
	}))
	defer backend.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "url.txt")
	auditFile := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(tokenFile,
		[]byte("dsh web: http://127.0.0.1:"+strconv.Itoa(portOf(t, backend))+"/?token=t\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	secret := []byte("0123456789abcdefghij") // 20 字节，满足 >=10
	hash, err := auth.HashPassword("testpass123")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AuthEnabled: true,
		DshHost:     "127.0.0.1", DshAttach: true, DshTokenFile: tokenFile,
		DshReadyMS: 5000, DshIdleMin: 30,
		PublicOrigin: "https://dsh.example",
		SessionDays:  14, SessionAbsMaxDays: 30,
		TempHours: 2, TempAbsHours: 6,
		RotateTempMin: 30, RotatePersistHours: 24,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		LocalCIDRs:   nil, // 没有本地豁免：连 127.0.0.1 也必须登录
		AuditLogPath: auditFile,
		Credentials: &config.Credentials{
			Version: 2, PasswordHash: hash, TOTPSecretB32: auth.Base32Encode(secret),
			TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1",
		},
	}
	logf := func(string, ...any) {}
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), supervisor.NewSupervisor(cfg, logf), logf)
	front := httptest.NewServer(gw)
	defer front.Close()

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	goodCode := func() string {
		return auth.HOTP(secret, uint64(time.Now().Unix()/auth.TOTPStep))
	}
	badCode := func() string {
		return auth.HOTP(secret, uint64(time.Now().Unix()/auth.TOTPStep)+7)
	}
	// 模拟浏览器：GET 登录页拿 challenge token + cookie，POST 时两者都带上。
	login := func(password, code, extra string) *http.Response {
		req, _ := http.NewRequest(http.MethodGet, front.URL+gw.paths.path(opLogin), nil)
		page, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(page.Body)
		page.Body.Close()
		chCookie := findCookie(page, auth.CookieChallenge)
		if chCookie == nil {
			t.Fatal("login page must set challenge cookie")
		}
		m := challengeFieldRe.FindSubmatch(body)
		if m == nil {
			t.Fatalf("login page missing challenge field: %s", body)
		}
		form := "ch=" + string(m[1]) + "&password=" + password + "&code=" + code + extra
		r, _ := http.NewRequest(http.MethodPost, front.URL+gw.paths.path(opLogin), strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(chCookie)
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("POST login: %v", err)
		}
		return resp
	}

	// 1. 未登录访问首页 → 跳当前登录页（带浏览器导航头）
	navReq, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	navReq.Header.Set("Accept", "text/html")
	resp, err := client.Do(navReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != gw.paths.path(opLogin) {
		t.Fatalf("unauth: code=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// 2. 密码错 / 动态码错 → 都不签发会话，且错误文案一致（不泄漏哪个因子错）
	errText := func(resp *http.Response) string {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := regexp.MustCompile(`<p class="err">([^<]*)</p>`).FindSubmatch(b)
		if m == nil {
			return ""
		}
		return string(m[1])
	}
	badPwd := errText(login("wrong", badCode(), ""))
	badTOTP := errText(login("testpass123", badCode(), ""))
	if badPwd != "认证失败" || badTOTP != "认证失败" {
		t.Fatalf("errors must be unified: pwd=%q totp=%q", badPwd, badTOTP)
	}

	// 3. 两个因子都对 → 303 到 /，只签发一枚设备票（没有中转票、没有 refresh）
	good := login("testpass123", goodCode(), "&remember=1")
	good.Body.Close()
	if good.StatusCode != http.StatusSeeOther || good.Header.Get("Location") != "/" {
		t.Fatalf("login: code=%d loc=%q", good.StatusCode, good.Header.Get("Location"))
	}
	sess := findCookie(good, auth.CookieDevice)
	if sess == nil {
		t.Fatal("successful login must issue a device cookie")
	}
	if extra := findCookie(good, "dsh_rt"); extra != nil {
		t.Fatal("there must be no second (refresh) cookie")
	}
	if devices := gw.authenticator.Ledger().List(""); len(devices) != 1 {
		t.Fatalf("devices after login = %d, want 1", len(devices))
	}

	// 4. 带设备票访问受保护页面 → 真的转发到后端
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/some/page", nil)
	req.AddCookie(sess)
	final, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Body.Close()
	body, _ := io.ReadAll(final.Body)
	if final.StatusCode != http.StatusOK || !strings.Contains(string(body), "BACKEND path=/some/page") {
		t.Fatalf("proxied after login: code=%d body=%q", final.StatusCode, body)
	}

	// 5. 同一动态码不能重放。
	replayCode := auth.HOTP(secret, uint64(time.Now().Unix()/auth.TOTPStep)+1)
	first := login("testpass123", replayCode, "")
	first.Body.Close()
	if findCookie(first, auth.CookieDevice) == nil {
		t.Fatal("first use of a fresh code must issue a session (test setup broken)")
	}
	replay := login("testpass123", replayCode, "")
	replay.Body.Close()
	if c := findCookie(replay, auth.CookieDevice); c != nil {
		t.Fatal("replayed totp code must not issue a second session")
	}

	// 审计必须真的落盘：成功登录与失败尝试都要有一行，且绝不包含凭据原文。
	auditData, err := os.ReadFile(auditFile)
	if err != nil {
		t.Fatalf("audit log missing: %v", err)
	}
	text := string(auditData)
	if !strings.Contains(text, `"ev":"login"`) {
		t.Fatalf("audit must record login events: %s", text)
	}
	if !strings.Contains(text, `"ok":true`) || !strings.Contains(text, `"ok":false`) {
		t.Fatalf("audit must record both success and failure: %s", text)
	}
	if strings.Contains(text, "testpass123") || strings.Contains(text, "dsh_dev=") {
		t.Fatalf("audit must never contain credentials: %s", text)
	}
}

// 撤销设备后，原本有效的票立即失效——这是无状态票做不到的能力。
func TestRevokeDeviceKillsSession(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled: true, PublicOrigin: "https://dsh.example",
		SessionDays: 14, SessionAbsMaxDays: 30, TempHours: 2, TempAbsHours: 6,
		RotateTempMin: 30, RotatePersistHours: 24,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		Credentials: &config.Credentials{Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6,
			TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
	authn := auth.NewAuthenticator(cfg)
	ip := net.ParseIP("10.9.9.9")
	payload, err := authn.NewSession(ip, "ua", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authn.Check(payload, ip, "ua"); err != nil {
		t.Fatalf("fresh session must pass: %v", err)
	}
	if !authn.Ledger().Revoke(payload.Fam) {
		t.Fatal("revoke must remove something")
	}
	if _, _, err := authn.Check(payload, ip, "ua"); err != auth.ErrSessionUnknown {
		t.Fatalf("session must be unknown after revoke, got %v", err)
	}
	if n := len(authn.Ledger().List("")); n != 0 {
		t.Fatalf("device list must be empty after revoke, got %d", n)
	}
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// auth_enabled = false：非本机来源直通，不签发也不校验会话；
// 来源门禁（CSWSH）不受影响，跨站请求仍然 403。
func TestAuthDisabledPassthrough(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = w.Write([]byte("BACKEND path=" + r.URL.Path))
	}))
	defer backend.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "url.txt")
	if err := os.WriteFile(tokenFile,
		[]byte("dsh web: http://127.0.0.1:"+strconv.Itoa(portOf(t, backend))+"/?token=t\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		AuthEnabled: false,
		DshHost:     "127.0.0.1", DshAttach: true, DshTokenFile: tokenFile,
		DshReadyMS: 5000, DshIdleMin: 30,
		PublicOrigin: "https://dsh.example", SessionDays: 30, SessionAbsMaxDays: 90, TempHours: 2,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		Credentials: &config.Credentials{
			Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1",
		},
	}
	logf := func(string, ...any) {}
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), supervisor.NewSupervisor(cfg, logf), logf)
	front := httptest.NewServer(gw)
	defer front.Close()

	// 非本机来源（10.x）直接转发到后端，不需要会话 cookie。
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/some/page", nil)
	req.RemoteAddr = "10.9.9.9:1234"
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "BACKEND path=/some/page") {
		t.Fatalf("status=%d body=%q, want 200 + backend echo", resp.StatusCode, body)
	}

	// 跨站 WS 握手仍然被来源门禁挡掉（认证关闭不等于来源校验关闭）。
	ws, _ := http.NewRequest(http.MethodGet, front.URL+"/api/remote.mux", nil)
	ws.RemoteAddr = "10.9.9.9:1234"
	ws.Header.Set("Connection", "Upgrade")
	ws.Header.Set("Upgrade", "websocket")
	ws.Header.Set("Origin", "https://evil.example")
	ws.Header.Set("Sec-WebSocket-Version", "13")
	ws.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	wresp, err := front.Client().Do(ws)
	if err != nil {
		t.Fatal(err)
	}
	wresp.Body.Close()
	if wresp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site WS = %d, want 403 with auth disabled", wresp.StatusCode)
	}

	// 认证关闭时登录页必须 404：公网上一张能回答"密码对不对"的死登录页就是探针。
	// 旧两步登录的 v 端点路径同样必须 404，不能落到转发。
	oldTOTPScript := strings.Replace(gw.paths.path(opLogin), "/l", "/v", 1)
	for _, p := range []string{gw.paths.path(opLogin), oldTOTPScript, "/_g/OLDTOKEN123/l"} {
		req, _ := http.NewRequest(http.MethodGet, front.URL+p, nil)
		req.RemoteAddr = "10.9.9.9:1234"
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s with auth disabled = %d, want 404", p, resp.StatusCode)
		}
	}
}

// restart 端点：只认本机，非本机一律 404（连端点存在都不暴露）。
// 用 spawn 模式（fake-dsh）证明重启真的杀掉进程。
func TestGatewayRestart(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not on PATH")
	}
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "fake-dsh.js"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		AuthEnabled: true,
		NodeBin:     "node", DshBin: abs, DshCwd: t.TempDir(),
		DshProfile: "web", DshHost: "127.0.0.1", DshPort: 0,
		DshReadyMS: 5000, EnsureWaitMS: 20000, DshIdleMin: 30, Home: t.TempDir(),
		LocalCIDRs:   []*net.IPNet{mustCIDR(t, "127.0.0.0/8")},
		PublicOrigin: "https://dsh.example", SessionDays: 30, SessionAbsMaxDays: 90, TempHours: 2,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		Credentials: &config.Credentials{
			Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1",
		},
	}
	logf := func(string, ...any) {}
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), supervisor.NewSupervisor(cfg, logf), logf)
	front := httptest.NewServer(gw)
	defer front.Close()

	// 先拉起，拿到端口，确认 running。
	rt, err := ensureCtx(t, gw.supervisor, 8*time.Second)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	port := rt.Port

	restartPath := gw.paths.path(opRestart)

	// 本机 GET 不允许（防 CSRF 的简单方法面）。
	req, _ := http.NewRequest(http.MethodGet, front.URL+restartPath, nil)
	resp, err := front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET restart = %d, want 405", resp.StatusCode)
	}

	// 本机 POST → 200，且进程真的被终止（端口关闭）。
	req, _ = http.NewRequest(http.MethodPost, front.URL+restartPath, nil)
	resp, err = front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("local POST restart = %d body=%q, want 200", resp.StatusCode, body)
	}
	if !waitPortClosed(t, port, 5*time.Second) {
		t.Fatalf("dsh port %d still open after restart", port)
	}
	if got := gw.supervisor.State(); got != supervisor.StateStopped {
		t.Fatalf("state after restart = %s, want stopped", got)
	}

	// 非本机 POST → 404，连端点存在都不暴露。RemoteAddr 客户端不可控，
	// 用一层包装把远端地址改写成非本机。
	cross := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "10.9.9.9:1234"
		gw.ServeHTTP(w, r)
	}))
	defer cross.Close()
	req, _ = http.NewRequest(http.MethodPost, cross.URL+restartPath, nil)
	resp, err = cross.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("non-local POST restart = %d, want 404", resp.StatusCode)
	}
	// 旧片段路径也必须 404。
	req, _ = http.NewRequest(http.MethodPost, front.URL+"/_g/OLDTOKEN123/r", nil)
	resp, err = front.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("stale path restart = %d, want 404", resp.StatusCode)
	}
}

func TestChallengePageIntegration(t *testing.T) {
	cfg := &config.Config{
		AuthEnabled: true, DshHost: "127.0.0.1", DshAttach: true,
		DshReadyMS: 5000, DshIdleMin: 30,
		PublicOrigin: "https://dsh.example", SessionDays: 30, SessionAbsMaxDays: 90, TempHours: 2,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		Credentials: &config.Credentials{Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6,
			TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
	logf := func(string, ...any) {}
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), supervisor.NewSupervisor(cfg, logf), logf)
	front := httptest.NewServer(gw)
	defer front.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pageResp, err := client.Get(front.URL + gw.paths.path(opLogin))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(pageResp.Body)
	pageResp.Body.Close()
	chCookie := findCookie(pageResp, auth.CookieChallenge)
	if chCookie == nil || challengeFieldRe.FindSubmatch(body) == nil {
		t.Fatalf("login page missing challenge: cookie=%v body=%s", chCookie, body)
	}

	// 无 challenge 直接 POST → 不签发会话。
	r, _ := http.NewRequest(http.MethodPost, front.URL+gw.paths.path(opLogin), strings.NewReader("password=x&code=000000"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if findCookie(resp, auth.CookieDevice) != nil {
		t.Fatal("POST without challenge must not issue a session")
	}
}

func portOf(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

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

func ensureCtx(t *testing.T, sup *supervisor.Supervisor, d time.Duration) (*supervisor.Runtime, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return sup.Ensure(ctx)
}

// 无效设备票：导航请求跳登录页，程序化请求给 401，绝不放行。
func TestInvalidDeviceCookieRejected(t *testing.T) {
	hash, err := auth.HashPassword("bad-cookie-pass")
	if err != nil {
		t.Fatal(err)
	}
	cfg := authTestConfig(t, hash, nil, "")
	logf := func(string, ...any) {}
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), supervisor.NewSupervisor(cfg, logf), logf)
	front := httptest.NewServer(gw)
	defer front.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	fake := &http.Cookie{Name: auth.CookieDevice, Value: "v1.invalid.invalid"}

	nav, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	nav.Header.Set("Accept", "text/html")
	nav.AddCookie(fake)
	resp, err := client.Do(nav)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("navigation with bad cookie: code=%d, want 303 to login", resp.StatusCode)
	}

	xhr, _ := http.NewRequest(http.MethodGet, front.URL+"/api/state", nil)
	xhr.AddCookie(fake)
	resp2, err := client.Do(xhr)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("XHR with bad cookie: code=%d, want 401", resp2.StatusCode)
	}
}

// 代数到周期后，网关在同一个响应里下发新票；旧票随即被台账判为过期代数。
// 这是"cookie 被动泄露后可被挤掉"的链路级证据。
func TestRotationReissuesCookie(t *testing.T) {
	hash, err := auth.HashPassword("rotate-test-pass")
	if err != nil {
		t.Fatal(err)
	}
	cfg := authTestConfig(t, hash, nil, "")
	cfg.SessionDays = 14
	cfg.SessionAbsMaxDays = 30
	cfg.RotatePersistHours = 24
	logf := t.Logf
	authn := auth.NewAuthenticator(cfg)
	gw := NewGateway(cfg, authn, supervisor.NewSupervisor(cfg, logf), logf)
	// RemoteAddr 由客户端设置是无效的，必须在这一层改写来源地址。
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "10.9.9.9:1234"
		gw.ServeHTTP(w, r)
	}))
	defer front.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	const ua = "rotate-agent"
	ip := net.ParseIP("10.9.9.9")
	payload, err := authn.NewSession(ip, ua, true)
	if err != nil {
		t.Fatal(err)
	}
	oldTok, err := authn.Device().Mint(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 把台账时钟推到轮换周期之后（idle 14 天、abs 30 天都还没到）。
	authn.Ledger().SetClock(func() time.Time { return time.Now().Add(25 * time.Hour) })

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/some/page", nil)
	req.Header.Set("User-Agent", ua)
	req.AddCookie(&http.Cookie{Name: auth.CookieDevice, Value: oldTok})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	next := findCookie(resp, auth.CookieDevice)
	if next == nil {
		t.Fatalf("rotation must issue a new device cookie on the same response (status=%d set-cookie=%v)",
			resp.StatusCode, resp.Header.Values("Set-Cookie"))
	}
	if next.Value == oldTok {
		t.Fatal("rotated cookie must differ from the old one")
	}
	if next.MaxAge <= 0 {
		t.Fatalf("rotated cookie must carry Max-Age, got %d", next.MaxAge)
	}

	// 旧票在新代数下必须被拒（用新实例读同一路径，避免依赖上面那条连接）。
	p2, ok := authn.Device().Verify(next.Value)
	if !ok {
		t.Fatal("new cookie must verify")
	}
	if p2.Gen == payload.Gen {
		t.Fatalf("generation must advance: %d -> %d", payload.Gen, p2.Gen)
	}
}
