package web

import (
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/bingoct/dsh-auth-gateway/internal/supervisor"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func authTestConfig(t *testing.T, hash string, local []*net.IPNet, tokenFile string) *config.Config {
	t.Helper()
	return &config.Config{
		AuthEnabled: true,
		DshHost:     "127.0.0.1", DshAttach: true, DshTokenFile: tokenFile,
		DshReadyMS: 5000, DshIdleMin: 30,
		PublicOrigin: "https://dsh.example",
		SessionDays:  14, SessionAbsMaxDays: 30,
		TempHours: 2, TempAbsHours: 6,
		RotateTempMin: 30, RotatePersistHours: 24,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		LocalCIDRs: local,
		Credentials: &config.Credentials{
			Version: 2, PasswordHash: hash, TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1",
		},
	}
}

// 登录页可达：GET 当前混淆路径返回 200 且带表单与 challenge 字段；
// 未认证导航请求 303 到同一个当前路径。这两条都不需要真实凭据。
func TestLoginPageReachable(t *testing.T) {
	hash, err := auth.HashPassword("page-test-pass")
	if err != nil {
		t.Fatal(err)
	}
	cfg := authTestConfig(t, hash, nil, "")
	logf := func(string, ...any) {}
	gw := NewGateway(cfg, auth.NewAuthenticator(cfg), supervisor.NewSupervisor(cfg, logf), logf)
	front := httptest.NewServer(gw)
	defer front.Close()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	resp, err := client.Get(front.URL + gw.paths.path(opLogin))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET login = %d, want 200", resp.StatusCode)
	}
	for _, field := range []string{"<form", `name="password"`, `name="code"`, `name="remember"`, `name="ch"`} {
		if !strings.Contains(string(body), field) {
			t.Fatalf("login page missing %q", field)
		}
	}
	if !strings.Contains(string(body), "prefers-color-scheme:dark") {
		t.Fatal("login page must follow the system dark mode")
	}

	nav, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	nav.Header.Set("Accept", "text/html")
	redir, err := client.Do(nav)
	if err != nil {
		t.Fatal(err)
	}
	redir.Body.Close()
	if redir.StatusCode != http.StatusSeeOther || redir.Header.Get("Location") != gw.paths.path(opLogin) {
		t.Fatalf("unauth navigate = %d loc=%q, want 303 -> %s",
			redir.StatusCode, redir.Header.Get("Location"), gw.paths.path(opLogin))
	}
}

// 旧会话失效：两条独立路径都必须让旧票过不了鉴权门。
//  1. cookie 改名：旧名 dsh_auth_session 不再被读取；
//  2. 凭据轮换：用户重新 init 后 passwordHash 变化，签名密钥随之变化，旧票验签失败。
//
// 用真实后端跑通"当前 cookie + 当前凭据 = 200"作为对照，避免把"全都 401"误当成通过。
func TestOldSessionInvalid(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = w.Write([]byte("BACKEND"))
	}))
	defer backend.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "url.txt")
	if err := os.WriteFile(tokenFile,
		[]byte("dsh web: http://127.0.0.1:"+strconv.Itoa(portOf(t, backend))+"/?token=t\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	oldHash, err := auth.HashPassword("old-password-1")
	if err != nil {
		t.Fatal(err)
	}
	newHash, err := auth.HashPassword("old-password-2")
	if err != nil {
		t.Fatal(err)
	}

	// 192.0.2.0/24 是文档保留段，10.9.9.9 会被判为非本机 → 必须带会话。
	local := []*net.IPNet{mustCIDR(t, "192.0.2.0/24")}
	cfg := authTestConfig(t, oldHash, local, tokenFile)
	logf := t.Logf
	// 票表必须与网关共用同一个实例，否则第六道门（family 在表中）看不到外面签的票。
	authn := auth.NewAuthenticator(cfg)
	gw := NewGateway(cfg, authn, supervisor.NewSupervisor(cfg, logf), logf)

	ipPrefixValue := net.ParseIP("10.9.9.9")
	const ua = "test-ua"

	// 对照组：同一套凭据签出的票，网关必须认。
	payload, err := authn.NewSession(ipPrefixValue, ua, false)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := authn.Device().Mint(payload)
	if err != nil {
		t.Fatal(err)
	}

	// 凭据轮换后签名密钥变了，这张票的签名在网关侧必然验不过。
	rotated := *cfg
	rotated.Credentials = &config.Credentials{Version: 2, PasswordHash: newHash}
	rotatedAuthn := auth.NewAuthenticator(&rotated)
	rotatedPayload, err := rotatedAuthn.NewSession(ipPrefixValue, ua, false)
	if err != nil {
		t.Fatal(err)
	}
	afterInit, err := rotatedAuthn.Device().Mint(rotatedPayload)
	if err != nil {
		t.Fatal(err)
	}

	// RemoteAddr 客户端不可控，用一层包装改写为公网来源。
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = "10.9.9.9:1234"
		gw.ServeHTTP(w, r)
	}))
	defer front.Close()

	get := func(cookieName, token string) int {
		req, _ := http.NewRequest(http.MethodGet, front.URL+"/some/page", nil)
		req.Header.Set("User-Agent", ua)
		if token != "" {
			req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
		}
		resp, err := front.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	if got := get("dsh_auth_session", valid); got != http.StatusUnauthorized {
		t.Fatalf("old cookie name = %d, want 401", got)
	}
	if got := get(auth.CookieDevice, afterInit); got != http.StatusUnauthorized {
		t.Fatalf("ticket signed before credential rotation = %d, want 401", got)
	}
	if got := get("", ""); got != http.StatusUnauthorized {
		t.Fatalf("no cookie = %d, want 401", got)
	}
	// 正向对照：当前 cookie 名 + 当前凭据 → 真转发到后端。
	if got := get(auth.CookieDevice, valid); got != http.StatusOK {
		t.Fatalf("current cookie + current credential = %d, want 200", got)
	}
}
