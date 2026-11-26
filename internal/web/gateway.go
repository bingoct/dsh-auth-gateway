package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/audit"
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/bingoct/dsh-auth-gateway/internal/supervisor"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type rtKey struct{}

// Gateway 是数据面：认证门禁 + 转发 + 把 dsh 的 v1 cookie 维护在网关侧。
type Gateway struct {
	cfg           *config.Config
	authenticator *auth.Authenticator
	supervisor    *supervisor.Supervisor
	pages         *Pages
	paths         *PathRouter
	challenge     *auth.ChallengeGuard
	proxy         *httputil.ReverseProxy
	transport     *http.Transport
	active        atomic.Int64
	audit         *audit.Logger
	tunnels       *tunnelTable
	policy        auth.Policy
	// tunnelIdle 是 WS 的空闲超时：这么久没有任何字节就断开重连。
	// dsh 每 2 秒发 ping、浏览器自动回 pong，所以活跃连接不会被误判。
	tunnelIdle time.Duration
	// tunnelMax 是隧道最长寿命；SSE 只受它约束（dsh 的 SSE 没有周期保活）。
	tunnelMax time.Duration
	// reconcileEvery 是后台对账间隔（撤销传播 / 空闲检测 / last_seen 落盘）。
	reconcileEvery time.Duration
	logf           func(string, ...any)
}

func NewGateway(cfg *config.Config, authenticator *auth.Authenticator, sup *supervisor.Supervisor, logf func(string, ...any)) *Gateway {
	g := &Gateway{
		cfg: cfg, authenticator: authenticator, supervisor: sup, logf: logf,
		paths:          newPathRouter(cfg.Credentials.PasswordHash),
		challenge:      auth.NewChallengeGuard(cfg.Credentials.PasswordHash),
		tunnels:        newTunnelTable(),
		policy:         authenticator.Policy(),
		reconcileEvery: 2 * time.Second,
	}
	if cfg.TunnelIdleSec > 0 {
		g.tunnelIdle = time.Duration(cfg.TunnelIdleSec) * time.Second
	}
	g.pages = newPages(cfg, g.paths)
	g.audit = audit.New(cfg.AuditLogPath)
	if cfg.TunnelMaxMin > 0 {
		g.tunnelMax = time.Duration(cfg.TunnelMaxMin) * time.Minute
	}
	g.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
	}
	g.proxy = &httputil.ReverseProxy{
		Rewrite:        g.rewrite,
		Transport:      g.transport,
		FlushInterval:  -1, // 每个 write 立即下发，流式与 WS 必需
		ModifyResponse: g.modifyResponse,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			g.logf("[proxy] upstream error %s %s: %v", r.Method, r.URL.Path, err)
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return g
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.active.Add(1)
	defer g.active.Add(-1)
	g.supervisor.Touch()

	ip := g.remoteIP(r)
	isLocal := ip != nil && auth.IPInCIDRs(ip, g.cfg.LocalCIDRs)

	// 每日轮换片段：跨天立即生效，不等重启。
	g.paths.maybeRotate()

	// 内部端点走独立路由。旧片段命中前缀但不是当日值 → 404，
	// 绝不能落到转发，否则旧 URL 打到了 dsh 上。
	if oper, matched, current := g.paths.match(r.URL.Path); matched {
		if !current {
			http.NotFound(w, r)
			return
		}
		switch oper {
		case opHealth:
			g.handleHealth(w, r)
			return
		case opStatus:
			g.handleStatus(w, r, ip, isLocal)
			return
		case opRestart:
			g.handleRestart(w, r, ip, isLocal)
			return
		case opLogin, opLogout:
			// 认证关闭时留着登录页就是公网上一张能被扫描到的死探针，
			// 既泄露实现又能回答"密码对不对"。直接 404。
			if !g.cfg.AuthEnabled {
				http.NotFound(w, r)
				return
			}
			switch oper {
			case opLogin:
				g.handleLogin(w, r, ip, isLocal)
			case opLogout:
				g.handleLogout(w, r)
			}
			return
		default:
			http.NotFound(w, r)
			return
		}
	}

	// 来源门禁先于一切转发：跨站请求（含 WebSocket 握手）在这里被挡。
	if !isLocal && !g.originOK(r) {
		g.logf("[gate] cross-site %s %s origin=%q site=%q", r.Method, r.URL.Path,
			r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site"))
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}

	// 认证门：一枚设备票 → 验签 → 台账判定（存在/绑定/idle/abs/代数）。
	// 代理到期或落在交接窗口时，checkDevice 会顺手把新 cookie 写进本响应。
	family := ""
	if g.cfg.AuthEnabled && !isLocal {
		fam, ok := g.checkDevice(w, r, ip)
		if !ok {
			g.unauthorized(w, r)
			return
		}
		family = fam
	}

	// 拉起 dsh 允许最多等 20s：冷启动通常 4-6s，超时后返回等待页让浏览器自动重试，
	// 拉起本身继续跑，不会被请求取消打断。
	wait := time.Duration(g.cfg.EnsureWaitMS) * time.Millisecond
	if wait <= 0 {
		wait = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), wait)
	rt, err := g.supervisor.Ensure(ctx)
	cancel()
	if err != nil {
		if errors.Is(err, supervisor.ErrStarting) {
			g.pages.renderStarting(w)
			return
		}
		g.logf("[proxy] dsh unavailable: %v", err)
		g.pages.renderUnavailable(w, err)
		return
	}

	target := net.JoinHostPort(g.cfg.DshHost, strconv.Itoa(rt.Port))

	// WebSocket 由网关自己接管握手：只有拿到 conn 才能在撤销时断开、
	// 才能用"读到字节就刷新"判断空死连接。ReverseProxy 在内部 hijack，拿不到。
	if isWebSocket(r) {
		g.serveWebSocket(w, r, target, rt.Cookie, family)
		return
	}

	// SSE 是普通流式响应，交给 ReverseProxy；用 handler 生命周期当 tunnel 生命周期。
	// 但它没有周期保活，所以只受最长寿命约束，不做空闲判定。
	if isSSE(r) {
		// 撤销必须能中断 SSE：它的 conn 在 ReverseProxy 内部，我们拿不到，
		// 唯一的取消入口是请求 context——tunnel.Close() 调的就是这个 cancel。
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		if g.tunnelMax > 0 {
			var tcancel context.CancelFunc
			ctx, tcancel = context.WithTimeout(ctx, g.tunnelMax)
			defer tcancel()
		}
		if family != "" {
			t := g.tunnels.add(family, tunnelKindSSE, nil, nil, cancel)
			defer func() {
				g.tunnels.remove(t)
				g.audit.Log(auditTunnelEvent(family, "closed", tunnelKindSSE))
			}()
			g.audit.Log(auditTunnelEvent(family, "open", tunnelKindSSE))
		}
		ctx = context.WithValue(ctx, rtKey{}, rt)
		g.proxy.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	ctx = context.WithValue(r.Context(), rtKey{}, rt)
	g.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// checkDevice 是每请求的认证门。返回 family 供隧道登记使用。
// 失败时只记日志与审计，由调用方决定跳登录页还是 401。
func (g *Gateway) checkDevice(w http.ResponseWriter, r *http.Request, ip net.IP) (string, bool) {
	c, err := r.Cookie(auth.CookieDevice)
	if err != nil {
		return "", false
	}
	p, ok := g.authenticator.Device().Verify(c.Value)
	if !ok {
		return "", false
	}
	sess, rotate, err := g.authenticator.Check(p, ip, r.UserAgent())
	if err != nil {
		if errors.Is(err, auth.ErrSessionStale) {
			// 旧代数被拒：有人在用已经被换掉的票。这是安全信号，必须留痕。
			g.audit.Log(audit.Event{Event: audit.EvStale, OK: false,
				Family: audit.ShortFamily(p.Fam), IP: ip.String(), Mode: p.Mode,
				Detail: "generation superseded"})
		}
		g.logf("[auth] reject family=%s: %v", audit.ShortFamily(p.Fam), err)
		return "", false
	}
	if rotate {
		g.issueDeviceCookie(w, *sess)
	}
	return sess.Family, true
}

// setDeviceCookie 写一枚设备票。两档的 cookie 生命周期不同：
//
//	persist  Max-Age = 绝对上限（30 天），写进磁盘，关浏览器仍在
//	temp     不写 Max-Age（会话 cookie），浏览器进程结束即丢弃
//
// 它只是"浏览器还带不带"，不是安全边界：判活始终看台账的 idle/abs，
// 所以关浏览器丢掉 temp 票不会让服务端那条记录提前失效。
func (g *Gateway) setDeviceCookie(w http.ResponseWriter, tok, mode string) {
	age := int(g.policy.Abs(mode).Seconds())
	if mode != auth.ModePersist {
		age = 0 // 0 = 不写 Max-Age，浏览器按会话 cookie 处理
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.CookieDevice, Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: g.cfg.CookieSecure(),
		MaxAge: age,
	})
}

// issueDeviceCookie 在代数轮换后按台账里的当前记录重签票。
func (g *Gateway) issueDeviceCookie(w http.ResponseWriter, sess auth.DeviceSession) {
	tok, err := g.authenticator.Device().Mint(auth.DevicePayload{
		Fam: sess.Family, Mode: sess.Mode, Iat: sess.CreatedAt,
		IP: sess.IP, UA: sess.UA, Gen: sess.Gen,
	})
	if err != nil {
		g.logf("[auth] mint device cookie family=%s: %v", audit.ShortFamily(sess.Family), err)
		return
	}
	g.setDeviceCookie(w, tok, sess.Mode)
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func isSSE(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream")
}

// rewrite 是唯一改写上游请求的地方：换目标、换 Host、注入 dsh cookie、剥离浏览器来源头。
func (g *Gateway) rewrite(pr *httputil.ProxyRequest) {
	rt, _ := pr.In.Context().Value(rtKey{}).(*supervisor.Runtime)
	if rt == nil {
		return
	}
	addr := net.JoinHostPort(g.cfg.DshHost, strconv.Itoa(rt.Port))
	pr.Out.URL.Scheme = "http"
	pr.Out.URL.Host = addr
	// dsh 的 cookie 名由 authority 派生，Host 必须与换 cookie 时一致。
	pr.Out.Host = addr

	pr.Out.Header.Del("Cookie")
	if rt.Cookie != "" {
		pr.Out.Header.Set("Cookie", rt.Cookie)
	}

	// 剥离浏览器来源头：dsh 对缺失 Origin 的请求直接放行，保留反而会与改写后的
	// Host 不一致而被它自己拒掉。我们的来源校验已在这一步之前完成。
	for _, h := range []string{
		"Origin", "Referer",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User",
	} {
		pr.Out.Header.Del(h)
	}

	pr.SetXForwarded()
	proto := "http"
	if pr.In.TLS != nil {
		proto = "https"
	}
	if g.cfg.TrustProxy {
		if v := pr.In.Header.Get("X-Forwarded-Proto"); v != "" {
			proto = v
		}
	}
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
}

// modifyResponse 剥掉上游的 Set-Cookie：v1 cookie 只属于网关与 dsh 之间，不能落到浏览器。
func (g *Gateway) modifyResponse(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	return nil
}

// ---- 内部端点 ----

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	state := g.supervisor.State()
	body := map[string]any{
		"ok":    true,
		"totp":  true,
		"temp":  g.cfg.TempHours > 0,
		"dsh":   state == supervisor.StateRunning,
		"state": state.String(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

// handleStatus 暴露 dsh 生命周期状态。进程信息只给已认证来源或本机。
func (g *Gateway) handleStatus(w http.ResponseWriter, r *http.Request, ip net.IP, isLocal bool) {
	if !isLocal {
		if _, ok := g.checkDevice(w, r, ip); !ok {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(g.supervisor.Status(g.Active()))
}

// handleRestart 终止当前 dsh 实例；下一个请求会重新拉起。
// 管理操作，只认本机（local_cidrs），非本机一律 404 —— 连端点存在都不暴露。
// 远程管理走 SSH，不在公网留管理端点。attach 模式不拥有 dsh，拒绝。
func (g *Gateway) handleRestart(w http.ResponseWriter, r *http.Request, ip net.IP, isLocal bool) {
	if !isLocal {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if g.cfg.DshAttach {
		http.Error(w, "attach mode does not own dsh; restart the external instance", http.StatusConflict)
		return
	}

	wasRunning := g.supervisor.State() == supervisor.StateRunning
	g.logf("[gate] restart requested from %s (state=%s)", ip, g.supervisor.State())
	g.supervisor.Shutdown()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"was_running": wasRunning,
		"note":        "dsh terminated; the next request spawns a fresh instance",
	})
}

// handleLogin 是单页双因子登录：密码 + 动态码一次 POST 全验完，直接签发 dsh_sid。
// 两个因子共用同一个错误文案，避免告诉攻击者"密码对了，动态码错了"。
func (g *Gateway) handleLogin(w http.ResponseWriter, r *http.Request, ip net.IP, isLocal bool) {
	if r.Method == http.MethodGet {
		token, cookie := g.challenge.Issue(g.cfg.CookieSecure())
		http.SetCookie(w, cookie)
		g.pages.renderLogin(w, "", token)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLocal && !g.originOK(r) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	formToken := r.PostFormValue("ch")
	cookieToken := ""
	if c, err := r.Cookie(auth.CookieChallenge); err == nil {
		cookieToken = c.Value
	}
	// 挑战因子失败就重新签一张并渲染，不落到因子校验，断掉重放路径。
	if err := g.challenge.Consume(formToken, cookieToken); err != nil {
		token, cookie := g.challenge.Issue(g.cfg.CookieSecure())
		http.SetCookie(w, cookie)
		g.pages.renderLogin(w, "登录已过期，请重试", token)
		return
	}
	key := ip.String()
	if !g.authenticator.AllowLogin(key) {
		http.Error(w, "too many attempts; try later", http.StatusTooManyRequests)
		return
	}

	// 两个因子都过了才签发会话；任一失败都走同一个"认证失败"文案。
	passwordOK := g.authenticator.CheckPassword(r.PostFormValue("password"))
	totpOK := g.authenticator.VerifyTOTP(r.PostFormValue("code")) == nil
	if !passwordOK || !totpOK {
		// 不区分哪个因子错，审计里也不记因子名，避免日志本身变成探测依据。
		g.audit.Log(audit.Event{Event: audit.EvLogin, OK: false,
			IP: ip.String(), Detail: "factor rejected"})
		g.authenticator.RecordFail(key)
		token, cookie := g.challenge.Issue(g.cfg.CookieSecure())
		http.SetCookie(w, cookie)
		g.pages.renderLogin(w, "认证失败", token)
		return
	}
	g.authenticator.RecordSuccess(key)

	persist := r.PostFormValue("remember") == "1"
	payload, err := g.authenticator.NewSession(ip, r.UserAgent(), persist)
	if err != nil {
		g.logf("[auth] create session: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tok, err := g.authenticator.Device().Mint(payload)
	if err != nil {
		g.logf("[auth] mint device cookie: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g.setDeviceCookie(w, tok, payload.Mode)
	g.audit.Log(audit.Event{Event: audit.EvLogin, OK: true,
		Family: audit.ShortFamily(payload.Fam), Device: auth.DeviceName(r.UserAgent()),
		IP: ip.String(), Mode: payload.Mode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (g *Gateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !g.originOK(r) {
		http.Error(w, "cross-site request rejected", http.StatusForbidden)
		return
	}
	// 登出是两步：先删台账记录（断根，之后再也握手不进来），
	// 再关这条 family 的所有隧道（断枝，正在用的连接立刻断）。
	if c, err := r.Cookie(auth.CookieDevice); err == nil {
		if p, ok := g.authenticator.Device().Verify(c.Value); ok {
			g.authenticator.Ledger().Revoke(p.Fam)
			n := g.tunnels.closeFamily(p.Fam)
			g.audit.Log(audit.Event{Event: audit.EvLogout, OK: true,
				Family: audit.ShortFamily(p.Fam), Detail: fmt.Sprintf("tunnels closed=%d", n)})
		}
	}
	http.SetCookie(w, &http.Cookie{Name: auth.CookieDevice, Value: "", Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: g.cfg.CookieSecure(), MaxAge: -1})
	http.Redirect(w, r, g.paths.path(opLogin), http.StatusSeeOther)
}

// Start 启动后台对账与看门狗，ctx 取消后停止并关闭全部隧道。
func (g *Gateway) Start(ctx context.Context) {
	go g.reconcileLoop(ctx)
}

// reconcileLoop 每 reconcileEvery 做三件事：
//  1. Flush 台账（同时把外部 CLI 的撤销吃进来）
//  2. 关掉台账里已经不存在的 family 的所有隧道（撤销传播）
//  3. 关掉空闲超时或寿命到期的隧道
func (g *Gateway) reconcileLoop(ctx context.Context) {
	tick := time.NewTicker(g.reconcileEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			g.tunnels.closeAll()
			return
		case now := <-tick.C:
			alive := g.ledger().ActiveFamilies()
			for _, fam := range g.tunnels.orphanFamilies(alive) {
				n := g.tunnels.closeFamily(fam)
				g.audit.Log(audit.Event{Event: audit.EvRevoke, OK: true,
					Family: audit.ShortFamily(fam), Detail: fmt.Sprintf("tunnels closed=%d", n)})
			}
			for _, t := range g.tunnels.snapshot() {
				if g.tunnelIdle > 0 && t.kind == tunnelKindWS && t.idleFor(now) > g.tunnelIdle {
					g.audit.Log(auditTunnelEvent(t.family, "idle", t.kind))
					t.Close()
					continue
				}
				if g.tunnelMax > 0 && now.Sub(t.created) > g.tunnelMax {
					g.audit.Log(auditTunnelEvent(t.family, "max lifetime", t.kind))
					t.Close()
				}
			}
		}
	}
}

func (g *Gateway) ledger() *auth.Ledger { return g.authenticator.Ledger() }

// unauthorized 区分导航与程序化请求：导航跳登录页，其余给 401 而不是 302。
func (g *Gateway) unauthorized(w http.ResponseWriter, r *http.Request) {
	navigate := r.Method == http.MethodGet &&
		(strings.Contains(r.Header.Get("Accept"), "text/html") ||
			r.Header.Get("Sec-Fetch-Dest") == "document")
	if navigate {
		g.paths.redirectToLogin(w, r)
		return
	}
	w.Header().Set("WWW-Authenticate", `Session realm="dsh"`)
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// originOK 判定请求来源。三档：Origin 存在则比对 authority；Origin 为 null 时
// 用 Sec-Fetch-Site 兜底（Edge 会在标准顶层表单里发 null）；两者都缺按非浏览器放行。
func (g *Gateway) originOK(r *http.Request) bool {
	base := config.OriginAuthority(g.cfg.PublicOrigin)
	host := r.Host
	match := func(u string) bool {
		if strings.EqualFold(u, "null") {
			return false
		}
		a := config.OriginAuthority(u)
		if a == "" {
			return false
		}
		return strings.EqualFold(a, base) || strings.EqualFold(a, host)
	}
	if o := r.Header.Get("Origin"); o != "" {
		if strings.EqualFold(o, "null") {
			return !strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site")
		}
		return match(o)
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return match(ref)
	}
	return true
}

// remoteIP 取真实客户端地址：仅当直连方是可信反代时采信 XFF，并从右往左跳过可信跳。
func (g *Gateway) remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if !g.cfg.TrustProxy || !auth.IPInCIDRs(ip, g.cfg.ProxyTrusted) {
		return ip
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return ip
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		cand := net.ParseIP(strings.TrimSpace(parts[i]))
		if cand == nil {
			continue
		}
		if auth.IPInCIDRs(cand, g.cfg.ProxyTrusted) {
			continue
		}
		return cand
	}
	return ip
}

// Active 返回当前在途请求数，供空闲回收判断。
func (g *Gateway) Active() int {
	return int(g.active.Load())
}
