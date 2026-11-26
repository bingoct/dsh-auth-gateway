package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var pathB64 = base64.RawURLEncoding

// 内部端点的操作名。URL 里只有当日片段 + 操作名，不含 auth/gateway 这类字样。
const (
	opHealth  = "h"
	opStatus  = "s"
	opRestart = "r"
	opLogin   = "l"
	opLogout  = "o"
)

// PathRouter 把内部端点路径与每日轮换片段绑定。
// 片段由 HMAC(secret, UTC 日期) 派生，无需下发、无需状态；跨天自动切换。
type PathRouter struct {
	secret []byte
	prefix string
	day    string
	token  string
}

func newPathRouter(passwordHash string) *PathRouter {
	sum := sha256.Sum256([]byte("dsh-path-v1:" + passwordHash))
	pr := &PathRouter{secret: sum[:], prefix: "/_g"}
	pr.rotate(time.Now().UTC())
	return pr
}

func (p *PathRouter) rotate(now time.Time) {
	day := now.Format("2006-01-02")
	if day == p.day && p.token != "" {
		return
	}
	m := hmac.New(sha256.New, p.secret)
	m.Write([]byte(day))
	p.day = day
	p.token = pathB64.EncodeToString(m.Sum(nil))[:12]
}

// path 生成当前有效路径。
func (p *PathRouter) path(op string) string {
	return p.prefix + "/" + p.token + "/" + op
}

// match 判断请求路径是否属于内部端点。
// 返回 (op, matched, current)：matched 表示前缀对（旧片段也算），
// current 表示片段是否为当日值。旧片段必须 404，不能落到转发。
func (p *PathRouter) match(urlPath string) (op string, matched bool, current bool) {
	head := p.prefix + "/"
	if !strings.HasPrefix(urlPath, head) {
		return "", false, false
	}
	rest := strings.TrimPrefix(urlPath, head)
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false, false
	}
	tok, oper := parts[0], parts[1]
	cur := subtle.ConstantTimeCompare([]byte(tok), []byte(p.token)) == 1
	return oper, true, cur
}

// maybeRotate 在每次请求时检查跨天，保证 0 点后立刻切换，不等重启。
func (p *PathRouter) maybeRotate() { p.rotate(time.Now().UTC()) }

// redirectToLogin 构造到当前登录页的 303 目标，保留原始请求路径便于登录后返回。
func (p *PathRouter) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := p.path(opLogin)
	if r.URL.RawQuery != "" && r.URL.Path == "/" {
		target += "?next=/"
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// pathError 用于旧片段/未知操作的统一 404，不泄露端点是否存在。
func pathError(w http.ResponseWriter) { http.NotFound(w, nil) }

// debugString 只在日志里用，不写到响应。
func (p *PathRouter) debugString() string {
	return fmt.Sprintf("%s/%s", p.prefix, p.token)
}
