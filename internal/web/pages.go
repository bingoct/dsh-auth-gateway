package web

import (
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"html/template"
	"net/http"
)

// Pages 只负责渲染表单页。安全优先：无外部资源、无脚本、CSP 收紧到最小。
type Pages struct {
	login  *template.Template
	failed *template.Template
	paths  *PathRouter
}

func newPages(cfg *config.Config, paths *PathRouter) *Pages {
	return &Pages{
		login:  template.Must(template.New("login").Parse(loginHTML)),
		failed: template.Must(template.New("failed").Parse(failedHTML)),
		paths:  paths,
	}
}

func pageHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}

func (p *Pages) renderLogin(w http.ResponseWriter, errMsg, challenge string) {
	pageHeaders(w)
	w.WriteHeader(http.StatusOK)
	_ = p.login.Execute(w, struct {
		Error     string
		Challenge string
		Action    string
	}{errMsg, challenge, p.paths.path(opLogin)})
}

// renderStarting 在 dsh 拉起期间返回 503 + 自动刷新页。刷新会重新走一次转发。
func (p *Pages) renderStarting(w http.ResponseWriter) {
	pageHeaders(w)
	w.Header().Set("Retry-After", "2")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(startingHTML))
}

// renderUnavailable 在拉起失败或进入退避窗口时返回 503 + 错误摘要。
func (p *Pages) renderUnavailable(w http.ResponseWriter, err error) {
	pageHeaders(w)
	w.Header().Set("Retry-After", "5")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = p.failed.Execute(w, struct{ Error string }{err.Error()})
}

// darkCSS 用 prefers-color-scheme 跟随系统深色模式；纯 CSS，不引脚本、不改 CSP。
const darkCSS = `
:root{color-scheme:light dark}
@media (prefers-color-scheme:dark){
 :root{color-scheme:dark}
 body{background:#151515;color:#eee}
 label,.remember{color:#bbb}
 input[type=password]{background:#222;color:#eee;border-color:#555}
 button{background:#e8e8e8;color:#111}
 p{color:#aaa}
 pre{background:#222;border-color:#444;color:#ddd}
 a{color:#9cf}
}`

const loginHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>登录</title>
<style>
body{font-family:system-ui,sans-serif;max-width:22rem;margin:10vh auto;padding:0 1rem;color:#111;background:#fff}
h1{font-size:1.1rem;font-weight:600;margin:0 0 1.2rem}
label{display:block;font-size:.85rem;margin:.9rem 0 .3rem;color:#444}
input[type=password]{width:100%;box-sizing:border-box;padding:.55rem .6rem;font-size:1rem;
 border:1px solid #bbb;border-radius:4px;background:#fff;color:#111}
input.code{font-size:1.4rem;letter-spacing:.35em;text-align:center}
.remember{display:flex;align-items:center;gap:.5rem;margin-top:1.1rem;font-size:.85rem;color:#333}
.remember input{margin:0;width:auto}
button{margin-top:1.4rem;width:100%;padding:.6rem;font-size:1rem;border:0;border-radius:4px;
 background:#1a1a1a;color:#fff;cursor:pointer}
.err{color:#b00020;font-size:.85rem;margin:.8rem 0 0}
` + darkCSS + `
</style></head><body>
<h1>登录</h1>
<form method="post" action="{{.Action}}" autocomplete="on">
<input type="hidden" name="ch" value="{{.Challenge}}">
<label for="password">密码</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<label for="code">动态码</label>
<input id="code" name="code" class="code" type="password" inputmode="numeric"
 autocomplete="one-time-code" required>
<label class="remember"><input type="checkbox" name="remember" value="1">在此设备保持登录</label>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
<button type="submit">登录</button>
</form>
</body></html>`

const startingHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="2">
<meta name="color-scheme" content="light dark">
<title>正在启动</title>
<style>
body{font-family:system-ui,sans-serif;max-width:26rem;margin:16vh auto;padding:0 1rem;color:#111;background:#fff;text-align:center}
h1{font-size:1.05rem;font-weight:600;margin:0 0 .6rem}
p{font-size:.9rem;color:#555;line-height:1.6;margin:0}
` + darkCSS + `
</style></head><body>
<h1>dsh 正在启动</h1>
<p>首次访问需要拉起服务，通常几秒钟。本页会自动刷新。</p>
</body></html>`

const failedHTML = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="color-scheme" content="light dark">
<title>启动失败</title>
<style>
body{font-family:system-ui,sans-serif;max-width:32rem;margin:14vh auto;padding:0 1rem;color:#111;background:#fff}
h1{font-size:1.05rem;font-weight:600;margin:0 0 .6rem}
p{font-size:.9rem;color:#555;line-height:1.6;margin:0 0 1rem}
pre{font-size:.8rem;background:#f5f5f5;border:1px solid #ddd;border-radius:4px;
 padding:.7rem;overflow:auto;white-space:pre-wrap;word-break:break-word}
a{font-size:.9rem}
` + darkCSS + `
</style></head><body>
<h1>dsh 启动失败</h1>
<p>网关会在几秒后重试。若持续失败，检查 dsh 可执行文件路径与 profile 配置。</p>
<pre>{{.Error}}</pre>
<a href="/">重试</a>
</body></html>`
