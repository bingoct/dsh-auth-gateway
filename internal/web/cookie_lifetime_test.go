package web

import (
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"net/http/httptest"
	"strings"
	"testing"
)

// 两档 cookie 的生命周期必须不同：temp 是会话 cookie（关浏览器即失效），
// persist 才写 Max-Age。写反了不会有报错，只会静默变成"临时票关浏览器还在"。
func TestDeviceCookieLifetimeByMode(t *testing.T) {
	gw := &Gateway{cfg: &config.Config{PublicOrigin: "https://dsh.example"}, policy: auth.DefaultPolicy()}

	temp := httptest.NewRecorder()
	gw.setDeviceCookie(temp, "tok", auth.ModeTemp)
	if sc := temp.Header().Get("Set-Cookie"); strings.Contains(sc, "Max-Age") {
		t.Fatalf("temp cookie must be session-scoped (no Max-Age), got %q", sc)
	}

	persist := httptest.NewRecorder()
	gw.setDeviceCookie(persist, "tok", auth.ModePersist)
	if sc := persist.Header().Get("Set-Cookie"); !strings.Contains(sc, "Max-Age=2592000") {
		t.Fatalf("persist cookie must live 30 days (2592000s), got %q", sc)
	}
}
