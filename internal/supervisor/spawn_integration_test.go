//go:build integration

package supervisor

import (
	"context"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 直接用网关自己的 Supervisor.spawn 拉真 dsh，
// 与探针（手写 exec.Command）对照：探针成、这里败 → 差异在网关代码；
// 这里也成 → 差异在网关进程的执行上下文。
func TestRealDshSpawnViaSupervisor(t *testing.T) {
	home, _ := os.UserHomeDir()
	cfg := &config.Config{
		AuthEnabled: true,
		DshHost:     "127.0.0.1", DshPort: 0, DshProfile: "web",
		DshCwd:  filepath.Join(home, "WorkBuddy", "dsh"),
		DshBin:  filepath.Join(home, "scoop", "apps", "dsh", "current", "lib", "bin.js"),
		NodeBin: filepath.Join(home, ".workbuddy", "binaries", "node", "versions", "22.22.2-6", "node.exe"),
		Home:    filepath.Join(home, ".dsh"),

		DshReadyMS:   90000,
		EnsureWaitMS: 90000,
		PublicOrigin: "https://x", SessionDays: 30, TempHours: 2,
		RateWindowMin: 15, RateMaxFails: 8, RateBanMin: 15,
		Credentials: &config.Credentials{Version: 2, PasswordHash: "scrypt$A$A", TOTPDigits: 6, TOTPPeriod: 30, TOTPAlgorithm: "SHA1"},
	}
	sup := NewSupervisor(cfg, func(f string, a ...any) { t.Logf(f, a...) })
	defer sup.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	rt, err := sup.Ensure(ctx)
	if err != nil {
		t.Fatalf("real dsh spawn failed: %v", err)
	}
	t.Logf("READY port=%d cookie_prefix=%.20s...", rt.Port, rt.Cookie)
}
