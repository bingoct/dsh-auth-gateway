package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"

	"github.com/BurntSushi/toml"
)

var fixedNow = func() time.Time { return time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC) }

func initOpts(password string, force, only bool) initOptions {
	return initOptions{
		force: force, passwordOnly: only,
		readPassword: func() (string, error) { return password, nil },
		now:          fixedNow,
	}
}

func loadCreds(t *testing.T, path string) *config.Credentials {
	t.Helper()
	var doc struct {
		Credentials *config.Credentials `toml:"credentials"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toml.Decode(string(data), &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Credentials
}

// 首次运行写入完整凭据，密码哈希可校验、TOTP 链接与自动生成的 secret 一致。
func TestInitFirstRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	res, err := initCredentials(path, initOpts("strong-pass-1", false, false))
	if err != nil {
		t.Fatal(err)
	}
	if res.uri == "" || !strings.HasPrefix(res.uri, "otpauth://totp/") {
		t.Fatalf("uri = %q, want otpauth link", res.uri)
	}
	cred := loadCreds(t, path)
	if cred.Version != 2 || cred.TOTPSecretB32 == "" {
		t.Fatalf("cred = %+v", cred)
	}
	if !auth.VerifyPassword("strong-pass-1", cred.PasswordHash) {
		t.Fatal("stored hash does not verify the password")
	}
	if !strings.Contains(res.uri, cred.TOTPSecretB32) {
		t.Fatal("QR uri secret differs from stored secret")
	}
}

// 凭据已存在且无 flag → 拒绝，且原文件不变。
func TestInitRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	if _, err := initCredentials(path, initOpts("first-pass-1", false, false)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	_, err := initCredentials(path, initOpts("other-pass-1", false, false))
	if err == nil || !strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), "--password-only") {
		t.Fatalf("err = %v, want refusal with both flags named", err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("refused init must not modify the file")
	}
}

// --force 全量重置：密码哈希与 TOTP secret 都换，认证器要重绑。
func TestInitForceRotatesBoth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	first, _ := initCredentials(path, initOpts("first-pass-1", false, false))
	old := loadCreds(t, path)
	second, err := initCredentials(path, initOpts("second-pass-1", true, false))
	if err != nil {
		t.Fatal(err)
	}
	fresh := loadCreds(t, path)
	if second.uri == "" || second.totpB32 == old.TOTPSecretB32 {
		t.Fatal("force must generate a new TOTP secret")
	}
	if fresh.PasswordHash == old.PasswordHash || fresh.TOTPSecretB32 == old.TOTPSecretB32 {
		t.Fatal("force did not rotate credentials")
	}
	if !auth.VerifyPassword("second-pass-1", fresh.PasswordHash) {
		t.Fatal("new password does not verify")
	}
	if auth.VerifyPassword("first-pass-1", fresh.PasswordHash) {
		t.Fatal("old password still verifies after force")
	}
	if first.totpB32 == "" {
		t.Fatal("first run must have set a TOTP secret")
	}
}

// --password-only 只换密码：TOTP secret 不变、不打印二维码、写 password_updated_at。
func TestInitPasswordOnlyKeepsTOTP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	_, _ = initCredentials(path, initOpts("first-pass-1", false, false))
	old := loadCreds(t, path)
	res, err := initCredentials(path, initOpts("third-pass-1", false, true))
	if err != nil {
		t.Fatal(err)
	}
	fresh := loadCreds(t, path)
	if !res.rotatedOnly || res.uri != "" {
		t.Fatalf("result = %+v, want rotatedOnly=true uri empty", res)
	}
	if fresh.TOTPSecretB32 != old.TOTPSecretB32 {
		t.Fatal("password-only must keep the TOTP secret")
	}
	if fresh.PasswordUpdatedAt == "" || fresh.CreatedAt != old.CreatedAt {
		t.Fatalf("timestamps = created %q updated %q", fresh.CreatedAt, fresh.PasswordUpdatedAt)
	}
	if !auth.VerifyPassword("third-pass-1", fresh.PasswordHash) {
		t.Fatal("new password does not verify")
	}
}

// flag 冲突与无凭据时 --password-only 都要拒绝。
func TestInitRejectsInvalidFlagCombos(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	_, err := initCredentials(path, initOptions{force: true, passwordOnly: true,
		readPassword: func() (string, error) { return "x", nil }})
	if err == nil {
		t.Fatal("force + password-only must be rejected")
	}
	_, err = initCredentials(path, initOpts("some-pass-1", false, true))
	if err == nil || !strings.Contains(err.Error(), "existing credentials") {
		t.Fatalf("password-only without credentials: err = %v", err)
	}
}

// 密码短于 8 字符拒绝；stdin 路径由 readPasswordStdin 单独覆盖不了（需真实管道），
// 这里验证注入的 readPassword 为短密码时 init 会拒绝，等价于 stdin 读进来的短密码。
func TestInitRejectsShortPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	_, err := initCredentials(path, initOpts("short", false, false))
	if err == nil || !strings.Contains(err.Error(), "8-128") {
		t.Fatalf("err = %v, want length error", err)
	}
}

// 已存在的文件里若已有其他段，替换 [credentials] 时不能吃掉后面的配置。
func TestInitPreservesOtherSections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.toml")
	base := "[server]\nlisten_port = 33080\n\n[auth]\npublic_origin = \"https://dsh.example\"\n\n"
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := initCredentials(path, initOpts("some-pass-1", false, false)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	got := string(data)
	for _, want := range []string{"[server]", "listen_port = 33080", "[auth]", "https://dsh.example", "[credentials]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("result missing %q:\n%s", want, got)
		}
	}
}

// 中文别名占两列：按 rune 数补齐会让后面的列全部错位。
func TestPadRightWideRunes(t *testing.T) {
	if got := padRight("办公室平板", 10); got != "办公室平板" {
		t.Fatalf("wide runes should fill exactly: %q", got)
	}
	if got := padRight("ab", 6); got != "ab    " {
		t.Fatalf("ascii padding: %q", got)
	}
}
