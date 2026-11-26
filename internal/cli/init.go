package cli

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"io"
	"os"
	"strings"
	"time"
)

// ---- init ----

type initCLIOptions struct {
	configPath    string
	passwordStdin bool
	force         bool
	passwordOnly  bool
}

type initOptions struct {
	force        bool
	passwordOnly bool
	readPassword func() (string, error)
	now          func() time.Time
}

type initResult struct {
	path         string
	passwordHash string
	totpB32      string
	uri          string // 非空 = 新生成了 TOTP，CLI 层打印二维码；只改密码时为空
	rotatedOnly  bool
}

// runInit 把 CLI 信号翻译成 initOptions；真正的写盘逻辑在 initCredentials，
// 后者接收注入的 readPassword/now，便于单测覆盖首次/拒绝/force/只改密码/stdin。
func runInit(opts initCLIOptions) error {
	if opts.force && opts.passwordOnly {
		return fmt.Errorf("--force and --password-only are mutually exclusive")
	}
	var read func() (string, error)
	if opts.passwordStdin {
		read = readPasswordStdin
	} else {
		read = readPasswordInteractive
	}
	path := opts.configPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	result, err := initCredentials(path, initOptions{
		force: opts.force, passwordOnly: opts.passwordOnly,
		readPassword: read, now: time.Now,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "凭据已写入 %s\n", result.path)
	if result.rotatedOnly {
		fmt.Fprintln(os.Stderr, "已保留原 TOTP secret，认证器不用重新绑定。")
		return nil
	}
	qr, qrErr := qrcode.New(result.uri, qrcode.Medium)
	if qrErr == nil {
		fmt.Fprintln(os.Stderr, "扫描下方二维码，或手动录入链接到认证器：")
		fmt.Fprintln(os.Stderr, qr.ToSmallString(false))
	} else {
		fmt.Fprintln(os.Stderr, "二维码生成失败，请手动录入下方链接：")
	}
	fmt.Fprintf(os.Stderr, "%s\n", result.uri)
	return nil
}

// readPasswordInteractive 用 term.ReadPassword 隐藏回显，读两次比对。要求 stdin 是终端。
func readPasswordInteractive() (string, error) {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return "", fmt.Errorf("interactive password requires a terminal; use --password-stdin")
	}
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, "新密码: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(os.Stderr, "再输入一次: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("confirm password: %w", err)
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(first), nil
}

// readPasswordStdin 从管道读一行作为密码，不回显、不进 shell 历史、无二次确认。
func readPasswordStdin() (string, error) {
	fi, err := os.Stdin.Stat()
	if err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return "", fmt.Errorf("--password-stdin expects piped input")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// initCredentials 写凭据段：首次创建 / 默认拒绝 / --force 全量重置 / --password-only 只改密码。
func initCredentials(path string, opts initOptions) (*initResult, error) {
	raw, err := os.ReadFile(path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	var existing *config.Credentials
	if exists {
		var doc struct {
			Credentials *config.Credentials `toml:"credentials"`
		}
		if _, err := toml.Decode(string(raw), &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		existing = doc.Credentials
	}
	if exists && existing != nil && !opts.force && !opts.passwordOnly {
		return nil, fmt.Errorf("credentials already exist in %s; use --force (new password + new TOTP) or --password-only (keep TOTP)", path)
	}
	if opts.passwordOnly && existing == nil {
		return nil, fmt.Errorf("--password-only needs existing credentials; run init without flags first")
	}

	password, err := opts.readPassword()
	if err != nil {
		return nil, err
	}
	if len(password) < 8 || len(password) > 128 {
		return nil, fmt.Errorf("password must be 8-128 characters")
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := opts.now
	if now == nil {
		now = time.Now
	}
	stamp := now().UTC().Format(time.RFC3339)
	cred := &config.Credentials{
		Version:       2,
		CreatedAt:     stamp,
		PasswordHash:  hash,
		TOTPDigits:    6,
		TOTPPeriod:    30,
		TOTPAlgorithm: "SHA1",
	}
	result := &initResult{path: path, passwordHash: hash}
	if opts.passwordOnly {
		cred.CreatedAt = existing.CreatedAt
		cred.PasswordUpdatedAt = stamp
		cred.TOTPSecretB32 = existing.TOTPSecretB32
		result.totpB32 = existing.TOTPSecretB32
		result.rotatedOnly = true
	} else {
		secret := make([]byte, 20)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		cred.TOTPSecretB32 = auth.Base32Encode(secret)
		result.totpB32 = cred.TOTPSecretB32
		result.uri = auth.OTPAuthURI("dsh", "bingo", cred.TOTPSecretB32)
	}

	var b strings.Builder
	b.WriteString("[credentials]\n")
	if err := toml.NewEncoder(&b).Encode(cred); err != nil {
		return nil, err
	}

	if !exists {
		if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			return nil, err
		}
	} else {
		updated := replaceCredentialsSection(string(raw), b.String())
		if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func replaceCredentialsSection(doc, section string) string {
	const marker = "[credentials]"
	idx := 0
	for {
		i := strings.Index(doc[idx:], marker)
		if i < 0 {
			return strings.TrimRight(doc, "\n") + "\n\n" + section
		}
		i += idx
		if i != 0 && doc[i-1] != '\n' { // 必须是行首，避免撞到注释里的同名字样
			idx = i + len(marker)
			continue
		}
		start := i
		end := len(doc)
		for j := i + len(marker); j < len(doc); j++ {
			if doc[j] == '[' && doc[j-1] == '\n' { // 下一个表头即本段结束
				end = j
				break
			}
		}
		return doc[:start] + section + doc[end:]
	}
}
func newInitCmd(configPath *string) *cobra.Command {
	var stdinPassword, force, passwordOnly bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "create or rotate credentials; print the otpauth link and terminal QR code",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(initCLIOptions{
				configPath: *configPath, passwordStdin: stdinPassword,
				force: force, passwordOnly: passwordOnly,
			})
		},
	}
	cmd.Flags().BoolVar(&stdinPassword, "password-stdin", false, "read the new password from stdin (one line, no echo, no confirmation)")
	cmd.Flags().BoolVar(&force, "force", false, "reset existing credentials: new password AND new TOTP (re-bind authenticator)")
	cmd.Flags().BoolVar(&passwordOnly, "password-only", false, "change only the password, keep the existing TOTP secret")
	return cmd
}
