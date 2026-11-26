package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	TOTPStep   = 30
	totpWindow = 1 // ±1 步，容忍时钟漂移
)

// Base32Decode 兼容有无 padding、大小写与空格分组。
func Base32Decode(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(strings.TrimSpace(s)))
	if clean == "" {
		return nil, fmt.Errorf("empty secret")
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func Base32Encode(raw []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

// HOTP 是 RFC 4226 动态截断，输出 6 位。
func HOTP(secret []byte, step uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], step)
	m := hmac.New(sha1.New, secret)
	m.Write(buf[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 |
		uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 |
		uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1_000_000)
}

// TOTPGuard 记住每个密钥已用过的最大步长，保证同一码不能用第二次。
type TOTPGuard struct {
	mu   sync.Mutex
	last map[[32]byte]uint64
}

func NewTOTPGuard() *TOTPGuard {
	return &TOTPGuard{last: make(map[[32]byte]uint64)}
}

// verify 校验 6 位码；成功后把命中的步长写回，重放同一码会失败。
func (g *TOTPGuard) verify(secret []byte, code string) error {
	if len(code) != 6 {
		return fmt.Errorf("code must be 6 digits")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return fmt.Errorf("code must be 6 digits")
		}
	}
	if len(secret) < 10 {
		return fmt.Errorf("totp secret too short")
	}

	key := sha256.Sum256(secret)
	now := time.Now().Unix() / TOTPStep

	g.mu.Lock()
	defer g.mu.Unlock()
	last := g.last[key]
	hit := uint64(0)
	for d := int64(-totpWindow); d <= totpWindow; d++ {
		step := now + d
		if step <= 0 || uint64(step) <= last {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(HOTP(secret, uint64(step))), []byte(code)) == 1 {
			hit = uint64(step)
			break
		}
	}
	if hit == 0 {
		return fmt.Errorf("invalid or replayed code")
	}
	g.last[key] = hit
	return nil
}

// OTPAuthURI 生成给认证器扫描的 otpauth:// 链接。
func OTPAuthURI(issuer, account, secretB32 string) string {
	esc := func(s string) string {
		return strings.NewReplacer(":", "%3A", "/", "%2F", "?", "%3F", "&", "%26", "=", "%3D", " ", "%20").Replace(s)
	}
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		esc(issuer), esc(account), secretB32, esc(issuer))
}
