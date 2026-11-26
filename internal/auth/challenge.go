package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	challengeTTL   = 5 * time.Minute
	challengeSweep = 2 * time.Minute
)

// ChallengeGuard 管理登录挑战因子：自包含 token + 服务端一次性 used 表。
// token 格式：<unix_millis>.<nonce_b64u>.<hmac_b64u>
type ChallengeGuard struct {
	secret []byte
	mu     sync.Mutex
	used   map[[32]byte]time.Time
	stop   chan struct{}
	done   chan struct{}
}

func NewChallengeGuard(passwordHash string) *ChallengeGuard {
	sum := sha256.Sum256([]byte("dsh-challenge-v1:" + passwordHash))
	c := &ChallengeGuard{
		secret: sum[:],
		used:   make(map[[32]byte]time.Time),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go c.sweepLoop()
	return c
}

// Close 停止清理 goroutine，供测试与优雅退出调用。幂等。
func (c *ChallengeGuard) Close() {
	c.mu.Lock()
	select {
	case <-c.stop:
		c.mu.Unlock()
		return
	default:
		close(c.stop)
	}
	c.mu.Unlock()
	<-c.done
}

func (c *ChallengeGuard) sign(body string) []byte {
	m := hmac.New(sha256.New, c.secret)
	m.Write([]byte(body))
	return m.Sum(nil)
}

// Issue 签发一次性挑战，返回 token 与写入浏览器的 cookie。
func (c *ChallengeGuard) Issue(secure bool) (string, *http.Cookie) {
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	ms := time.Now().UnixMilli()
	body := strconv.FormatInt(ms, 10) + "." + B64.EncodeToString(nonce)
	token := body + "." + B64.EncodeToString(c.sign(body))
	cookie := &http.Cookie{
		Name: CookieChallenge, Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: secure,
		MaxAge: int(challengeTTL.Seconds()),
	}
	return token, cookie
}

// Consume 校验并核销挑战。表单值与 cookie 必须一致（双持，兼防 CSRF）。
func (c *ChallengeGuard) Consume(formToken, cookieToken string) error {
	if formToken == "" || cookieToken == "" {
		return fmt.Errorf("challenge missing")
	}
	if subtle.ConstantTimeCompare([]byte(formToken), []byte(cookieToken)) != 1 {
		return fmt.Errorf("challenge mismatch")
	}
	parts := strings.Split(formToken, ".")
	if len(parts) != 3 {
		return fmt.Errorf("challenge malformed")
	}
	body := parts[0] + "." + parts[1]
	sig, err := B64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(c.sign(body), sig) {
		return fmt.Errorf("challenge signature invalid")
	}
	ms, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return fmt.Errorf("challenge timestamp invalid")
	}
	issued := time.UnixMilli(ms)
	if time.Since(issued) > challengeTTL || time.Until(issued) > time.Minute {
		return fmt.Errorf("challenge expired")
	}

	key := sha256.Sum256([]byte(formToken))
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, used := c.used[key]; used {
		return fmt.Errorf("challenge replayed")
	}
	c.used[key] = time.Now()
	return nil
}

func (c *ChallengeGuard) sweepLoop() {
	defer close(c.done)
	t := time.NewTicker(challengeSweep)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.mu.Lock()
			cut := time.Now().Add(-challengeTTL)
			for k, at := range c.used {
				if at.Before(cut) {
					delete(c.used, k)
				}
			}
			c.mu.Unlock()
		case <-c.stop:
			return
		}
	}
}
