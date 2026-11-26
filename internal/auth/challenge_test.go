package auth

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestChallengeIssueConsume(t *testing.T) {
	g := NewChallengeGuard("scrypt$test$hash")
	defer g.Close()

	token, cookie := g.Issue(false)
	if token == "" || cookie == nil || cookie.Value != token {
		t.Fatalf("issue: token=%q cookie=%+v", token, cookie)
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("challenge cookie must be HttpOnly + SameSite=Strict")
	}
	if err := g.Consume(token, token); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := g.Consume(token, token); err == nil {
		t.Fatal("replayed token must be rejected")
	}
}

func TestChallengeMismatchAndMalformed(t *testing.T) {
	g := NewChallengeGuard("scrypt$test$hash")
	defer g.Close()

	if err := g.Consume("a.b.c", "different"); err == nil {
		t.Fatal("form/cookie mismatch must be rejected")
	}
	if err := g.Consume("garbage", "garbage"); err == nil {
		t.Fatal("malformed token must be rejected")
	}
	token, _ := g.Issue(false)
	parts := strings.Split(token, ".")
	parts[2] = "AAAA"
	forged := strings.Join(parts, ".")
	if err := g.Consume(forged, forged); err == nil {
		t.Fatal("forged signature must be rejected")
	}
}

func TestChallengeExpired(t *testing.T) {
	g := NewChallengeGuard("scrypt$test$hash")
	defer g.Close()

	ms := time.Now().Add(-6 * time.Minute).UnixMilli()
	body := strconv.FormatInt(ms, 10) + "." + B64.EncodeToString([]byte("0123456789abcdef"))
	token := body + "." + B64.EncodeToString(g.sign(body))
	if err := g.Consume(token, token); err == nil {
		t.Fatal("expired challenge must be rejected")
	}
}

func TestChallengeGuardConcurrentConsume(t *testing.T) {
	g := NewChallengeGuard("scrypt$test$hash")
	defer g.Close()

	token, _ := g.Issue(false)
	const n = 32
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { results <- g.Consume(token, token) }()
	}
	ok := 0
	for i := 0; i < n; i++ {
		if err := <-results; err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("concurrent consume successes = %d, want exactly 1", ok)
	}
}
