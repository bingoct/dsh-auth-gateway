package auth

import (
	"strings"
	"testing"
	"time"
)

func mustMint(t *testing.T, c *DeviceCookie, fam string) string {
	t.Helper()
	tok, err := c.Mint(DevicePayload{
		Fam: fam, Mode: ModePersist, Iat: time.Now().Unix(), Gen: 1,
		IP: "10.0.0.0/24", UA: UAHash("test-agent"),
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func TestDeviceCookieRoundTrip(t *testing.T) {
	c := NewDeviceCookie("scrypt$abc$def")
	fam := "AAAAAAAAAAAAAAAAAAAAAA"
	tok := mustMint(t, c, fam)
	p, ok := c.Verify(tok)
	if !ok {
		t.Fatal("minted cookie must verify")
	}
	if p.Fam != fam || p.Mode != ModePersist || p.V != deviceCookieVersion {
		t.Fatalf("payload mismatch: %+v", p)
	}
	if p.IP != "10.0.0.0/24" || p.UA != UAHash("test-agent") {
		t.Fatalf("binding fields lost: %+v", p)
	}
}

func TestDeviceCookieTamperedPayload(t *testing.T) {
	c := NewDeviceCookie("scrypt$abc$def")
	tok := mustMint(t, c, "FAMILY_A")
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatal("unexpected token shape")
	}
	// 换成一个不同 family 的合法 payload，但沿用旧签名。
	other := mustMint(t, c, "FAMILY_B")
	otherParts := strings.Split(other, ".")
	forged := parts[0] + "." + otherParts[1] + "." + parts[2]
	if _, ok := c.Verify(forged); ok {
		t.Fatal("payload swap must be rejected")
	}
}

func TestDeviceCookieTamperedSignature(t *testing.T) {
	c := NewDeviceCookie("scrypt$abc$def")
	tok := mustMint(t, c, "FAMILY_A")
	if _, ok := c.Verify(tok[:len(tok)-1] + "x"); ok {
		t.Fatal("modified signature must be rejected")
	}
}

func TestDeviceCookieWrongKey(t *testing.T) {
	a := NewDeviceCookie("scrypt$abc$def")
	b := NewDeviceCookie("scrypt$changed$hash")
	tok := mustMint(t, a, "FAMILY_A")
	if _, ok := b.Verify(tok); ok {
		t.Fatal("cookie signed with another key must be rejected")
	}
}

func TestDeviceCookieMalformed(t *testing.T) {
	c := NewDeviceCookie("scrypt$abc$def")
	for _, bad := range []string{"", "v1", "v1.a", "v2.a.b", "v1..b", "v1.a.b.c"} {
		if _, ok := c.Verify(bad); ok {
			t.Fatalf("malformed %q must be rejected", bad)
		}
	}
}

func TestDeviceCookieRejectsZeroGen(t *testing.T) {
	c := NewDeviceCookie("scrypt$abc$def")
	if _, err := c.Mint(DevicePayload{Fam: "F", Mode: ModeTemp, Iat: time.Now().Unix(), Gen: 0}); err == nil {
		t.Fatal("gen=0 must be rejected at mint: a cookie without generation can never be valid")
	}
}

func TestDeviceCookieRejectsBadMode(t *testing.T) {
	c := NewDeviceCookie("scrypt$abc$def")
	if _, err := c.Mint(DevicePayload{Fam: "F", Mode: "forever", Iat: time.Now().Unix(), Gen: 1}); err == nil {
		t.Fatal("unknown mode must be rejected at mint")
	}
}

func TestPolicyWindows(t *testing.T) {
	p := DefaultPolicy()
	if p.Idle(ModeTemp) != 2*time.Hour || p.Abs(ModeTemp) != 6*time.Hour {
		t.Fatalf("temp windows wrong: %+v", p)
	}
	if p.Idle(ModePersist) != 14*24*time.Hour || p.Abs(ModePersist) != 30*24*time.Hour {
		t.Fatalf("persist windows wrong: %+v", p)
	}
}
