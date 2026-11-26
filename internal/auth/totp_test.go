package auth

import (
	"testing"
	"time"
)

// RFC 6238 附录 B 的 SHA1 测试向量，码长为 6 位（原表是 8 位，取后 6 位）。
// 算法本身错了会导致"密码对但永远登不上"，必须钉住。
func TestHOTPRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := []struct {
		step uint64
		want string
	}{
		{1, "287082"},         // T=59
		{37037036, "081804"},  // T=1111111109
		{37037037, "050471"},  // T=1111111111
		{41152263, "005924"},  // T=1234567890
		{66666666, "279037"},  // T=2000000000
		{666666666, "353130"}, // T=20000000000
	}
	for _, c := range cases {
		if got := HOTP(secret, c.step); got != c.want {
			t.Errorf("hotp(step=%d) = %s, want %s", c.step, got, c.want)
		}
	}
}

// 同一动态码不能消费两次；窗口外的码不接受。
func TestTOTPReplayAndWindow(t *testing.T) {
	secret := []byte("0123456789abcdefghij")
	guard := NewTOTPGuard()
	now := uint64(time.Now().Unix() / TOTPStep)
	cur := HOTP(secret, now)
	if err := guard.verify(secret, cur); err != nil {
		t.Fatalf("fresh code rejected: %v", err)
	}
	if err := guard.verify(secret, cur); err == nil {
		t.Fatal("replayed code accepted")
	}
	// 偏离窗口 5 步的码必须拒绝。
	off := HOTP(secret, now+5)
	if err := guard.verify(secret, off); err == nil {
		t.Fatal("out-of-window code accepted")
	}
}

// 格式错误直接拒绝，不做无谓的 HMAC 计算。
func TestTOTPRejectsMalformed(t *testing.T) {
	guard := NewTOTPGuard()
	secret := []byte("0123456789abcdefghij")
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
		if err := guard.verify(secret, bad); err == nil {
			t.Fatalf("malformed code %q accepted", bad)
		}
	}
	if err := guard.verify([]byte("short"), "123456"); err == nil {
		t.Fatal("short secret accepted")
	}
}

// base32 解码要容忍空格、短横线、小写和 padding。
func TestBase32DecodeTolerant(t *testing.T) {
	want := "JBSWY3DPEHPK3PXP"
	for _, in := range []string{
		want,
		"jbswy3dpehpk3pxp",
		"JBSW Y3DP EHPK 3PXP",
		"JBSW-Y3DP-EHPK-3PXP",
		"JBSWY3DPEHPK3PXP=",
	} {
		raw, err := Base32Decode(in)
		if err != nil {
			t.Fatalf("decode %q: %v", in, err)
		}
		if Base32Encode(raw) != want {
			t.Fatalf("round trip %q got %q", in, Base32Encode(raw))
		}
	}
}
