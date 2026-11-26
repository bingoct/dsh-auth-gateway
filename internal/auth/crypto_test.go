package auth

import (
	"net"
	"testing"
)

// Node crypto.scryptSync('testpass123', '0123456789abcdef', 64, {N:16384,r:8,p:1})
// 生成一次后固化为常量，用来锁住与 Node / Rust 版凭据的兼容性。
//
// 这里的密码与盐都是**构造的测试向量**，不对应任何真实凭据：
// 盐是 "0123456789abcdef" 的 base64url，而 init 用 crypto/rand 生成盐，
// 撞上这个值的概率是 2^-128。保留它是因为它由另一套实现产出，
// 能验证"Go 能不能吃下 Node 生成的 hash"，比自产自销有说服力。
const (
	nodeVectorSalt = "MDEyMzQ1Njc4OWFiY2RlZg"
	nodeVectorHash = "SrA0REV7LqqYnim_7xf-OxXNvn4h0uDMAIX0KFJ33iZI7IN_6Oa6XWRlVSxq3KC-MQEnR09CeJuZI3phfyfZaQ"
)

// 既有凭据是 Node/Rust 生成的，Go 侧必须能校验同一个 hash，否则换实现即锁死登录。
func TestVerifyPasswordMatchesNodeScrypt(t *testing.T) {
	encoded := "scrypt$" + nodeVectorSalt + "$" + nodeVectorHash
	if !VerifyPassword("testpass123", encoded) {
		t.Fatal("Go scrypt must accept a hash produced by Node with N=16384,r=8,p=1")
	}
	if VerifyPassword("testpass124", encoded) {
		t.Fatal("wrong password accepted")
	}
	if VerifyPassword("testpass123", "scrypt$"+nodeVectorSalt) {
		t.Fatal("malformed hash accepted")
	}
	if VerifyPassword("testpass123", "bcrypt$"+nodeVectorSalt+"$"+nodeVectorHash) {
		t.Fatal("unknown scheme accepted")
	}
}

// 本实现生成的 hash 必须能被自己验证，且盐每次不同。
func TestHashPasswordRoundTrip(t *testing.T) {
	a, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("salt must be random per hash")
	}
	if !VerifyPassword("s3cret-pass", a) || !VerifyPassword("s3cret-pass", b) {
		t.Fatal("round trip failed")
	}
}

// 绑定粒度按档位分：temp 绑完整地址（换地址即失效），
// persist 绑前缀（容忍家宽重新拨号换 IPv6 前缀）。
func TestBindIPGranularity(t *testing.T) {
	v4 := net.ParseIP("203.0.113.45")
	if got := BindIP(v4, ModeTemp); got != "203.0.113.45" {
		t.Fatalf("temp ipv4 = %q, want full address", got)
	}
	if got := BindIP(v4, ModePersist); got != "203.0.113.0/24" {
		t.Fatalf("persist ipv4 = %q, want /24", got)
	}

	v6 := net.ParseIP("2001:db8:abcd:1234:5678:9abc:def0:1")
	if got := BindIP(v6, ModeTemp); got != v6.String() {
		t.Fatalf("temp ipv6 = %q, want full address", got)
	}
	// /56 = 前 7 字节，第 8 字节（0x34 的高半字节）之后清零。
	if got := BindIP(v6, ModePersist); got != "2001:db8:abcd:1200::/56" {
		t.Fatalf("persist ipv6 = %q, want /56 mask", got)
	}

	if got := BindIP(nil, ModeTemp); got != "" {
		t.Fatalf("nil ip = %q, want empty", got)
	}
}

// IPPrefix 的 IPv6 分支曾经把 8 字节切片当 IP 打印成 "?hex" 形式，这里锁住正确行为。
func TestIPPrefixIPv6(t *testing.T) {
	v6 := net.ParseIP("2001:db8:abcd:1234:5678:9abc:def0:1")
	if got := IPPrefix(v6); got != "2001:db8:abcd:1234::/64" {
		t.Fatalf("ipv6 prefix = %q", got)
	}
	if got := IPPrefix(net.ParseIP("203.0.113.45")); got != "203.0.113.0/24" {
		t.Fatalf("ipv4 prefix = %q", got)
	}
}
