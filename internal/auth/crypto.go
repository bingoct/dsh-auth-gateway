package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// 必须与既有凭据兼容：Node crypto.scryptSync 默认 N=16384,r=8,p=1，输出 64 字节。
const (
	scryptLogN = 14
	scryptR    = 8
	scryptP    = 1
	scryptKey  = 64
)

var B64 = base64.RawURLEncoding

// VerifyPassword 校验 `scrypt$<salt_b64u>$<hash_b64u>`。
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "scrypt" {
		return false
	}
	salt, err := B64.DecodeString(parts[1])
	if err != nil {
		return false
	}
	expected, err := B64.DecodeString(parts[2])
	if err != nil || len(expected) == 0 {
		return false
	}
	actual, err := scrypt.Key([]byte(password), salt, 1<<scryptLogN, scryptR, scryptP, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	out, err := scrypt.Key([]byte(password), salt, 1<<scryptLogN, scryptR, scryptP, scryptKey)
	if err != nil {
		return "", err
	}
	return "scrypt$" + B64.EncodeToString(salt) + "$" + B64.EncodeToString(out), nil
}

// IPPrefix 把客户端地址归并成绑定前缀：IPv4 /24，IPv6 /64。
// 会话绑的是网段不是具体地址，换网内 IP（DHCP 续租）不掉线，换网络会掉。
func IPPrefix(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	if v6 := ip.To16(); v6 != nil {
		return v6.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
	return ""
}

// BindIP 给出会话绑定实际使用的地址粒度，按信任等级分档：
//
//	模式       IPv4        IPv6
//	temp      完整地址     完整地址   —— 非信任设备，换地址即失效
//	persist   /24         /56        —— 信任设备，容忍家宽重新拨号换前缀
//
// IPv6 的 /56 是运营商给家庭用户的整块（/64 只是其中一段子网，重新拨号常变），
// 因此 persist 绑 /56 而不是 /64。temp 绑完整地址是因为它只活 6h，
// 且 IPv6 隐私扩展地址（RFC 4941）每天轮换对短会话没有影响。
func BindIP(ip net.IP, mode string) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		if mode == ModePersist {
			return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
		}
		return v4.String()
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	if mode == ModePersist {
		return v6.Mask(net.CIDRMask(56, 128)).String() + "/56"
	}
	return v6.String()
}

// IPInCIDRs 判断地址是否落在任一网段。
func IPInCIDRs(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
