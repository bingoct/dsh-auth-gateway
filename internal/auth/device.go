package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// CookieDevice 是浏览器侧唯一的凭据（设备票）。
// 与旧的双票（dsh_sid + dsh_rt）不同：它不含 exp，时效完全由服务端台账判定。
// 这样只有一处真相，也不会出现"cookie 说过期、台账说没过期"的分歧。
const CookieDevice = "dsh_dev"

// 设备档位。临时档给别人的设备用，持久档给自己常用的设备用。
const (
	ModeTemp    = "temp"
	ModePersist = "persist"
)

const (
	deviceCookieVersion = 1
	deviceKeyPrefix     = "dsh-session-v3:"
	familyIDBytes       = 16
)

var (
	ErrDeviceCookieMalformed = errors.New("device cookie malformed")
	ErrDeviceCookieSignature = errors.New("device cookie signature mismatch")
)

// DevicePayload 是设备票的明文部分。字段名短，因为它会出现在每个请求的 Cookie 头里。
//
// Iat 是**首次登录**时刻，不是本次签发时刻：它是绝对上限（abs）的基准，
// 任何情况下都不能被刷新，否则 abs 会退化成"永不到期"。
//
// Gen 是轮换代数。服务端台账持有当前代数，定期把它 +1 并下发新 cookie；
// 旧代数的票随即失效。这正是"cookie 被动泄露后可被自动挤掉"的机制——
// 攻击者手里的旧票在用户下一次活跃轮换后就作废，不需要用户察觉或 revoke。
type DevicePayload struct {
	V    int    `json:"v"`
	Fam  string `json:"fam"`
	Mode string `json:"mode"`
	Iat  int64  `json:"iat"`
	IP   string `json:"ip"`
	UA   string `json:"ua"`
	Gen  uint32 `json:"gen"`
}

// DeviceCookie 负责签发与校验设备票。签名密钥由 password_hash 派生，
// 因此改密码会让所有已签发的设备票同时失效（无需额外状态）。
type DeviceCookie struct {
	key []byte
}

// NewDeviceCookie 用当前密码哈希派生签名密钥。
func NewDeviceCookie(passwordHash string) *DeviceCookie {
	sum := sha256.Sum256([]byte(deviceKeyPrefix + passwordHash))
	return &DeviceCookie{key: sum[:]}
}

// Mint 签发一枚设备票，格式 v1.<b64u(json)>.<b64u(hmac)>。
func (c *DeviceCookie) Mint(p DevicePayload) (string, error) {
	if p.V == 0 {
		p.V = deviceCookieVersion
	}
	if p.V != deviceCookieVersion || p.Fam == "" || p.Iat <= 0 || p.Gen == 0 {
		return "", ErrDeviceCookieMalformed
	}
	if p.Mode != ModeTemp && p.Mode != ModePersist {
		return "", ErrDeviceCookieMalformed
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	signed := "v1." + base64.RawURLEncoding.EncodeToString(body)
	return signed + "." + c.mac(signed), nil
}

// Verify 校验签名并解出 payload。签名比对用常数时间，避免按字节试探。
// 它只验"这枚票是我签的、格式正确"，不验时效——时效在台账里。
func (c *DeviceCookie) Verify(token string) (DevicePayload, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" || parts[1] == "" || parts[2] == "" {
		return DevicePayload{}, false
	}
	signed := parts[0] + "." + parts[1]
	want := c.mac(signed)
	if subtle.ConstantTimeCompare([]byte(want), []byte(parts[2])) != 1 {
		return DevicePayload{}, false
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return DevicePayload{}, false
	}
	var p DevicePayload
	if json.Unmarshal(body, &p) != nil {
		return DevicePayload{}, false
	}
	if p.V != deviceCookieVersion || p.Fam == "" || p.Iat <= 0 || p.Gen == 0 {
		return DevicePayload{}, false
	}
	if p.Mode != ModeTemp && p.Mode != ModePersist {
		return DevicePayload{}, false
	}
	return p, true
}

func (c *DeviceCookie) mac(signed string) string {
	m := hmac.New(sha256.New, c.key)
	m.Write([]byte(signed))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// NewFamilyID 生成一次登录的family 标识（128 位随机，22 字符 base64url）。
// 它出现在 cookie 里，所以不能可预测；但也不是凭据——伪造它没有用，因为票要验签。
func NewFamilyID() (string, error) {
	buf := make([]byte, familyIDBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Policy 是两种档位的时效上限与轮换周期。
//
// Idle：多久没请求就失效（滑动，靠 last_seen 判定）。
// Abs：从首次登录起最多活多久（硬顶，靠 created_at 判定）。
// Rotate：每隔多久换一代 cookie（靠 gen 判定）。必须显著小于 Idle，
// 否则"旧代数作废"这件事永远等不到触发点。
//
// Idle 与 Abs 必须同时满足才放行，缺一个都会退化成"永久有效"或"一用就掉"。
type Policy struct {
	TempIdle      time.Duration
	TempAbs       time.Duration
	TempRotate    time.Duration
	PersistIdle   time.Duration
	PersistAbs    time.Duration
	PersistRotate time.Duration
}

// DefaultPolicy 返回默认时效。
//
//	临时：2h 闲置 / 6h 硬顶 / 30min 轮换
//	持久：14d 闲置 / 30d 硬顶 / 24h 轮换
//
// 持久档的 abs 必须显著大于 idle，否则"滑动"没有空间（abs 一到就死，与是否活跃无关）。
// 轮换把"cookie 被动泄露后的可用窗口"从 abs 压到 rotate 周期：
// 用户下一次活跃就会把代数 +1，攻击者手里的旧票随即失效。
func DefaultPolicy() Policy {
	return Policy{
		TempIdle:      2 * time.Hour,
		TempAbs:       6 * time.Hour,
		TempRotate:    30 * time.Minute,
		PersistIdle:   14 * 24 * time.Hour,
		PersistAbs:    30 * 24 * time.Hour,
		PersistRotate: 24 * time.Hour,
	}
}

// Idle 返回该档位的闲置上限。
func (p Policy) Idle(mode string) time.Duration {
	if mode == ModePersist {
		return p.PersistIdle
	}
	return p.TempIdle
}

// Abs 返回该档位的绝对上限。
func (p Policy) Abs(mode string) time.Duration {
	if mode == ModePersist {
		return p.PersistAbs
	}
	return p.TempAbs
}

// Rotate 返回该档位的轮换周期。<=0 表示关闭轮换（退回"一枚票用到 abs"）。
func (p Policy) Rotate(mode string) time.Duration {
	if mode == ModePersist {
		return p.PersistRotate
	}
	return p.TempRotate
}
