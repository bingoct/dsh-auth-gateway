package auth

import (
	"crypto/sha256"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"net"
	"sync"
	"time"
)

// CookieChallenge 是登录表单的一次性挑战因子（与设备票无关，登录前使用）。
const CookieChallenge = "dsh_ch"

// Authenticator 负责口令、TOTP、登录限流，并持有设备票签发器与设备台账。
//
// 它与旧的"双票"实现的分工差别：这里没有 access/refresh 之分，
// 只有一枚自包含设备票（DeviceCookie）+ 一张服务端台账（Ledger）。
// 时效、绑定、撤销、轮换全部集中在 Ledger.Check 一处。
type Authenticator struct {
	cfg    *config.Config
	totp   *TOTPGuard
	device *DeviceCookie
	ledger *Ledger
	policy Policy

	mu    sync.Mutex
	fails map[string]*failState
}

type failState struct {
	count    int
	windowAt time.Time
	bannedAt time.Time
}

func NewAuthenticator(cfg *config.Config) *Authenticator {
	policy := PolicyFromConfig(cfg)
	return &Authenticator{
		cfg:    cfg,
		totp:   NewTOTPGuard(),
		device: NewDeviceCookie(cfg.Credentials.PasswordHash),
		ledger: NewLedger(ledgerPath(cfg), policy),
		policy: policy,
		fails:  make(map[string]*failState),
	}
}

// PolicyFromConfig 把配置换算成时效策略，并对不合法组合做兜底。
//
// 三条防呆是必要的，否则配置写错会静默变成"永不过期"或"永不轮换"：
//   - abs 必须大于 idle，否则没有滑动空间（按 idle 的倍数补齐）
//   - rotate 必须小于 idle，否则等不到触发点（按 idle 的分数回落）
//   - idle 必须为正，0 或负数回落到默认值
func PolicyFromConfig(cfg *config.Config) Policy {
	def := DefaultPolicy()
	p := Policy{
		TempIdle:      time.Duration(cfg.TempHours) * time.Hour,
		TempAbs:       time.Duration(cfg.TempAbsHours) * time.Hour,
		TempRotate:    time.Duration(cfg.RotateTempMin) * time.Minute,
		PersistIdle:   time.Duration(cfg.SessionDays) * 24 * time.Hour,
		PersistAbs:    time.Duration(cfg.SessionAbsMaxDays) * 24 * time.Hour,
		PersistRotate: time.Duration(cfg.RotatePersistHours) * time.Hour,
	}
	if p.TempIdle <= 0 {
		p.TempIdle = def.TempIdle
	}
	if p.TempAbs <= p.TempIdle {
		p.TempAbs = p.TempIdle * 3
	}
	if p.PersistIdle <= 0 {
		p.PersistIdle = def.PersistIdle
	}
	if p.PersistAbs <= p.PersistIdle {
		p.PersistAbs = p.PersistIdle * 2
	}
	if p.TempRotate < 0 {
		p.TempRotate = 0
	}
	if p.PersistRotate < 0 {
		p.PersistRotate = 0
	}
	if p.TempRotate > 0 && p.TempRotate >= p.TempIdle {
		p.TempRotate = p.TempIdle / 4
	}
	if p.PersistRotate > 0 && p.PersistRotate >= p.PersistIdle {
		p.PersistRotate = p.PersistIdle / 8
	}
	return p
}

// ledgerPath 允许测试用空路径退化成纯内存台账。
func ledgerPath(cfg *config.Config) string {
	if cfg.SessionStorePath != "" {
		return cfg.SessionStorePath
	}
	if cfg.Home != "" {
		return cfg.Home + "/sessions.json"
	}
	return ""
}

// Device 暴露设备票签发器。
func (a *Authenticator) Device() *DeviceCookie { return a.device }

// Ledger 暴露设备台账给 web 层与 CLI 做判定、设备管理与撤销。
func (a *Authenticator) Ledger() *Ledger { return a.ledger }

// Policy 返回实际生效的时效策略（配置兜底之后）。
func (a *Authenticator) Policy() Policy { return a.policy }

func (a *Authenticator) CheckPassword(password string) bool {
	return VerifyPassword(password, a.cfg.Credentials.PasswordHash)
}

func (a *Authenticator) VerifyTOTP(code string) error {
	secret, err := Base32Decode(a.cfg.Credentials.TOTPSecretB32)
	if err != nil {
		return err
	}
	return a.totp.verify(secret, code)
}

// NewSession 建一台设备记录并返回待签发的设备票 payload（第一代）。
// 调用方随后用 Device().Mint 把它变成 cookie。
//
// ip 传原始地址，绑定粒度由 BindIP 按 mode 决定（temp 完整地址 / persist 网段）。
func (a *Authenticator) NewSession(ip net.IP, ua string, persist bool) (DevicePayload, error) {
	fam, err := NewFamilyID()
	if err != nil {
		return DevicePayload{}, err
	}
	mode := ModeTemp
	if persist {
		mode = ModePersist
	}
	bind := BindIP(ip, mode)
	now := time.Now().Unix()
	sess := a.ledger.Add(DeviceSession{
		Family: fam, Device: DeviceName(ua), Mode: mode,
		IP: bind, UA: UAHash(ua),
		CreatedAt: now, LastSeen: now,
	})
	return DevicePayload{
		V:    deviceCookieVersion,
		Fam:  fam,
		Mode: mode,
		Iat:  now,
		IP:   bind,
		UA:   UAHash(ua),
		Gen:  sess.Gen,
	}, nil
}

// Check 是每请求的判定入口：台账存在性、绑定、idle/abs、代数。
// rotate=true 表示调用方应用返回记录里的 Gen 重签 cookie 并下发。
//
// ua 传原始 User-Agent：这里负责哈希，台账只存和比对哈希值。
// 让调用方自己哈希是错的多发点——漏一次就会表现成"明明登录了却 401"。
func (a *Authenticator) Check(p DevicePayload, ip net.IP, ua string) (*DeviceSession, bool, error) {
	return a.ledger.Check(p.Fam, p.Gen, ip, UAHash(ua))
}

// AllowLogin 判定该来源当前是否允许尝试登录（窗口内失败超限则封禁）。
func (a *Authenticator) AllowLogin(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.fails[ip]
	if st == nil {
		return true
	}
	now := time.Now()
	if !st.bannedAt.IsZero() {
		if now.Before(st.bannedAt) {
			return false
		}
		// 封禁结束，重新计数
		st.bannedAt = time.Time{}
		st.count = 0
		st.windowAt = now
		return true
	}
	if now.Sub(st.windowAt) > time.Duration(a.cfg.RateWindowMin)*time.Minute {
		st.count = 0
		st.windowAt = now
	}
	return true
}

func (a *Authenticator) RecordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	st := a.fails[ip]
	if st == nil {
		st = &failState{windowAt: now}
		a.fails[ip] = st
	}
	if now.Sub(st.windowAt) > time.Duration(a.cfg.RateWindowMin)*time.Minute {
		st.count = 0
		st.windowAt = now
	}
	st.count++
	if st.count >= a.cfg.RateMaxFails {
		st.bannedAt = now.Add(time.Duration(a.cfg.RateBanMin) * time.Minute)
	}
}

func (a *Authenticator) RecordSuccess(ip string) {
	a.mu.Lock()
	delete(a.fails, ip)
	a.mu.Unlock()
}

func UAHash(ua string) string {
	sum := sha256.Sum256([]byte(ua))
	return B64.EncodeToString(sum[:16])
}
