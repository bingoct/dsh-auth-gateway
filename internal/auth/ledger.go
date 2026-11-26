package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 设备台账的错误分类。调用方据此决定回 401 还是 500。
var (
	ErrSessionUnknown = errors.New("session unknown")
	ErrSessionIdle    = errors.New("session idle beyond idle window")
	ErrSessionAbs     = errors.New("session beyond absolute lifetime")
	ErrSessionBinding = errors.New("session binding mismatch")
	ErrSessionStale   = errors.New("session credential superseded by rotation")
)

const (
	ledgerVersion        = 2
	ledgerFileMode       = 0o600
	defaultFlushInterval = 60 * time.Second
	// rotateGraceSeconds 是轮换交接窗口。同域的多个标签页共享 cookie jar，
	// 但两个标签页同时发请求时都会带旧代数：第一个把代数 +1，第二个就会命中"代数过期"。
	// 窗口内接受上一代并回一枚当前代的 cookie，窗口外才判定为旧票滥用。
	rotateGraceSeconds = 10
)

// DeviceSession 是台账里的一条记录：一台设备一次登录。
// 它不含任何票面（没有 token、没有 hash）——设备票本身是自包含签名的，
// 台账只需要回答"这个 family 还在不在、上次什么时候来"。
type DeviceSession struct {
	Family    string `json:"family"`
	Device    string `json:"device"`
	Mode      string `json:"mode"`
	IP        string `json:"ip"`
	UA        string `json:"ua"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
	// Gen 是当前轮换代数；PrevGen 只在 rotateGraceSeconds 内被接受。
	// 代数每次轮换 +1，旧代数的票随即失效——这让"被动泄露的 cookie"在用户
	// 下一次活跃时自动作废，不需要用户察觉或手动 revoke。
	Gen     uint32 `json:"gen"`
	PrevGen uint32 `json:"prev_gen,omitempty"`
	GenAt   int64  `json:"gen_at"`
	// Alias 是用户起的别名（CLI: alias），只用于展示，不参与判活、绑定或撤销。
	Alias string `json:"alias,omitempty"`
}

// Ledger 是设备台账：单进程内存 map + JSON 文件持久化。
//
// 它同时承担两个职责，这也是有状态设计的意义所在：
//   - 判活：idle（last_seen）+ abs（created_at）
//   - 可撤销：删掉记录，该 family 立刻不能再握手
//
// 写盘策略是"先合并磁盘再写"：CLI 的 revoke 直接改文件，
// 若网关刷 last_seen 时不先读，就会把撤销覆盖回去。
type Ledger struct {
	mu         sync.Mutex
	path       string
	sessions   map[string]*DeviceSession
	policy     Policy
	now        func() time.Time
	lastMod    time.Time
	dirty      bool
	lastFlush  time.Time
	flushEvery time.Duration
}

// NewLedger 创建台账并从 path 恢复。文件损坏时按空表处理（fail-closed：
// 所有设备都要重新登录，而不是放行未知状态）。
func NewLedger(path string, p Policy) *Ledger {
	l := &Ledger{
		path:       path,
		sessions:   make(map[string]*DeviceSession),
		policy:     p,
		now:        time.Now,
		flushEvery: defaultFlushInterval,
	}
	l.mu.Lock()
	l.syncLocked()
	l.mu.Unlock()
	return l
}

// SetClock 替换时钟，仅供测试。
func (l *Ledger) SetClock(fn func() time.Time) {
	l.mu.Lock()
	l.now = fn
	l.mu.Unlock()
}

// SetFlushInterval 调整 last_seen 落盘节流间隔；0 表示每次变更都写。
func (l *Ledger) SetFlushInterval(d time.Duration) {
	l.mu.Lock()
	l.flushEvery = d
	l.mu.Unlock()
}

// Add 登记一次登录，返回新记录。
func (l *Ledger) Add(s DeviceSession) *DeviceSession {
	now := l.now()
	if s.CreatedAt == 0 {
		s.CreatedAt = now.Unix()
	}
	if s.LastSeen == 0 {
		s.LastSeen = now.Unix()
	}
	if s.Mode != ModePersist {
		s.Mode = ModeTemp
	}
	if s.Gen == 0 {
		s.Gen = 1
	}
	if s.GenAt == 0 {
		s.GenAt = now.Unix()
	}
	rec := &s
	l.mu.Lock()
	l.syncLocked()
	l.sessions[rec.Family] = rec
	l.writeLocked()
	l.dirty = false
	l.lastFlush = now
	l.mu.Unlock()
	return rec
}

// Check 是每个请求都要走的判定：
// 存在 → 绑定 → idle → abs → 代数 → 刷新 last_seen。
//
// 返回 rotate=true 表示调用方应当用返回记录里的 Gen 重签 cookie 并下发：
//   - 到了轮换周期（代数刚 +1）
//   - 或者落在交接宽限窗口内（另一个标签页刚换过代，回给它当前代的票）
//
// 它**不读磁盘**：sync 交给后台 Flush（2 秒一次）。实测每请求 os.Stat 要 26µs，
// 比纯内存判断慢 600 倍，而撤销延迟从 0 变成 ≤2 秒是可接受的（本来 reconcile 也是 2 秒）。
//
// 绑定失败与代数失败都不刷新 last_seen：否则攻击者可以靠不断试探把记录续活。
// 过期则删记录（fail-closed），避免"已失效但还留在表里"的假活状态。
//
// ip 传原始地址：绑定粒度按记录自己的 mode 计算（temp 完整地址 / persist 网段），
// 所以同一份台账里两种档位可以并存，不需要在票里额外存粒度。
func (l *Ledger) Check(family string, gen uint32, ip net.IP, ua string) (*DeviceSession, bool, error) {
	if family == "" {
		return nil, false, ErrSessionUnknown
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	s := l.sessions[family]
	if s == nil {
		return nil, false, ErrSessionUnknown
	}
	if want := BindIP(ip, s.Mode); s.IP != "" && want != "" && s.IP != want {
		return nil, false, ErrSessionBinding
	}
	if s.UA != "" && ua != "" && s.UA != ua {
		return nil, false, ErrSessionBinding
	}

	now := l.now()
	// 时钟回拨（或文件被手工改成未来值）会让 idle 判定变成负数而永远通过。
	// 把未来时间夹到现在，宁可多算一次活跃。
	if s.LastSeen > now.Unix() {
		s.LastSeen = now.Unix()
	}
	if now.Unix()-s.LastSeen >= int64(l.policy.Idle(s.Mode).Seconds()) {
		delete(l.sessions, family)
		l.writeLocked()
		l.dirty = false
		l.lastFlush = now
		return nil, false, ErrSessionIdle
	}
	if now.Unix()-s.CreatedAt >= int64(l.policy.Abs(s.Mode).Seconds()) {
		delete(l.sessions, family)
		l.writeLocked()
		l.dirty = false
		l.lastFlush = now
		return nil, false, ErrSessionAbs
	}

	rotate, err := l.checkGenerationLocked(s, gen, now)
	if err != nil {
		return nil, false, err
	}

	s.LastSeen = now.Unix()
	l.dirty = true
	if rotate && s.Gen != gen {
		// 代数变更必须立即落盘：否则进程重启后从磁盘读到旧代数，
		// 攻击者手里那枚"已被作废"的票会重新生效。
		l.writeLocked()
		l.dirty = false
		l.lastFlush = now
	} else {
		l.flushLocked(now)
	}
	return s, rotate, nil
}

// checkGenerationLocked 判定票的代数是否仍然有效，并在到期时推进代数。
//
// 三种情形：
//   - gen == 当前代数：正常；若距上次轮换超过周期，则推进代数并回 rotate=true
//   - gen == 上一代 且 在宽限窗口内：并发交接，接受并回当前代（rotate=true，不改代数）
//   - 其余：已作废，拒绝
func (l *Ledger) checkGenerationLocked(s *DeviceSession, gen uint32, now time.Time) (bool, error) {
	if gen == s.Gen {
		period := l.policy.Rotate(s.Mode)
		if period > 0 && now.Sub(time.Unix(s.GenAt, 0)) >= period {
			s.PrevGen = s.Gen
			s.Gen++
			s.GenAt = now.Unix()
			return true, nil
		}
		return false, nil
	}
	if s.PrevGen != 0 && gen == s.PrevGen && now.Unix()-s.GenAt <= rotateGraceSeconds {
		return true, nil
	}
	return false, ErrSessionStale
}

// Touch 把某台设备的 last_seen 刷新到当前时刻。
//
// 它给隧道用：用户挂着 WS/SSE 干活时可能几小时不发一个 HTTP 请求，
// 只看 Check 的话会话会因为"没有 HTTP 请求"而判定闲置。
// 连接上有字节流动同样是活跃证据。
//
// 它不判活、不删记录：过期的判定只在 Check 里做，避免两条路径出现分歧。
func (l *Ledger) Touch(family string) {
	if family == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.sessions[family]
	if s == nil {
		return
	}
	now := l.now()
	if s.LastSeen >= now.Unix() {
		return
	}
	s.LastSeen = now.Unix()
	l.dirty = true
	l.flushLocked(now)
}

// Revoke 撤销一台设备，返回是否命中。
func (l *Ledger) Revoke(family string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked()
	if _, ok := l.sessions[family]; !ok {
		return false
	}
	delete(l.sessions, family)
	l.writeLocked()
	l.dirty = false
	l.lastFlush = l.now()
	return true
}

// SetAlias 给一台设备起别名（空串表示清除）。只影响展示，不参与判活、绑定或撤销。
func (l *Ledger) SetAlias(family, alias string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked()
	s, ok := l.sessions[family]
	if !ok {
		return false
	}
	s.Alias = strings.TrimSpace(alias)
	l.writeLocked()
	l.dirty = false
	l.lastFlush = l.now()
	return true
}

// RevokeAll 清空台账，返回撤销条数。
func (l *Ledger) RevokeAll() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked()
	n := len(l.sessions)
	l.sessions = make(map[string]*DeviceSession)
	l.writeLocked()
	l.dirty = false
	l.lastFlush = l.now()
	return n
}

// ActiveFamilies 返回当前仍然有效的 family 集合。
// reconcile 用它对比连接表：不在集合里的 tunnel 必须关掉。
func (l *Ledger) ActiveFamilies() map[string]struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked()
	now := l.now()
	out := make(map[string]struct{}, len(l.sessions))
	for fam, s := range l.sessions {
		if now.Unix()-s.LastSeen >= int64(l.policy.Idle(s.Mode).Seconds()) {
			continue
		}
		if now.Unix()-s.CreatedAt >= int64(l.policy.Abs(s.Mode).Seconds()) {
			continue
		}
		out[fam] = struct{}{}
	}
	return out
}

// Flush 把内存里的 last_seen 变化落盘。后台定时调用。
func (l *Ledger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked()
	if !l.dirty {
		return
	}
	l.writeLocked()
	l.dirty = false
	l.lastFlush = l.now()
}

// List 列出当前有效设备，按最近使用倒序。
func (l *Ledger) List(currentFamily string) []DeviceView {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.syncLocked()
	now := l.now()
	out := make([]DeviceView, 0, len(l.sessions))
	for _, s := range l.sessions {
		if now.Unix()-s.LastSeen >= int64(l.policy.Idle(s.Mode).Seconds()) {
			continue
		}
		if now.Unix()-s.CreatedAt >= int64(l.policy.Abs(s.Mode).Seconds()) {
			continue
		}
		out = append(out, DeviceView{
			FamilyID:  s.Family,
			Device:    s.Device,
			Alias:     s.Alias,
			IP:        s.IP,
			CreatedAt: time.Unix(s.CreatedAt, 0),
			LastSeen:  time.Unix(s.LastSeen, 0),
			ExpiresAt: time.Unix(s.CreatedAt, 0).Add(l.policy.Abs(s.Mode)),
			Persist:   s.Mode == ModePersist,
			Current:   s.Family == currentFamily,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// flushLocked 按间隔节流落盘，避免每个请求都写磁盘。
func (l *Ledger) flushLocked(now time.Time) {
	if !l.dirty {
		return
	}
	if l.flushEvery > 0 && now.Sub(l.lastFlush) < l.flushEvery {
		return
	}
	l.writeLocked()
	l.dirty = false
	l.lastFlush = now
}

// syncLocked 合并磁盘改动。规则固定：
//   - 磁盘有、内存没有 → 采用磁盘（外部新增）
//   - 内存有、磁盘没有 → 丢弃（被 CLI 撤销，不能写回）
//   - 两边都有 → 集合以磁盘为准，last_seen 取较大值（内存更新更频繁）
//
// 最后一条是防"网关把 last_seen 刷回旧值"，第一/二条是防"网关把撤销覆盖掉"。
func (l *Ledger) syncLocked() {
	if l.path == "" {
		return
	}
	fi, err := os.Stat(l.path)
	if err != nil {
		if !l.lastMod.IsZero() {
			l.sessions = make(map[string]*DeviceSession)
			l.lastMod = time.Time{}
		}
		return
	}
	if fi.ModTime().Equal(l.lastMod) {
		return
	}
	disk := l.readLocked()
	for fam, ds := range disk {
		if ms, ok := l.sessions[fam]; ok && ms.LastSeen > ds.LastSeen {
			ds.LastSeen = ms.LastSeen
		}
	}
	l.sessions = disk
	l.lastMod = fi.ModTime()
}

func (l *Ledger) readLocked() map[string]*DeviceSession {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return make(map[string]*DeviceSession)
	}
	var doc struct {
		Version  int              `json:"version"`
		Sessions []*DeviceSession `json:"sessions"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return make(map[string]*DeviceSession)
	}
	out := make(map[string]*DeviceSession, len(doc.Sessions))
	now := l.now()
	for _, s := range doc.Sessions {
		if s == nil || s.Family == "" || s.CreatedAt <= 0 {
			continue
		}
		if s.Mode != ModePersist {
			s.Mode = ModeTemp
		}
		if now.Unix()-s.CreatedAt >= int64(l.policy.Abs(s.Mode).Seconds()) {
			continue
		}
		out[s.Family] = s
	}
	return out
}

func (l *Ledger) writeLocked() {
	if l.path == "" {
		return
	}
	sessions := make([]*DeviceSession, 0, len(l.sessions))
	for _, s := range l.sessions {
		sessions = append(sessions, s)
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].CreatedAt < sessions[j].CreatedAt })
	raw, err := json.Marshal(struct {
		Version  int              `json:"version"`
		Sessions []*DeviceSession `json:"sessions"`
	}{Version: ledgerVersion, Sessions: sessions})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, raw, ledgerFileMode); err != nil {
		return
	}
	if err := os.Rename(tmp, l.path); err != nil {
		return
	}
	if fi, err := os.Stat(l.path); err == nil {
		l.lastMod = fi.ModTime()
	}
}

// DeviceView 是给 CLI 展示的设备摘要，不含任何票面或 hash。
type DeviceView struct {
	FamilyID  string
	Device    string
	Alias     string
	IP        string
	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time
	Persist   bool
	Current   bool
}

// DeviceName 从 UA 粗略识别设备，只用于展示，不参与安全判定。
func DeviceName(ua string) string {
	osName := "未知系统"
	switch {
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPad"):
		osName = "iOS"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		osName = "macOS"
	case strings.Contains(ua, "Linux"):
		osName = "Linux"
	}
	browser := "浏览器"
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	if ua == "" {
		return "未知设备"
	}
	return fmt.Sprintf("%s / %s", browser, osName)
}
