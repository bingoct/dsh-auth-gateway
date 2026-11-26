package auth

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeClock struct {
	start time.Time
	t     time.Time
}

func newFakeClock() *fakeClock {
	now := time.Now().Truncate(time.Second)
	return &fakeClock{start: now, t: now}
}

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestLedger(t *testing.T, path string) (*Ledger, *fakeClock) {
	t.Helper()
	clk := newFakeClock()
	l := NewLedger(path, DefaultPolicy())
	l.SetClock(clk.now)
	l.SetFlushInterval(0) // 测试里每次都落盘，便于断言文件内容
	return l, clk
}

func genOf(l *Ledger, fam string) uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.sessions[fam]; s != nil {
		return s.Gen
	}
	return 1
}

// checkErr 用当前代数发起一次判定，绝大多数用例不关心代数细节。
func checkErr(l *Ledger, fam, ip, ua string) error {
	_, _, err := l.Check(fam, genOf(l, fam), parseAddr(ip), ua)
	return err
}

// parseAddr 把测试里写的绑定值还原成地址："10.0.0.0/24" → 10.0.0.0。
// 真实调用方传的是 net.IP，测试写成网段形式只是为了可读。
func parseAddr(s string) net.IP {
	if host, _, err := net.ParseCIDR(s); err == nil {
		return host
	}
	return net.ParseIP(s)
}

func addTemp(l *Ledger, fam string) *DeviceSession {
	return l.Add(DeviceSession{
		Family: fam, Device: "test", Mode: ModeTemp,
		// temp 档绑完整地址（BindIP 对 temp 不给掩码），台账里就存单个地址。
		IP: "10.0.0.0", UA: UAHash("agent"),
	})
}

func TestLedgerIdleExpires(t *testing.T) {
	l, clk := newTestLedger(t, "")
	addTemp(l, "fam1")
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != nil {
		t.Fatalf("fresh session must pass: %v", err)
	}
	clk.advance(2*time.Hour - time.Second)
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != nil {
		t.Fatalf("within idle window must pass: %v", err)
	}
	clk.advance(2 * time.Hour)
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != ErrSessionIdle {
		t.Fatalf("idle window exceeded: err=%v, want ErrSessionIdle", err)
	}
	// 过期即删：再查是 unknown，不是 idle
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != ErrSessionUnknown {
		t.Fatalf("expired record must be removed: err=%v", err)
	}
}

func TestLedgerAbsCapsEvenWhenActive(t *testing.T) {
	l, clk := newTestLedger(t, "")
	addTemp(l, "fam1")
	// 每 30 分钟活跃一次，last_seen 一直很新，但 6h 硬顶必须生效。
	for i := 0; i < 11; i++ {
		clk.advance(30 * time.Minute)
		if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != nil {
			t.Fatalf("step %d within abs must pass: %v", i, err)
		}
	}
	clk.advance(30 * time.Minute) // 累计 6h，距上次活跃 30 分钟，idle 未超
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != ErrSessionAbs {
		t.Fatalf("abs must cap even when active: err=%v, want ErrSessionAbs", err)
	}
}

func TestLedgerPersistWindow(t *testing.T) {
	l, clk := newTestLedger(t, "")
	l.Add(DeviceSession{Family: "p1", Mode: ModePersist, IP: "10.0.0.0/24", UA: UAHash("agent")})
	// 每 10 天活跃一次，累计到 30 天：idle 从未超（10d < 14d），只有 abs 能拒绝。
	for i := 0; i < 2; i++ {
		clk.advance(10 * 24 * time.Hour)
		if err := checkErr(l, "p1", "10.0.0.0/24", UAHash("agent")); err != nil {
			t.Fatalf("step %d within abs must pass: %v", i, err)
		}
	}
	clk.advance(10 * 24 * time.Hour) // 累计 30d
	if err := checkErr(l, "p1", "10.0.0.0/24", UAHash("agent")); err != ErrSessionAbs {
		t.Fatalf("30d abs must reject: err=%v, want ErrSessionAbs", err)
	}
}

func TestLedgerBindingMismatch(t *testing.T) {
	l, clk := newTestLedger(t, "")
	addTemp(l, "fam1")
	if err := checkErr(l, "fam1", "10.0.1.0/24", UAHash("agent")); err != ErrSessionBinding {
		t.Fatalf("ip mismatch: err=%v", err)
	}
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("other")); err != ErrSessionBinding {
		t.Fatalf("ua mismatch: err=%v", err)
	}
	// 绑定失败不能刷新 last_seen：否则试探请求会把会话续活。
	sess, ok := l.sessions["fam1"]
	if !ok {
		t.Fatal("binding mismatch must not delete the session")
	}
	if sess.LastSeen != clk.start.Unix() {
		t.Fatalf("binding mismatch must not refresh last_seen: got %d, want %d", sess.LastSeen, clk.start.Unix())
	}
}

func TestLedgerRevoke(t *testing.T) {
	l, _ := newTestLedger(t, "")
	addTemp(l, "fam1")
	if !l.Revoke("fam1") {
		t.Fatal("revoke must hit an existing session")
	}
	if l.Revoke("fam1") {
		t.Fatal("second revoke must report miss")
	}
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != ErrSessionUnknown {
		t.Fatalf("revoked session must be unknown: err=%v", err)
	}
}

func TestLedgerRevokeAll(t *testing.T) {
	l, _ := newTestLedger(t, "")
	addTemp(l, "a")
	addTemp(l, "b")
	if n := l.RevokeAll(); n != 2 {
		t.Fatalf("revoke all = %d, want 2", n)
	}
	if len(l.ActiveFamilies()) != 0 {
		t.Fatal("no family may remain active after revoke all")
	}
}

func TestLedgerActiveFamiliesFiltersExpired(t *testing.T) {
	l, clk := newTestLedger(t, "")
	addTemp(l, "idle")  // 会被 idle 过滤
	addTemp(l, "fresh") // 正常
	clk.advance(2*time.Hour + time.Second)
	addTemp(l, "fresh2")
	// 让 idle 只在 last_seen 上过期：fresh2 刚加，fresh 已经 2h 没动
	active := l.ActiveFamilies()
	if _, ok := active["idle"]; ok {
		t.Fatal("idle family must be filtered out")
	}
	if _, ok := active["fresh"]; ok {
		t.Fatal("family past idle window must be filtered out")
	}
	if _, ok := active["fresh2"]; !ok {
		t.Fatal("fresh family must stay active")
	}
}

func TestLedgerPersistReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	l, _ := newTestLedger(t, path)
	addTemp(l, "fam1")

	// 模拟网关重启：新实例从同一文件恢复。
	l2, _ := newTestLedger(t, path)
	if err := checkErr(l2, "fam1", "10.0.0.0/24", UAHash("agent")); err != nil {
		t.Fatalf("session must survive reload: %v", err)
	}
}

func TestLedgerFlushDoesNotResurrectRevoked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	l, _ := newTestLedger(t, path)
	addTemp(l, "victim")
	addTemp(l, "keeper")

	// 外部（CLI revoke）删掉 victim，同时加一条其他记录
	time.Sleep(10 * time.Millisecond)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version  int              `json:"version"`
		Sessions []*DeviceSession `json:"sessions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	kept := make([]*DeviceSession, 0, len(doc.Sessions))
	for _, s := range doc.Sessions {
		if s.Family != "victim" {
			kept = append(kept, s)
		}
	}
	doc.Sessions = kept
	raw, _ = json.Marshal(doc)
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// 网关再写一次（Add 会触发 writeLocked），victim 不能被写回
	addTemp(l, "newcomer")

	final, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(final, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, s := range doc.Sessions {
		got[s.Family] = true
	}
	if got["victim"] {
		t.Fatal("revoked session must not be resurrected by gateway flush")
	}
	if !got["keeper"] || !got["newcomer"] {
		t.Fatalf("other sessions must survive: %v", got)
	}
}

func TestLedgerFlushKeepsNewerLastSeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	l, clk := newTestLedger(t, path)
	l.SetFlushInterval(time.Hour) // 内存更新先不落盘
	addTemp(l, "fam1")

	clk.advance(100 * time.Second)
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != nil {
		t.Fatal(err)
	}
	want := clk.now().Unix()

	// 外部改动（另一个 family），磁盘上 fam1 的 last_seen 仍是旧值
	time.Sleep(10 * time.Millisecond)
	raw, _ := os.ReadFile(path)
	var doc struct {
		Version  int              `json:"version"`
		Sessions []*DeviceSession `json:"sessions"`
	}
	_ = json.Unmarshal(raw, &doc)
	doc.Sessions = append(doc.Sessions, &DeviceSession{
		Family: "other", Mode: ModePersist, CreatedAt: clk.now().Unix(), LastSeen: clk.now().Unix(),
	})
	raw, _ = json.Marshal(doc)
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	l.Flush()

	final, _ := os.ReadFile(path)
	if err := json.Unmarshal(final, &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range doc.Sessions {
		if s.Family == "fam1" && s.LastSeen != want {
			t.Fatalf("last_seen rolled back: got %d, want %d", s.LastSeen, want)
		}
	}
}

func TestLedgerListOrderAndCurrent(t *testing.T) {
	l, clk := newTestLedger(t, "")
	addTemp(l, "old")
	clk.advance(60 * time.Second)
	addTemp(l, "new")

	list := l.List("new")
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2", len(list))
	}
	if list[0].FamilyID != "new" {
		t.Fatalf("list must be ordered by last seen desc: %+v", list)
	}
	if !list[0].Current {
		t.Fatal("current family must be flagged")
	}
	if list[0].Persist {
		t.Fatal("temp device must not be marked persist")
	}
}

func TestLedgerThrottledFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	l, _ := newTestLedger(t, path)
	l.SetFlushInterval(time.Hour)
	addTemp(l, "fam1")

	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("last_seen update must be throttled, file must not be rewritten")
	}
}

func BenchmarkDeviceCookieVerify(b *testing.B) {
	c := NewDeviceCookie("scrypt$abc$def")
	tok, err := c.Mint(DevicePayload{
		Fam: "FAMILYFAMILYFAMILYFAM", Mode: ModePersist,
		Iat: time.Now().Unix(), IP: "10.0.0.0/24", UA: UAHash("test-agent"),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.Verify(tok); !ok {
			b.Fatal("verify failed")
		}
	}
}

func BenchmarkLedgerCheckMemory(b *testing.B) {
	l := NewLedger("", DefaultPolicy())
	rec := l.Add(DeviceSession{Family: "fam", Mode: ModePersist, IP: "10.0.0.0/24", UA: UAHash("agent")})
	ua, gen := UAHash("agent"), rec.Gen
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := l.Check("fam", gen, parseAddr("10.0.0.0/24"), ua); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLedgerCheckWithFile(b *testing.B) {
	path := filepath.Join(b.TempDir(), "sessions.json")
	l := NewLedger(path, DefaultPolicy())
	l.SetFlushInterval(time.Hour)
	rec := l.Add(DeviceSession{Family: "fam", Mode: ModePersist, IP: "10.0.0.0/24", UA: UAHash("agent")})
	ua, gen := UAHash("agent"), rec.Gen
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := l.Check("fam", gen, parseAddr("10.0.0.0/24"), ua); err != nil {
			b.Fatal(err)
		}
	}
}

// 挂着 WS/SSE 干活时可能几小时不发 HTTP 请求，Touch 让"连接活跃"也算活跃。
func TestLedgerTouchKeepsAlive(t *testing.T) {
	l, clk := newTestLedger(t, "")
	addTemp(l, "fam1")

	// 1h50m 时连接上仍有字节：刷新 last_seen
	clk.advance(110 * time.Minute)
	l.Touch("fam1")

	// 再过 1h50m：距上次 Touch 只有 110 分钟，idle 未超
	clk.advance(110 * time.Minute)
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != nil {
		t.Fatalf("touch must keep session alive past idle: %v", err)
	}

	// 但不做任何 Touch 时，超过 2h 必须失效
	l2, clk2 := newTestLedger(t, "")
	addTemp(l2, "fam2")
	clk2.advance(121 * time.Minute)
	if err := checkErr(l2, "fam2", "10.0.0.0/24", UAHash("agent")); err != ErrSessionIdle {
		t.Fatalf("without touch, idle must expire: %v", err)
	}
}

// Touch 不能复活已撤销或不存在的会话：否则"踢设备"会被一条残留连接抵消。
func TestLedgerTouchDoesNotResurrect(t *testing.T) {
	l, _ := newTestLedger(t, "")
	addTemp(l, "fam1")
	l.Revoke("fam1")
	l.Touch("fam1")
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != ErrSessionUnknown {
		t.Fatalf("touch must not resurrect a revoked session: %v", err)
	}
	l.Touch("never-existed") // 不应 panic
}

// Touch 也不能绕过 abs：连接一直活着，到 6h 仍然必须失效。
func TestLedgerTouchCannotBypassAbs(t *testing.T) {
	l, clk := newTestLedger(t, "")
	addTemp(l, "fam1")
	for i := 0; i < 12; i++ {
		clk.advance(30 * time.Minute)
		l.Touch("fam1")
	}
	// 累计 6h，last_seen 是 30 分钟前，idle 未超，只能由 abs 拒绝
	if err := checkErr(l, "fam1", "10.0.0.0/24", UAHash("agent")); err != ErrSessionAbs {
		t.Fatalf("abs must still cap an active tunnel: %v, want ErrSessionAbs", err)
	}
}

func TestLedgerRotatesAfterPeriod(t *testing.T) {
	l, clk := newTestLedger(t, "")
	rec := addTemp(l, "fam1")
	gen := rec.Gen

	clk.advance(29 * time.Minute)
	_, rotate, err := l.Check("fam1", gen, parseAddr("10.0.0.0/24"), UAHash("agent"))
	if err != nil || rotate {
		t.Fatalf("before period: err=%v rotate=%v, want no rotation", err, rotate)
	}

	clk.advance(2 * time.Minute) // 累计 31 分钟
	sess, rotate, err := l.Check("fam1", gen, parseAddr("10.0.0.0/24"), UAHash("agent"))
	if err != nil {
		t.Fatal(err)
	}
	if !rotate || sess.Gen != gen+1 {
		t.Fatalf("must rotate: rotate=%v gen=%d want %d", rotate, sess.Gen, gen+1)
	}

	// 新票不触发再轮换
	if _, rotate, err = l.Check("fam1", sess.Gen, parseAddr("10.0.0.0/24"), UAHash("agent")); err != nil || rotate {
		t.Fatalf("fresh gen must not rotate again: err=%v rotate=%v", err, rotate)
	}
}

func TestLedgerRotationGraceForConcurrentTabs(t *testing.T) {
	l, clk := newTestLedger(t, "")
	rec := addTemp(l, "fam1")
	gen := rec.Gen

	clk.advance(31 * time.Minute)
	if _, _, err := l.Check("fam1", gen, parseAddr("10.0.0.0/24"), UAHash("agent")); err != nil {
		t.Fatal(err)
	}

	// 同一时刻另一个标签页带旧代数：落在宽限窗口里，应放行并要求换票
	_, rotate, err := l.Check("fam1", gen, parseAddr("10.0.0.0/24"), UAHash("agent"))
	if err != nil {
		t.Fatalf("within grace must pass: %v", err)
	}
	if !rotate {
		t.Fatal("grace hit must ask the caller to reissue the current cookie")
	}

	// 窗口外（这里同时越过了 idle，所以断言"被拒"而不是具体错误码）
	clk.advance(11 * time.Second)
	if _, _, err := l.Check("fam1", gen, parseAddr("10.0.0.0/24"), UAHash("agent")); err == nil {
		t.Fatal("stale generation outside grace must be rejected")
	}
}

// 这条是"轮换到底换来什么"的核心证据：
// 攻击者拿到一枚静态 cookie，用户下一次活跃就把它挤掉。
func TestLeakedCookieDiesAfterOwnerRotation(t *testing.T) {
	l, clk := newTestLedger(t, "")
	rec := addTemp(l, "fam1")

	leaked := rec.Gen // 攻击者手里的代数
	if _, _, err := l.Check("fam1", leaked, parseAddr("10.0.0.0/24"), UAHash("agent")); err != nil {
		t.Fatal(err)
	}

	// 用户继续使用，跨过轮换周期，拿到新票
	clk.advance(31 * time.Minute)
	sess, rotate, err := l.Check("fam1", leaked, parseAddr("10.0.0.0/24"), UAHash("agent"))
	if err != nil || !rotate {
		t.Fatalf("owner request must rotate: err=%v rotate=%v", err, rotate)
	}
	if sess.Gen == leaked {
		t.Fatal("generation must advance")
	}

	// 过了交接窗口，攻击者的旧票彻底作废——不需要用户 revoke，也不需要他察觉
	clk.advance(11 * time.Second)
	if _, _, err := l.Check("fam1", leaked, parseAddr("10.0.0.0/24"), UAHash("agent")); err != ErrSessionStale {
		t.Fatalf("leaked cookie must be dead after rotation: err=%v, want ErrSessionStale", err)
	}

	// 而用户手里的新票仍然可用
	if _, _, err := l.Check("fam1", sess.Gen, parseAddr("10.0.0.0/24"), UAHash("agent")); err != nil {
		t.Fatalf("owner's new cookie must keep working: %v", err)
	}
}

func TestLedgerRotationDoesNotExtendAbs(t *testing.T) {
	l, clk := newTestLedger(t, "")
	rec := addTemp(l, "fam1")
	gen := rec.Gen

	for i := 0; i < 11; i++ { // 11 × 31min = 5h41m，仍在 6h 内
		clk.advance(31 * time.Minute)
		sess, _, err := l.Check("fam1", gen, parseAddr("10.0.0.0/24"), UAHash("agent"))
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		gen = sess.Gen
	}
	clk.advance(20 * time.Minute) // 累计 6h01m，abs 已过
	if _, _, err := l.Check("fam1", gen, parseAddr("10.0.0.0/24"), UAHash("agent")); err != ErrSessionAbs {
		t.Fatalf("rotation must not extend abs: err=%v, want ErrSessionAbs", err)
	}
}

func TestLedgerGenPersistedAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.json")
	l, clk := newTestLedger(t, path)
	rec := addTemp(l, "fam1")
	old := rec.Gen

	clk.advance(31 * time.Minute)
	sess, rotate, err := l.Check("fam1", old, parseAddr("10.0.0.0/24"), UAHash("agent"))
	if err != nil || !rotate {
		t.Fatalf("rotation must happen: err=%v rotate=%v", err, rotate)
	}

	// 重启后从磁盘恢复：代数必须保留，否则旧票会复活
	l2, clk2 := newTestLedger(t, path)
	clk2.advance(time.Unix(sess.GenAt, 0).Sub(clk2.start) + 11*time.Second)
	if _, _, err := l2.Check("fam1", old, parseAddr("10.0.0.0/24"), UAHash("agent")); err != ErrSessionStale {
		t.Fatalf("old generation must stay dead after restart: err=%v", err)
	}
}

func TestLedgerRotationDisabled(t *testing.T) {
	l := NewLedger("", Policy{TempIdle: 2 * time.Hour, TempAbs: 6 * time.Hour, TempRotate: 0})
	clk := newFakeClock()
	l.SetClock(clk.now)
	l.SetFlushInterval(0)
	rec := addTemp(l, "fam1")

	clk.advance(90 * time.Minute)
	if _, rotate, err := l.Check("fam1", rec.Gen, parseAddr("10.0.0.0/24"), UAHash("agent")); err != nil || rotate {
		t.Fatalf("rotate=0 must disable rotation: err=%v rotate=%v", err, rotate)
	}
}

// 别名只影响展示：设置、清除、未知 family 都要给出确定结果。
func TestSetAlias(t *testing.T) {
	l, _ := newTestLedger(t, filepath.Join(t.TempDir(), "s.json"))
	addTemp(l, "famA")

	if !l.SetAlias("famA", "  办公室平板 ") {
		t.Fatal("SetAlias should succeed for a known family")
	}
	views := l.List("")
	if len(views) != 1 || views[0].Alias != "办公室平板" {
		t.Fatalf("alias not stored/trimmed: %+v", views)
	}
	if l.SetAlias("nope", "x") {
		t.Fatal("SetAlias must fail for unknown family")
	}
	if !l.SetAlias("famA", "") {
		t.Fatal("clearing alias should succeed")
	}
	if v := l.List(""); len(v) == 1 && v[0].Alias != "" {
		t.Fatalf("alias should be cleared, got %q", v[0].Alias)
	}
}
