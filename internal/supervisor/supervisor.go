package supervisor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// State 是 dsh 的生命周期状态。网关对外只暴露这四种。
type State int32

const (
	StateStopped  State = iota // 未运行，可拉起
	StateStarting              // 正在拉起或等待 token
	StateRunning               // 就绪，可转发
	StateFailed                // 上次拉起失败，处于退避窗口
)

func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateFailed:
		return "failed"
	default:
		return "stopped"
	}
}

// ErrStarting 表示 dsh 尚未就绪但拉起正在进行，调用方应返回等待页而不是错误。
var ErrStarting = errors.New("dsh is starting")

// retryBackoff 是拉起失败后的冷却时间，防止每个请求都触发一次 spawn。
const retryBackoff = 5 * time.Second

// Runtime 是已就绪 dsh 的对外契约：内网端口 + 可用于 v1 的 cookie。
type Runtime struct {
	Port        int
	LaunchToken string
	Cookie      string
}

// Status 是网关状态端点的载荷。
type Status struct {
	State     string `json:"state"`
	PID       int    `json:"pid,omitempty"`
	Port      int    `json:"port,omitempty"`
	UptimeSec int64  `json:"uptime_sec,omitempty"`
	IdleSec   int64  `json:"idle_sec"`
	Active    int    `json:"active"`
	LastError string `json:"last_error,omitempty"`
}

// Supervisor 管理 dsh 子进程的生命周期：按需拉起、等待就绪、健康探针、崩溃重建、空闲回收。
// 并发请求共享同一次拉起，拉起本身不随请求取消而中断。
type Supervisor struct {
	cfg  *config.Config
	logf func(format string, args ...any)

	mu     sync.Mutex // 保护 cmd / rt / pid
	cmd    *exec.Cmd
	rt     *Runtime
	pid    int
	exited atomic.Bool

	spawnMu   sync.Mutex    // 保护拉起决策与 spawnDone
	spawnDone chan struct{} // 非 nil 表示有一次拉起正在进行

	tail        *tailBuffer
	state       atomic.Int32
	lastErr     atomic.Value // string
	startedAt   atomic.Int64 // unix ms
	nextRetryAt atomic.Int64 // unix ms
	lastActive  atomic.Int64 // unix ms
}

func NewSupervisor(cfg *config.Config, logf func(string, ...any)) *Supervisor {
	s := &Supervisor{cfg: cfg, logf: logf, tail: newTailBuffer(24)}
	s.lastErr.Store("")
	s.lastActive.Store(time.Now().UnixMilli())
	return s
}

func (s *Supervisor) Touch() {
	s.lastActive.Store(time.Now().UnixMilli())
}

func (s *Supervisor) State() State {
	return State(s.state.Load())
}

// Runtime 返回当前就绪实例的快照；未就绪返回 nil。
func (s *Supervisor) Runtime() *Runtime {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt == nil {
		return nil
	}
	copy := *s.rt
	return &copy
}

func (s *Supervisor) lastError() error {
	msg, _ := s.lastErr.Load().(string)
	if msg == "" {
		return errors.New("dsh unavailable")
	}
	return errors.New(msg)
}

// Ensure 保证 dsh 就绪。返回 ErrStarting 表示正在拉起，调用方应让客户端稍后重试。
func (s *Supervisor) Ensure(ctx context.Context) (*Runtime, error) {
	s.Touch()
	if rt := s.Runtime(); rt != nil {
		return rt, nil
	}

	s.spawnMu.Lock()
	if rt := s.Runtime(); rt != nil {
		s.spawnMu.Unlock()
		return rt, nil
	}

	// 已有一次拉在进行：等它，不重复 spawn。
	if s.State() == StateStarting && s.spawnDone != nil {
		ch := s.spawnDone
		s.spawnMu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return nil, ErrStarting
		}
		if rt := s.Runtime(); rt != nil {
			return rt, nil
		}
		return nil, s.lastError()
	}

	if now := time.Now().UnixMilli(); now < s.nextRetryAt.Load() {
		wait := (s.nextRetryAt.Load() - now + 999) / 1000
		err := fmt.Errorf("%w (retry in %ds)", s.lastError(), wait)
		s.spawnMu.Unlock()
		return nil, err
	}

	s.state.Store(int32(StateStarting))
	s.spawnDone = make(chan struct{})
	ch := s.spawnDone
	s.spawnMu.Unlock()

	go s.runSpawn(ch)

	select {
	case <-ch:
	case <-ctx.Done():
		// 请求超时不终止拉起：进程继续启动，后续请求直接拿结果。
		return nil, ErrStarting
	}
	if rt := s.Runtime(); rt != nil {
		return rt, nil
	}
	return nil, s.lastError()
}

// runSpawn 执行一次完整拉起，并把结果广播给所有等待者。
func (s *Supervisor) runSpawn(done chan struct{}) {
	var (
		rt  *Runtime
		err error
	)
	if s.cfg.DshAttach {
		rt, err = s.attach()
	} else {
		rt, err = s.spawn()
	}

	s.spawnMu.Lock()
	defer s.spawnMu.Unlock()
	defer close(done)

	if err != nil {
		err = s.withTail(err)
		s.state.Store(int32(StateFailed))
		s.lastErr.Store(err.Error())
		s.nextRetryAt.Store(time.Now().Add(retryBackoff).UnixMilli())
		s.spawnDone = nil
		s.logf("[supervisor] start failed: %v", err)
		return
	}
	s.state.Store(int32(StateRunning))
	s.lastErr.Store("")
	s.nextRetryAt.Store(0)
	s.startedAt.Store(time.Now().UnixMilli())
	s.spawnDone = nil
	s.logf("[supervisor] ready on port %d", rt.Port)
}

func (s *Supervisor) spawn() (out *Runtime, rerr error) {
	port := resolveDshPort(s.cfg.DshHost, s.cfg.DshPort)

	args := []string{
		s.cfg.DshBin,
		"--profile=" + s.cfg.DshProfile,
		"--no-open",
		fmt.Sprintf("--host=%s", s.cfg.DshHost),
		fmt.Sprintf("--port=%d", port),
	}
	args = append(args, s.cfg.DshExtraArgs...)
	s.logf("[supervisor] spawn: %s %s", s.cfg.NodeBin, strings.Join(args, " "))

	s.tail.reset()
	cmd := exec.Command(s.cfg.NodeBin, args...)
	cmd.Dir = s.cfg.DshCwd
	cmd.Env = append(envWithout(os.Environ(), "NODE_OPTIONS"), "DSH_HOME="+s.cfg.Home)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start dsh: %w", err)
	}
	// 立刻登记进程句柄：拉起失败或网关退出时，必须能杀掉这个还没就绪的子进程。
	s.exited.Store(false)
	s.mu.Lock()
	s.cmd = cmd
	s.mu.Unlock()
	// 未走到成功分支就退出时，必须回收子进程，避免僵尸与管道泄漏。
	ok := false
	defer func() {
		if !ok {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			s.exited.Store(true)
			s.mu.Lock()
			if s.cmd == cmd {
				s.cmd = nil
			}
			s.mu.Unlock()
		}
	}()

	go pumpLines(stderr, func(line string) {
		redacted := redactToken(line)
		s.tail.add(redacted)
		s.logf("[dsh.err] %s", redacted)
	})

	lines := make(chan string, 128)
	go func() {
		pumpLines(stdout, func(line string) {
			s.logf("[dsh] %s", redactToken(line))
			select {
			case lines <- line:
			default:
			}
		})
		// stdout EOF 说明进程已退出（或即将退出）：必须关闭通道，
		// 否则等待 token 的一方会一直挂到 ready_ms 超时才失败。
		close(lines)
	}()

	type readyMsg struct {
		line string
		err  error
	}
	readyCh := make(chan readyMsg, 1)
	go func() {
		for line := range lines {
			if strings.Contains(line, "dsh web:") && strings.Contains(line, "token=") {
				readyCh <- readyMsg{line: line}
				return
			}
		}
		readyCh <- readyMsg{err: errors.New("dsh exited before printing token")}
	}()

	var got readyMsg
	select {
	case got = <-readyCh:
	case <-time.After(time.Duration(s.cfg.DshReadyMS) * time.Millisecond):
		got = readyMsg{err: fmt.Errorf("token timeout after %dms", s.cfg.DshReadyMS)}
	}
	if got.err != nil {
		return nil, got.err
	}

	token := extractLaunchToken(got.line)
	if token == "" {
		return nil, errors.New("parse launch token failed")
	}
	innerPort := extractURLPort(got.line)
	if innerPort == 0 {
		innerPort = port
	}
	if innerPort == 0 {
		return nil, errors.New("parse inner port failed")
	}

	cookie, err := s.exchangeToken(innerPort, token)
	if err != nil {
		return nil, err
	}
	if !s.probe(innerPort, cookie) {
		s.logf("[supervisor] warning: readiness probe failed; cookie may be rejected until first request")
	}

	rt := &Runtime{Port: innerPort, LaunchToken: token, Cookie: cookie}
	s.exited.Store(false)
	s.mu.Lock()
	s.rt = rt
	s.pid = cmd.Process.Pid
	s.mu.Unlock()

	// 回收退出状态，并清掉随之失效的 cookie。
	go func() {
		_ = cmd.Wait()
		s.exited.Store(true)
		s.mu.Lock()
		if s.cmd == cmd {
			s.cmd = nil
			s.rt = nil
			s.pid = 0
			s.state.Store(int32(StateStopped))
		}
		s.mu.Unlock()
		s.logf("[supervisor] dsh process exited")
	}()

	ok = true
	copy := *rt
	return &copy, nil
}

// attach 模式：不持有 dsh，从文件读外部实例打印的 URL。
func (s *Supervisor) attach() (*Runtime, error) {
	raw, err := os.ReadFile(s.cfg.DshTokenFile)
	if err != nil {
		return nil, fmt.Errorf("attach: read %s: %w", s.cfg.DshTokenFile, err)
	}
	line := ""
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.Contains(l, "token=") {
			line = l
			break
		}
	}
	if line == "" {
		return nil, fmt.Errorf("attach: no token line in %s", s.cfg.DshTokenFile)
	}
	token := extractLaunchToken(line)
	port := extractURLPort(line)
	if token == "" || port == 0 {
		return nil, errors.New("attach: parse token/port failed")
	}
	cookie, err := s.exchangeToken(port, token)
	if err != nil {
		return nil, err
	}
	if !s.probe(port, cookie) {
		s.logf("[supervisor] warning: readiness probe failed for attached dsh")
	}
	rt := &Runtime{Port: port, LaunchToken: token, Cookie: cookie}
	s.mu.Lock()
	s.rt = rt
	s.pid = 0
	s.mu.Unlock()
	return &Runtime{Port: port, LaunchToken: token, Cookie: cookie}, nil
}

// exchangeToken 用启动 token 换 dsh 的 v1 cookie。只认 303 与 Set-Cookie，不跟随重定向。
func (s *Supervisor) exchangeToken(port int, token string) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	url := fmt.Sprintf("http://%s:%d/?token=%s", s.cfg.DshHost, port, token)
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("exchange request: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))

	if resp.StatusCode != http.StatusSeeOther {
		return "", fmt.Errorf("exchange status: %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name != "" && c.Value != "" {
			return c.Name + "=" + c.Value, nil
		}
	}
	return "", errors.New("no set-cookie in exchange")
}

// probe 用拿到的 cookie 打一次首页，确认 cookie 真的被 dsh 接受。
// 失败不阻断启动：不同 profile 的首页行为可能不同，误判会把可用实例判死。
func (s *Supervisor) probe(port int, cookie string) bool {
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:%d/", s.cfg.DshHost, port), nil)
	if err != nil {
		return false
	}
	req.Header.Set("Cookie", cookie)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode < 400
}

// ReapIfIdle 在无活跃请求且空闲超过阈值时终止 dsh。attach 模式不回收（不拥有它）。
//
// 默认关闭（dsh_idle_reap = false）。dsh 可能正在跑定时任务或长任务，而这类活动
// 网关无法可靠观测，自动杀进程的收益（省内存）远小于代价（任务半路中断）。
// 只有显式打开开关、且 dsh_idle_min > 0 时才生效；0 分钟一律视为关闭，
// 不能理解成"0 分钟即立刻回收"。
//
// 即便开关打开，也还要过一道会话活跃检查：页面关了但 agent 仍在跑任务时会话文件
// 在写，这时不杀。该检查只覆盖"正在写盘"，长时间单步工具调用仍可能被误判。
func (s *Supervisor) ReapIfIdle(active int) {
	if !s.cfg.DshIdleReap || s.cfg.DshAttach || active > 0 || s.cfg.DshIdleMin <= 0 {
		return
	}
	if s.State() != StateRunning {
		return
	}
	idle := time.Now().UnixMilli() - s.lastActive.Load()
	if idle < int64(s.cfg.DshIdleMin)*60_000 {
		return
	}
	if s.sessionsBusy(reapSessionWindow) {
		s.logf("[supervisor] idle %dmin but session files still active; skip reap", s.cfg.DshIdleMin)
		s.Touch()
		return
	}

	s.mu.Lock()
	cmd := s.cmd
	s.cmd = nil
	s.rt = nil
	s.pid = 0
	s.mu.Unlock()

	if cmd == nil {
		return
	}
	s.logf("[supervisor] idle %dmin, terminating dsh", s.cfg.DshIdleMin)
	s.killAndWait(cmd)
	s.state.Store(int32(StateStopped))
	s.Touch()
}

func (s *Supervisor) Shutdown() {
	s.mu.Lock()
	cmd := s.cmd
	s.cmd = nil
	s.rt = nil
	s.pid = 0
	s.mu.Unlock()
	s.killAndWait(cmd)
	s.state.Store(int32(StateStopped))
}

// killAndWait 杀掉子进程并等它真的退出。
// 不等的话，调用方紧接着删除工作目录（测试、部署脚本、临时工作区）会被
// 尚未退出的进程占用而失败。
func (s *Supervisor) killAndWait(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	for i := 0; i < 40; i++ {
		if s.exited.Load() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// reapSessionWindow 是"会话仍在写"的判定窗口。比巡检间隔长，避免刚好错过一次写入。
const reapSessionWindow = 5 * time.Minute

// sessionsBusy 判断 dsh 最近是否还在写会话文件。
// 只看 mtime，不解压内容；命中一个就返回，避免遍历整棵目录。
func (s *Supervisor) sessionsBusy(window time.Duration) bool {
	root := filepath.Join(s.cfg.Home, "sessions")
	cutoff := time.Now().Add(-window)
	busy := false
	seen := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if seen++; seen > 20000 { // 兜底：目录异常膨胀时不拖住巡检
			return fs.SkipAll
		}
		if info, err := d.Info(); err == nil && info.ModTime().After(cutoff) {
			busy = true
			return fs.SkipAll
		}
		return nil
	})
	return busy
}

// Status 汇总当前状态，供网关状态端点使用。
func (s *Supervisor) Status(active int) Status {
	s.mu.Lock()
	pid, port := s.pid, 0
	if s.rt != nil {
		port = s.rt.Port
	}
	s.mu.Unlock()

	st := Status{
		State:   s.State().String(),
		PID:     pid,
		Port:    port,
		IdleSec: (time.Now().UnixMilli() - s.lastActive.Load()) / 1000,
		Active:  active,
	}
	if started := s.startedAt.Load(); started > 0 && s.State() == StateRunning {
		st.UptimeSec = (time.Now().UnixMilli() - started) / 1000
	}
	if msg, _ := s.lastErr.Load().(string); msg != "" && s.State() != StateRunning {
		st.LastError = msg
	}
	return st
}

// ---- helpers ----

func envWithout(env []string, key string) []string {
	prefix := key + "="
	out := make([]string, 0, len(env))
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func pumpLines(r io.Reader, fn func(string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fn(sc.Text())
	}
}

// extractLaunchToken 取 `token=` 之后的 URL-safe 连续串。
func extractLaunchToken(line string) string {
	i := strings.Index(line, "token=")
	if i < 0 {
		return ""
	}
	rest := line[i+len("token="):]
	end := 0
	for end < len(rest) {
		c := rest[end]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			end++
			continue
		}
		break
	}
	return rest[:end]
}

// extractURLPort 从行内第一个 http(s):// 的 authority 里取端口。
func extractURLPort(line string) int {
	i := strings.Index(line, "http://")
	if i < 0 {
		i = strings.Index(line, "https://")
	}
	if i < 0 {
		return 0
	}
	rest := line[i:]
	j := strings.Index(rest, "://")
	hostPart := rest[j+3:]
	if k := strings.IndexByte(hostPart, '/'); k >= 0 {
		hostPart = hostPart[:k]
	}
	_, portStr, err := net.SplitHostPort(hostPart)
	if err != nil {
		return 0
	}
	port := 0
	for _, ch := range portStr {
		if ch < '0' || ch > '9' {
			return 0
		}
		port = port*10 + int(ch-'0')
	}
	return port
}

// resolveDshPort 端口被占则退回 0（OS 随机分配），网关从打印的 URL 解析真实端口。
func resolveDshPort(host string, wanted int) int {
	if wanted == 0 {
		return 0
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", host, wanted))
	if err != nil {
		return 0
	}
	_ = ln.Close()
	return wanted
}

// redactToken 把日志里的启动 token 就地抹掉：token 随进程失效，但日志是长期资产。
func redactToken(line string) string {
	const needle = "token="
	var b strings.Builder
	rest := line
	for {
		i := strings.Index(rest, needle)
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		b.WriteString(rest[:i+len(needle)])
		rest = rest[i+len(needle):]
		end := 0
		for end < len(rest) && rest[end] != '&' && rest[end] != ' ' && rest[end] != '\n' && rest[end] != '\r' {
			end++
		}
		if end > 0 {
			b.WriteString("***")
		}
		rest = rest[end:]
	}
}

// tailBuffer 保留子进程 stderr 的最后若干行，拉起失败时附在错误里，
// 让失败页能直接显示根因（例如 EPERM、端口占用、profile 损坏）。
type tailBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newTailBuffer(max int) *tailBuffer {
	return &tailBuffer{max: max}
}

func (t *tailBuffer) add(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, line)
	if len(t.lines) > t.max {
		t.lines = t.lines[len(t.lines)-t.max:]
	}
}

func (t *tailBuffer) reset() {
	t.mu.Lock()
	t.lines = nil
	t.mu.Unlock()
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(strings.Join(t.lines, "\n"))
}

// withTail 把 stderr 尾部挂到错误上，空缓冲时原样返回。
func (s *Supervisor) withTail(err error) error {
	// stderr 由独立 goroutine 转发，进程刚退出时最后几行可能还在管道里。
	// 失败路径多等 50ms，让失败页能显示真正的根因。
	time.Sleep(50 * time.Millisecond)
	tail := s.tail.String()
	if tail == "" {
		return err
	}
	return fmt.Errorf("%w\n--- dsh stderr ---\n%s", err, tail)
}
