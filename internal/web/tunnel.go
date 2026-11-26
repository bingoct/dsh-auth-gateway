package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/audit"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 隧道类型。WS 需要网关自己接管 101（否则拿不到 conn，撤销和空闲检测都无从谈起），
// SSE 是普通流式响应，交给 ReverseProxy，但用 handler 的生命周期当作 tunnel 生命周期。
const (
	tunnelKindWS  = "ws"
	tunnelKindSSE = "sse"
)

// tunnel 是一条已经建立的管道。它不携带任何票面：
// "凭据"就是这条连接本身，所以它只活在内存里，进程重启即全部消失。
type tunnel struct {
	id       uint64
	family   string
	kind     string
	client   net.Conn // 浏览器侧；SSE 为 nil
	upstream net.Conn // dsh 侧；SSE 为 nil
	// cancel 是 SSE 的唯一撤销入口：它的 conn 藏在 ReverseProxy 内部，
	// 我们既拿不到也关不掉，只能取消请求 context 让 handler 自行结束。
	cancel context.CancelFunc
	// wmu 串行化"往浏览器写"这件事：转发线程在写数据帧，
	// 撤销线程要插一个 Close 帧，不互斥就会把帧结构写坏。
	wmu     sync.Mutex
	created time.Time
	lastIO  atomic.Int64 // unix nano，任一方向读到字节就刷新
	once    sync.Once
}

func newTunnel(family, kind string, client, upstream net.Conn, cancel context.CancelFunc) *tunnel {
	t := &tunnel{family: family, kind: kind, client: client, upstream: upstream,
		cancel: cancel, created: time.Now()}
	t.lastIO.Store(time.Now().UnixNano())
	return t
}

// closeCodeRevoked 是自定义关闭码（4000–4999 留给应用），语义对齐 HTTP 401：
// 会话已被撤销，别重连，去重新登录。前端读到它就能区分"被踢"和"网络抖动"。
const closeCodeRevoked = 4401

// Close 幂等关闭。先取消 context（SSE 只能这样断），再给 WS 发 Close 帧，最后关 conn。
func (t *tunnel) Close() {
	t.once.Do(func() {
		if t.cancel != nil {
			t.cancel()
		}
		if t.client != nil {
			if t.kind == tunnelKindWS {
				// 发帧失败不影响关闭：对端可能已经走了。
				_ = t.client.SetWriteDeadline(time.Now().Add(time.Second))
				t.wmu.Lock()
				_ = writeCloseFrame(t.client, closeCodeRevoked, "session revoked")
				t.wmu.Unlock()
			}
			_ = t.client.Close()
		}
		if t.upstream != nil {
			_ = t.upstream.Close()
		}
	})
}

// writeCloseFrame 按 RFC 6455 §5.5.1 编码一个 Close 帧。服务端到客户端不加掩码。
func writeCloseFrame(w io.Writer, code uint16, reason string) error {
	if len(reason) > 123 {
		reason = reason[:123]
	}
	payload := make([]byte, 2+len(reason))
	binary.BigEndian.PutUint16(payload, code)
	copy(payload[2:], reason)

	frame := make([]byte, 0, 2+len(payload))
	frame = append(frame, 0x88) // FIN=1, opcode=0x8(close)
	switch n := len(payload); {
	case n <= 125:
		frame = append(frame, byte(n))
	case n <= 65535:
		frame = append(frame, 126, byte(n>>8), byte(n))
	default:
		return fmt.Errorf("close payload too long: %d", n)
	}
	frame = append(frame, payload...)
	_, err := w.Write(frame)
	return err
}

func (t *tunnel) touch() {
	t.lastIO.Store(time.Now().UnixNano())
}

func (t *tunnel) idleFor(now time.Time) time.Duration {
	return now.Sub(time.Unix(0, t.lastIO.Load()))
}

// tunnelTable 是 family → 连接集合。允许一个 family 有多条（多标签页），
// 不像官方的 API Peer 那样"一凭据一 socket / 409"——那条约束是为可被 HTTP 引用的
// peer 设计的，我们不需要。
type tunnelTable struct {
	mu     sync.Mutex
	nextID uint64
	m      map[string]map[*tunnel]struct{}
}

func newTunnelTable() *tunnelTable {
	return &tunnelTable{m: make(map[string]map[*tunnel]struct{})}
}

func (tt *tunnelTable) add(family, kind string, client, upstream net.Conn, cancel context.CancelFunc) *tunnel {
	t := newTunnel(family, kind, client, upstream, cancel)
	tt.mu.Lock()
	tt.nextID++
	t.id = tt.nextID
	set := tt.m[family]
	if set == nil {
		set = make(map[*tunnel]struct{})
		tt.m[family] = set
	}
	set[t] = struct{}{}
	tt.mu.Unlock()
	return t
}

func (tt *tunnelTable) remove(t *tunnel) {
	tt.mu.Lock()
	if set := tt.m[t.family]; set != nil {
		delete(set, t)
		if len(set) == 0 {
			delete(tt.m, t.family)
		}
	}
	tt.mu.Unlock()
}

// closeFamily 关掉一台设备的所有连接，返回关闭条数。
func (tt *tunnelTable) closeFamily(family string) int {
	tt.mu.Lock()
	set := tt.m[family]
	list := make([]*tunnel, 0, len(set))
	for t := range set {
		list = append(list, t)
	}
	delete(tt.m, family)
	tt.mu.Unlock()
	for _, t := range list {
		t.Close()
	}
	return len(list)
}

func (tt *tunnelTable) closeAll() int {
	tt.mu.Lock()
	all := make([]*tunnel, 0, len(tt.m))
	for _, set := range tt.m {
		for t := range set {
			all = append(all, t)
		}
	}
	tt.m = make(map[string]map[*tunnel]struct{})
	tt.mu.Unlock()
	for _, t := range all {
		t.Close()
	}
	return len(all)
}

// orphanFamilies 返回台账里已经不存在（或已过期）的 family。
func (tt *tunnelTable) orphanFamilies(alive map[string]struct{}) []string {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	var out []string
	for fam := range tt.m {
		// 空 family 是本机 / 认证关闭时的隧道，没有台账可对，不参与撤销对账。
		if fam == "" {
			continue
		}
		if _, ok := alive[fam]; !ok {
			out = append(out, fam)
		}
	}
	return out
}

func (tt *tunnelTable) snapshot() []*tunnel {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	out := make([]*tunnel, 0, len(tt.m))
	for _, set := range tt.m {
		for t := range set {
			out = append(out, t)
		}
	}
	return out
}

func (tt *tunnelTable) count() int {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	n := 0
	for _, set := range tt.m {
		n += len(set)
	}
	return n
}

// ---- WS 接管 ----

// serveWebSocket 自己完成 WS 握手并双向转发原始字节。
//
// 为什么不让 httputil.ReverseProxy 处理：它在内部 Hijack，我们拿不到 conn，
// 于是既不能在撤销时断开，也无法用"读到字节就刷新"判断空死连接。
// 这里不解析帧、不解压，permessage-deflate 原样透传——只管理管道，不管理内容。
func (g *Gateway) serveWebSocket(w http.ResponseWriter, r *http.Request, target, upstreamCookie, family string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "websocket unsupported", http.StatusInternalServerError)
		return
	}

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		g.logf("[tunnel] dial %s: %v", target, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	out := r.Clone(r.Context())
	out.Host = target
	out.URL.Scheme = "http"
	out.URL.Host = target
	out.Header = r.Header.Clone()
	out.Header.Del("Cookie")
	if upstreamCookie != "" {
		out.Header.Set("Cookie", upstreamCookie)
	}
	// 剥离浏览器来源头：dsh 对缺失 Origin 的请求放行，保留反而与改写后的 Host 冲突。
	for _, h := range []string{
		"Origin", "Referer",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User",
	} {
		out.Header.Del(h)
	}
	out.Header.Set("X-Forwarded-Proto", forwardedProto(r, g.cfg.TrustProxy))

	if err := out.Write(upstream); err != nil {
		_ = upstream.Close()
		g.logf("[tunnel] write handshake: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	br := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(br, out)
	if err != nil {
		_ = upstream.Close()
		g.logf("[tunnel] read handshake response: %v", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	client, cbuf, err := hj.Hijack()
	if err != nil {
		_ = resp.Body.Close()
		_ = upstream.Close()
		g.logf("[tunnel] hijack: %v", err)
		return
	}
	defer client.Close()
	defer upstream.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// 上游拒绝升级（403/404 等）：把响应原样回给浏览器，不登记隧道。
		_ = resp.Write(client)
		return
	}

	// 101 必须手写：resp.Write 会把 Body 当作数据继续拷贝，而 101 之后是裸字节流。
	var head strings.Builder
	head.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(&head, "%s: %s\r\n", k, v)
		}
	}
	head.WriteString("\r\n")
	if _, err := client.Write([]byte(head.String())); err != nil {
		return
	}

	t := g.tunnels.add(family, tunnelKindWS, client, upstream, nil)
	defer func() {
		g.tunnels.remove(t)
		g.audit.Log(auditTunnelEvent(family, "closed", tunnelKindWS))
	}()
	g.audit.Log(auditTunnelEvent(family, "open", tunnelKindWS))

	// 客户端可能在握手后立刻发了帧，Hijack 的缓冲里已经有字节，必须一起转发。
	var fromClient io.Reader = client
	if n := cbuf.Reader.Buffered(); n > 0 {
		peeked, _ := cbuf.Reader.Peek(n)
		fromClient = io.MultiReader(bytes.NewReader(peeked), client)
		_, _ = cbuf.Reader.Discard(n)
	}

	done := make(chan struct{}, 2)
	go func() {
		_ = copyTunnel(upstream, fromClient, t, nil)
		done <- struct{}{}
	}()
	go func() {
		// 往浏览器方向与撤销时插入的 Close 帧共用一把锁。
		_ = copyTunnel(client, br, t, &t.wmu)
		done <- struct{}{}
	}()

	// 任一方向结束就关两侧：半开连接保留另一半没有意义，反而占着资源。
	<-done
}

// copyTunnel 单向搬运字节，并在每次读到数据时刷新活跃时间。
// writeMu 非 nil 时串行化写入（浏览器方向，需要与撤销时的 Close 帧互斥）。
// 返回值不用，因为连接错误就是结束信号。
func copyTunnel(dst io.Writer, src io.Reader, t *tunnel, writeMu *sync.Mutex) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			t.touch()
			if writeMu != nil {
				writeMu.Lock()
			}
			_, werr := dst.Write(buf[:n])
			if writeMu != nil {
				writeMu.Unlock()
			}
			if werr != nil {
				return werr
			}
		}
		if err != nil {
			return err
		}
	}
}

func forwardedProto(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
			return v
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// auditTunnelEvent 生成一条隧道事件。只记 family 短标识与动作，不记任何票面。
func auditTunnelEvent(family, action, kind string) audit.Event {
	return audit.Event{Event: audit.EvTunnel, OK: true,
		Family: audit.ShortFamily(family), Detail: action + " " + kind}
}
