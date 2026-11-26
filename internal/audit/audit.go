// Package audit 把认证相关的关键事件追加写进 JSONL 文件。
//
// 只追加、不改写、不轮转：进程崩溃最多丢最后一行，之前的内容仍然可读。
// 每次写都重新打开文件（O_APPEND），这样网关和 CLI 两个进程可以同时写，
// 不会互相覆盖，也不需要在进程间共享文件句柄。
//
// 这里绝不记录凭据、票的原文、动态码——只记 family 短标识、设备名、IP 段和结果。
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const fileMode = 0o600

// 事件名固定成常量，避免拼写漂移导致事后查不到。
const (
	EvLogin      = "login"
	EvLogout     = "logout"
	EvRefresh    = "refresh"
	EvReuse      = "reuse"
	EvRevoke     = "revoke"
	EvGateReject = "gate_reject"
	// EvTunnel 记录隧道打开/关闭/被动断开。
	EvTunnel = "tunnel"
	// EvStale 是旧代数凭据被拒：这是"有人拿着已经被换掉的票"的信号。
	EvStale = "stale"
)

// Event 是一行审计记录。
type Event struct {
	TS     string `json:"ts"`
	Event  string `json:"ev"`
	OK     bool   `json:"ok"`
	Family string `json:"family,omitempty"`
	Device string `json:"device,omitempty"`
	IP     string `json:"ip,omitempty"`
	// Mode 只在登录/会话事件里出现，值域 temp | persist。
	Mode   string `json:"mode,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// Logger 是追加写入器。零值不可用；用 New 构造，New 返回 nil 时调用方按关闭处理。
type Logger struct {
	mu   sync.Mutex
	path string
}

// New 创建写入器。path 为空或 "off" 表示关闭，返回 nil。
func New(path string) *Logger {
	if path == "" || path == "off" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	return &Logger{path: path}
}

// Log 追加一条记录。logger 为 nil（未启用）时是空操作，调用方不必判空。
func (l *Logger) Log(ev Event) {
	if l == nil {
		return
	}
	if ev.TS == "" {
		ev.TS = time.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(ev)
	if err != nil {
		return
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, fileMode)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// ShortFamily 截断 family 标识，审计里只需要能区分是哪一条会话，不需要全串。
func ShortFamily(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
