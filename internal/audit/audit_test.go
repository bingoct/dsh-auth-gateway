package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogAppendsJSONLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := New(path)

	l.Log(Event{Event: EvLogin, OK: true, Family: "abcd1234", Device: "Edge", IP: "1.2.3.0/24"})
	l.Log(Event{Event: EvLogin, OK: false, Detail: "factor rejected"})
	l.Log(Event{Event: EvReuse, OK: false, Family: "abcd1234", Detail: "family revoked"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d: %q", len(lines), data)
	}
	for i, line := range lines {
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("line %d is not valid json: %v (%s)", i, err, line)
		}
		if ev.TS == "" {
			t.Fatalf("line %d missing timestamp", i)
		}
	}
	var first Event
	_ = json.Unmarshal([]byte(lines[0]), &first)
	if first.Event != EvLogin || !first.OK || first.Family != "abcd1234" {
		t.Fatalf("first line mismatch: %+v", first)
	}
}

// 未启用审计时 logger 是 nil，调用点不必判空——这里锁住"不会 panic"。
func TestNilLoggerIsNoop(t *testing.T) {
	var l *Logger
	l.Log(Event{Event: EvLogin})
	if l := New(""); l != nil {
		t.Fatal(`New("") must return nil (audit disabled)`)
	}
	if l := New("off"); l != nil {
		t.Fatal(`New("off") must return nil (audit disabled)`)
	}
}

// 文件只追加：第二次 New 同一个路径不会清空已有内容。
func TestReopenAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	New(path).Log(Event{Event: EvLogin, OK: true})
	New(path).Log(Event{Event: EvLogout, OK: true})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; n != 2 {
		t.Fatalf("reopening must append, got %d lines", n)
	}
}

func TestShortFamily(t *testing.T) {
	if got := ShortFamily("0123456789abcdef"); got != "01234567" {
		t.Fatalf("ShortFamily = %q", got)
	}
	if got := ShortFamily("abc"); got != "abc" {
		t.Fatalf("ShortFamily short input = %q", got)
	}
}
