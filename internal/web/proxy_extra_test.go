package web

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// 20MB 上传必须完整到达上游，且不能因分块而丢字节。
func TestProxyLargeBodyUpload(t *testing.T) {
	const size = 20 << 20
	payload := bytes.Repeat([]byte("0123456789abcdef"), size/16)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
		}
		fmt.Fprintf(w, "%d:%x", n, h.Sum(nil))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/upload", bytes.NewReader(payload))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	want := fmt.Sprintf("%d:%x", len(payload), sha256.Sum256(payload))
	if string(got) != want {
		t.Fatalf("upstream got %q, want %q", got, want)
	}
}

// 8MB 响应必须完整回到客户端。
func TestProxyLargeBodyDownload(t *testing.T) {
	const size = 8 << 20
	blob := bytes.Repeat([]byte("x"), size)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = w.Write(blob)
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	resp, err := http.Get(front.URL + "/blob")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, resp.Body)
	if n != size {
		t.Fatalf("client got %d bytes, want %d", n, size)
	}
}

// 上游分块输出必须逐块到达客户端，不能被网关攒到最后才发。
func TestProxyStreamsFlush(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("chunk1\n"))
		w.(http.Flusher).Flush()
		time.Sleep(400 * time.Millisecond)
		_, _ = w.Write([]byte("chunk2\n"))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	// 对照：直连上游，判断延迟是上游的 flush 还是网关的缓冲。
	{
		direct, err := http.Get(backend.URL + "/stream")
		if err == nil {
			t0 := time.Now()
			_, _ = bufio.NewReader(direct.Body).ReadString('\n')
			t.Logf("direct upstream first chunk: %v", time.Since(t0))
			direct.Body.Close()
		}
	}

	// 预热：首次请求会走 attach + token 交换 + 就绪探针，那 400ms 不属于流式路径。
	if warm, err := http.Get(front.URL + "/stream"); err == nil {
		_, _ = io.Copy(io.Discard, warm.Body)
		warm.Body.Close()
	}

	start := time.Now()
	resp, err := http.Get(front.URL + "/stream")
	headerAt := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	t.Logf("headers arrived after %v (content-length=%d)", headerAt, resp.ContentLength)

	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	firstAt := time.Since(start)
	if line != "chunk1\n" {
		t.Fatalf("first line = %q", line)
	}
	if firstAt > 300*time.Millisecond {
		t.Fatalf("first chunk arrived after %v, gateway buffered the stream", firstAt)
	}
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "chunk2") {
		t.Fatalf("tail = %q", rest)
	}
}

// 并发 50 路请求全部成功，且只 exchange 一次 token。
func TestProxyConcurrent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := http.Get(fmt.Sprintf("%s/item/%d", front.URL, i))
			if err != nil {
				errs <- err
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 || string(body) != "ok" {
				errs <- fmt.Errorf("req %d: code=%d body=%q", i, resp.StatusCode, body)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

// HEAD 必须保持无 body 且保留上游长度。
func TestProxyHead(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		w.Header().Set("Content-Length", "5")
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("hello"))
		}
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	resp, err := http.Head(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || len(body) != 0 || resp.ContentLength != 5 {
		t.Fatalf("HEAD: code=%d body=%d len=%d", resp.StatusCode, len(body), resp.ContentLength)
	}
}

// 上游在运行期挂掉 → 502，而不是 panic 或挂住。
func TestProxyUpstreamDown(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	// 先确认基线可用，再拆掉上游。
	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	backend.Close()

	down, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer down.Body.Close()
	if down.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream down: code=%d, want 502", down.StatusCode)
	}
}

// cookie 语义：客户端 cookie 被剥掉，只转发网关持有的 dsh cookie。
func TestProxyCookieIsolation(t *testing.T) {
	var seenCookie string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		seenCookie = r.Header.Get("Cookie")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/", nil)
	req.Header.Set("Cookie", "dsh_auth_session=should-not-leak; other=1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if strings.Contains(seenCookie, "should-not-leak") || strings.Contains(seenCookie, "other=1") {
		t.Fatalf("client cookie leaked upstream: %q", seenCookie)
	}
	if !strings.Contains(seenCookie, "dsh-auth-test=ok") {
		t.Fatalf("gateway cookie missing upstream: %q", seenCookie)
	}
}

// 浏览器的 Origin / Sec-Fetch-* 必须在转发前剥掉，交给上游的是裸请求。
func TestProxyStripsBrowserOrigin(t *testing.T) {
	var seenOrigin, seenSite string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "" {
			http.SetCookie(w, &http.Cookie{Name: "dsh-auth-test", Value: "ok", Path: "/"})
			w.WriteHeader(http.StatusSeeOther)
			return
		}
		seenOrigin = r.Header.Get("Origin")
		seenSite = r.Header.Get("Sec-Fetch-Site")
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	gw := testGateway(t, backendPort(t, backend))
	front := httptest.NewServer(gw)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/api/action", strings.NewReader("x=1"))
	req.Header.Set("Origin", "https://dsh.example") // 与 PublicOrigin 同源，能过门禁
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if seenOrigin != "" || seenSite != "" {
		t.Fatalf("browser origin headers leaked upstream: origin=%q site=%q", seenOrigin, seenSite)
	}
}
