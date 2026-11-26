package cli

import (
	"context"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/bingoct/dsh-auth-gateway/internal/supervisor"
	"github.com/bingoct/dsh-auth-gateway/internal/web"
	"github.com/spf13/cobra"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func runGateway(configPath, publicOrigin string) error {
	cfg, err := config.LoadConfigWithPublicOrigin(configPath, publicOrigin)
	if err != nil {
		return fmt.Errorf("[config] %w", err)
	}
	if err := cfg.Credentials.Validate(); err != nil {
		return fmt.Errorf("[config] %w (run `dsh-auth-proxy init`)", err)
	}

	logf := func(format string, args ...any) { log.Printf(format, args...) }
	authenticator := auth.NewAuthenticator(cfg)
	sup := supervisor.NewSupervisor(cfg, logf)
	gw := web.NewGateway(cfg, authenticator, sup, logf)
	runCtx, stopRun := context.WithCancel(context.Background())
	defer stopRun()
	gw.Start(runCtx)

	logf("[gateway] config=%s listen=%s:%d public_origin=%s dsh=%s profile=%s cwd=%s",
		cfg.ConfigPath, cfg.ListenHost, cfg.ListenPort, cfg.PublicOrigin,
		cfg.DshBin, cfg.DshProfile, cfg.DshCwd)

	stopReaper := make(chan struct{})
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				sup.ReapIfIdle(gw.Active())
			case <-stopReaper:
				return
			}
		}
	}()

	// listen_host 可能是多个地址（逗号分隔），也可能来自网卡名解析。
	// 每个地址各起一个 listener，共用同一个 http.Server——Shutdown 会一并关闭。
	addrs := cfg.ListenAddrs
	if len(addrs) == 0 {
		addrs = []string{cfg.ListenHost}
	}
	var listeners []net.Listener
	for _, h := range addrs {
		hp := net.JoinHostPort(h, fmt.Sprint(cfg.ListenPort))
		ln, err := net.Listen("tcp", hp)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			close(stopReaper)
			return fmt.Errorf("[gateway] listen %s: %w", hp, err)
		}
		listeners = append(listeners, ln)
	}

	srv := &http.Server{
		Handler:           gw,
		ReadHeaderTimeout: 10 * time.Second, // 只限首部，上传与长连接不受影响
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.Default(),
	}

	if !cfg.AuthEnabled {
		logf("[gateway] ⚠ AUTH DISABLED：所有来源免认证直通 dsh，仅限临时体验，公网暴露前必须开回")
	}
	var bound []string
	for _, ln := range listeners {
		bound = append(bound, "http://"+ln.Addr().String())
	}
	logf("[gateway] listening on %s", strings.Join(bound, ", "))

	serveErr := make(chan error, len(listeners))
	for _, ln := range listeners {
		// 每个 listener 各自限流 256 条在途连接，超出在 Accept 处排队而不是把内存吃满。
		limited := newLimitListener(ln, 256)
		go func(l net.Listener) {
			if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
				serveErr <- fmt.Errorf("[gateway] serve: %w", err)
			}
		}(limited)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		logf("[gateway] shutting down")
	case err := <-serveErr:
		close(stopReaper)
		return err
	}

	close(stopReaper)
	stopRun() // 先关隧道，否则 Shutdown 会被长连接拖到超时
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	sup.Shutdown()
	return nil
}

// ---- 连接数上限 ----

type limitListener struct {
	net.Listener
	sem chan struct{}
}

func newLimitListener(ln net.Listener, n int) net.Listener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, n)}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.sem <- struct{}{}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

type limitConn struct {
	net.Conn
	once    bool
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	if !c.once {
		c.once = true
		c.release()
	}
	return err
}

// ---- 命令 ----

func newServeCmd(configPath, publicOrigin *string) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "run the gateway (default when no subcommand is given)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGateway(*configPath, *publicOrigin)
		},
	}
}
