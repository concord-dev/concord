// concord-server is the v0 multi-tenant HTTP API for Concord. It loads a
// controls library + concord.yaml at startup and exposes a small REST surface
// over them. Designed to run behind a reverse proxy (Caddy, ALB, Cloudflare)
// that terminates TLS and adds auth.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/concord-dev/concord/internal/server"
)

// version is set at build time via -ldflags "-X main.version=<sha>". Defaults
// to "dev" so a plain `go run ./cmd/server` still surfaces a value.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listenAddr   string
		controlsDir  string
		configPath   string
		outputDir    string
		fixturesOnly bool
	)
	flag.StringVar(&listenAddr, "listen", ":8080", "Listen address (host:port)")
	flag.StringVar(&controlsDir, "controls", "./controls", "Path to controls directory")
	flag.StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	flag.StringVar(&outputDir, "output-dir", ".concord", "Where last-run.json is persisted")
	flag.BoolVar(&fixturesOnly, "fixtures", true, "Force fixture-only mode (v0 default: true — live collectors land via env later)")
	flag.Parse()

	c, err := server.NewConcord(server.Options{
		ControlsDir:  controlsDir,
		ConfigPath:   configPath,
		OutputDir:    outputDir,
		FixturesOnly: fixturesOnly,
		Version:      version,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           c.Router(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute, // accommodate /v1/check's 10m budget + headroom
		IdleTimeout:       120 * time.Second,
	}

	fmt.Fprintf(os.Stderr, "concord-server %s listening on %s (%d controls loaded)\n",
		version, listenAddr, len(c.Controls))

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "shutting down…")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
