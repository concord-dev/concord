// concord-server is the multi-tenant HTTP API for Concord. It loads a
// controls library + concord.yaml at startup, connects to Postgres for tenant
// + run persistence, and exposes a REST surface guarded by API tokens.
// Designed to run behind a reverse proxy (Caddy, ALB, Cloudflare) that
// terminates TLS.
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
	"github.com/concord-dev/concord/internal/store"
)

// version is set at build time via -ldflags "-X main.version=<sha>".
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
		fixturesOnly bool
		databaseURL  string
		adminToken   string
		skipMigrate  bool
	)
	flag.StringVar(&listenAddr, "listen", envOr("LISTEN_ADDR", ":8080"), "Listen address (host:port)")
	flag.StringVar(&controlsDir, "controls", envOr("CONCORD_CONTROLS_DIR", "./controls"), "Path to controls directory")
	flag.StringVar(&configPath, "config", envOr("CONCORD_CONFIG", "./concord.yaml"), "Path to concord.yaml")
	flag.BoolVar(&fixturesOnly, "fixtures", true, "Force fixture-only mode (v0 default: true)")
	flag.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"), "Postgres DSN (or set DATABASE_URL)")
	flag.StringVar(&adminToken, "admin-token", os.Getenv("CONCORD_ADMIN_TOKEN"), "Admin token for /admin/v1/* (or set CONCORD_ADMIN_TOKEN)")
	flag.BoolVar(&skipMigrate, "skip-migrate", false, "Don't run schema migrations on startup")
	flag.Parse()

	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required (e.g. postgres://concord:dev@localhost:5432/concord?sslmode=disable)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	if !skipMigrate {
		if err := st.Migrate(ctx); err != nil {
			return fmt.Errorf("running migrations: %w", err)
		}
	}

	c, err := server.NewConcord(server.Options{
		ControlsDir:  controlsDir,
		ConfigPath:   configPath,
		FixturesOnly: fixturesOnly,
		Store:        st,
		AdminToken:   adminToken,
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
		WriteTimeout:      11 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	if adminToken == "" {
		fmt.Fprintln(os.Stderr, "warning: CONCORD_ADMIN_TOKEN not set; /admin/v1/* will refuse every request")
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

// envOr returns the named environment variable or a fallback when unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
