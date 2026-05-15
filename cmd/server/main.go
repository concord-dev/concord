// concord-server is the multi-tenant HTTP API for Concord. It loads a
// controls library + concord.yaml at startup, connects to Postgres for tenant
// + run persistence, and exposes a REST surface guarded by API tokens.
// Designed to run behind a reverse proxy (Caddy, ALB, Cloudflare) that
// terminates TLS.
//
// Subcommands:
//
//	concord-server                   start the HTTP server (default)
//	concord-server seed-tenant [...] bootstrap first org + owner + API token
//	concord-server version           print build version
//	concord-server help              show usage
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/concord-dev/concord/internal/server"
	"github.com/concord-dev/concord/internal/store"
)

// version is set at build time via -ldflags "-X main.version=<sha>".
var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	var err error
	switch cmd {
	case "", "serve":
		err = runServe(args)
	case "seed-tenant":
		err = runSeedTenant(args)
	case "version", "--version", "-v":
		fmt.Println(version)
		return
	case "help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", cmd)
		printUsage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: concord-server <subcommand> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  (none) | serve   Start the HTTP server (default)")
	fmt.Fprintln(os.Stderr, "  seed-tenant      Bootstrap a tenant: organization + owner user + API token")
	fmt.Fprintln(os.Stderr, "  version          Print build version and exit")
	fmt.Fprintln(os.Stderr, "  help             Show this help and exit")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run `concord-server <subcommand> -h` for subcommand-specific flags.")
}

func runServe(args []string) error {
	var (
		listenAddr   string
		controlsDir  string
		configPath   string
		fixturesOnly bool
		databaseURL  string
		operatorToken string
		skipMigrate  bool
	)
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&listenAddr, "listen", envOr("LISTEN_ADDR", ":8080"), "Listen address (host:port)")
	fs.StringVar(&controlsDir, "controls", envOr("CONCORD_CONTROLS_DIR", "./controls"), "Path to controls directory")
	fs.StringVar(&configPath, "config", envOr("CONCORD_CONFIG", "./concord.yaml"), "Path to concord.yaml")
	fs.BoolVar(&fixturesOnly, "fixtures", true, "Force fixture-only mode (v0 default: true)")
	fs.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"), "Postgres DSN (or set DATABASE_URL)")
	fs.StringVar(&operatorToken, "operator-token", os.Getenv("CONCORD_OPERATOR_TOKEN"), "Operator token for /operator/v1/* (or set CONCORD_OPERATOR_TOKEN)")
	fs.BoolVar(&skipMigrate, "skip-migrate", false, "Don't run schema migrations on startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if databaseURL == "" {
		return fmt.Errorf("DATABASE_URL is required (e.g. postgres://concord:dev@localhost:5432/concord?sslmode=disable)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, databaseURL, store.PoolOptions{
		MaxConns:        20,
		MinConns:        2,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	})
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
		OperatorToken: operatorToken,
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

	if operatorToken == "" {
		fmt.Fprintln(os.Stderr, "warning: CONCORD_OPERATOR_TOKEN not set; /operator/v1/* will refuse every request")
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
		// Stop accepting new HTTP requests first, then drain in-flight jobs.
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintln(os.Stderr, "http shutdown:", err)
		}
		if err := c.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("worker drain: %w", err)
		}
		return nil
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
