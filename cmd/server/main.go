// concord-server is the multi-tenant HTTP API for Concord. Customers'
// agents (the `concord` CLI) run scans on their own infrastructure with
// their own credentials and POST completed findings to this server.
// concord-server never holds customer cloud credentials.
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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/concord-dev/concord/internal/logx"
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
	case "migrate-down":
		err = runMigrateDown(args)
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
	fmt.Fprintln(os.Stderr, "  migrate-down     DEV ONLY: roll back the most-recently-applied migrations")
	fmt.Fprintln(os.Stderr, "  version          Print build version and exit")
	fmt.Fprintln(os.Stderr, "  help             Show this help and exit")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Run `concord-server <subcommand> -h` for subcommand-specific flags.")
}

func runServe(args []string) error {
	var (
		listenAddr    string
		controlsDir   string
		configPath    string
		databaseURL   string
		operatorToken string
		corsOrigins   string
		logFormat     string
		logLevel      string
		skipMigrate   bool
	)
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.StringVar(&listenAddr, "listen", envOr("LISTEN_ADDR", ":8080"), "Listen address (host:port)")
	fs.StringVar(&controlsDir, "controls", envOr("CONCORD_CONTROLS_DIR", "./controls"), "Path to controls directory")
	fs.StringVar(&configPath, "config", envOr("CONCORD_CONFIG", "./concord.yaml"), "Path to concord.yaml")
	fs.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"), "Postgres DSN (or set DATABASE_URL)")
	fs.StringVar(&operatorToken, "operator-token", os.Getenv("CONCORD_OPERATOR_TOKEN"), "Operator token for /operator/v1/* (or set CONCORD_OPERATOR_TOKEN)")
	fs.StringVar(&corsOrigins, "cors-allow-origins", os.Getenv("CONCORD_CORS_ALLOWED_ORIGINS"),
		"Comma-separated exact origins permitted to call the API from a browser (e.g. https://app.example.com). Empty disables CORS.")
	fs.StringVar(&logFormat, "log-format", envOr("CONCORD_LOG_FORMAT", "json"), "Log output format: json|text")
	fs.StringVar(&logLevel, "log-level", envOr("CONCORD_LOG_LEVEL", "info"), "Minimum log level: debug|info|warn|error")
	fs.BoolVar(&skipMigrate, "skip-migrate", false, "Don't run schema migrations on startup")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logx.Init(logFormat, logLevel)

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
		ControlsDir:        controlsDir,
		ConfigPath:         configPath,
		Store:              st,
		OperatorToken:      operatorToken,
		Version:            version,
		CORSAllowedOrigins: splitCSV(corsOrigins),
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
		slog.Warn("operator token not set; /operator/v1/* will refuse every request")
	}
	slog.Info("listening",
		slog.String("version", version),
		slog.String("addr", listenAddr),
		slog.Int("controls", len(c.Controls)),
		slog.String("mode", "agent-push"))

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
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("http shutdown failed", slog.String("err", err.Error()))
		}
		return c.Shutdown(shutdownCtx)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// splitCSV trims and de-empties a comma-separated origin list. We don't use
// strings.Split alone because " ,, foo , " is a likely operator typo and a
// silently-included empty origin would match the special "no Origin header"
// case in some servers, which we want to avoid here.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
