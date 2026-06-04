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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/notify/mail"
	"github.com/concord-dev/concord/internal/otelx"
	"github.com/concord-dev/concord/internal/redisx"
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
	var shutdownTimeoutStr string
	fs.StringVar(&shutdownTimeoutStr, "shutdown-timeout", envOr("CONCORD_SHUTDOWN_TIMEOUT", "30s"),
		"Maximum time to drain HTTP + webhook + email backlog on SIGTERM before forcing exit")
	// OpenTelemetry tracing — disabled when --otel-endpoint is empty.
	// Env names mirror the OTEL_* conventions so a generic operator stack
	// can hand the chart its OTLP endpoint without per-app translation.
	var (
		otelEndpoint    string
		otelProtocol    string
		otelInsecure    bool
		otelSampleRatio float64
	)
	fs.StringVar(&otelEndpoint, "otel-endpoint", envOr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		"OTLP collector endpoint (host:port). Empty disables tracing.")
	fs.StringVar(&otelProtocol, "otel-protocol", envOr("OTEL_EXPORTER_OTLP_PROTOCOL", "http"),
		"OTLP wire format: http (port 4318) or grpc (port 4317)")
	fs.BoolVar(&otelInsecure, "otel-insecure", envOr("OTEL_EXPORTER_OTLP_INSECURE", "true") == "true",
		"Skip TLS on the OTLP collector connection (safe for in-cluster sidecar deploys)")
	fs.Float64Var(&otelSampleRatio, "otel-sample-ratio", parseFloatEnvOr("OTEL_TRACES_SAMPLER_ARG", 1.0),
		"Head-sampling ratio in [0.0, 1.0]")
	// SMTP — leave Host empty for the dev-mode LogMailer (no real
	// delivery, body printed to slog so the developer can still click the
	// reset / invite URL out of the terminal).
	var (
		smtpHost     string
		smtpPortStr  string
		smtpUser     string
		smtpPassword string
		smtpFrom     string
		smtpTLS      string
	)
	fs.StringVar(&smtpHost, "smtp-host", os.Getenv("CONCORD_SMTP_HOST"),
		"SMTP relay hostname (or CONCORD_SMTP_HOST). Empty disables SMTP and falls back to logging.")
	fs.StringVar(&smtpPortStr, "smtp-port", envOr("CONCORD_SMTP_PORT", "587"),
		"SMTP relay port (or CONCORD_SMTP_PORT)")
	fs.StringVar(&smtpUser, "smtp-username", os.Getenv("CONCORD_SMTP_USERNAME"),
		"SMTP PLAIN auth username (or CONCORD_SMTP_USERNAME). Empty disables auth.")
	fs.StringVar(&smtpPassword, "smtp-password", os.Getenv("CONCORD_SMTP_PASSWORD"),
		"SMTP PLAIN auth password (or CONCORD_SMTP_PASSWORD).")
	fs.StringVar(&smtpFrom, "smtp-from", os.Getenv("CONCORD_SMTP_FROM"),
		"From: address used on outbound mail (or CONCORD_SMTP_FROM). e.g. 'Concord <noreply@acme.test>'.")
	fs.StringVar(&smtpTLS, "smtp-tls", envOr("CONCORD_SMTP_TLS", "auto"),
		"SMTP transport encryption: auto|none|starttls|implicit (or CONCORD_SMTP_TLS).")
	// Rate limiter — leave --rate-limiter empty (or "memory") for the
	// in-memory per-pod buckets; set "redis" with --redis-addr (or
	// --redis-sentinel-addrs + --redis-sentinel-master) to share buckets
	// across the fleet. The Lua-scripted Redis impl atomically refills +
	// spends a token per call; on Redis error the FailoverBucket drops to
	// a tightened in-memory bucket so auth keeps responding.
	var (
		rateLimiter           string
		redisMode             string
		redisAddr             string
		redisSentinelMaster   string
		redisSentinelAddrsCSV string
		redisUsername         string
		redisPassword         string
		redisDB               int
		redisTLS              bool
		redisInsecureSkip     bool
		redisServerName       string
		redisDialTimeoutStr   string
		redisReadTimeoutStr   string
		redisWriteTimeoutStr  string
		limiterFallbackRatio  float64
	)
	fs.StringVar(&rateLimiter, "rate-limiter", envOr("CONCORD_RATE_LIMITER", "memory"),
		"Rate limiter backend: memory|redis. Memory is per-pod; redis shares budgets across replicas.")
	fs.StringVar(&redisMode, "redis-mode", envOr("CONCORD_REDIS_MODE", ""),
		"Redis topology: single|sentinel. Inferred from --redis-sentinel-addrs / --redis-addr when empty.")
	fs.StringVar(&redisAddr, "redis-addr", os.Getenv("CONCORD_REDIS_ADDR"),
		"Redis host:port (single mode).")
	fs.StringVar(&redisSentinelMaster, "redis-sentinel-master", os.Getenv("CONCORD_REDIS_SENTINEL_MASTER"),
		"Sentinel master name (sentinel mode).")
	fs.StringVar(&redisSentinelAddrsCSV, "redis-sentinel-addrs", os.Getenv("CONCORD_REDIS_SENTINEL_ADDRS"),
		"Comma-separated Sentinel host:port list (sentinel mode).")
	fs.StringVar(&redisUsername, "redis-username", os.Getenv("CONCORD_REDIS_USERNAME"),
		"Redis AUTH username (Redis 6+ ACL).")
	fs.StringVar(&redisPassword, "redis-password", os.Getenv("CONCORD_REDIS_PASSWORD"),
		"Redis AUTH password.")
	fs.IntVar(&redisDB, "redis-db", 0, "Redis logical DB index (single mode only).")
	fs.BoolVar(&redisTLS, "redis-tls", envOr("CONCORD_REDIS_TLS", "false") == "true",
		"Connect to Redis over TLS.")
	fs.BoolVar(&redisInsecureSkip, "redis-tls-insecure", envOr("CONCORD_REDIS_TLS_INSECURE", "false") == "true",
		"Skip TLS verification (dev only; never enable in production).")
	fs.StringVar(&redisServerName, "redis-tls-servername", os.Getenv("CONCORD_REDIS_TLS_SERVERNAME"),
		"SNI server name for the Redis TLS handshake.")
	fs.StringVar(&redisDialTimeoutStr, "redis-dial-timeout", envOr("CONCORD_REDIS_DIAL_TIMEOUT", "2s"),
		"Redis dial timeout (Go duration).")
	fs.StringVar(&redisReadTimeoutStr, "redis-read-timeout", envOr("CONCORD_REDIS_READ_TIMEOUT", "200ms"),
		"Redis read timeout per command.")
	fs.StringVar(&redisWriteTimeoutStr, "redis-write-timeout", envOr("CONCORD_REDIS_WRITE_TIMEOUT", "200ms"),
		"Redis write timeout per command.")
	fs.Float64Var(&limiterFallbackRatio, "limiter-fallback-ratio", parseFloatEnvOr("CONCORD_LIMITER_FALLBACK_RATIO", 0.33),
		"Per-pod fallback budget as a fraction of the shared Redis budget. 0.33 keeps the fleet-wide ceiling near the configured rate for the canonical 3-replica deploy.")
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

	smtpPort, err := strconv.Atoi(smtpPortStr)
	if err != nil {
		return fmt.Errorf("--smtp-port must be an integer: %w", err)
	}

	// OTel init goes here so the provider exists before NewConcord wires
	// it into the org-handler tracer. A failure to reach the collector
	// must not crash the process — slog the error and fall through with
	// a no-op provider so tracing is best-effort.
	otelCtx, otelCancel := context.WithTimeout(ctx, 5*time.Second)
	tracing, otelErr := otelx.Init(otelCtx, otelx.Config{
		Endpoint:       otelEndpoint,
		Protocol:       otelProtocol,
		Insecure:       otelInsecure,
		SampleRatio:    otelSampleRatio,
		ServiceName:    envOr("OTEL_SERVICE_NAME", "concord-server"),
		ServiceVersion: version,
	})
	otelCancel()
	if otelErr != nil {
		slog.Error("otel init failed; continuing without tracing",
			slog.String("err", otelErr.Error()))
		tracing, _ = otelx.Init(ctx, otelx.Config{}) // safe no-op fallback
	}

	// Redis rate limiter — only built when --rate-limiter=redis. We
	// intentionally fail fast on misconfiguration (unparseable timeouts,
	// missing Sentinel master) so the operator sees the error at startup
	// instead of as a runtime 500 the first time a login arrives.
	rdb, err := openLimiterRedis(ctx, rateLimiter, redisx.Config{
		Mode:               redisx.Mode(redisMode),
		Addr:               redisAddr,
		SentinelMaster:     redisSentinelMaster,
		SentinelAddrs:      redisx.ParseSentinelAddrs(redisSentinelAddrsCSV),
		Username:           redisUsername,
		Password:           redisPassword,
		DB:                 redisDB,
		TLS:                redisTLS,
		ServerName:         redisServerName,
		InsecureSkipVerify: redisInsecureSkip,
		DialTimeout:        mustDuration(redisDialTimeoutStr, "redis-dial-timeout"),
		ReadTimeout:        mustDuration(redisReadTimeoutStr, "redis-read-timeout"),
		WriteTimeout:       mustDuration(redisWriteTimeoutStr, "redis-write-timeout"),
	})
	if err != nil {
		return err
	}
	if rdb != nil {
		defer rdb.Close()
	}

	c, err := server.NewConcord(server.Options{
		ControlsDir:        controlsDir,
		ConfigPath:         configPath,
		Store:              st,
		OperatorToken:      operatorToken,
		Version:            version,
		CORSAllowedOrigins: splitCSV(corsOrigins),
		SMTP: mail.Config{
			Host:     smtpHost,
			Port:     smtpPort,
			Username: smtpUser,
			Password: smtpPassword,
			From:     smtpFrom,
			TLS:      mail.TLSMode(smtpTLS),
		},
		Tracing:                tracing,
		RedisLimiter:           rdb,
		LimiterFallbackTighten: limiterFallbackRatio,
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

	shutdownTimeout, err := time.ParseDuration(shutdownTimeoutStr)
	if err != nil || shutdownTimeout <= 0 {
		return fmt.Errorf("--shutdown-timeout must be a positive Go duration (got %q)", shutdownTimeoutStr)
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		// Drain order:
		//   1. srv.Shutdown — stop accepting new connections, let
		//      in-flight HTTP requests finish.
		//   2. c.Shutdown   — wait for tracked background goroutines
		//      (webhook deliveries, transactional emails) to finish.
		// Both share the same overall budget; if HTTP drain takes the
		// whole window, the background drain returns DeadlineExceeded
		// instantly. That's intentional — a deploy waiting on us is a
		// stronger signal than "give every webhook one more retry".
		slog.Info("shutting down",
			slog.String("timeout", shutdownTimeout.String()))
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		drainStart := time.Now()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Error("http shutdown failed", slog.String("err", err.Error()))
		}
		httpDrain := time.Since(drainStart)
		bgErr := c.Shutdown(shutdownCtx)
		totalDrain := time.Since(drainStart)
		switch {
		case bgErr != nil:
			slog.Error("background drain timed out — some webhooks/emails may not have shipped",
				slog.Duration("http_drain", httpDrain),
				slog.Duration("total", totalDrain),
				slog.String("err", bgErr.Error()))
		default:
			slog.Info("shutdown complete",
				slog.Duration("http_drain", httpDrain),
				slog.Duration("total", totalDrain))
		}
		// OTel last so the "shutdown complete" + any final spans actually
		// reach the collector. Best-effort; an unreachable collector at
		// shutdown is not worth blocking exit on.
		if tracing != nil {
			if err := tracing.Shutdown(shutdownCtx); err != nil {
				slog.Warn("otel shutdown failed (some spans may have been dropped)",
					slog.String("err", err.Error()))
			}
		}
		return bgErr
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// parseFloatEnvOr reads a float64 from the named env var, falling back
// to fallback when unset or malformed. Used for OTEL_TRACES_SAMPLER_ARG
// which OTel publishes as a string; we need to bind it to a float64 flag.
func parseFloatEnvOr(key string, fallback float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

// openLimiterRedis builds the rate-limiter Redis client when --rate-limiter
// is "redis", or returns (nil, nil) when it's anything else. A non-nil
// client is verified with a short Ping before NewConcord wires it; an
// unreachable Redis at startup is treated as a configuration error so the
// pod restarts via k8s instead of silently running on per-pod limits.
func openLimiterRedis(ctx context.Context, mode string, cfg redisx.Config) (*redis.Client, error) {
	switch mode {
	case "", "memory":
		return nil, nil
	case "redis":
		rdb, err := redisx.Open(cfg)
		if err != nil {
			return nil, fmt.Errorf("redis limiter: %w", err)
		}
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := redisx.Ping(pingCtx, rdb); err != nil {
			_ = rdb.Close()
			return nil, fmt.Errorf("redis limiter: unable to reach redis at startup: %w", err)
		}
		slog.Info("rate limiter: redis backend enabled",
			slog.String("mode", string(cfg.Mode)),
			slog.String("addr", cfg.Addr))
		return rdb, nil
	default:
		return nil, fmt.Errorf("unknown --rate-limiter %q (want memory|redis)", mode)
	}
}

// mustDuration parses a Go duration string, panicking with a flag-named
// message on failure. Used for the Redis timeout flags where a bad value
// is a deploy-time configuration mistake — better to crash loudly at
// startup than ship a server that silently uses the zero default.
func mustDuration(s, flag string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(fmt.Sprintf("--%s must be a Go duration (got %q): %v", flag, s, err))
	}
	return d
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
