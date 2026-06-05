// concord-worker consumes the durable concord.events topic and drives
// outbound webhook delivery with retries and per-attempt forensics in
// webhook_delivery. It is the consumer-side counterpart to
// concord-server's outbox Dispatcher (Phase 2).
//
// Two long-running goroutines per pod:
//
//   - Consumer reads the Kafka topic via a consumer group, dedupes
//     event_ids via Redis (24h TTL), and drives the first delivery
//     attempt for every matching webhook.
//
//   - Retrier polls webhook_delivery for status='failed' rows whose
//     backoff has elapsed and re-runs the Executor. SELECT FOR UPDATE
//     SKIP LOCKED lets multiple worker replicas cooperate.
//
// Crash safety: the consumer commits Kafka offsets only AFTER all
// delivery rows for a message are persisted. A crash mid-batch
// reprocesses the message; the dedupe + UNIQUE (webhook_id, event_id)
// guarantees idempotency.
//
// Subcommands:
//
//	concord-worker            start the worker (default)
//	concord-worker version    print build version
//	concord-worker help       show usage
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker"

	"github.com/concord-dev/concord/internal/kafkax"
	"github.com/concord-dev/concord/internal/logx"
	"github.com/concord-dev/concord/internal/otelx"
	"github.com/concord-dev/concord/internal/redisx"
	"github.com/concord-dev/concord/internal/store"
	"github.com/concord-dev/concord/internal/worker"
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
	fmt.Fprintln(os.Stderr, "Usage: concord-worker <subcommand> [flags]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Subcommands:")
	fmt.Fprintln(os.Stderr, "  (none) | serve   Run the Kafka consumer + retrier (default)")
	fmt.Fprintln(os.Stderr, "  version          Print build version and exit")
	fmt.Fprintln(os.Stderr, "  help             Show this help and exit")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Required env / flags:")
	fmt.Fprintln(os.Stderr, "  DATABASE_URL         Postgres DSN (or --database-url)")
	fmt.Fprintln(os.Stderr, "  --kafka-brokers      Comma-separated bootstrap brokers")
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)

	var (
		listenAddr    string
		databaseURL   string
		logFormat     string
		logLevel      string
		shutdownStr   string
		consumerGroup string
		topic         string
	)
	fs.StringVar(&listenAddr, "listen", envOr("LISTEN_ADDR", ":9090"),
		"HTTP bind address for /healthz + /metrics")
	fs.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"),
		"Postgres DSN (or set DATABASE_URL)")
	fs.StringVar(&logFormat, "log-format", envOr("CONCORD_LOG_FORMAT", "json"),
		"Log output format: json|text")
	fs.StringVar(&logLevel, "log-level", envOr("CONCORD_LOG_LEVEL", "info"),
		"Minimum log level: debug|info|warn|error")
	fs.StringVar(&shutdownStr, "shutdown-timeout", envOr("CONCORD_SHUTDOWN_TIMEOUT", "30s"),
		"Maximum time to drain HTTP + worker goroutines on SIGTERM")
	fs.StringVar(&consumerGroup, "kafka-group", envOr("CONCORD_KAFKA_GROUP", "concord-worker"),
		"Kafka consumer group ID (all worker replicas must share this).")
	fs.StringVar(&topic, "kafka-topic", envOr("CONCORD_KAFKA_TOPIC", "concord.events"),
		"Topic to consume from.")

	// Kafka transport config — mirrors cmd/server flags so a deploy
	// passes the same env vars to both binaries.
	var (
		kafkaBrokersCSV    string
		kafkaClientID      string
		kafkaTLS           bool
		kafkaTLSInsecure   bool
		kafkaTLSServerName string
		kafkaSASLMech      string
		kafkaSASLUsername  string
		kafkaSASLPassword  string
		kafkaMaxWaitStr    string
	)
	fs.StringVar(&kafkaBrokersCSV, "kafka-brokers", os.Getenv("CONCORD_KAFKA_BROKERS"),
		"Comma-separated Kafka bootstrap brokers (host:port).")
	fs.StringVar(&kafkaClientID, "kafka-client-id", envOr("CONCORD_KAFKA_CLIENT_ID", "concord-worker"),
		"Kafka client ID for broker-side telemetry.")
	fs.BoolVar(&kafkaTLS, "kafka-tls", envOr("CONCORD_KAFKA_TLS", "false") == "true",
		"Connect to Kafka over TLS.")
	fs.BoolVar(&kafkaTLSInsecure, "kafka-tls-insecure", envOr("CONCORD_KAFKA_TLS_INSECURE", "false") == "true",
		"Skip Kafka TLS verification (dev only).")
	fs.StringVar(&kafkaTLSServerName, "kafka-tls-servername", os.Getenv("CONCORD_KAFKA_TLS_SERVERNAME"),
		"SNI for the Kafka TLS handshake.")
	fs.StringVar(&kafkaSASLMech, "kafka-sasl-mechanism", envOr("CONCORD_KAFKA_SASL_MECHANISM", ""),
		"plain|scram-sha-256|scram-sha-512.")
	fs.StringVar(&kafkaSASLUsername, "kafka-sasl-username", os.Getenv("CONCORD_KAFKA_SASL_USERNAME"), "")
	fs.StringVar(&kafkaSASLPassword, "kafka-sasl-password", os.Getenv("CONCORD_KAFKA_SASL_PASSWORD"), "")
	fs.StringVar(&kafkaMaxWaitStr, "kafka-max-wait", envOr("CONCORD_KAFKA_MAX_WAIT", "1s"),
		"How long the consumer blocks waiting for new messages (Go duration).")

	// Redis dedupe — optional. When unset the worker falls back to
	// DB-side dedupe via the UNIQUE constraint.
	var (
		dedupeRedis        string
		dedupeRedisMode    string
		dedupeRedisMaster  string
		dedupeRedisAddrCSV string
		dedupeRedisUser    string
		dedupeRedisPass    string
		dedupeTTLStr       string
	)
	fs.StringVar(&dedupeRedis, "dedupe-redis", envOr("CONCORD_DEDUPE_REDIS", ""),
		"Redis backend for dedupe: redis|''. Empty disables the dedupe (DB UNIQUE still protects us).")
	fs.StringVar(&dedupeRedisMode, "dedupe-redis-mode", envOr("CONCORD_DEDUPE_REDIS_MODE", ""),
		"single|sentinel (inferred when empty).")
	fs.StringVar(&dedupeRedisAddrCSV, "dedupe-redis-addr", os.Getenv("CONCORD_DEDUPE_REDIS_ADDR"),
		"host:port (single) or sentinel master addr.")
	fs.StringVar(&dedupeRedisMaster, "dedupe-redis-sentinel-master", os.Getenv("CONCORD_DEDUPE_REDIS_SENTINEL_MASTER"),
		"Sentinel master name (sentinel mode).")
	fs.StringVar(&dedupeRedisUser, "dedupe-redis-username", os.Getenv("CONCORD_DEDUPE_REDIS_USERNAME"), "")
	fs.StringVar(&dedupeRedisPass, "dedupe-redis-password", os.Getenv("CONCORD_DEDUPE_REDIS_PASSWORD"), "")
	fs.StringVar(&dedupeTTLStr, "dedupe-ttl", envOr("CONCORD_DEDUPE_TTL", "24h"),
		"Lifetime of the dedupe Redis key.")

	// Executor / Retrier knobs.
	var (
		maxAttempts     int
		backoffBaseStr  string
		backoffMaxStr   string
		retrierPollStr  string
		retrierBatch    int
		breakerMaxFails int
		breakerHalfOpen int
		breakerOpenStr  string
	)
	fs.IntVar(&maxAttempts, "max-attempts", parseIntEnvOr("CONCORD_WORKER_MAX_ATTEMPTS", 5),
		"Per-row retry cap before status='dead'.")
	fs.StringVar(&backoffBaseStr, "backoff-base", envOr("CONCORD_WORKER_BACKOFF_BASE", "1s"),
		"Minimum backoff between attempts.")
	fs.StringVar(&backoffMaxStr, "backoff-max", envOr("CONCORD_WORKER_BACKOFF_MAX", "60s"),
		"Maximum backoff between attempts.")
	fs.StringVar(&retrierPollStr, "retrier-poll-interval", envOr("CONCORD_WORKER_RETRIER_POLL", "1s"),
		"How often the retrier polls when previously idle.")
	fs.IntVar(&retrierBatch, "retrier-batch-size", parseIntEnvOr("CONCORD_WORKER_RETRIER_BATCH", 25),
		"Maximum rows the retrier claims per tick.")
	fs.IntVar(&breakerMaxFails, "breaker-max-fails", parseIntEnvOr("CONCORD_WORKER_BREAKER_MAX_FAILS", 5),
		"Consecutive failures per receiver-host before its circuit breaker opens.")
	fs.IntVar(&breakerHalfOpen, "breaker-half-open-max", parseIntEnvOr("CONCORD_WORKER_BREAKER_HALF_OPEN_MAX", 1),
		"In-flight half-open probes allowed when a breaker tests recovery.")
	fs.StringVar(&breakerOpenStr, "breaker-open-timeout", envOr("CONCORD_WORKER_BREAKER_OPEN_TIMEOUT", "30s"),
		"How long a tripped breaker stays open before allowing a half-open probe.")

	// OpenTelemetry — same toggles as cmd/server so an OTel collector
	// sees both binaries' spans.
	var (
		otelEndpoint string
		otelProtocol string
		otelInsecure bool
		otelSample   float64
	)
	fs.StringVar(&otelEndpoint, "otel-endpoint", envOr("OTEL_EXPORTER_OTLP_ENDPOINT", ""), "OTLP endpoint.")
	fs.StringVar(&otelProtocol, "otel-protocol", envOr("OTEL_EXPORTER_OTLP_PROTOCOL", "http"), "http|grpc")
	fs.BoolVar(&otelInsecure, "otel-insecure", envOr("OTEL_EXPORTER_OTLP_INSECURE", "true") == "true",
		"Skip TLS on OTLP connection.")
	fs.Float64Var(&otelSample, "otel-sample-ratio", parseFloatEnvOr("OTEL_TRACES_SAMPLER_ARG", 1.0), "0..1")

	if err := fs.Parse(args); err != nil {
		return err
	}

	logx.Init(logFormat, logLevel)

	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	if kafkaBrokersCSV == "" {
		return errors.New("--kafka-brokers / CONCORD_KAFKA_BROKERS is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Store — shared by Consumer (UpsertDelivery, ListEnabledWebhooks)
	// and Retrier (ClaimPendingDeliveries).
	st, err := store.Open(ctx, databaseURL, store.PoolOptions{
		MaxConns:        16,
		MinConns:        2,
		MaxConnLifetime: 30 * time.Minute,
		MaxConnIdleTime: 5 * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	// OTel — fails open. If the collector is unreachable at startup we
	// log + continue with a no-op provider so a missing OTel doesn't
	// keep the worker from processing events.
	otelCtx, otelCancel := context.WithTimeout(ctx, 5*time.Second)
	tracing, otelErr := otelx.Init(otelCtx, otelx.Config{
		Endpoint:       otelEndpoint,
		Protocol:       otelProtocol,
		Insecure:       otelInsecure,
		SampleRatio:    otelSample,
		ServiceName:    envOr("OTEL_SERVICE_NAME", "concord-worker"),
		ServiceVersion: version,
	})
	otelCancel()
	if otelErr != nil {
		slog.Error("otel init failed; continuing without tracing", slog.String("err", otelErr.Error()))
		tracing, _ = otelx.Init(ctx, otelx.Config{})
	}

	// Redis dedupe — optional. Fail-fast on unreachable Redis at
	// startup so misconfiguration surfaces immediately.
	var rdb *redis.Client
	if dedupeRedis == "redis" {
		// One CSV flag covers both topologies: a single "host:port" is
		// single-mode; a comma-separated list with a SentinelMaster is
		// sentinel-mode. Branch on the master being set so the address
		// list goes to the right Config field.
		cfg := redisx.Config{
			Mode:               redisx.Mode(dedupeRedisMode),
			Username:           dedupeRedisUser,
			Password:           dedupeRedisPass,
			DialTimeout:        2 * time.Second,
			ReadTimeout:        200 * time.Millisecond,
			WriteTimeout:       200 * time.Millisecond,
		}
		if dedupeRedisMaster != "" {
			cfg.SentinelMaster = dedupeRedisMaster
			cfg.SentinelAddrs = redisx.ParseSentinelAddrs(dedupeRedisAddrCSV)
		} else {
			cfg.Addr = dedupeRedisAddrCSV
		}
		rdb, err = redisx.Open(cfg)
		if err != nil {
			return fmt.Errorf("dedupe redis: %w", err)
		}
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := redisx.Ping(pingCtx, rdb)
		cancel()
		if err != nil {
			_ = rdb.Close()
			return fmt.Errorf("dedupe redis unreachable: %w", err)
		}
		defer rdb.Close()
		slog.Info("dedupe redis enabled", slog.String("mode", dedupeRedisMode))
	}

	// Metrics — private registry + /metrics HTTP handler.
	m := newMetrics()
	executor, err := worker.NewExecutor(st, worker.ExecutorConfig{
		MaxAttempts: maxAttempts,
		BackoffBase: mustDuration(backoffBaseStr, "backoff-base"),
		BackoffMax:  mustDuration(backoffMaxStr, "backoff-max"),
		UserAgent:   "concord-worker/" + version,
	}, m.executorMetrics())
	if err != nil {
		return err
	}
	// Wire per-host circuit breakers in front of every outbound POST.
	// Trips after 5 consecutive failures, 30s open, then 1 half-open
	// probe. State is per-pod in-memory — load-shedding, not a
	// correctness guarantee.
	executor.SetBreakers(worker.NewBreakers(worker.BreakerConfig{
		MaxConsecutiveFails: uint32(breakerMaxFails),
		OpenTimeout:         mustDuration(breakerOpenStr, "breaker-open-timeout"),
		HalfOpenMaxRequests: uint32(breakerHalfOpen),
		OnStateChange:       m.onBreakerStateChange,
	}))

	consumer, err := worker.NewConsumer(st, rdb, executor, worker.ConsumerConfig{
		Brokers:   kafkax.ParseBrokers(kafkaBrokersCSV),
		Topic:     topic,
		GroupID:   consumerGroup,
		MaxWait:   mustDuration(kafkaMaxWaitStr, "kafka-max-wait"),
		DedupeTTL: mustDuration(dedupeTTLStr, "dedupe-ttl"),
	}, m.consumerMetrics())
	if err != nil {
		return err
	}

	retrier, err := worker.NewRetrier(st, executor, worker.RetrierConfig{
		PollInterval: mustDuration(retrierPollStr, "retrier-poll-interval"),
		BatchSize:    retrierBatch,
	}, m.retrierMetrics())
	if err != nil {
		return err
	}

	// Verify Kafka reachability before starting the consumer; same
	// fail-fast philosophy as cmd/server.
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := kafkax.Ping(pingCtx, kafkax.Config{
		Brokers:            kafkax.ParseBrokers(kafkaBrokersCSV),
		Topic:              topic,
		ClientID:           kafkaClientID,
		TLS:                kafkaTLS,
		ServerName:         kafkaTLSServerName,
		InsecureSkipVerify: kafkaTLSInsecure,
		SASLMechanism:      kafkax.SASLMechanism(kafkaSASLMech),
		SASLUsername:       kafkaSASLUsername,
		SASLPassword:       kafkaSASLPassword,
	}); err != nil {
		pingCancel()
		return fmt.Errorf("kafka unreachable: %w", err)
	}
	pingCancel()

	// HTTP surface for /healthz + /readyz + /metrics. The worker
	// doesn't terminate user-facing HTTP, but liveness/readiness probes
	// + metrics scraping make it a first-class k8s citizen.
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		// Ready iff DB + Kafka reachable. Both checks short-timeout
		// so the readiness probe doesn't pile up goroutines on a
		// failing dep.
		dbCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := st.Pool().Ping(dbCtx); err != nil {
			http.Error(w, "database unreachable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		kCtx, kcancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer kcancel()
		if err := kafkax.Ping(kCtx, kafkax.Config{
			Brokers: kafkax.ParseBrokers(kafkaBrokersCSV),
		}); err != nil {
			http.Error(w, "kafka unreachable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	httpSrv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		slog.Info("concord-worker: HTTP listening",
			slog.String("addr", listenAddr),
			slog.String("version", version))
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server failed", slog.String("err", err.Error()))
		}
	}()

	// Worker goroutines. Run on the parent ctx so SIGTERM cancels both
	// at once.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); consumer.Run(ctx) }()
	go func() { defer wg.Done(); retrier.Run(ctx) }()

	slog.Info("concord-worker: running",
		slog.String("topic", topic),
		slog.String("group", consumerGroup))

	<-ctx.Done()

	shutdownTimeout, err := time.ParseDuration(shutdownStr)
	if err != nil || shutdownTimeout <= 0 {
		shutdownTimeout = 30 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	slog.Info("concord-worker: shutting down", slog.Duration("timeout", shutdownTimeout))

	// Stop accepting new HTTP first so readiness flips to NotReady;
	// then wait for the consumer + retrier goroutines.
	_ = httpSrv.Shutdown(shutdownCtx)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		slog.Info("concord-worker: shutdown complete")
	case <-shutdownCtx.Done():
		slog.Warn("concord-worker: shutdown timeout — some in-flight work may be lost")
	}

	if tracing != nil {
		_ = tracing.Shutdown(shutdownCtx)
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

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

func parseIntEnvOr(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return parsed
}

func mustDuration(s, flag string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		panic(fmt.Sprintf("--%s must be a Go duration (got %q): %v", flag, s, err))
	}
	return d
}

// metrics is the worker's private Prometheus registry + collectors.
// Kept inside cmd/concord-worker (rather than internal/server/metrics)
// because the worker is a separate binary; sharing collectors would
// force one process to import the other's metric definitions.
type metrics struct {
	reg *prometheus.Registry

	// Consumer
	consumed    *prometheus.CounterVec
	dedupeHits  *prometheus.CounterVec
	badMessages *prometheus.CounterVec
	noWebhooks  *prometheus.CounterVec
	fanoutSize  *prometheus.HistogramVec
	commitErrs  prometheus.Counter

	// Executor
	attemptStarted  *prometheus.CounterVec
	attemptOutcome  *prometheus.CounterVec
	attemptDuration prometheus.Histogram
	dead            *prometheus.CounterVec

	// Retrier
	retrierTicks      prometheus.Counter
	retrierClaimed    prometheus.Counter
	retrierTickErrors prometheus.Counter

	// Breaker
	breakerStateChanges *prometheus.CounterVec
}

func newMetrics() *metrics {
	reg := prometheus.NewRegistry()
	m := &metrics{
		reg: reg,
		consumed: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_consumed_total",
			Help: "Kafka messages the worker successfully consumed and dispatched, by event kind.",
		}, []string{"kind"}),
		dedupeHits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_dedupe_hits_total",
			Help: "Messages the Redis dedupe skipped because the event_id was already seen.",
		}, []string{"kind"}),
		badMessages: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_bad_messages_total",
			Help: "Malformed Kafka messages the worker committed without processing (poison-pill defence). Labels: reason.",
		}, []string{"reason"}),
		noWebhooks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_no_webhooks_total",
			Help: "Events that matched no enabled webhook for their org, by event kind.",
		}, []string{"kind"}),
		fanoutSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "concord_worker_fanout_size",
			Help:    "Number of webhook deliveries each event triggered.",
			Buckets: []float64{0, 1, 2, 5, 10, 25, 100},
		}, []string{"kind"}),
		commitErrs: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_worker_commit_errors_total",
			Help: "Kafka offset commit failures (offset will be re-delivered).",
		}),
		attemptStarted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_attempts_started_total",
			Help: "Webhook delivery attempts the Executor has started, by kind + retry (true/false).",
		}, []string{"kind", "retry"}),
		attemptOutcome: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_attempts_total",
			Help: "Webhook delivery attempts the Executor completed, by kind + outcome (succeeded|non_2xx|network_error).",
		}, []string{"kind", "outcome"}),
		attemptDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "concord_worker_attempt_duration_seconds",
			Help:    "HTTP exchange wall-time for a single webhook delivery attempt.",
			Buckets: prometheus.DefBuckets,
		}),
		dead: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_dead_total",
			Help: "Deliveries that hit max-attempts and were left as dead-letters for operator inspection, by kind.",
		}, []string{"kind"}),
		retrierTicks: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_worker_retrier_ticks_total",
			Help: "Retrier loop iterations.",
		}),
		retrierClaimed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_worker_retrier_claimed_total",
			Help: "Failed-delivery rows the retrier has picked up since process start.",
		}),
		retrierTickErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_worker_retrier_tick_errors_total",
			Help: "Retrier ticks that errored (DB or executor).",
		}),
		breakerStateChanges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_worker_breaker_state_changes_total",
			Help: "Per-receiver-host circuit breaker transitions, partitioned by new state (closed|open|half-open).",
		}, []string{"state"}),
	}
	reg.MustRegister(
		m.consumed, m.dedupeHits, m.badMessages, m.noWebhooks, m.fanoutSize, m.commitErrs,
		m.attemptStarted, m.attemptOutcome, m.attemptDuration, m.dead,
		m.retrierTicks, m.retrierClaimed, m.retrierTickErrors,
		m.breakerStateChanges,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

func (m *metrics) handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

func (m *metrics) consumerMetrics() worker.ConsumerMetrics {
	return worker.ConsumerMetrics{
		Consumed:    func(k string) { m.consumed.WithLabelValues(k).Inc() },
		DedupeHit:   func(k string) { m.dedupeHits.WithLabelValues(k).Inc() },
		BadMessage:  func(r string) { m.badMessages.WithLabelValues(r).Inc() },
		NoWebhooks:  func(k string) { m.noWebhooks.WithLabelValues(k).Inc() },
		FanoutSize:  func(k string, n int) { m.fanoutSize.WithLabelValues(k).Observe(float64(n)) },
		CommitErr:   func(error) { m.commitErrs.Inc() },
	}
}

func (m *metrics) executorMetrics() worker.ExecutorMetrics {
	return worker.ExecutorMetrics{
		AttemptStarted:  func(k string, retry bool) { m.attemptStarted.WithLabelValues(k, strconv.FormatBool(retry)).Inc() },
		AttemptResult:   func(k, o string) { m.attemptOutcome.WithLabelValues(k, o).Inc() },
		AttemptDuration: func(s float64) { m.attemptDuration.Observe(s) },
		Dead:            func(k string) { m.dead.WithLabelValues(k).Inc() },
	}
}

func (m *metrics) retrierMetrics() worker.RetrierMetrics {
	return worker.RetrierMetrics{
		Tick:      func() { m.retrierTicks.Inc() },
		Claimed:   func(n int) { m.retrierClaimed.Add(float64(n)) },
		TickError: func(error) { m.retrierTickErrors.Inc() },
	}
}

// onBreakerStateChange is what the Executor's breaker pool calls on
// every transition. Label cardinality is bounded at 3 (closed | open |
// half-open) — host is logged in slog but kept out of metrics so a
// fleet with thousands of webhook hosts doesn't explode the series.
func (m *metrics) onBreakerStateChange(_ string, _, to gobreaker.State) {
	m.breakerStateChanges.WithLabelValues(to.String()).Inc()
}
