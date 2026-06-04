// Package kafkax is a thin wrapper around segmentio/kafka-go that produces
// a configured *kafka.Writer from a flat Config.
//
// Concord publishes the canonical event topic (default concord.events) via
// this writer; downstream consumers (Phase 3's concord-worker, and any
// external sink an operator points at the topic) read partitioned by
// org_id so per-tenant ordering is preserved.
//
// The wrapper exists so cmd/server keeps its dependency tree shallow and
// every Kafka knob (TLS, SASL mechanism, compression, timeouts) is wired
// in one place. The writer is concurrency-safe; share one across the
// process.
package kafkax

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
)

// SASLMechanism enumerates the auth shapes Concord accepts. PLAIN is fine
// over TLS; SCRAM-256/512 are preferred when the broker supports them.
type SASLMechanism string

const (
	SASLNone        SASLMechanism = ""
	SASLPlain       SASLMechanism = "plain"
	SASLScramSHA256 SASLMechanism = "scram-sha-256"
	SASLScramSHA512 SASLMechanism = "scram-sha-512"
)

// Compression enumerates the wire compressors kafka-go understands.
type Compression string

const (
	CompressionNone   Compression = ""
	CompressionSnappy Compression = "snappy"
	CompressionGzip   Compression = "gzip"
	CompressionLZ4    Compression = "lz4"
	CompressionZstd   Compression = "zstd"
)

// Config is the bundle cmd/server passes in. Most fields have sane
// defaults; for local-dev a caller can leave everything but Brokers and
// Topic at the zero value.
type Config struct {
	// Brokers is the bootstrap broker list. At least one is required.
	Brokers []string

	// Topic is the destination topic. Required.
	Topic string

	// ClientID identifies this producer to the broker. Defaults to
	// "concord-server".
	ClientID string

	// TLS enables TLS to the brokers. ServerName overrides SNI when the
	// broker certs use a different name from the bootstrap host.
	TLS                bool
	ServerName         string
	InsecureSkipVerify bool

	// SASL credentials. Mechanism empty disables SASL.
	SASLMechanism SASLMechanism
	SASLUsername  string
	SASLPassword  string

	// Compression for the produce wire. Snappy is a good default for
	// JSON event payloads; throughput-bound deployments may prefer LZ4.
	Compression Compression

	// WriteTimeout caps each produce. Defaults to 5s. A stuck broker
	// returns context.DeadlineExceeded promptly so the dispatcher can
	// schedule the row for retry.
	WriteTimeout time.Duration

	// BatchTimeout is the linger before a partial batch is flushed.
	// 10ms is a sane production default — small enough to keep latency
	// low, large enough to amortise broker round-trips on bursty load.
	BatchTimeout time.Duration

	// MaxAttempts is the number of broker-side retries kafka-go performs
	// internally before returning an error. The outbox dispatcher does
	// its own retry-with-backoff layered on top, so this number is kept
	// modest (default 3).
	MaxAttempts int
}

// NewWriter returns a configured *kafka.Writer ready for produce. Errors
// out if Brokers or Topic are missing — those are configuration mistakes
// the operator wants to catch at startup, not at the first publish.
//
// The returned writer is safe for concurrent use; share one across the
// process and call Close() on shutdown to flush any in-flight batch.
func NewWriter(cfg Config) (*kafka.Writer, error) {
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("kafkax: Brokers must be non-empty")
	}
	if cfg.Topic == "" {
		return nil, errors.New("kafkax: Topic is required")
	}

	tlsCfg, err := buildTLS(cfg)
	if err != nil {
		return nil, err
	}
	saslMech, err := buildSASL(cfg)
	if err != nil {
		return nil, err
	}

	transport := &kafka.Transport{
		ClientID: defaultStr(cfg.ClientID, "concord-server"),
		TLS:      tlsCfg,
		SASL:     saslMech,
		// kafka-go's default DialTimeout (10s) is fine; not exposing it
		// as a knob until an operator hits a real-world need.
	}

	w := &kafka.Writer{
		Addr:                   kafka.TCP(cfg.Brokers...),
		Topic:                  cfg.Topic,
		Balancer:               &kafka.Hash{}, // hash(Key) → partition; with Key=org_id this preserves per-tenant ordering
		RequiredAcks:           kafka.RequireAll,
		Async:                  false, // we want errors back so the dispatcher can retry
		MaxAttempts:            defaultInt(cfg.MaxAttempts, 3),
		WriteTimeout:           defaultDur(cfg.WriteTimeout, 5*time.Second),
		BatchTimeout:           defaultDur(cfg.BatchTimeout, 10*time.Millisecond),
		Compression:            compressionToKafka(cfg.Compression),
		Transport:              transport,
		AllowAutoTopicCreation: false, // explicit topic mgmt — auto-create masks misconfig
	}
	return w, nil
}

// Ping reads the cluster metadata as a cheap reachability check. Used by
// /readyz so a wedged Kafka takes the pod out of the Service. Hard upper
// bound at 2s — a longer probe would just stack readiness checks.
func Ping(ctx context.Context, cfg Config) error {
	if len(cfg.Brokers) == 0 {
		return errors.New("kafkax: Brokers must be non-empty")
	}
	tlsCfg, err := buildTLS(cfg)
	if err != nil {
		return err
	}
	saslMech, err := buildSASL(cfg)
	if err != nil {
		return err
	}
	d := &kafka.Dialer{
		ClientID:      defaultStr(cfg.ClientID, "concord-server"),
		TLS:           tlsCfg,
		SASLMechanism: saslMech,
		Timeout:       2 * time.Second,
	}
	conn, err := d.DialContext(ctx, "tcp", cfg.Brokers[0])
	if err != nil {
		return fmt.Errorf("kafkax: dial %s: %w", cfg.Brokers[0], err)
	}
	defer conn.Close()
	_, err = conn.Brokers() // forces a metadata round-trip
	return err
}

// ParseBrokers accepts a comma-separated host:port list and trims it into
// a slice. Empty input returns nil so callers can pass through env vars
// without an extra unset-check.
func ParseBrokers(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func buildTLS(cfg Config) (*tls.Config, error) {
	if !cfg.TLS {
		return nil, nil
	}
	return &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}, nil
}

func buildSASL(cfg Config) (sasl.Mechanism, error) {
	switch cfg.SASLMechanism {
	case SASLNone:
		return nil, nil
	case SASLPlain:
		if cfg.SASLUsername == "" || cfg.SASLPassword == "" {
			return nil, errors.New("kafkax: SASL PLAIN requires username and password")
		}
		return plain.Mechanism{Username: cfg.SASLUsername, Password: cfg.SASLPassword}, nil
	case SASLScramSHA256:
		return scram.Mechanism(scram.SHA256, cfg.SASLUsername, cfg.SASLPassword)
	case SASLScramSHA512:
		return scram.Mechanism(scram.SHA512, cfg.SASLUsername, cfg.SASLPassword)
	default:
		return nil, fmt.Errorf("kafkax: unknown SASL mechanism %q (want plain|scram-sha-256|scram-sha-512)", cfg.SASLMechanism)
	}
}

func compressionToKafka(c Compression) kafka.Compression {
	switch c {
	case CompressionSnappy:
		return kafka.Snappy
	case CompressionGzip:
		return kafka.Gzip
	case CompressionLZ4:
		return kafka.Lz4
	case CompressionZstd:
		return kafka.Zstd
	default:
		return 0
	}
}

func defaultStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func defaultInt(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

func defaultDur(v, fallback time.Duration) time.Duration {
	if v <= 0 {
		return fallback
	}
	return v
}
