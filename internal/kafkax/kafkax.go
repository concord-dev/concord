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

type SASLMechanism string

const (
	SASLNone        SASLMechanism = ""
	SASLPlain       SASLMechanism = "plain"
	SASLScramSHA256 SASLMechanism = "scram-sha-256"
	SASLScramSHA512 SASLMechanism = "scram-sha-512"
)

type Compression string

const (
	CompressionNone   Compression = ""
	CompressionSnappy Compression = "snappy"
	CompressionGzip   Compression = "gzip"
	CompressionLZ4    Compression = "lz4"
	CompressionZstd   Compression = "zstd"
)

type Config struct {
	Brokers []string

	Topic string

	ClientID string

	TLS                bool
	ServerName         string
	InsecureSkipVerify bool

	SASLMechanism SASLMechanism
	SASLUsername  string
	SASLPassword  string

	Compression Compression

	WriteTimeout time.Duration

	BatchTimeout time.Duration

	MaxAttempts int
}

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
