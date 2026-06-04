// Package redisx is a thin wrapper around go-redis that produces a configured
// client (single-node or Sentinel-failover) from a flat Config.
//
// The wrapper exists so cmd/server can keep its dependency tree shallow and
// every downstream consumer (rate limiter, idempotency cache, future feature
// flags) shares the same connection lifecycle, TLS posture, and timeouts.
//
// Concord uses go-redis v9. Sentinel mode is preferred for production
// deployments — a single-node Redis is a single point of failure for both
// rate limiting and (eventually) Idempotency-Key dedupe. The library handles
// master failover internally; consumers just see request timeouts during the
// few seconds while Sentinel promotes a replica.
package redisx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Mode selects between a single-node Redis and a Sentinel-fronted cluster.
type Mode string

const (
	ModeSingle   Mode = "single"
	ModeSentinel Mode = "sentinel"
)

// Config is the bundle cmd/server passes in. Every field except Addr (single
// mode) / SentinelAddrs+SentinelMaster (sentinel mode) has a sane default; a
// caller can leave the rest zero-valued for local-dev posture.
type Config struct {
	Mode Mode

	Addr string // host:port — only consulted in ModeSingle

	SentinelMaster string   // master name registered with Sentinel
	SentinelAddrs  []string // sentinel host:port list

	Username string
	Password string
	DB       int

	// TLS enables TLS to Redis. ServerName lets the operator pin SNI when
	// the chart wires a managed Redis with a wildcard certificate.
	TLS        bool
	ServerName string
	// InsecureSkipVerify is escape-hatch only for self-signed dev redis;
	// production deployments should always leave it false.
	InsecureSkipVerify bool

	// Timeouts apply to every command. Defaults are tuned to fail fast so
	// a slow / unreachable Redis can't pin handler goroutines.
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// PoolSize sets the maximum number of socket connections per node. The
	// default (10 * runtime.NumCPU() in go-redis) is fine for most loads;
	// callers override only when contention metrics demand it.
	PoolSize int

	// MaxRetries on transient command errors. -1 disables.
	MaxRetries int
}

// Open builds a redis.Client from cfg. Returns an error if required fields
// for the chosen mode are missing, or if no mode is set.
//
// The returned client is goroutine-safe; share one across the process.
func Open(cfg Config) (*redis.Client, error) {
	mode := cfg.Mode
	if mode == "" {
		// Heuristic: if the operator filled in SentinelAddrs they wanted
		// sentinel mode but forgot the explicit Mode. Treat that as
		// ModeSentinel rather than failing with a confusing error.
		if len(cfg.SentinelAddrs) > 0 {
			mode = ModeSentinel
		} else if cfg.Addr != "" {
			mode = ModeSingle
		} else {
			return nil, errors.New("redisx: Mode (or Addr / SentinelAddrs) is required")
		}
	}

	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = 2 * time.Second
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 200 * time.Millisecond
	}
	writeTimeout := cfg.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 200 * time.Millisecond
	}
	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = 1
	}

	var tlsCfg *tls.Config
	if cfg.TLS {
		tlsCfg = &tls.Config{
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
	}

	switch mode {
	case ModeSingle:
		if cfg.Addr == "" {
			return nil, errors.New("redisx: Addr is required in single mode")
		}
		return redis.NewClient(&redis.Options{
			Addr:         cfg.Addr,
			Username:     cfg.Username,
			Password:     cfg.Password,
			DB:           cfg.DB,
			DialTimeout:  dialTimeout,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			PoolSize:     cfg.PoolSize,
			MaxRetries:   maxRetries,
			TLSConfig:    tlsCfg,
		}), nil

	case ModeSentinel:
		if cfg.SentinelMaster == "" {
			return nil, errors.New("redisx: SentinelMaster is required in sentinel mode")
		}
		if len(cfg.SentinelAddrs) == 0 {
			return nil, errors.New("redisx: SentinelAddrs must be non-empty in sentinel mode")
		}
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:    cfg.SentinelMaster,
			SentinelAddrs: cfg.SentinelAddrs,
			Username:      cfg.Username,
			Password:      cfg.Password,
			DB:            cfg.DB,
			DialTimeout:   dialTimeout,
			ReadTimeout:   readTimeout,
			WriteTimeout:  writeTimeout,
			PoolSize:      cfg.PoolSize,
			MaxRetries:    maxRetries,
			TLSConfig:     tlsCfg,
		}), nil

	default:
		return nil, fmt.Errorf("redisx: unknown mode %q (want single|sentinel)", mode)
	}
}

// Ping is a thin readiness helper. cmd/server's /readyz probe calls it
// against a short context so a stuck Redis can't keep the pod in service.
func Ping(ctx context.Context, c *redis.Client) error {
	if c == nil {
		return errors.New("redisx: client is nil")
	}
	return c.Ping(ctx).Err()
}

// ParseSentinelAddrs accepts a comma-separated host:port list and trims it
// into a slice. Empty input returns nil so callers can pass through env
// vars without an extra unset-check.
func ParseSentinelAddrs(s string) []string {
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
