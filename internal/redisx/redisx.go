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

type Mode string

const (
	ModeSingle   Mode = "single"
	ModeSentinel Mode = "sentinel"
)

type Config struct {
	Mode Mode

	Addr string // host:port — only consulted in ModeSingle

	SentinelMaster string   // master name registered with Sentinel
	SentinelAddrs  []string // sentinel host:port list

	Username string
	Password string
	DB       int

	TLS        bool
	ServerName string
	InsecureSkipVerify bool

	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	PoolSize int

	MaxRetries int
}

func Open(cfg Config) (*redis.Client, error) {
	mode := cfg.Mode
	if mode == "" {
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

func Ping(ctx context.Context, c *redis.Client) error {
	if c == nil {
		return errors.New("redisx: client is nil")
	}
	return c.Ping(ctx).Err()
}

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
