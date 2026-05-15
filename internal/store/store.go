// Package store is the Postgres-backed persistence layer for concord-server.
// It owns the schema (see migrations/*.up.sql), maintains the connection
// pool, and exposes typed CRUD over the RBAC + domain tables:
//
//	organization, "user", role, permission, role_permission, user_org_role,
//	api_token, user_session, control_override, schedule, webhook, run
//
// Per-entity methods live in dedicated files (organization.go, user.go,
// role.go, membership.go, api_token.go, session.go, control_override.go,
// schedule.go, webhook.go, run.go). This file owns only the Store type and
// its lifecycle.
package store

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")

// PoolOptions tune the pgxpool configuration.
type PoolOptions struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// Store is the typed handle around a pgxpool.Pool.
type Store struct {
	pool *pgxpool.Pool
}

// Open dials Postgres via pgxpool. dsn is a libpq URL. The pool is
// health-checked before returning so misconfiguration surfaces immediately.
func Open(ctx context.Context, dsn string, opts PoolOptions) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing dsn: %w", err)
	}
	applyPoolOptions(cfg, opts)

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("opening pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging db: %w", err)
	}
	return &Store{pool: pool}, nil
}

// applyPoolOptions copies non-zero PoolOptions fields onto the pgx config.
// Zero values fall back to pgx's own defaults.
func applyPoolOptions(cfg *pgxpool.Config, opts PoolOptions) {
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}
	if opts.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = opts.MaxConnLifetime
	}
	if opts.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = opts.MaxConnIdleTime
	}
}

// Close drains the connection pool. Idempotent.
func (s *Store) Close() { s.pool.Close() }

// Pool exposes the raw pgxpool handle for exotic queries; prefer typed
// methods for everything else.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// hexToBytes is the tiny shim used by token-bearing tables (invitation,
// password_reset) that store sha256 hashes as BYTEA. auth.HashSecret returns
// hex; we decode it once at the call site rather than storing hex.
func hexToBytes(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decoding token hash hex: %w", err)
	}
	return b, nil
}
