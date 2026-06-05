package store

import (
	"context"
	"time"
)

// AuditPartition is the row shape concord_ensure_audit_partition
// returns. Distinct from EventOutboxRow et al. — this is partition
// bookkeeping, not domain data.
type AuditPartition struct {
	Name       string    `json:"name"`
	RangeStart time.Time `json:"range_start"`
	RangeEnd   time.Time `json:"range_end"`
	Created    bool      `json:"created"`
}

// EnsureAuditPartition idempotently creates the monthly audit_event
// partition that contains month. Returns the partition's name and
// bounds, plus a boolean indicating whether this call actually
// created the partition (false → it already existed).
//
// The PL/pgSQL function does the heavy lifting (locking semantics,
// name derivation, range arithmetic); this Go wrapper just calls it.
// Idempotent + safe to invoke concurrently from multiple server
// replicas — each replica that wins the race creates the partition;
// the rest see "already existed" and move on.
func (s *Store) EnsureAuditPartition(ctx context.Context, month time.Time) (AuditPartition, error) {
	var p AuditPartition
	err := s.pool.QueryRow(ctx,
		`SELECT name, range_start, range_end, created
		 FROM concord_ensure_audit_partition($1)`,
		month.UTC(),
	).Scan(&p.Name, &p.RangeStart, &p.RangeEnd, &p.Created)
	return p, err
}

// ListAuditPartitions returns every audit_event partition currently
// attached to the parent, ordered by their range start. Operators
// use this to verify next month exists ahead of the rollover.
func (s *Store) ListAuditPartitions(ctx context.Context) ([]AuditPartition, error) {
	// Query pg_inherits to find every partition of audit_event, then
	// read the partition expression to recover the bounds. The
	// expression is stored as "FOR VALUES FROM ('2026-06-01') TO ('2026-07-01')"
	// so we parse it via pg_get_expr.
	rows, err := s.pool.Query(ctx, `
		SELECT
		  c.relname,
		  (regexp_match(pg_get_expr(c.relpartbound, c.oid),
		                $$FROM \('([^']+)'\) TO \('([^']+)'\)$$))[1]::timestamptz AS range_start,
		  (regexp_match(pg_get_expr(c.relpartbound, c.oid),
		                $$FROM \('([^']+)'\) TO \('([^']+)'\)$$))[2]::timestamptz AS range_end
		FROM pg_inherits i
		JOIN pg_class c       ON c.oid = i.inhrelid
		JOIN pg_class parent  ON parent.oid = i.inhparent
		WHERE parent.relname = 'audit_event'
		ORDER BY range_start
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditPartition
	for rows.Next() {
		var p AuditPartition
		if err := rows.Scan(&p.Name, &p.RangeStart, &p.RangeEnd); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
