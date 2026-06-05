package store

import (
	"context"
	"time"
)

type AuditPartition struct {
	Name       string    `json:"name"`
	RangeStart time.Time `json:"range_start"`
	RangeEnd   time.Time `json:"range_end"`
	Created    bool      `json:"created"`
}

func (s *Store) EnsureAuditPartition(ctx context.Context, month time.Time) (AuditPartition, error) {
	var p AuditPartition
	err := s.pool.QueryRow(ctx,
		`SELECT name, range_start, range_end, created
		 FROM concord_ensure_audit_partition($1)`,
		month.UTC(),
	).Scan(&p.Name, &p.RangeStart, &p.RangeEnd, &p.Created)
	return p, err
}

func (s *Store) ListAuditPartitions(ctx context.Context) ([]AuditPartition, error) {
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
