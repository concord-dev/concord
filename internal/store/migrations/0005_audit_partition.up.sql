-- Migration 0005 — convert audit_event to a monthly partitioned table.
--
-- WHY: audit_event grows linearly with traffic and we keep it forever
-- for compliance. Without partitioning, every operator query
-- (`/v1/orgs/{slug}/audit`, audit-package export) scans an
-- ever-larger table, and a future `VACUUM FULL` would block writes.
-- Monthly RANGE partitions keep each partition bounded, let us
-- ATTACH / DETACH old months for archival, and turn the operator's
-- "last 30 days" filter into a single-partition scan.
--
-- HOW: native Postgres declarative partitioning by RANGE
-- (occurred_at). The partition key must be in every UNIQUE / PK
-- index, so the PK becomes (id, occurred_at). Composite is fine
-- because lookups are still by id and the index on (id, occurred_at)
-- has id as the leftmost column.
--
-- Pre-launch — no data to preserve, so we simply DROP and recreate.
-- A future migration handling live data would need pg_dump-style
-- migration into the new structure.
--
-- A PL/pgSQL helper `concord_ensure_audit_partition(month TIMESTAMPTZ)`
-- creates a month's partition idempotently. concord-server runs it
-- once a day via a background tick (see internal/server/auditpart) so
-- next month's partition always exists ahead of the rollover.

DROP TABLE audit_event;

CREATE TABLE audit_event (
    id              UUID        NOT NULL DEFAULT gen_random_uuid(),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_kind      TEXT        NOT NULL
        CHECK (actor_kind IN ('user', 'token', 'operator', 'unauthenticated', 'system')),
    actor_user_id   UUID                 REFERENCES "user"(id)     ON DELETE SET NULL,
    actor_token_id  UUID                 REFERENCES api_token(id)  ON DELETE SET NULL,
    org_id          UUID                 REFERENCES organization(id) ON DELETE CASCADE,
    action          TEXT        NOT NULL,
    target_type     TEXT,
    target_id       UUID,
    ip              INET,
    user_agent      TEXT,
    request_id      TEXT,
    details         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, occurred_at)
) PARTITION BY RANGE (occurred_at);

-- Indexes on the parent propagate to every partition (Postgres 11+).
-- The org+occurred and actor+occurred indexes are partial so they
-- don't index NULLs from background-system audits.
CREATE INDEX idx_audit_event_org_occurred  ON audit_event(org_id, occurred_at DESC)
    WHERE org_id IS NOT NULL;
CREATE INDEX idx_audit_event_actor_user    ON audit_event(actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX idx_audit_event_action        ON audit_event(action, occurred_at DESC);

-- concord_ensure_audit_partition(month TIMESTAMPTZ) creates the
-- monthly partition that contains `month` if it doesn't already
-- exist. Idempotent — operator playbook lines and the background
-- task call this freely. Returns the partition's bounds as a row
-- so callers can log "I created audit_event_2027_01 covering Jan 1
-- → Feb 1".
--
-- Locking: CREATE TABLE ... PARTITION OF takes an ACCESS EXCLUSIVE
-- lock on the parent. That blocks writes for the duration of the
-- statement, but partition creation is sub-millisecond so the
-- contention window is unmeasurable in practice. We deliberately
-- DO NOT pre-create indexes on the partition (they inherit from the
-- parent) to keep the lock short.
CREATE OR REPLACE FUNCTION concord_ensure_audit_partition(month TIMESTAMPTZ)
RETURNS TABLE(name TEXT, range_start TIMESTAMPTZ, range_end TIMESTAMPTZ, created BOOLEAN)
LANGUAGE plpgsql AS $$
DECLARE
    month_start TIMESTAMPTZ := date_trunc('month', month AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    month_end   TIMESTAMPTZ := month_start + interval '1 month';
    part_name   TEXT        := 'audit_event_' || to_char(month_start AT TIME ZONE 'UTC', 'YYYY_MM');
    existed     BOOLEAN     := false;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class
        WHERE relname = part_name AND relkind = 'r'
    ) THEN
        existed := true;
    ELSE
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF audit_event FOR VALUES FROM (%L) TO (%L)',
            part_name, month_start, month_end
        );
    END IF;
    name := part_name;
    range_start := month_start;
    range_end := month_end;
    created := NOT existed;
    RETURN NEXT;
END;
$$;

-- Bootstrap: create partitions for the current month and 6 months
-- forward. The background task tops this up over time; the bootstrap
-- gives us a 6-month buffer so even a wedged tick (server crashed
-- and didn't restart for a long weekend) doesn't drop audit writes.
DO $$
DECLARE
    cur DATE := date_trunc('month', now())::date;
    i   INT;
BEGIN
    FOR i IN 0..6 LOOP
        PERFORM concord_ensure_audit_partition((cur + (i || ' months')::interval)::timestamptz);
    END LOOP;
END $$;
