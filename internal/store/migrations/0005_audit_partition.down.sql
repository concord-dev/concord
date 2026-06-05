DROP FUNCTION IF EXISTS concord_ensure_audit_partition(TIMESTAMPTZ);

-- Drop every monthly partition first — they're independent tables.
DO $$
DECLARE
    p TEXT;
BEGIN
    FOR p IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c ON c.oid = i.inhrelid
        JOIN pg_class parent ON parent.oid = i.inhparent
        WHERE parent.relname = 'audit_event'
    LOOP
        EXECUTE format('DROP TABLE IF EXISTS %I', p);
    END LOOP;
END $$;

DROP TABLE IF EXISTS audit_event;

-- Recreate the non-partitioned table so the rest of the schema
-- (audit handlers, FK references from siblings) still works after
-- a rollback. Same shape as 0001.
CREATE TABLE audit_event (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
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
    details         JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_audit_event_org_occurred  ON audit_event(org_id, occurred_at DESC)
    WHERE org_id IS NOT NULL;
CREATE INDEX idx_audit_event_actor_user    ON audit_event(actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX idx_audit_event_action        ON audit_event(action, occurred_at DESC);
