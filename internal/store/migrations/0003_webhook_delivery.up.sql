-- Migration 0003 — webhook_delivery: per (webhook, event) audit + retry state.
--
-- This is the durable table the concord-worker writes to. One row per
-- (webhook_id, event_id); attempts accumulate on the row rather than
-- creating new rows, so "show me failing webhooks" stays a simple
-- WHERE-clause query.
--
-- Lifecycle of a row:
--   1. Consumer / Retrier INSERTs with status='delivering' (or upserts
--      onto an existing row from a prior attempt).
--   2. After the HTTP POST: UPDATE attempt_count, last_status, last_error.
--      - 2xx        → status='succeeded', next_attempt_at=NULL
--      - non-2xx /
--        network    → status='failed' (under max) or 'dead' (at max),
--                     next_attempt_at = now() + backoff(attempt_count).
--   3. Retrier polls status='failed' AND next_attempt_at <= now() with
--      SELECT FOR UPDATE SKIP LOCKED so multiple replicas don't
--      double-retry the same row.
--   4. attempts_log JSONB captures per-attempt forensics (when, status,
--      error). Capped at MaxAttempts (default 5) entries in code.
--
-- The (webhook_id, event_id) UNIQUE constraint is what makes the whole
-- pipe idempotent: a re-delivered Kafka message (Kafka guarantees
-- at-least-once) lands on the same row, so the consumer code path
-- becomes an UPSERT that's safe to re-execute.

CREATE TABLE webhook_delivery (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Target of the delivery. ON DELETE CASCADE so deleting a webhook
    -- also cleans up its delivery history — operators can purge a
    -- webhook without leaving orphan rows.
    webhook_id      UUID        NOT NULL REFERENCES webhook(id) ON DELETE CASCADE,

    -- The originating event. Consumers dedupe by event_id (Kafka's
    -- at-least-once delivery means duplicate fetches are routine), so
    -- this column is the canonical idempotency key.
    event_id        UUID        NOT NULL,

    -- Denormalised — saves a join on the operator audit view, and
    -- ON DELETE CASCADE on org_id is the second cleanup line of defence
    -- if the webhook FK ever goes ON DELETE SET NULL.
    org_id          UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    event_kind      TEXT        NOT NULL,

    -- State machine: delivering | succeeded | failed | dead.
    --   delivering — POST currently in flight (or worker crashed; the
    --                retrier picks these up after grace_period).
    --   succeeded  — terminal success state.
    --   failed     — will retry after next_attempt_at.
    --   dead       — exceeded MaxAttempts; operator must intervene.
    status          TEXT        NOT NULL,

    attempt_count   INT         NOT NULL DEFAULT 0,

    -- HTTP status from the last response (0 = network error / no
    -- response). last_error captures the textual error or the response
    -- body prefix on non-2xx.
    last_http_status INT        NOT NULL DEFAULT 0,
    last_error       TEXT       NULL,

    -- Per-attempt forensics. Array of {attempted_at, http_status,
    -- error?, duration_ms} so operators can see the full history
    -- without paging through a separate table.
    attempts_log     JSONB      NOT NULL DEFAULT '[]'::jsonb,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_attempted_at TIMESTAMPTZ NULL,
    next_attempt_at  TIMESTAMPTZ NULL,
    succeeded_at     TIMESTAMPTZ NULL,

    UNIQUE (webhook_id, event_id)
);

-- Hot path for the retrier loop. Partial — succeeded / dead rows are
-- terminal and don't need to be scanned.
CREATE INDEX idx_webhook_delivery_pending
    ON webhook_delivery (next_attempt_at, created_at)
    WHERE status = 'failed';

-- Operator-facing index: "what's failing right now in org X?"
CREATE INDEX idx_webhook_delivery_org_status
    ON webhook_delivery (org_id, status, created_at DESC);

-- Per-webhook audit: "show me the last 100 deliveries to this hook".
CREATE INDEX idx_webhook_delivery_webhook_recent
    ON webhook_delivery (webhook_id, created_at DESC);

-- Dead-letter view: "everything stuck waiting for operator attention".
CREATE INDEX idx_webhook_delivery_dead
    ON webhook_delivery (org_id, created_at DESC)
    WHERE status = 'dead';
