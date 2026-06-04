-- Migration 0002 — transactional outbox for the concord.events Kafka topic.
--
-- Every domain event (run.queued, run.completed, drift.detected, ...) is
-- INSERTed here in the same transaction as the state change it
-- describes. A separate Dispatcher polls pending rows and ships them to
-- Kafka. This is the canonical "transactional outbox" pattern; it is the
-- only safe way to avoid the dual-write problem (DB commits but Kafka
-- fails, or vice versa).
--
-- Lifecycle of a row:
--   1. Handler INSERTs (published_at IS NULL, attempt_count=0).
--   2. Dispatcher SELECT FOR UPDATE SKIP LOCKED claims a batch where
--      published_at IS NULL AND next_attempt_at <= now().
--   3. On Kafka success → UPDATE published_at = now().
--   4. On Kafka failure → UPDATE attempt_count++, last_error=$err,
--      next_attempt_at = now() + backoff(attempt_count).
--   5. Once attempt_count reaches outbox.maxAttempts the row stays
--      unpublished (dispatcher stops touching it). Phase 4 will add an
--      operator endpoint to inspect + replay these dead-letter rows.
--   6. Cleanup sweep deletes rows where published_at < now() - 7 days.

CREATE TABLE event_outbox (
    -- Surrogate primary key. Random UUIDv4 — order of inserts is
    -- preserved by created_at, not by id, so we don't need v7 here.
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- The consumer-facing idempotency key. Generated at the originating
    -- handler so a retried handler call produces the same event_id and
    -- the worker can dedupe via this column. Unique so a buggy caller
    -- can't double-insert by accident.
    event_id        UUID        NOT NULL UNIQUE,

    -- Partition key on the Kafka wire. Per-tenant ordering is preserved
    -- because all of an org's events hash to one partition.
    org_id          UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,

    -- Event taxonomy: "run.completed", "drift.detected", etc. Indexed
    -- so an operator can find all events of one kind quickly.
    kind            TEXT        NOT NULL,

    -- The serialized event envelope (the bytes that go on the wire).
    -- jsonb so an operator can grep with SQL without parsing.
    payload         JSONB       NOT NULL,

    -- W3C tracecontext for cross-service trace stitching. Captured at
    -- enqueue time so the consumer span links back to the originating
    -- HTTP request.
    traceparent     TEXT        NULL,

    -- When the *domain* event happened (e.g. the run completed). Distinct
    -- from created_at, which is when the row was inserted — usually the
    -- same instant, but exposing both lets the consumer report wall-clock
    -- delivery latency.
    occurred_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- NULL until the dispatcher has shipped this row to Kafka.
    published_at    TIMESTAMPTZ NULL,

    -- Retry bookkeeping. attempt_count increments on every dispatch
    -- failure; next_attempt_at is the earliest wall-clock at which the
    -- dispatcher will pick this row up again.
    attempt_count   INT         NOT NULL DEFAULT 0,
    last_error      TEXT        NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dispatcher's hot-path index. Partial — only unpublished rows matter,
-- so a years-old archive of published rows doesn't cost us anything on
-- the scan. The (next_attempt_at, created_at) sort keeps the dispatcher
-- fair: the row that's been waiting longest at any given retry tier
-- gets picked first.
CREATE INDEX idx_event_outbox_pending
    ON event_outbox (next_attempt_at, created_at)
    WHERE published_at IS NULL;

-- Cleanup index. Partial again — only published rows are eligible for
-- the 7-day delete sweep.
CREATE INDEX idx_event_outbox_published
    ON event_outbox (published_at)
    WHERE published_at IS NOT NULL;

-- Operator-facing index: "show me the dead-letter rows" — rows that
-- have hit the max-attempts ceiling and are stuck pending.
CREATE INDEX idx_event_outbox_dead
    ON event_outbox (org_id, kind, created_at)
    WHERE published_at IS NULL AND attempt_count >= 20;
