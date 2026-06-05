-- Migration 0004 — operator-facing dead-letter abandon column.
--
-- Phase 2's event_outbox.attempt_count and Phase 3's webhook_delivery.status
-- already give us "stuck waiting for operator attention" via the dead-letter
-- partial indexes. What's missing is a way for the operator to mark a row
-- as "I've looked at this, it's not coming back" without losing the
-- forensic trail (attempts_log, last_error, original payload).
--
-- abandoned_at fills that gap. Setting it:
--   - hides the row from the dispatcher/retrier (their claim queries gain
--     an AND abandoned_at IS NULL filter)
--   - leaves the row + all its forensic columns in place, so compliance
--     queries can still trace "we received event X, we tried Y times,
--     we gave up at Z"
--   - is reversible: an operator replay clears abandoned_at as well as
--     attempt_count, putting the row back in flight.

ALTER TABLE event_outbox ADD COLUMN abandoned_at TIMESTAMPTZ NULL;
ALTER TABLE webhook_delivery ADD COLUMN abandoned_at TIMESTAMPTZ NULL;

-- Tighten the dispatcher's pending-rows partial index so abandoned rows
-- don't widen the scan. Same shape as the original; the WHERE clause
-- adds the new gate. Drop + recreate is the simplest path since the
-- index name needs to stay stable for operator runbook queries.
DROP INDEX IF EXISTS idx_event_outbox_pending;
CREATE INDEX idx_event_outbox_pending
    ON event_outbox (next_attempt_at, created_at)
    WHERE published_at IS NULL AND abandoned_at IS NULL;

-- Same treatment for the retrier's hot path.
DROP INDEX IF EXISTS idx_webhook_delivery_pending;
CREATE INDEX idx_webhook_delivery_pending
    ON webhook_delivery (next_attempt_at, created_at)
    WHERE status = 'failed' AND abandoned_at IS NULL;

-- DLQ inspection indexes — operators paging through "stuck rows" want
-- (created_at DESC) ordering scoped to the dead population. Partial
-- so they cost nothing on the published / succeeded majority.
CREATE INDEX idx_event_outbox_dlq
    ON event_outbox (created_at DESC)
    WHERE published_at IS NULL AND abandoned_at IS NULL AND attempt_count >= 20;

CREATE INDEX idx_webhook_delivery_dlq
    ON webhook_delivery (created_at DESC)
    WHERE status = 'dead' AND abandoned_at IS NULL;
