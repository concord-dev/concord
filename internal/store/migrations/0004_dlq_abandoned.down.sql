DROP INDEX IF EXISTS idx_webhook_delivery_dlq;
DROP INDEX IF EXISTS idx_event_outbox_dlq;

DROP INDEX IF EXISTS idx_webhook_delivery_pending;
CREATE INDEX idx_webhook_delivery_pending
    ON webhook_delivery (next_attempt_at, created_at)
    WHERE status = 'failed';

DROP INDEX IF EXISTS idx_event_outbox_pending;
CREATE INDEX idx_event_outbox_pending
    ON event_outbox (next_attempt_at, created_at)
    WHERE published_at IS NULL;

ALTER TABLE webhook_delivery DROP COLUMN IF EXISTS abandoned_at;
ALTER TABLE event_outbox DROP COLUMN IF EXISTS abandoned_at;
