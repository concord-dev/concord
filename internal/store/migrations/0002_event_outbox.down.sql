DROP INDEX IF EXISTS idx_event_outbox_dead;
DROP INDEX IF EXISTS idx_event_outbox_published;
DROP INDEX IF EXISTS idx_event_outbox_pending;
DROP TABLE IF EXISTS event_outbox;
