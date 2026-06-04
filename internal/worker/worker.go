// Package worker is concord-worker's domain logic — separated from the
// cmd/concord-worker entry point so the consumer + retrier are unit
// testable without a full process boot.
//
// Three pieces:
//
//   - Executor is the shared HTTP delivery primitive used by both the
//     first-attempt consumer and the retrier. It POSTs the event body
//     to a webhook URL with HMAC-SHA256 signing, observes the result,
//     and stamps the webhook_delivery row via the supplied Store.
//
//   - Consumer reads concord.events via segmentio/kafka-go in a
//     consumer group, dedupes incoming event_ids via Redis SETNX
//     (24h TTL), fans out to every enabled webhook for the org, and
//     drives a first attempt via the Executor. The Kafka offset is
//     committed only AFTER every delivery row is persisted, so a
//     crash mid-batch reprocesses the event on the next consumer
//     fetch (the dedupe + UNIQUE (webhook_id, event_id) constraint
//     keep that re-delivery idempotent).
//
//   - Retrier polls webhook_delivery for status='failed' rows whose
//     next_attempt_at has elapsed, locks them with SELECT FOR UPDATE
//     SKIP LOCKED so multiple workers don't double-fire, and runs the
//     Executor for each. Bounded by the per-row attempt_count <
//     MaxAttempts filter so a single bad webhook can't burn through
//     budget indefinitely.
//
// All three are safe to run multiple instances of concurrently — Kafka
// partitions itself, and the SKIP LOCKED tail handles the retry race.
package worker
