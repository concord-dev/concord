package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/segmentio/kafka-go"

	"github.com/concord-dev/concord/internal/eventbus"
	"github.com/concord-dev/concord/internal/store"
)

// ConsumerConfig configures the Kafka consumer + the deduper. Sane
// defaults are filled by NewConsumer.
type ConsumerConfig struct {
	// Brokers + Topic + GroupID identify the consumer group. The group
	// is what gives us partition rebalancing across worker replicas;
	// every worker must use the SAME GroupID.
	Brokers []string
	Topic   string
	GroupID string

	// MinBytes / MaxBytes tune the fetch envelope. Defaults aim for
	// low-latency single-event fetches without starving high-throughput
	// bursts.
	MinBytes int
	MaxBytes int

	// MaxWait caps how long a fetch can block waiting for new
	// messages. Lower → more responsive shutdown; higher → fewer
	// broker round-trips on idle topics. Default 1s.
	MaxWait time.Duration

	// DedupeTTL is the lifetime of the Redis dedupe key. 24h covers
	// any reasonable replay window without leaking unbounded keys.
	DedupeTTL time.Duration

	// DedupeKeyPrefix namespaces the dedupe keys; default
	// "concord:worker:seen:". Override to share a Redis with another
	// app or with a per-environment prefix.
	DedupeKeyPrefix string
}

// ConsumerMetrics is the bumps the Consumer pushes. Each field optional.
type ConsumerMetrics struct {
	Consumed    func(kind string)            // every successfully fetched + processed message
	DedupeHit   func(kind string)            // event_id already seen — skipped
	BadMessage  func(reason string)          // malformed envelope or missing headers
	NoWebhooks  func(kind string)            // event had no matching enabled webhooks
	FanoutSize  func(kind string, size int)  // how many webhook deliveries one event spawned
	CommitErr   func(err error)              // observability for offset-commit failures
	ConsumerLag func(seconds float64)        // optional: not implemented here
}

// Consumer is the Kafka reader + event-fan-out loop. Construct via
// NewConsumer; start with Run(ctx); cancel ctx to stop. Run blocks
// until ctx is done; on exit, the underlying kafka-go Reader is
// closed.
type Consumer struct {
	store    *store.Store
	redis    *redis.Client
	executor *Executor
	cfg      ConsumerConfig
	metrics  ConsumerMetrics
	reader   *kafka.Reader
}

// NewConsumer wires the Reader + dedupe + Executor. The redis client
// may be nil — dedupe falls back to the DB-side UNIQUE (webhook_id,
// event_id) constraint alone. That's still correct (at-least-once);
// you just pay an extra round trip per duplicate.
func NewConsumer(s *store.Store, rdb *redis.Client, executor *Executor, cfg ConsumerConfig, metrics ConsumerMetrics) (*Consumer, error) {
	if s == nil {
		return nil, errors.New("worker: NewConsumer needs a Store")
	}
	if executor == nil {
		return nil, errors.New("worker: NewConsumer needs an Executor")
	}
	if len(cfg.Brokers) == 0 {
		return nil, errors.New("worker: NewConsumer needs at least one broker")
	}
	if cfg.Topic == "" {
		return nil, errors.New("worker: NewConsumer needs a topic")
	}
	if cfg.GroupID == "" {
		cfg.GroupID = "concord-worker"
	}
	if cfg.MinBytes <= 0 {
		cfg.MinBytes = 1
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 10 * 1024 * 1024
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 1 * time.Second
	}
	if cfg.DedupeTTL <= 0 {
		cfg.DedupeTTL = 24 * time.Hour
	}
	if cfg.DedupeKeyPrefix == "" {
		cfg.DedupeKeyPrefix = "concord:worker:seen:"
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        cfg.Brokers,
		Topic:          cfg.Topic,
		GroupID:        cfg.GroupID,
		MinBytes:       cfg.MinBytes,
		MaxBytes:       cfg.MaxBytes,
		MaxWait:        cfg.MaxWait,
		CommitInterval: 0, // manual commits — we control the at-least-once boundary
		StartOffset:    kafka.FirstOffset,
		// Larger session timeout so a slow tick (DB stall, downstream
		// receiver chunking) doesn't trigger a rebalance.
		SessionTimeout: 30 * time.Second,
	})
	return &Consumer{
		store:    s,
		redis:    rdb,
		executor: executor,
		cfg:      cfg,
		metrics:  metrics,
		reader:   reader,
	}, nil
}

// Run is the main loop. Each iteration:
//
//   1. FetchMessage (blocks until ctx is done or a message arrives).
//   2. Process: dedupe → parse envelope → resolve webhooks → fan-out
//      first-attempt deliveries via the Executor.
//   3. CommitMessages: commit ONLY after all delivery rows are
//      persisted. A crash before commit reprocesses the message; the
//      dedupe + UNIQUE constraint keeps that idempotent.
//
// Returns when ctx is done. Always closes the underlying Reader.
func (c *Consumer) Run(ctx context.Context) {
	slog.Info("worker consumer: starting",
		slog.String("topic", c.cfg.Topic),
		slog.String("group", c.cfg.GroupID),
		slog.Any("brokers", c.cfg.Brokers),
	)
	defer func() {
		_ = c.reader.Close()
		slog.Info("worker consumer: stopped")
	}()

	for {
		m, err := c.reader.FetchMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Transient fetch error — log + small sleep so we don't
			// hot-loop against a wedged broker, then retry.
			slog.Warn("worker consumer: fetch error",
				slog.String("err", err.Error()))
			sleep(ctx, 1*time.Second)
			continue
		}
		if err := c.processOne(ctx, m); err != nil {
			// processOne already logged the cause; do NOT commit and
			// let Kafka redeliver after the session times out. We
			// can't retry inline here without risking double-fan-out
			// for the slice of webhooks we'd already delivered.
			slog.Warn("worker consumer: process error (will redeliver)",
				slog.Int64("offset", m.Offset),
				slog.String("err", err.Error()))
			sleep(ctx, 500*time.Millisecond)
			continue
		}
		if err := c.reader.CommitMessages(ctx, m); err != nil {
			if c.metrics.CommitErr != nil {
				c.metrics.CommitErr(err)
			}
			slog.Error("worker consumer: commit failed (offset will be re-delivered)",
				slog.Int64("offset", m.Offset),
				slog.String("err", err.Error()))
			// Do NOT bail; the next CommitMessages call will retry
			// committing this offset alongside any newer ones.
		}
	}
}

// processOne is the per-message work. Errors here propagate up to Run
// which will refuse to commit — the message is reprocessed on the next
// fetch.
func (c *Consumer) processOne(ctx context.Context, m kafka.Message) error {
	// Extract event-id + event-kind from headers (cheap) before
	// touching the body. A malformed header (no event-id) is fatal
	// for this row: we have nothing to dedupe on, so commit and move
	// on to avoid a poison-pill loop. Log loudly so an operator
	// notices.
	headers := headerMap(m.Headers)
	eventIDStr := headers["event-id"]
	kind := headers["event-kind"]
	if eventIDStr == "" {
		if c.metrics.BadMessage != nil {
			c.metrics.BadMessage("missing_event_id")
		}
		slog.Error("worker consumer: message missing event-id header — skipping (will commit)",
			slog.String("topic", m.Topic),
			slog.Int64("offset", m.Offset))
		return nil
	}
	eventID, err := uuid.Parse(eventIDStr)
	if err != nil {
		if c.metrics.BadMessage != nil {
			c.metrics.BadMessage("malformed_event_id")
		}
		slog.Error("worker consumer: malformed event-id header — skipping",
			slog.String("event_id", eventIDStr),
			slog.String("err", err.Error()))
		return nil
	}

	// Redis dedupe. SETNX with TTL — if the key is already set, this
	// event has been processed (or is in flight) by another worker.
	if c.redis != nil {
		key := c.cfg.DedupeKeyPrefix + eventID.String()
		setCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		ok, err := c.redis.SetNX(setCtx, key, "1", c.cfg.DedupeTTL).Result()
		cancel()
		if err != nil {
			// Redis transient — fall through to DB dedupe (UNIQUE
			// constraint). At-least-once is still preserved.
			slog.Warn("worker consumer: redis dedupe error (falling back to DB constraint)",
				slog.String("event_id", eventID.String()),
				slog.String("err", err.Error()))
		} else if !ok {
			if c.metrics.DedupeHit != nil {
				c.metrics.DedupeHit(kind)
			}
			return nil
		}
	}

	// Parse the envelope to extract the org_id for webhook routing.
	// The body bytes are what we'll forward to each receiver
	// unchanged — preserving the version + event_id so consumers can
	// dedupe themselves.
	var env eventbus.Envelope
	if err := json.Unmarshal(m.Value, &env); err != nil {
		if c.metrics.BadMessage != nil {
			c.metrics.BadMessage("malformed_envelope")
		}
		slog.Error("worker consumer: malformed envelope JSON — skipping",
			slog.String("event_id", eventID.String()),
			slog.String("err", err.Error()))
		return nil
	}
	if env.OrgID == uuid.Nil {
		if c.metrics.BadMessage != nil {
			c.metrics.BadMessage("missing_org_id")
		}
		slog.Error("worker consumer: envelope missing org_id — skipping",
			slog.String("event_id", eventID.String()))
		return nil
	}

	hooks, err := c.store.ListEnabledWebhooks(ctx, env.OrgID)
	if err != nil {
		return fmt.Errorf("list webhooks: %w", err)
	}
	matched := 0
	for _, h := range hooks {
		if !kindAllowed(h.EventKinds, env.Kind) {
			continue
		}
		matched++
		if err := c.deliverFirstAttempt(ctx, h, env.Kind, eventID, env.OrgID, m.Value); err != nil {
			// Persistence error on this row — abort the message so
			// Kafka redelivers. The other webhooks for this event
			// that already succeeded persist on the next pass (the
			// UPSERT becomes a no-op for the row that already has
			// status='succeeded').
			return fmt.Errorf("deliver webhook=%s: %w", h.ID, err)
		}
	}
	if matched == 0 && c.metrics.NoWebhooks != nil {
		c.metrics.NoWebhooks(kind)
	}
	if c.metrics.FanoutSize != nil {
		c.metrics.FanoutSize(kind, matched)
	}
	if c.metrics.Consumed != nil {
		c.metrics.Consumed(kind)
	}
	return nil
}

// deliverFirstAttempt UPSERTs the delivery row in 'delivering' state,
// then runs the Executor. If the row already existed (a duplicate
// fetch), we still re-run the attempt only if the row is still
// 'delivering' or 'failed' — terminal states ('succeeded' / 'dead')
// are left alone.
func (c *Consumer) deliverFirstAttempt(ctx context.Context, h store.Webhook, kind string, eventID, orgID uuid.UUID, body []byte) error {
	id, created, err := c.store.UpsertDelivery(ctx, store.UpsertDeliveryParams{
		WebhookID: h.ID,
		EventID:   eventID,
		OrgID:     orgID,
		EventKind: kind,
	})
	if err != nil {
		return err
	}
	if !created {
		// Existing row — check the current state. If terminal, skip.
		existing, err := c.store.GetWebhookDelivery(ctx, id)
		if err != nil {
			return fmt.Errorf("re-read existing delivery: %w", err)
		}
		switch existing.Status {
		case store.DeliverySucceeded, store.DeliveryDead:
			return nil // nothing more to do
		}
		// 'failed' / 'delivering' — leave it for the Retrier rather
		// than racing it from the consumer path. The Retrier will
		// honour the existing next_attempt_at backoff.
		return nil
	}

	_, err = c.executor.Attempt(ctx, nil, id, kind, h.URL, h.Secret, body, false)
	return err
}

// headerMap flattens kafka.Header pairs into a map for convenient
// lookup. Duplicate keys keep the last value (kafka allows duplicates;
// concord-server never produces them).
func headerMap(hs []kafka.Header) map[string]string {
	out := make(map[string]string, len(hs))
	for _, h := range hs {
		out[h.Key] = string(h.Value)
	}
	return out
}

// kindAllowed mirrors the server-side filter: empty allow list = all
// kinds, non-empty = exact match.
func kindAllowed(allowed []string, kind string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, k := range allowed {
		if k == kind {
			return true
		}
	}
	return false
}

// sleep is the same context-aware sleep the eventbus dispatcher uses,
// duplicated here so internal/worker doesn't pull in eventbus solely
// for a 6-line helper.
func sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
