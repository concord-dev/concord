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

type ConsumerConfig struct {
	Brokers         []string
	Topic           string
	GroupID         string
	MinBytes        int
	MaxBytes        int
	MaxWait         time.Duration
	DedupeTTL       time.Duration
	DedupeKeyPrefix string
}

type ConsumerMetrics struct {
	Consumed    func(kind string)
	DedupeHit   func(kind string)
	BadMessage  func(reason string)
	NoWebhooks  func(kind string)
	FanoutSize  func(kind string, size int)
	CommitErr   func(err error)
	ConsumerLag func(seconds float64)
}

type Consumer struct {
	store    *store.Store
	redis    *redis.Client
	executor *Executor
	cfg      ConsumerConfig
	metrics  ConsumerMetrics
	reader   *kafka.Reader
}

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
		CommitInterval: 0,
		StartOffset:    kafka.FirstOffset,
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
			slog.Warn("worker consumer: fetch error",
				slog.String("err", err.Error()))
			sleep(ctx, 1*time.Second)
			continue
		}
		if err := c.processOne(ctx, m); err != nil {
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
		}
	}
}

func (c *Consumer) processOne(ctx context.Context, m kafka.Message) error {
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

	if c.redis != nil {
		key := c.cfg.DedupeKeyPrefix + eventID.String()
		setCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		ok, err := c.redis.SetNX(setCtx, key, "1", c.cfg.DedupeTTL).Result()
		cancel()
		if err != nil {
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
		existing, err := c.store.GetWebhookDelivery(ctx, id)
		if err != nil {
			return fmt.Errorf("re-read existing delivery: %w", err)
		}
		switch existing.Status {
		case store.DeliverySucceeded, store.DeliveryDead:
			return nil
		}
		return nil
	}

	_, err = c.executor.Attempt(ctx, nil, id, kind, h.URL, h.Secret, body, false)
	return err
}

func headerMap(hs []kafka.Header) map[string]string {
	out := make(map[string]string, len(hs))
	for _, h := range hs {
		out[h.Key] = string(h.Value)
	}
	return out
}

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
