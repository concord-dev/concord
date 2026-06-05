package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"

	"github.com/concord-dev/concord/internal/eventbus"
	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/store"
)

const (
	kindRunCompleted  = "run.completed"
	kindDriftDetected = "drift.detected"
)

func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func VerifyWebhookSignature(secret string, body []byte, headerValue string) bool {
	want := signPayload(secret, body)
	return hmac.Equal([]byte(want), []byte(headerValue))
}

func (c *Concord) Broadcast(run store.Run, summary []byte) {
	at := time.Now().UTC()
	if run.CompletedAt != nil {
		at = *run.CompletedAt
	}
	evt := bus.Event{
		Kind:    bus.RunCompleted,
		OrgID:   run.OrgID,
		RunID:   run.ID,
		At:      at,
		Status:  string(run.Status),
		Summary: summary,
	}
	c.bus.Publish(evt)
	c.enqueueOutbox(context.Background(), kindRunCompleted, run.OrgID, at, map[string]any{
		"run_id":  run.ID,
		"status":  string(run.Status),
		"summary": json.RawMessage(summary),
	})
}

func (c *Concord) BroadcastDrift(run store.Run, transitions []bus.Transition) {
	if len(transitions) == 0 {
		return
	}
	at := time.Now().UTC()
	if run.CompletedAt != nil {
		at = *run.CompletedAt
	}
	evt := bus.Event{
		Kind:        bus.ControlDrifted,
		OrgID:       run.OrgID,
		RunID:       run.ID,
		At:          at,
		Transitions: transitions,
	}
	c.bus.Publish(evt)
	c.enqueueOutbox(context.Background(), kindDriftDetected, run.OrgID, at, map[string]any{
		"run_id":      run.ID,
		"transitions": transitions,
	})
}

func (c *Concord) enqueueOutbox(ctx context.Context, kind string, orgID uuid.UUID, occurredAt time.Time, data any) {
	if c.outbox == nil {
		return
	}
	var traceparent string
	carrier := propagation.MapCarrier{}
	otel.GetTextMapPropagator().Inject(ctx, carrier)
	if tp, ok := carrier["traceparent"]; ok {
		traceparent = tp
	}
	if _, err := c.outbox.Enqueue(ctx, eventbus.Event{
		EventID:     uuid.New(),
		OrgID:       orgID,
		Kind:        kind,
		OccurredAt:  occurredAt,
		Data:        data,
		Traceparent: traceparent,
	}); err != nil {
		c.metrics.OutboxTickErrorsTotal.WithLabelValues("enqueue").Inc()
		slog.Error("event outbox enqueue failed",
			slog.String("kind", kind),
			slog.String("org_id", orgID.String()),
			slog.String("err", err.Error()))
		return
	}
	c.metrics.RecordOutboxEnqueued(kind)
}
