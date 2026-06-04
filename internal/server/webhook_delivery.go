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

// kindRunCompleted and kindDriftDetected are the canonical Kafka event
// names — distinct from the in-process bus.Kind values so the wire
// schema doesn't bleed the internal SSE event taxonomy. The consumer
// (cmd/concord-worker) switches on these to drive webhook delivery.
const (
	kindRunCompleted  = "run.completed"
	kindDriftDetected = "drift.detected"
)

// signPayload returns the value for the X-Concord-Signature header. The
// "sha256=" prefix matches the GitHub / Stripe convention so receivers can
// pick the algorithm from the header.
//
// Webhook *delivery* lives in cmd/concord-worker; this helper exists
// because the public VerifyWebhookSignature below — used by tests and
// any receiver that wires the server's package — needs to compute the
// same MAC. Worker delivery uses internal/worker/executor.go's sign()
// (byte-identical implementation).
func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature is exported for receivers (and tests) that want to
// check signatures. Uses constant-time comparison.
func VerifyWebhookSignature(secret string, body []byte, headerValue string) bool {
	want := signPayload(secret, body)
	return hmac.Equal([]byte(want), []byte(headerValue))
}

// Broadcast is the post-SubmitRun side-effect: publish run.completed on
// the in-process bus (so SSE subscribers see it instantly) and enqueue
// a durable event_outbox row so cmd/concord-worker can ship the event
// to Kafka and fan out to registered webhooks. No in-process webhook
// delivery any more — operators must deploy the worker for webhooks to
// fire.
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

// BroadcastDrift publishes a control.drifted event when SubmitRun
// detected at least one control transition. Mirrors Broadcast's shape
// but carries the per-control transition payload. No-op when
// transitions is empty so callers don't need to guard.
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

// enqueueOutbox writes one row to event_outbox so the dispatcher ships
// it to Kafka. Best-effort: the underlying SubmitRun has already
// committed the run row by the time we're called, so an outbox failure
// here means a missed event but a valid run. The error path bumps the
// tick-error metric and logs loudly so an operator notices a sustained
// outage; for the canonical happy path the call is sub-millisecond
// because the INSERT goes against a single-row index.
//
// The traceparent header is captured from the caller's context (when
// present) so the consumer span links back to the originating HTTP
// request.
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
