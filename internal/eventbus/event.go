// Package eventbus is the durable event pipeline that connects Concord's
// HTTP handlers to the downstream worker (Phase 3) via Kafka. It owns two
// concerns:
//
//  1. The transactional outbox table (event_outbox). Handlers call
//     Outbox.Enqueue inside the same SQL transaction as the state change
//     they describe. This is the only safe way to avoid the dual-write
//     problem (DB commits but Kafka fails, or vice versa).
//
//  2. A long-running Dispatcher that polls event_outbox, ships rows to
//     Kafka, and records published_at on success. Failed publishes
//     bump attempt_count with exponential backoff; rows that exceed
//     MaxAttempts stay un-published for operator inspection.
//
// The package does not import the kafka SDK directly. Publisher is a
// small interface — cmd/server wires the concrete kafkax-backed
// implementation; tests pass a fake. This keeps the dispatcher
// independently testable without booting a real broker.
package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Event is the in-memory shape a handler enqueues. The Outbox marshals it
// to the canonical Envelope JSON before persisting; the wire bytes are
// what eventually lands on the Kafka topic.
//
// EventID is the consumer-facing idempotency key. Generate it at the
// originating handler so a retried handler call produces the same
// EventID and the consumer can dedupe.
//
// OccurredAt is the *domain* time (the run completed, the drift was
// detected). It can differ from when the outbox row is inserted (e.g. a
// backfill replays historical runs).
type Event struct {
	EventID     uuid.UUID `json:"event_id"`
	OrgID       uuid.UUID `json:"org_id"`
	Kind        string    `json:"kind"`
	OccurredAt  time.Time `json:"occurred_at"`
	Data        any       `json:"data,omitempty"`
	Traceparent string    `json:"-"` // captured into a column, not the JSON body
}

// Envelope is the canonical on-wire shape. Consumers parse this; bump
// Version on every breaking change to the schema so old workers can
// fail-loudly rather than silently mis-process. Today only Version=1
// exists.
type Envelope struct {
	Version    int             `json:"version"`
	EventID    uuid.UUID       `json:"event_id"`
	OrgID      uuid.UUID       `json:"org_id"`
	Kind       string          `json:"kind"`
	OccurredAt time.Time       `json:"occurred_at"`
	Data       json.RawMessage `json:"data,omitempty"`
}

// EnvelopeVersion is the current schema version. Bumped only on a
// breaking change; additive fields don't bump it.
const EnvelopeVersion = 1

// marshalEnvelope produces the bytes that go in both the outbox.payload
// column and on the Kafka wire. Returns an error on a non-serialisable
// Data — the caller should treat that as a programming bug (panic-worthy
// in a handler).
func marshalEnvelope(e Event) ([]byte, error) {
	var data json.RawMessage
	if e.Data != nil {
		b, err := json.Marshal(e.Data)
		if err != nil {
			return nil, err
		}
		data = b
	}
	return json.Marshal(Envelope{
		Version:    EnvelopeVersion,
		EventID:    e.EventID,
		OrgID:      e.OrgID,
		Kind:       e.Kind,
		OccurredAt: e.OccurredAt,
		Data:       data,
	})
}

// ErrInvalidEvent is returned by Enqueue when a required field is missing.
// Callers should treat this as a programming bug — a handler shouldn't
// be reachable without OrgID and Kind set.
var ErrInvalidEvent = errors.New("eventbus: event is missing required fields")

// validate is the cheap pre-flight gate Enqueue runs before opening the
// SQL transaction. Better to fail at the call site than to write a row
// that will fail at consume.
func (e *Event) validate() error {
	if e.OrgID == uuid.Nil {
		return ErrInvalidEvent
	}
	if e.Kind == "" {
		return ErrInvalidEvent
	}
	if e.EventID == uuid.Nil {
		// Allow callers to leave EventID empty for convenience; we
		// mint one. Doing it here means every outbox row has one, even
		// if a handler forgets.
		e.EventID = uuid.New()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	return nil
}

// Publisher is the small surface the Dispatcher uses to ship a marshaled
// envelope to its eventual destination. Concrete impl: a kafka-go
// Writer wrapper; test impl: an in-memory recorder.
//
// Publish is invoked with the partition key (= OrgID string) plus the
// already-marshaled envelope and per-message headers. The headers carry
// metadata the consumer wants to filter on without parsing the body
// (event-kind, event-id, traceparent). A non-nil error tells the
// dispatcher to retry with backoff.
type Publisher interface {
	Publish(ctx context.Context, key string, payload []byte, headers map[string]string) error
}

// PublisherFunc is the function-typed adapter for Publisher, useful for
// inline mocks in tests.
type PublisherFunc func(ctx context.Context, key string, payload []byte, headers map[string]string) error

// Publish satisfies the Publisher interface.
func (f PublisherFunc) Publish(ctx context.Context, key string, payload []byte, headers map[string]string) error {
	return f(ctx, key, payload, headers)
}
