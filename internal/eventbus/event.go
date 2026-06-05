package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	EventID     uuid.UUID `json:"event_id"`
	OrgID       uuid.UUID `json:"org_id"`
	Kind        string    `json:"kind"`
	OccurredAt  time.Time `json:"occurred_at"`
	Data        any       `json:"data,omitempty"`
	Traceparent string    `json:"-"`
}

type Envelope struct {
	Version    int             `json:"version"`
	EventID    uuid.UUID       `json:"event_id"`
	OrgID      uuid.UUID       `json:"org_id"`
	Kind       string          `json:"kind"`
	OccurredAt time.Time       `json:"occurred_at"`
	Data       json.RawMessage `json:"data,omitempty"`
}

const EnvelopeVersion = 1

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

var ErrInvalidEvent = errors.New("eventbus: event is missing required fields")

func (e *Event) validate() error {
	if e.OrgID == uuid.Nil {
		return ErrInvalidEvent
	}
	if e.Kind == "" {
		return ErrInvalidEvent
	}
	if e.EventID == uuid.Nil {
		e.EventID = uuid.New()
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	return nil
}

type Publisher interface {
	Publish(ctx context.Context, key string, payload []byte, headers map[string]string) error
}

type PublisherFunc func(ctx context.Context, key string, payload []byte, headers map[string]string) error

func (f PublisherFunc) Publish(ctx context.Context, key string, payload []byte, headers map[string]string) error {
	return f(ctx, key, payload, headers)
}
