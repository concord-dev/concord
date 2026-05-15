// Package bus is the in-process fan-out for per-org run-lifecycle events.
// Subscribers (the SSE handler) receive events filtered by org id; publishers
// (the worker) are non-blocking — slow consumers are dropped rather than
// stalling the producer.
package bus

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Kind enumerates the run-lifecycle events emitted by the worker.
type Kind string

const (
	RunStarted   Kind = "run.started"
	RunCompleted Kind = "run.completed"
	RunFailed    Kind = "run.failed"
)

// Event is the wire shape pushed over SSE to subscribed clients.
type Event struct {
	Kind    Kind            `json:"kind"`
	OrgID   uuid.UUID       `json:"org_id"`
	RunID   uuid.UUID       `json:"run_id"`
	At      time.Time       `json:"at"`
	Status  string          `json:"status,omitempty"`
	Summary json.RawMessage `json:"summary,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Bus fans events out to per-org subscribers.
type Bus struct {
	mu   sync.RWMutex
	subs map[uuid.UUID]map[*subscription]struct{}
}

type subscription struct {
	ch chan Event
}

// New returns an empty Bus.
func New() *Bus {
	return &Bus{subs: make(map[uuid.UUID]map[*subscription]struct{})}
}

// Subscribe registers a per-org subscriber and returns its receive channel
// plus an unsubscribe func. bufSize is the per-subscriber buffer; events
// beyond the buffer are dropped (never block the publisher).
//
// Note: the returned channel is intentionally NOT closed by the unsub func.
// Closing would race with concurrent Publish sends; callers signal "done" via
// context cancellation in their select loop.
func (b *Bus) Subscribe(orgID uuid.UUID, bufSize int) (<-chan Event, func()) {
	if bufSize <= 0 {
		bufSize = 16
	}
	sub := &subscription{ch: make(chan Event, bufSize)}
	b.mu.Lock()
	if b.subs[orgID] == nil {
		b.subs[orgID] = make(map[*subscription]struct{})
	}
	b.subs[orgID][sub] = struct{}{}
	b.mu.Unlock()

	unsub := func() {
		b.mu.Lock()
		if set, ok := b.subs[orgID]; ok {
			delete(set, sub)
			if len(set) == 0 {
				delete(b.subs, orgID)
			}
		}
		b.mu.Unlock()
	}
	return sub.ch, unsub
}

// Publish fans the event to every subscriber registered for the event's OrgID.
// The subscriber list is snapshotted under the lock so concurrent
// Subscribe/Unsubscribe calls don't race with the fan-out iteration.
func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	set := b.subs[e.OrgID]
	subs := make([]*subscription, 0, len(set))
	for s := range set {
		subs = append(subs, s)
	}
	b.mu.RUnlock()

	for _, sub := range subs {
		select {
		case sub.ch <- e:
		default:
			slog.Warn("bus subscriber backlog full; event dropped",
				slog.String("org_id", e.OrgID.String()),
				slog.String("kind", string(e.Kind)))
		}
	}
}

// SubscriberCount is exposed for tests + diagnostics.
func (b *Bus) SubscriberCount(orgID uuid.UUID) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[orgID])
}
