package server

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EventKind enumerates the run-lifecycle events emitted by the worker.
type EventKind string

const (
	EventRunStarted   EventKind = "run.started"
	EventRunCompleted EventKind = "run.completed"
	EventRunFailed    EventKind = "run.failed"
)

// Event is the wire shape pushed over SSE to subscribed clients.
type Event struct {
	Kind    EventKind       `json:"kind"`
	OrgID   uuid.UUID       `json:"org_id"`
	RunID   uuid.UUID       `json:"run_id"`
	At      time.Time       `json:"at"`
	Status  string          `json:"status,omitempty"`
	Summary json.RawMessage `json:"summary,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// Bus is the in-process fan-out for per-org events. Subscribers are
// non-blocking: a slow consumer is dropped rather than holding back the
// publisher. Multi-instance fan-out (Redis pub/sub, NATS, pg-notify) lands
// when concord-server itself goes horizontal.
type Bus struct {
	mu   sync.RWMutex
	subs map[uuid.UUID]map[*subscription]struct{}
}

type subscription struct {
	ch chan Event
}

// NewBus returns an empty Bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[uuid.UUID]map[*subscription]struct{})}
}

// Subscribe registers a per-org subscriber and returns its receive channel
// plus an unsubscribe func. bufSize is the per-subscriber buffer; events
// beyond the buffer are dropped (never block the publisher).
//
// Note: the returned channel is intentionally NOT closed by the unsub func.
// Closing would race with concurrent Publish sends; instead, callers signal
// "I'm done" via context cancellation in their select loop.
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

// Publish fans the event to every subscriber registered to the event's
// OrgID. Subscribers whose buffer is full are skipped (and a warning is
// logged to stderr) so a single slow client cannot stall the worker.
//
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
			fmt.Fprintf(os.Stderr, "bus: subscriber for org %s is full, dropping %s\n",
				e.OrgID, e.Kind)
		}
	}
}

// SubscriberCount is exposed for tests + diagnostics.
func (b *Bus) SubscriberCount(orgID uuid.UUID) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[orgID])
}
