package bus

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Kind string

const (
	RunStarted   Kind = "run.started"
	RunCompleted Kind = "run.completed"
	RunFailed    Kind = "run.failed"
	ControlDrifted Kind = "control.drifted"
)

type Transition struct {
	ControlID string `json:"control_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Rationale string `json:"rationale,omitempty"`
}

type Event struct {
	Kind        Kind            `json:"kind"`
	OrgID       uuid.UUID       `json:"org_id"`
	RunID       uuid.UUID       `json:"run_id"`
	At          time.Time       `json:"at"`
	Status      string          `json:"status,omitempty"`
	Summary     json.RawMessage `json:"summary,omitempty"`
	Error       string          `json:"error,omitempty"`
	Transitions []Transition `json:"transitions,omitempty"`
}

type Bus struct {
	mu   sync.RWMutex
	subs map[uuid.UUID]map[*subscription]struct{}
	OnDrop func(orgID uuid.UUID, kind Kind)
}

type subscription struct {
	ch chan Event
}

func New() *Bus {
	return &Bus{subs: make(map[uuid.UUID]map[*subscription]struct{})}
}

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
			if b.OnDrop != nil {
				b.OnDrop(e.OrgID, e.Kind)
			}
		}
	}
}

func (b *Bus) SubscriberCount(orgID uuid.UUID) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[orgID])
}
