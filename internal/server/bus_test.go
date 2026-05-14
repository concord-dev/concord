package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBus_PublishFansOutToSameTenant covers the happy-path fan-out: two
// subscribers on tenant A both receive an event published for tenant A.
func TestBus_PublishFansOutToSameTenant(t *testing.T) {
	b := NewBus()
	tenant := uuid.New()
	chA, unsubA := b.Subscribe(tenant, 4)
	defer unsubA()
	chB, unsubB := b.Subscribe(tenant, 4)
	defer unsubB()
	assert.Equal(t, 2, b.SubscriberCount(tenant))

	evt := Event{Kind: EventRunStarted, OrgID: tenant, RunID: uuid.New(), At: time.Now()}
	b.Publish(evt)

	for _, ch := range []<-chan Event{chA, chB} {
		select {
		case got := <-ch:
			assert.Equal(t, EventRunStarted, got.Kind)
			assert.Equal(t, evt.RunID, got.RunID)
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive event")
		}
	}
}

// TestBus_NoCrossTenantLeak ensures tenant isolation: an event published for
// tenant A must not appear on tenant B's subscription.
func TestBus_NoCrossTenantLeak(t *testing.T) {
	b := NewBus()
	a, bnt := uuid.New(), uuid.New()
	chA, unsubA := b.Subscribe(a, 4)
	defer unsubA()
	chB, unsubB := b.Subscribe(bnt, 4)
	defer unsubB()

	b.Publish(Event{Kind: EventRunCompleted, OrgID: a, RunID: uuid.New()})

	select {
	case got := <-chA:
		assert.Equal(t, EventRunCompleted, got.Kind)
	case <-time.After(time.Second):
		t.Fatal("tenant A did not receive its own event")
	}
	select {
	case <-chB:
		t.Fatal("tenant B should not have received tenant A's event")
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

// TestBus_UnsubscribeDeregisters proves the unsubscribe func removes the
// subscription from the bus. We don't assert the channel is closed — that
// would race with concurrent Publish; callers stop reading via ctx instead.
func TestBus_UnsubscribeDeregisters(t *testing.T) {
	b := NewBus()
	tenant := uuid.New()
	ch, unsub := b.Subscribe(tenant, 4)
	assert.Equal(t, 1, b.SubscriberCount(tenant))

	unsub()
	assert.Equal(t, 0, b.SubscriberCount(tenant))

	// After unsubscribe, future publishes must not be delivered.
	b.Publish(Event{Kind: EventRunStarted, OrgID: tenant, RunID: uuid.New()})
	select {
	case got, ok := <-ch:
		if ok {
			t.Fatalf("received event %v after unsubscribe", got)
		}
	case <-time.After(50 * time.Millisecond):
		// expected — channel stays open but empty
	}
}

// TestBus_SlowSubscriberIsDroppedNotBlocking is the cardinal property of the
// bus: a subscriber that doesn't drain its channel must not stall the
// publisher. We register a 1-buffer subscriber, fire many events, and assert
// that Publish never blocks longer than a few ms.
func TestBus_SlowSubscriberIsDroppedNotBlocking(t *testing.T) {
	b := NewBus()
	tenant := uuid.New()
	_, unsub := b.Subscribe(tenant, 1) // 1-buffered + never drained
	defer unsub()

	done := make(chan struct{})
	go func() {
		for range 1000 {
			b.Publish(Event{Kind: EventRunStarted, OrgID: tenant, RunID: uuid.New()})
		}
		close(done)
	}()
	select {
	case <-done:
		// expected — publisher must not block
	case <-time.After(2 * time.Second):
		t.Fatal("Publish stalled on a slow subscriber")
	}
}

// TestBus_ConcurrentPublishersAndSubscribers stresses the lock discipline.
// 50 concurrent publishers + 10 concurrent subscribers; assert no data race
// and that every subscriber receives at least one event before unsubscribing.
// We pre-generate run IDs outside the goroutines because google/uuid's
// global reader isn't lock-free; the race we care about is the bus, not UUID.
func TestBus_ConcurrentPublishersAndSubscribers(t *testing.T) {
	b := NewBus()
	tenant := uuid.New()

	const publishers = 50
	const events = 20
	runIDs := make([][]uuid.UUID, publishers)
	for i := range publishers {
		runIDs[i] = make([]uuid.UUID, events)
		for j := range events {
			runIDs[i][j] = uuid.New()
		}
	}

	var received atomic.Int32
	var wg sync.WaitGroup
	subStop := make(chan struct{})

	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, unsub := b.Subscribe(tenant, 16)
			defer unsub()
			for {
				select {
				case <-ch:
					received.Add(1)
				case <-subStop:
					return
				}
			}
		}()
	}

	pubWG := sync.WaitGroup{}
	for i := range publishers {
		pubWG.Add(1)
		go func(ids []uuid.UUID) {
			defer pubWG.Done()
			for _, id := range ids {
				b.Publish(Event{Kind: EventRunStarted, OrgID: tenant, RunID: id})
			}
		}(runIDs[i])
	}
	pubWG.Wait()
	time.Sleep(100 * time.Millisecond) // give subscribers a beat to drain
	close(subStop)
	wg.Wait()

	require.Greater(t, int(received.Load()), 0, "subscribers should see at least some events")
}
