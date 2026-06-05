package bus_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBus_PublishFansOutToSameTenant(t *testing.T) {
	b := bus.New()
	tenant := uuid.New()
	chA, unsubA := b.Subscribe(tenant, 4)
	defer unsubA()
	chB, unsubB := b.Subscribe(tenant, 4)
	defer unsubB()
	assert.Equal(t, 2, b.SubscriberCount(tenant))

	evt := bus.Event{Kind: bus.RunStarted, OrgID: tenant, RunID: uuid.New(), At: time.Now()}
	b.Publish(evt)

	for _, ch := range []<-chan bus.Event{chA, chB} {
		select {
		case got := <-ch:
			assert.Equal(t, bus.RunStarted, got.Kind)
			assert.Equal(t, evt.RunID, got.RunID)
		case <-time.After(time.Second):
			t.Fatal("subscriber did not receive event")
		}
	}
}

func TestBus_NoCrossTenantLeak(t *testing.T) {
	b := bus.New()
	a, bnt := uuid.New(), uuid.New()
	chA, unsubA := b.Subscribe(a, 4)
	defer unsubA()
	chB, unsubB := b.Subscribe(bnt, 4)
	defer unsubB()

	b.Publish(bus.Event{Kind: bus.RunCompleted, OrgID: a, RunID: uuid.New()})

	select {
	case got := <-chA:
		assert.Equal(t, bus.RunCompleted, got.Kind)
	case <-time.After(time.Second):
		t.Fatal("tenant A did not receive its own event")
	}
	select {
	case <-chB:
		t.Fatal("tenant B should not have received tenant A's event")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBus_UnsubscribeDeregisters(t *testing.T) {
	b := bus.New()
	tenant := uuid.New()
	ch, unsub := b.Subscribe(tenant, 4)
	assert.Equal(t, 1, b.SubscriberCount(tenant))

	unsub()
	assert.Equal(t, 0, b.SubscriberCount(tenant))

	b.Publish(bus.Event{Kind: bus.RunStarted, OrgID: tenant, RunID: uuid.New()})
	select {
	case got, ok := <-ch:
		if ok {
			t.Fatalf("received event %v after unsubscribe", got)
		}
	case <-time.After(50 * time.Millisecond):
	}
}

func TestBus_SlowSubscriberIsDroppedNotBlocking(t *testing.T) {
	b := bus.New()
	tenant := uuid.New()
	_, unsub := b.Subscribe(tenant, 1) // 1-buffered + never drained
	defer unsub()

	done := make(chan struct{})
	go func() {
		for range 1000 {
			b.Publish(bus.Event{Kind: bus.RunStarted, OrgID: tenant, RunID: uuid.New()})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish stalled on a slow subscriber")
	}
}

func TestBus_ConcurrentPublishersAndSubscribers(t *testing.T) {
	b := bus.New()
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
				b.Publish(bus.Event{Kind: bus.RunStarted, OrgID: tenant, RunID: id})
			}
		}(runIDs[i])
	}
	pubWG.Wait()
	time.Sleep(100 * time.Millisecond) // give subscribers a beat to drain
	close(subStop)
	wg.Wait()

	require.Greater(t, int(received.Load()), 0, "subscribers should see at least some events")
}
