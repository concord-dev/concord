package eventbus_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/eventbus"
	"github.com/concord-dev/concord/internal/kafkax"
)

// TestKafkaPublisher_RoundTripThroughOutbox is the integration test that
// proves the entire Phase 2 pipe: Enqueue → Dispatcher → Kafka writer
// → broker → consumer can read the canonical envelope. Skipped without
// CONCORD_TEST_KAFKA_BROKERS set; CI provides a Redpanda service
// container.
func TestKafkaPublisher_RoundTripThroughOutbox(t *testing.T) {
	brokersCSV := os.Getenv("CONCORD_TEST_KAFKA_BROKERS")
	if brokersCSV == "" {
		t.Skip("set CONCORD_TEST_KAFKA_BROKERS=host:port[,…] to run the Kafka integration test")
	}
	brokers := kafkax.ParseBrokers(brokersCSV)

	// Per-run topic so re-runs don't see stale messages.
	topic := "concord.events.test." + uuid.NewString()[:8]
	createTopic(t, brokers, topic)

	pool := openIsolatedPool(t)
	orgID := seedOrg(t, pool)
	outbox := eventbus.NewOutbox(pool)

	writer, err := kafkax.NewWriter(kafkax.Config{
		Brokers:      brokers,
		Topic:        topic,
		Compression:  kafkax.CompressionSnappy,
		WriteTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })
	publisher := eventbus.NewKafkaPublisher(writer)

	d, err := eventbus.NewDispatcher(outbox, publisher, eventbus.DispatcherConfig{
		PollInterval: 20 * time.Millisecond,
		BatchSize:    5,
	}, eventbus.DispatcherMetrics{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	// Enqueue three events.
	for i := 0; i < 3; i++ {
		_, err := outbox.Enqueue(ctx, eventbus.Event{
			OrgID:       orgID,
			Kind:        "run.completed",
			OccurredAt:  time.Now().UTC(),
			Data:        map[string]any{"i": i},
			Traceparent: "00-deadbeef-cafef00d-01",
		})
		require.NoError(t, err)
	}

	// Read them back from Kafka.
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:        brokers,
		Topic:          topic,
		StartOffset:    kafka.FirstOffset,
		MinBytes:       1,
		MaxBytes:       1 << 20,
		MaxWait:        100 * time.Millisecond,
		CommitInterval: 0,
		GroupID:        "", // standalone consumer
	})
	t.Cleanup(func() { _ = r.Close() })

	readCtx, readCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readCancel()
	got := make([]kafka.Message, 0, 3)
	for len(got) < 3 {
		m, err := r.ReadMessage(readCtx)
		require.NoError(t, err)
		got = append(got, m)
	}

	for _, m := range got {
		assert.Equal(t, orgID.String(), string(m.Key), "partition key must be org_id")

		// Headers must carry the metadata the consumer needs.
		hmap := map[string]string{}
		for _, h := range m.Headers {
			hmap[h.Key] = string(h.Value)
		}
		assert.Equal(t, "run.completed", hmap["event-kind"])
		assert.NotEmpty(t, hmap["event-id"])
		assert.Equal(t, "00-deadbeef-cafef00d-01", hmap["traceparent"])

		// Body is the canonical envelope.
		var env map[string]any
		require.NoError(t, json.Unmarshal(m.Value, &env))
		assert.EqualValues(t, 1, env["version"])
		assert.Equal(t, "run.completed", env["kind"])
		assert.Equal(t, orgID.String(), env["org_id"])
	}
}

// createTopic ensures the test topic exists. Redpanda accepts produces
// without an explicit topic create (auto-create on first produce) but
// kafka-go's writer is configured with AllowAutoTopicCreation=false so
// we have to create it ourselves.
func createTopic(t *testing.T, brokers []string, topic string) {
	t.Helper()
	conn, err := kafka.Dial("tcp", brokers[0])
	require.NoError(t, err)
	defer conn.Close()
	controller, err := conn.Controller()
	require.NoError(t, err)
	cc, err := kafka.Dial("tcp", controller.Host+":"+itoa(controller.Port))
	require.NoError(t, err)
	defer cc.Close()
	require.NoError(t, cc.CreateTopics(kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	}))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
