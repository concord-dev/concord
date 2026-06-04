package eventbus

import (
	"context"

	"github.com/segmentio/kafka-go"
)

// KafkaPublisher adapts a *kafka.Writer to the Publisher interface.
// Construct via NewKafkaPublisher. Defined here (rather than in
// internal/kafkax) so eventbus stays the single source of truth for the
// Publisher contract; the Writer is built by cmd/server via the kafkax
// factory and handed to this constructor.
type KafkaPublisher struct {
	writer *kafka.Writer
}

// NewKafkaPublisher wraps w. The writer must already be configured with
// Topic, RequiredAcks, etc. Caller owns w's lifecycle — call w.Close()
// on shutdown to flush in-flight batches.
func NewKafkaPublisher(w *kafka.Writer) *KafkaPublisher {
	return &KafkaPublisher{writer: w}
}

// Publish writes one message with key + payload + headers. Returns any
// broker error so the Dispatcher can mark the outbox row for retry.
//
// Headers are translated to kafka.Header pairs; consumers can read them
// without parsing the body so a worker can filter on event-kind before
// deciding whether to deserialize.
func (p *KafkaPublisher) Publish(ctx context.Context, key string, payload []byte, headers map[string]string) error {
	hs := make([]kafka.Header, 0, len(headers))
	for k, v := range headers {
		hs = append(hs, kafka.Header{Key: k, Value: []byte(v)})
	}
	return p.writer.WriteMessages(ctx, kafka.Message{
		Key:     []byte(key),
		Value:   payload,
		Headers: hs,
	})
}
