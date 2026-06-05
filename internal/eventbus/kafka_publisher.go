package eventbus

import (
	"context"

	"github.com/segmentio/kafka-go"
)

// KafkaPublisher adapts a *kafka.Writer to the Publisher interface.
type KafkaPublisher struct {
	writer *kafka.Writer
}

// NewKafkaPublisher wraps w. Caller owns w's lifecycle.
func NewKafkaPublisher(w *kafka.Writer) *KafkaPublisher {
	return &KafkaPublisher{writer: w}
}

// Publish writes one message with key + payload + headers.
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
