package eventbus

import (
	"context"

	"github.com/segmentio/kafka-go"
)

type KafkaPublisher struct {
	writer *kafka.Writer
}

func NewKafkaPublisher(w *kafka.Writer) *KafkaPublisher {
	return &KafkaPublisher{writer: w}
}

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
