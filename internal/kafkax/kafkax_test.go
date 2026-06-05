package kafkax_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/kafkax"
)

func TestParseBrokers(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "kafka:9092", []string{"kafka:9092"}},
		{"trio with spaces", " a:1, b:2 , c:3 ", []string{"a:1", "b:2", "c:3"}},
		{"only commas", ", ,", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, kafkax.ParseBrokers(c.in))
		})
	}
}

func TestNewWriter_RequiresBrokers(t *testing.T) {
	_, err := kafkax.NewWriter(kafkax.Config{Topic: "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Brokers")
}

func TestNewWriter_RequiresTopic(t *testing.T) {
	_, err := kafkax.NewWriter(kafkax.Config{Brokers: []string{"a:1"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Topic")
}

func TestNewWriter_RejectsUnknownSASLMechanism(t *testing.T) {
	_, err := kafkax.NewWriter(kafkax.Config{
		Brokers:       []string{"a:1"},
		Topic:         "x",
		SASLMechanism: kafkax.SASLMechanism("oauth-bearer"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown SASL mechanism")
}

func TestNewWriter_PlainRequiresCredentials(t *testing.T) {
	_, err := kafkax.NewWriter(kafkax.Config{
		Brokers:       []string{"a:1"},
		Topic:         "x",
		SASLMechanism: kafkax.SASLPlain,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PLAIN")
}

func TestNewWriter_Defaults(t *testing.T) {
	w, err := kafkax.NewWriter(kafkax.Config{
		Brokers: []string{"localhost:9092"},
		Topic:   "concord.events",
	})
	require.NoError(t, err)
	require.NotNil(t, w)
	_ = w.Close()
}
