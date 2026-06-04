package redisx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/redisx"
)

func TestParseSentinelAddrs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "redis-sentinel-0:26379", []string{"redis-sentinel-0:26379"}},
		{"trio with spaces", " a:1 , b:2 ,c:3", []string{"a:1", "b:2", "c:3"}},
		{"trailing comma", "a:1,", []string{"a:1"}},
		{"only commas", " , , ", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, redisx.ParseSentinelAddrs(c.in))
		})
	}
}

func TestOpen_RequiresAddrInSingleMode(t *testing.T) {
	_, err := redisx.Open(redisx.Config{Mode: redisx.ModeSingle})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Addr is required")
}

func TestOpen_RequiresMasterAndAddrsInSentinelMode(t *testing.T) {
	_, err := redisx.Open(redisx.Config{Mode: redisx.ModeSentinel, SentinelAddrs: []string{"s1:26379"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SentinelMaster")

	_, err = redisx.Open(redisx.Config{Mode: redisx.ModeSentinel, SentinelMaster: "mymaster"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SentinelAddrs")
}

func TestOpen_RejectsUnknownMode(t *testing.T) {
	_, err := redisx.Open(redisx.Config{Mode: redisx.Mode("redis-cluster"), Addr: "x:1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown mode")
}

func TestOpen_InfersModeFromSentinelAddrs(t *testing.T) {
	// Mode "" + SentinelAddrs set should infer sentinel mode (and then
	// fail because we didn't set SentinelMaster — proving the inference
	// happened).
	_, err := redisx.Open(redisx.Config{SentinelAddrs: []string{"s1:26379"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SentinelMaster",
		"empty Mode + SentinelAddrs must infer sentinel mode")
}

func TestOpen_InfersModeFromAddr(t *testing.T) {
	// Mode "" + Addr should produce a working single-mode client.
	rdb, err := redisx.Open(redisx.Config{Addr: "127.0.0.1:6379"})
	require.NoError(t, err)
	require.NotNil(t, rdb)
	_ = rdb.Close()
}
