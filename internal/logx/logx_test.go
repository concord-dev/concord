package logx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/logx"
)

func TestRequestIDRoundTripsThroughContext(t *testing.T) {
	ctx := logx.WithRequestID(context.Background(), "req-abc")
	assert.Equal(t, "req-abc", logx.RequestID(ctx))
}

func TestRequestID_AbsentReturnsEmpty(t *testing.T) {
	assert.Empty(t, logx.RequestID(context.Background()))
}

func TestFromContext_BindsRequestIDAttribute(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(logx.NewForTest(&buf, slog.LevelInfo))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := logx.WithRequestID(context.Background(), "req-xyz")
	logx.FromContext(ctx).Info("hello", slog.String("k", "v"))

	var rec map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec))
	assert.Equal(t, "req-xyz", rec["request_id"], "request_id must surface on every record")
	assert.Equal(t, "hello", rec["msg"])
	assert.Equal(t, "v", rec["k"])
}

func TestFromContext_NoIDOmitsAttribute(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(logx.NewForTest(&buf, slog.LevelInfo))
	t.Cleanup(func() { slog.SetDefault(prev) })

	logx.FromContext(context.Background()).Info("hi")

	var rec map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec))
	_, has := rec["request_id"]
	assert.False(t, has, "request_id must be absent when ctx has no ID")
}
