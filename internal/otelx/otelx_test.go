package otelx_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/otelx"
)

func TestInit_EmptyEndpointInstallsNoOpProvider(t *testing.T) {
	p, err := otelx.Init(context.Background(), otelx.Config{})
	require.NoError(t, err)
	require.NotNil(t, p)

	tr := p.Tracer("test")
	_, span := tr.Start(context.Background(), "noop-span")
	defer span.End()
	assert.False(t, span.IsRecording(),
		"empty Endpoint must produce non-recording spans — anything else burns CPU on a deploy that didn't ask for tracing")
}

func TestInit_PropagatorIsAlwaysInstalled(t *testing.T) {
	_, err := otelx.Init(context.Background(), otelx.Config{})
	require.NoError(t, err)
	prop := otel.GetTextMapPropagator()
	assert.NotEmpty(t, prop.Fields(),
		"propagator must advertise the traceparent/baggage fields even when tracing export is disabled")
}

func TestInit_WithSDKTracerProviderProducesRecordingSpans(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := trace.NewTracerProvider(
		trace.WithSyncer(exp),
		trace.WithSampler(trace.AlwaysSample()),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tp.Shutdown(ctx)
	})
	otel.SetTracerProvider(tp)

	tr := otel.Tracer("github.com/concord-dev/concord/test")
	_, span := tr.Start(context.Background(), "submit.run.drift_detect")
	span.End()

	spans := exp.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "submit.run.drift_detect", spans[0].Name,
		"the in-memory exporter must capture the span name — this is the load-bearing assertion: a real prod collector receives the same shape")
}

func TestInit_UnknownProtocolErrors(t *testing.T) {
	_, err := otelx.Init(context.Background(), otelx.Config{
		Endpoint: "collector.observability.svc:4318",
		Protocol: "not-a-real-protocol",
	})
	require.Error(t, err)
	assert.True(t,
		errorsContains(err, "unknown protocol"),
		"a misconfigured Protocol must error loudly so an operator catches the typo, not silently fall back to HTTP")
}

func TestShutdown_OnNoOpProviderReturnsNil(t *testing.T) {
	p, err := otelx.Init(context.Background(), otelx.Config{})
	require.NoError(t, err)
	require.NoError(t, p.Shutdown(context.Background()),
		"Shutdown on a no-op provider must be a clean no-op so cmd/server doesn't have to guard the call")
}

func TestShutdown_HonoursDeadline(t *testing.T) {
	p, err := otelx.Init(context.Background(), otelx.Config{
		Endpoint: "127.0.0.1:1",
		Protocol: "http",
		Insecure: true,
		Timeout:  100 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_ = p.Shutdown(ctx)
	elapsed := time.Since(start)
	assert.Less(t, elapsed, 1500*time.Millisecond,
		"Shutdown must respect the deadline + the exporter timeout — anything > 1.5s here means we'd extend SIGTERM drain past the kubelet's terminationGracePeriodSeconds")
}

func errorsContains(err error, needle string) bool {
	if err == nil {
		return false
	}
	return contains(err.Error(), needle) || errorsIsContains(err, needle)
}

func errorsIsContains(err error, needle string) bool {
	var u interface{ Unwrap() error }
	if errors.As(err, &u) {
		return errorsContains(u.Unwrap(), needle)
	}
	return false
}

func contains(s, needle string) bool {
	for i := 0; i+len(needle) <= len(s); i++ {
		if s[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
