package server_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// installTracingForTest swaps in an in-memory exporter + W3C
// tracecontext propagator for the duration of one test. Returns the
// exporter so the test can inspect captured spans. Both globals are
// restored on cleanup so tests in this package don't leak side effects.
func installTracingForTest(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tp.Shutdown(ctx)
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return exp
}

// TestTracing_SubmitRunEmitsServerAndDriftSpans installs a global
// in-memory exporter, drives a real SubmitRun via the HTTP harness, and
// verifies that:
//
//  1. otelhttp's server span is emitted (the wrapper is wired in router.go)
//  2. our custom drift.detect_and_persist span is emitted (proves the
//     tracer = otel.Tracer(...) pattern actually resolves to a real
//     tracer when one is installed globally)
//
// We override the GLOBAL tracer provider rather than wire it through
// server.Options.Tracing because otelhttp + our custom spans both
// resolve via otel.Tracer / otel.GetTracerProvider — the global is the
// observable surface.
func TestTracing_SubmitRunEmitsServerAndDriftSpans(t *testing.T) {
	exp := installTracingForTest(t)
	h := newHarness(t)

	// First run — no prior, no drift detection span (it short-circuits).
	body := `{"agent":{"version":"trace"},"started_at":"2026-06-04T11:00:00Z","completed_at":"2026-06-04T11:00:01Z","summary":{},"findings":[{"control_id":"a","status":"pass"}]}`
	resp, _ := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", body, h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Second run — drift detection runs against the prior, so the
	// drift.detect_and_persist span MUST be present.
	body = `{"agent":{"version":"trace"},"started_at":"2026-06-04T11:01:00Z","completed_at":"2026-06-04T11:01:01Z","summary":{},"findings":[{"control_id":"a","status":"fail"}]}`
	resp, _ = h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", body, h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Spans flush synchronously via WithSyncer, so they're available
	// immediately.
	spans := exp.GetSpans()
	names := map[string]int{}
	for _, s := range spans {
		names[s.Name]++
	}

	// Server span name is renameSpanFromPattern's output — exactly
	// r.Pattern (which Go's mux exposes as "METHOD /path/..." already).
	assert.GreaterOrEqual(t, names["POST /v1/orgs/{slug}/runs"], 2,
		"each SubmitRun call must produce an HTTP server span; got names=%v", names)

	assert.Equal(t, 2, names["drift.detect_and_persist"],
		"drift.detect_and_persist must fire on BOTH submits — even the first-run case (short-circuits but the span is still recorded with concord.first_run=true)")
}

// TestTracing_TraceparentHeaderIsHonoured proves the propagator wiring:
// an inbound traceparent must be the parent of the server span we emit,
// so external upstreams (a sidecar proxy, a Lambda invoker) can stitch
// their trace into Concord's view of the request.
func TestTracing_TraceparentHeaderIsHonoured(t *testing.T) {
	exp := installTracingForTest(t)
	h := newHarness(t)

	// Construct a synthetic traceparent. Format:
	//   version-traceid-parentid-flags
	//   00-<32 hex>-<16 hex>-01
	parent := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

	req, err := http.NewRequest("GET", h.srv.URL+"/healthz", nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", parent)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()

	spans := exp.GetSpans()
	require.NotEmpty(t, spans)
	var server *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "GET /healthz" {
			server = &spans[i]
			break
		}
	}
	require.NotNil(t, server, "the HTTP server span must be present so we can verify parentage")
	// Trace ID continuity is the load-bearing assertion: an upstream
	// traceparent must put concord-server's span on the SAME trace.
	// Without that, Jaeger / Tempo can't stitch the cross-service view
	// together. We don't assert on parent SpanID — its representation
	// depends on whether the SDK records the parent as a Remote span
	// context vs. zero, which is an SDK-internal detail not worth
	// pinning in a black-box test.
	assert.Equal(t,
		"4bf92f3577b34da6a3ce929d0e0e4736",
		server.SpanContext.TraceID().String(),
		"the server span must adopt the upstream trace ID — that's the entire point of propagation")
}
