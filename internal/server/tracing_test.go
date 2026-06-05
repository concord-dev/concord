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

func TestTracing_SubmitRunEmitsServerAndDriftSpans(t *testing.T) {
	exp := installTracingForTest(t)
	h := newHarness(t)

	body := `{"agent":{"version":"trace"},"started_at":"2026-06-04T11:00:00Z","completed_at":"2026-06-04T11:00:01Z","summary":{},"findings":[{"control_id":"a","status":"pass"}]}`
	resp, _ := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", body, h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	body = `{"agent":{"version":"trace"},"started_at":"2026-06-04T11:01:00Z","completed_at":"2026-06-04T11:01:01Z","summary":{},"findings":[{"control_id":"a","status":"fail"}]}`
	resp, _ = h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", body, h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	spans := exp.GetSpans()
	names := map[string]int{}
	for _, s := range spans {
		names[s.Name]++
	}

	assert.GreaterOrEqual(t, names["POST /v1/orgs/{slug}/runs"], 2,
		"each SubmitRun call must produce an HTTP server span; got names=%v", names)

	assert.Equal(t, 2, names["drift.detect_and_persist"],
		"drift.detect_and_persist must fire on BOTH submits — even the first-run case (short-circuits but the span is still recorded with concord.first_run=true)")
}

func TestTracing_TraceparentHeaderIsHonoured(t *testing.T) {
	exp := installTracingForTest(t)
	h := newHarness(t)

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
	assert.Equal(t,
		"4bf92f3577b34da6a3ce929d0e0e4736",
		server.SpanContext.TraceID().String(),
		"the server span must adopt the upstream trace ID — that's the entire point of propagation")
}
