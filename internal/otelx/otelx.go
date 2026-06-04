// Package otelx is the server's distributed-tracing facade. It wraps the
// OpenTelemetry SDK so the rest of the codebase imports otelx (not the
// SDK directly), keeping the wiring decisions — exporter choice, sampler,
// resource attributes — in one place.
//
// Wiring rules:
//
//   - When Config.Endpoint is empty, Init installs a no-op TracerProvider
//     so the `otel.Tracer(...)` calls everywhere else work unconditionally.
//     A production deploy WITHOUT an OTel collector pays zero CPU cost for
//     tracing — spans are constructed but immediately dropped.
//   - When Config.Endpoint is set, the TracerProvider exports OTLP. HTTP
//     (otlptracehttp) is the default — gRPC needs an extra port open and
//     fewer collectors run it; HTTP is the universal lowest-friction.
//   - Sampler is parent-based with a configurable head ratio. Default is
//     1.0 (sample everything) for low-volume deploys; bump down on a
//     fleet doing 1k+ rps.
//
// Shutdown blocks until the provider drains its export queue or the
// context expires. cmd/server should call this AFTER http.Server.Shutdown
// + Concord.Shutdown so the final spans (graceful drain markers) ship.
package otelx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Config controls how Init constructs the TracerProvider. The fields
// mirror the standard OTEL_* env-var contract so an operator can hand
// the chart a generic OTLP collector URL and have it work.
type Config struct {
	// Endpoint is the OTLP collector endpoint, e.g.
	// "otel-collector.observability.svc:4318" for HTTP or
	// "otel-collector.observability.svc:4317" for gRPC. Empty disables
	// tracing entirely (Init returns a no-op provider).
	Endpoint string

	// Protocol selects the exporter wire format: "http" (default,
	// otlptracehttp on port 4318) or "grpc" (otlptracegrpc on port 4317).
	// Both honour OTEL_EXPORTER_OTLP_HEADERS for vendor-specific auth.
	Protocol string

	// Insecure skips TLS on the collector connection. Useful in-cluster
	// where the collector is a sidecar / service-local; never set this
	// for cross-cluster or public collectors.
	Insecure bool

	// ServiceName populates the `service.name` resource attribute on
	// every emitted span. Required for the typical Jaeger / Tempo UI;
	// defaults to "concord-server" if unset.
	ServiceName string

	// ServiceVersion populates `service.version`. Wired to the build
	// SHA by cmd/server.
	ServiceVersion string

	// SampleRatio is the head sampler ratio in [0.0, 1.0]. 1.0 samples
	// every trace; 0.0 disables sampling. Defaults to 1.0 when zero/
	// unset — tracing volume is bounded by request volume.
	SampleRatio float64

	// Timeout caps the OTLP export call. Defaults to 5s; an overloaded
	// collector should never extend HTTP response latency.
	Timeout time.Duration
}

// Provider is the handle Init returns. Holds the SDK TracerProvider so
// Shutdown can drain it, plus a reference to the no-op detector for the
// "no-config" path.
type Provider struct {
	tp       trace.TracerProvider
	shutdown func(context.Context) error
}

// Tracer returns a Tracer for the named instrumentation scope. Pass a
// stable package-qualified name like "github.com/concord-dev/concord/...".
func (p *Provider) Tracer(name string) trace.Tracer {
	if p == nil || p.tp == nil {
		return noop.NewTracerProvider().Tracer(name)
	}
	return p.tp.Tracer(name)
}

// Shutdown drains the export queue or returns ctx.Err() on timeout.
// Safe to call on a no-op Provider — just returns nil.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// Init wires the OTel SDK. On success, the returned Provider's tracer
// factory is also installed as the global otel.TracerProvider so libraries
// (otelhttp, otelpgx, ...) reach it without explicit plumbing. The W3C
// trace-context propagator is installed unconditionally — incoming
// `traceparent` headers continue parent spans, outgoing requests carry
// the parent forward.
//
// When cfg.Endpoint is empty Init installs a no-op provider and returns
// a Provider whose Shutdown is a nil-error. Calling code stays
// unconditional: `tr := provider.Tracer("foo"); tr.Start(...)` just works.
func Init(ctx context.Context, cfg Config) (*Provider, error) {
	// W3C tracecontext + baggage propagators always installed — even on
	// the no-op path. That means an upstream traceparent header parses
	// correctly even when we're not exporting; useful for log/metric
	// correlation when traces are disabled.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	if strings.TrimSpace(cfg.Endpoint) == "" {
		tp := noop.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return &Provider{tp: tp}, nil
	}

	if cfg.ServiceName == "" {
		cfg.ServiceName = "concord-server"
	}
	if cfg.SampleRatio <= 0 {
		cfg.SampleRatio = 1.0
	}
	if cfg.SampleRatio > 1 {
		cfg.SampleRatio = 1.0
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
		resource.WithHost(),
		resource.WithProcessRuntimeName(),
		resource.WithProcessRuntimeVersion(),
	)
	if err != nil {
		// Resource construction failing means the OS lookups didn't
		// work; we shouldn't fail the whole process — fall back to a
		// minimal resource and continue.
		res = resource.NewSchemaless(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		)
	}

	exporter, err := newExporter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("otelx: build exporter: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			sdktrace.WithMaxExportBatchSize(512),
			sdktrace.WithBatchTimeout(2*time.Second),
		),
		sdktrace.WithResource(res),
		// ParentBased so an upstream sampled trace continues to be
		// sampled regardless of our local ratio, and an upstream-
		// dropped trace stays dropped. Cross-service consistency.
		sdktrace.WithSampler(sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(cfg.SampleRatio),
		)),
	)
	otel.SetTracerProvider(tp)

	return &Provider{
		tp: tp,
		shutdown: func(ctx context.Context) error {
			return tp.Shutdown(ctx)
		},
	}, nil
}

// newExporter picks otlptracehttp or otlptracegrpc per Config.Protocol.
// Endpoint normalization: strip a leading scheme — both SDK exporters
// take a bare host:port and a separate Insecure flag.
func newExporter(ctx context.Context, cfg Config) (sdktrace.SpanExporter, error) {
	endpoint := stripScheme(cfg.Endpoint)
	switch strings.ToLower(strings.TrimSpace(cfg.Protocol)) {
	case "", "http", "otlp", "otlphttp":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(endpoint),
			otlptracehttp.WithTimeout(cfg.Timeout),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		return otlptracehttp.New(ctx, opts...)
	case "grpc", "otlpgrpc":
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithTimeout(cfg.Timeout),
		}
		if cfg.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		return otlptracegrpc.New(ctx, opts...)
	default:
		return nil, errors.New("otelx: unknown protocol — use http or grpc")
	}
}

// stripScheme removes "http://" or "https://" from the endpoint since
// the SDK exporters use Insecure + bare host:port instead of a URL.
func stripScheme(s string) string {
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(s, p) {
			return strings.TrimPrefix(s, p)
		}
	}
	return s
}
