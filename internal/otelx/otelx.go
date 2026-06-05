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

type Config struct {
	Endpoint string

	Protocol string

	Insecure bool

	ServiceName string

	ServiceVersion string

	SampleRatio float64

	Timeout time.Duration
}

type Provider struct {
	tp       trace.TracerProvider
	shutdown func(context.Context) error
}

func (p *Provider) Tracer(name string) trace.Tracer {
	if p == nil || p.tp == nil {
		return noop.NewTracerProvider().Tracer(name)
	}
	return p.tp.Tracer(name)
}

func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

func Init(ctx context.Context, cfg Config) (*Provider, error) {
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

func stripScheme(s string) string {
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(s, p) {
			return strings.TrimPrefix(s, p)
		}
	}
	return s
}
