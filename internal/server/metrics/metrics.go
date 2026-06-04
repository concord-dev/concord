// Package metrics owns the server's Prometheus instrumentation. A private
// registry is used (rather than the global default) so each test can spin up
// an isolated Metrics instance and tests don't pollute one another via the
// process-wide default registry.
//
// Exposition is over /metrics on the main listener. If you don't want that
// publicly reachable, gate it at your ingress — every other Go service on
// the planet exposes /metrics on the same port and we don't want to be a
// snowflake.
package metrics

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics bundles every collector the server emits. Construct one per process
// (or per test) via New; pass it to the router for the HTTP middleware and
// to the Concord struct so domain code can record domain events.
type Metrics struct {
	reg *prometheus.Registry

	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPInflight        prometheus.Gauge

	WebhookDeliveriesTotal *prometheus.CounterVec
	BusEventsDroppedTotal  *prometheus.CounterVec

	// LimiterPrimaryErrorsTotal counts how often a Redis-backed rate
	// limiter failed its primary call and had to fall through to the
	// per-pod fallback bucket. A non-zero rate here is the canary signal
	// for "Redis is sick"; sustained high rate means the fleet is no
	// longer honouring the shared limit.
	LimiterPrimaryErrorsTotal *prometheus.CounterVec
}

// New builds a Metrics with a private registry and registers every collector
// plus the standard Go runtime + process collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_http_requests_total",
				Help: "HTTP requests processed, partitioned by method, route pattern, and status.",
			},
			[]string{"method", "pattern", "status"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "concord_http_request_duration_seconds",
				Help:    "HTTP request latency from the access-log middleware boundary.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "pattern"},
		),
		HTTPInflight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "concord_http_inflight_requests",
				Help: "HTTP requests currently being served.",
			},
		),
		WebhookDeliveriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_webhook_deliveries_total",
				Help: "Outbound webhook deliveries, partitioned by outcome (success | non_2xx | network_error).",
			},
			[]string{"outcome"},
		),
		BusEventsDroppedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_bus_events_dropped_total",
				Help: "Run-lifecycle events the in-process bus dropped because a subscriber's buffer was full.",
			},
			[]string{"kind"},
		),
		LimiterPrimaryErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_limiter_primary_errors_total",
				Help: "Times the Redis-backed rate limiter primary failed and the fallback bucket served the request instead.",
			},
			[]string{"gate"},
		),
	}
	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.HTTPInflight,
		m.WebhookDeliveriesTotal,
		m.BusEventsDroppedTotal,
		m.LimiterPrimaryErrorsTotal,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// RegisterDBPool wires a pgxpool.Stat-driven collector so concord_db_pool_*
// metrics surface live pool stats on every scrape (instead of being sampled
// on a fixed timer). Safe to call once during server construction.
func (m *Metrics) RegisterDBPool(pool *pgxpool.Pool) {
	m.reg.MustRegister(newPoolCollector(pool))
}

// Handler returns the /metrics HTTP handler bound to this private registry.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

// RecordWebhookDelivery is the thin call sites use to bump the outcome counter
// without depending on prometheus internals.
func (m *Metrics) RecordWebhookDelivery(outcome string) {
	m.WebhookDeliveriesTotal.WithLabelValues(outcome).Inc()
}

// RecordBusDrop bumps the dropped-event counter for the named bus kind.
func (m *Metrics) RecordBusDrop(kind string) {
	m.BusEventsDroppedTotal.WithLabelValues(kind).Inc()
}

// RecordLimiterPrimaryError bumps the rate-limiter outage counter for the
// named gate (e.g. "login_ip", "invite_accept_ip"). Wired from FailoverBucket
// in cmd/server's limiter factory.
func (m *Metrics) RecordLimiterPrimaryError(gate string) {
	m.LimiterPrimaryErrorsTotal.WithLabelValues(gate).Inc()
}
