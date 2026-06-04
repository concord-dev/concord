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

	BusEventsDroppedTotal *prometheus.CounterVec

	// LimiterPrimaryErrorsTotal counts how often a Redis-backed rate
	// limiter failed its primary call and had to fall through to the
	// per-pod fallback bucket. A non-zero rate here is the canary signal
	// for "Redis is sick"; sustained high rate means the fleet is no
	// longer honouring the shared limit.
	LimiterPrimaryErrorsTotal *prometheus.CounterVec

	// Outbox + Dispatcher instrumentation. The outbox is the canonical
	// transactional pipe to Kafka — a stalled dispatcher or a stuck
	// broker shows up here long before downstream consumers notice.
	//
	// OutboxEnqueuedTotal is bumped by handlers when they write to
	// event_outbox; the rest are bumped by the Dispatcher.
	OutboxEnqueuedTotal    *prometheus.CounterVec   // labels: kind
	OutboxPublishedTotal   *prometheus.CounterVec   // labels: kind
	OutboxFailedTotal      *prometheus.CounterVec   // labels: kind — publish failed, will retry
	OutboxDeadTotal        *prometheus.CounterVec   // labels: kind — reached MaxAttempts
	OutboxPublishDuration  prometheus.Histogram     // wall time of one Publish call
	OutboxLagSeconds       prometheus.Gauge         // age of oldest unpublished, non-dead row
	OutboxCleanupDeletedTotal prometheus.Counter    // rows the periodic delete sweep removed
	OutboxTickErrorsTotal  *prometheus.CounterVec   // labels: stage (tick|cleanup|lag)
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
		OutboxEnqueuedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_outbox_enqueued_total",
				Help: "Domain events written to event_outbox, partitioned by event kind.",
			},
			[]string{"kind"},
		),
		OutboxPublishedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_outbox_published_total",
				Help: "Outbox rows the Dispatcher successfully shipped to Kafka, partitioned by event kind.",
			},
			[]string{"kind"},
		),
		OutboxFailedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_outbox_failed_total",
				Help: "Outbox publishes that errored and will be retried (rows below max-attempts), partitioned by event kind.",
			},
			[]string{"kind"},
		),
		OutboxDeadTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_outbox_dead_total",
				Help: "Outbox rows that reached max-attempts and will not be retried automatically — operator intervention required.",
			},
			[]string{"kind"},
		),
		OutboxPublishDuration: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "concord_outbox_publish_duration_seconds",
				Help:    "Wall-time of a single Publish call from the Dispatcher.",
				Buckets: prometheus.ExponentialBuckets(0.005, 2, 10), // 5ms..2.5s
			},
		),
		OutboxLagSeconds: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "concord_outbox_lag_seconds",
				Help: "Age (seconds) of the oldest unpublished, non-dead outbox row. 0 when the queue is empty.",
			},
		),
		OutboxCleanupDeletedTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "concord_outbox_cleanup_deleted_total",
				Help: "Published outbox rows the periodic cleanup sweep has deleted since process start.",
			},
		),
		OutboxTickErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "concord_outbox_tick_errors_total",
				Help: "Unexpected errors from the Dispatcher loop (DB or internal), partitioned by stage (tick|cleanup|lag).",
			},
			[]string{"stage"},
		),
	}
	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.HTTPInflight,
		m.BusEventsDroppedTotal,
		m.LimiterPrimaryErrorsTotal,
		m.OutboxEnqueuedTotal,
		m.OutboxPublishedTotal,
		m.OutboxFailedTotal,
		m.OutboxDeadTotal,
		m.OutboxPublishDuration,
		m.OutboxLagSeconds,
		m.OutboxCleanupDeletedTotal,
		m.OutboxTickErrorsTotal,
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

// RecordOutboxEnqueued bumps the enqueue counter for the named event kind.
// Wired from handlers when they INSERT a row into event_outbox.
func (m *Metrics) RecordOutboxEnqueued(kind string) {
	m.OutboxEnqueuedTotal.WithLabelValues(kind).Inc()
}
