package metrics

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	reg *prometheus.Registry

	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec
	HTTPInflight        prometheus.Gauge

	BusEventsDroppedTotal *prometheus.CounterVec

	LimiterPrimaryErrorsTotal *prometheus.CounterVec

	OutboxEnqueuedTotal    *prometheus.CounterVec   // labels: kind
	OutboxPublishedTotal   *prometheus.CounterVec   // labels: kind
	OutboxFailedTotal      *prometheus.CounterVec   // labels: kind — publish failed, will retry
	OutboxDeadTotal        *prometheus.CounterVec   // labels: kind — reached MaxAttempts
	OutboxPublishDuration  prometheus.Histogram     // wall time of one Publish call
	OutboxLagSeconds       prometheus.Gauge         // age of oldest unpublished, non-dead row
	OutboxCleanupDeletedTotal prometheus.Counter    // rows the periodic delete sweep removed
	OutboxTickErrorsTotal  *prometheus.CounterVec   // labels: stage (tick|cleanup|lag)

	IdempotencyHitsTotal        prometheus.Counter
	IdempotencyMismatchTotal    prometheus.Counter
	IdempotencyPendingTotal     prometheus.Counter
	IdempotencyRedisErrorsTotal prometheus.Counter

	AuditPartitionRotatorTicksTotal  prometheus.Counter
	AuditPartitionRotatorErrorsTotal prometheus.Counter
	AuditPartitionsCreatedTotal      *prometheus.CounterVec
}

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
		IdempotencyHitsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_idempotency_hits_total",
			Help: "Idempotency-Key requests that returned a cached response (the happy-path dedupe outcome).",
		}),
		IdempotencyMismatchTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_idempotency_mismatch_total",
			Help: "Idempotency-Key reused with a different request fingerprint (responded 422). Caller-side bug.",
		}),
		IdempotencyPendingTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_idempotency_pending_total",
			Help: "Idempotency-Key reused while the original request is still in flight (responded 409).",
		}),
		IdempotencyRedisErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_idempotency_redis_errors_total",
			Help: "Idempotency middleware Redis-call failures; the middleware degraded to pass-through on each.",
		}),
		AuditPartitionRotatorTicksTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_audit_partition_rotator_ticks_total",
			Help: "Successful EnsureMonthsAhead invocations from the audit-partition background rotator.",
		}),
		AuditPartitionRotatorErrorsTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "concord_audit_partition_rotator_errors_total",
			Help: "Failed EnsureMonthsAhead invocations; rotator retries on the next tick.",
		}),
		AuditPartitionsCreatedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "concord_audit_partitions_created_total",
			Help: "Audit-event monthly partitions newly created by the rotator (does not count idempotent ensures).",
		}, []string{"name"}),
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
		m.IdempotencyHitsTotal,
		m.IdempotencyMismatchTotal,
		m.IdempotencyPendingTotal,
		m.IdempotencyRedisErrorsTotal,
		m.AuditPartitionRotatorTicksTotal,
		m.AuditPartitionRotatorErrorsTotal,
		m.AuditPartitionsCreatedTotal,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

func (m *Metrics) RegisterDBPool(pool *pgxpool.Pool) {
	m.reg.MustRegister(newPoolCollector(pool))
}

func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

func (m *Metrics) RecordBusDrop(kind string) {
	m.BusEventsDroppedTotal.WithLabelValues(kind).Inc()
}

func (m *Metrics) RecordLimiterPrimaryError(gate string) {
	m.LimiterPrimaryErrorsTotal.WithLabelValues(gate).Inc()
}

func (m *Metrics) RecordOutboxEnqueued(kind string) {
	m.OutboxEnqueuedTotal.WithLabelValues(kind).Inc()
}
