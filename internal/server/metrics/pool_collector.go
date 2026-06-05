package metrics

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

type poolCollector struct {
	pool         *pgxpool.Pool
	acquired     *prometheus.Desc
	idle         *prometheus.Desc
	total        *prometheus.Desc
	maxConns     *prometheus.Desc
	acquireCount *prometheus.Desc
}

func newPoolCollector(pool *pgxpool.Pool) *poolCollector {
	return &poolCollector{
		pool: pool,
		acquired: prometheus.NewDesc(
			"concord_db_pool_acquired_connections",
			"Number of currently-acquired (in-use) connections in the pgx pool.",
			nil, nil,
		),
		idle: prometheus.NewDesc(
			"concord_db_pool_idle_connections",
			"Number of idle connections in the pgx pool.",
			nil, nil,
		),
		total: prometheus.NewDesc(
			"concord_db_pool_total_connections",
			"Total open connections in the pgx pool (acquired + idle + constructing).",
			nil, nil,
		),
		maxConns: prometheus.NewDesc(
			"concord_db_pool_max_connections",
			"Pool max size — useful for detecting saturation (acquired ≈ max).",
			nil, nil,
		),
		acquireCount: prometheus.NewDesc(
			"concord_db_pool_acquires_total",
			"Cumulative successful Acquire calls since process start.",
			nil, nil,
		),
	}
}

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.acquired
	ch <- c.idle
	ch <- c.total
	ch <- c.maxConns
	ch <- c.acquireCount
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.pool.Stat()
	ch <- prometheus.MustNewConstMetric(c.acquired, prometheus.GaugeValue, float64(s.AcquiredConns()))
	ch <- prometheus.MustNewConstMetric(c.idle, prometheus.GaugeValue, float64(s.IdleConns()))
	ch <- prometheus.MustNewConstMetric(c.total, prometheus.GaugeValue, float64(s.TotalConns()))
	ch <- prometheus.MustNewConstMetric(c.maxConns, prometheus.GaugeValue, float64(s.MaxConns()))
	ch <- prometheus.MustNewConstMetric(c.acquireCount, prometheus.CounterValue, float64(s.AcquireCount()))
}
