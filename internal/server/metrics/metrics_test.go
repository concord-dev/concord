package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/metrics"
)

// helloHandler is the minimal handler used by middleware tests. Registered
// under a real ServeMux so r.Pattern gets populated the way it would in prod.
func helloHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hi", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hi")
	})
	mux.HandleFunc("POST /boom", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "kaboom", http.StatusInternalServerError)
	})
	return mux
}

func scrape(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	return rec.Body.String()
}

func TestMiddleware_RecordsMethodPatternStatus(t *testing.T) {
	m := metrics.New()
	srv := httptest.NewServer(m.Middleware(helloHandler()))
	t.Cleanup(srv.Close)

	resp, _ := http.Get(srv.URL + "/hi")
	resp.Body.Close()

	body := scrape(t, m)
	assert.Contains(t, body,
		`concord_http_requests_total{method="GET",pattern="GET /hi",status="200"} 1`,
		"counter must label by method/pattern/status — pattern keeps cardinality bounded")
	assert.Contains(t, body, `concord_http_request_duration_seconds_count{method="GET",pattern="GET /hi"} 1`,
		"histogram must observe one sample for the request")
	assert.Contains(t, body, `concord_http_inflight_requests 0`,
		"inflight gauge returns to zero after the request completes")
}

func TestMiddleware_5xxRecordedDistinctly(t *testing.T) {
	m := metrics.New()
	srv := httptest.NewServer(m.Middleware(helloHandler()))
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/boom", "text/plain", strings.NewReader(""))
	require.NoError(t, err)
	resp.Body.Close()

	body := scrape(t, m)
	assert.Contains(t, body,
		`concord_http_requests_total{method="POST",pattern="POST /boom",status="500"} 1`,
		"server errors must be discoverable from the metric")
}

func TestMiddleware_UnmatchedRoutesShareOnePatternLabel(t *testing.T) {
	// Hostile clients hitting random URLs must not blow up cardinality:
	// every 404 should fold into a single pattern="unmatched" series.
	m := metrics.New()
	srv := httptest.NewServer(m.Middleware(helloHandler()))
	t.Cleanup(srv.Close)

	for _, path := range []string{"/nope-1", "/nope-2", "/nope-3"} {
		resp, _ := http.Get(srv.URL + path)
		resp.Body.Close()
	}

	body := scrape(t, m)
	assert.Contains(t, body,
		`concord_http_requests_total{method="GET",pattern="unmatched",status="404"} 3`,
		"all unmatched routes must collapse into a single series")
}

func TestRecordWebhookDelivery_PartitionsByOutcome(t *testing.T) {
	m := metrics.New()
	m.RecordWebhookDelivery("success")
	m.RecordWebhookDelivery("success")
	m.RecordWebhookDelivery("non_2xx")
	m.RecordWebhookDelivery("network_error")

	body := scrape(t, m)
	assert.Contains(t, body, `concord_webhook_deliveries_total{outcome="success"} 2`)
	assert.Contains(t, body, `concord_webhook_deliveries_total{outcome="non_2xx"} 1`)
	assert.Contains(t, body, `concord_webhook_deliveries_total{outcome="network_error"} 1`)
}

func TestRecordBusDrop_PartitionsByKind(t *testing.T) {
	m := metrics.New()
	m.RecordBusDrop("run.completed")
	m.RecordBusDrop("run.completed")
	m.RecordBusDrop("run.failed")

	body := scrape(t, m)
	assert.Contains(t, body, `concord_bus_events_dropped_total{kind="run.completed"} 2`)
	assert.Contains(t, body, `concord_bus_events_dropped_total{kind="run.failed"} 1`)
}

func TestScrape_IncludesGoAndProcessCollectors(t *testing.T) {
	m := metrics.New()
	body := scrape(t, m)
	// The standard collectors are table-stakes for operator dashboards;
	// failing this means somebody removed them from registration.
	assert.Contains(t, body, "go_goroutines")
	assert.Contains(t, body, "process_cpu_seconds_total")
}
