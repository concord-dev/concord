package notify_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/notify"
	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func sampleEvent() watcher.Event {
	return watcher.Event{
		ControlID: "SOC2-CC8.1",
		Title:     "Default branch is protected",
		From:      apiv1.StatusPass,
		To:        apiv1.StatusFail,
		Reason:    "regression",
		At:        time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC),
	}
}

func TestStderr_OneLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	sink := notify.Stderr(&buf)
	sink(sampleEvent())

	out := buf.String()
	assert.Contains(t, out, "SOC2-CC8.1")
	assert.Contains(t, out, "pass → fail")
	assert.Contains(t, out, "regression")
	assert.Equal(t, 1, strings.Count(out, "\n"), "exactly one line")
}

func TestMulti_FansOutToEverySink(t *testing.T) {
	var a, b atomic.Int32
	sink := notify.Multi(
		func(e watcher.Event) { a.Add(1) },
		nil, // must skip nil sinks
		func(e watcher.Event) { b.Add(1) },
	)
	sink(sampleEvent())
	sink(sampleEvent())
	assert.Equal(t, int32(2), a.Load())
	assert.Equal(t, int32(2), b.Load())
}

func TestSlack_PostsBlockKitPayload(t *testing.T) {
	var got map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	var errBuf bytes.Buffer
	sink := notify.Slack(srv.URL, nil, &errBuf)
	sink(sampleEvent())

	mu.Lock()
	defer mu.Unlock()
	require.NotNil(t, got, "slack payload should have been received")
	text, _ := got["text"].(string)
	assert.Contains(t, text, "SOC2-CC8.1")
	assert.Contains(t, text, ":rotating_light:", "regression must surface red emoji")
	blocks, _ := got["blocks"].([]any)
	require.NotEmpty(t, blocks)
	assert.Empty(t, errBuf.String(), "happy path writes nothing to error stream")
}

func TestSlack_NonOKResponseLogsButDoesNotBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid_payload"))
	}))
	t.Cleanup(srv.Close)

	var errBuf bytes.Buffer
	sink := notify.Slack(srv.URL, nil, &errBuf)
	sink(sampleEvent()) // must not panic or block

	assert.Contains(t, errBuf.String(), "400")
	assert.Contains(t, errBuf.String(), "invalid_payload")
}

func TestSlack_UnreachableHostLogsError(t *testing.T) {
	var errBuf bytes.Buffer
	// Use an unrouted port so the request fails fast.
	sink := notify.Slack("http://127.0.0.1:1", &http.Client{Timeout: 500 * time.Millisecond}, &errBuf)
	sink(sampleEvent())
	assert.Contains(t, errBuf.String(), "slack notify:")
}

func TestWebhook_PostsRawEventAsJSON(t *testing.T) {
	var got watcher.Event
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Contains(t, r.Header.Get("User-Agent"), "concord-watch")
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	var errBuf bytes.Buffer
	sink := notify.Webhook(srv.URL, nil, &errBuf)
	sink(sampleEvent())

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "SOC2-CC8.1", got.ControlID)
	assert.Equal(t, apiv1.StatusPass, got.From)
	assert.Equal(t, apiv1.StatusFail, got.To)
	assert.Equal(t, "regression", got.Reason)
	assert.Empty(t, errBuf.String())
}

func TestWebhook_HTTPErrorLogsButDoesNotBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	t.Cleanup(srv.Close)

	var errBuf bytes.Buffer
	sink := notify.Webhook(srv.URL, nil, &errBuf)
	sink(sampleEvent())
	assert.Contains(t, errBuf.String(), "500")
}
