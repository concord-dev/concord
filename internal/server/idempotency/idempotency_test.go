package idempotency_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/idempotency"
)

// requireRedis returns a *redis.Client against CONCORD_TEST_REDIS_ADDR
// or skips. The idempotency tests need a real Redis because the
// middleware leans on SETNX semantics + TTLs.
func requireRedis(t *testing.T) *redis.Client {
	t.Helper()
	addr := os.Getenv("CONCORD_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("set CONCORD_TEST_REDIS_ADDR=host:port to run idempotency tests")
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:         addr,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis at %s not reachable: %v", addr, err)
	}
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

// newServer wraps a counting handler in the middleware so we can
// observe how many times it executed. Returns the test server URL +
// a pointer to the counter.
func newServer(t *testing.T, cfg idempotency.Config) (string, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"echo":` + strings.Trim(string(body), "\n") + `}`))
	})
	srv := httptest.NewServer(idempotency.Middleware(cfg)(handler))
	t.Cleanup(srv.Close)
	return srv.URL, &calls
}

func uniqueKey(t *testing.T) string {
	t.Helper()
	return "test-" + t.Name() + "-" + time.Now().Format("150405.000000")
}

func TestIdempotency_NoHeaderIsPassThrough(t *testing.T) {
	rdb := requireRedis(t)
	url, calls := newServer(t, idempotency.Config{Redis: rdb})

	for i := 0; i < 3; i++ {
		resp, err := http.Post(url, "application/json", strings.NewReader(`{}`))
		require.NoError(t, err)
		resp.Body.Close()
	}
	assert.Equal(t, int32(3), calls.Load(),
		"without Idempotency-Key the middleware must be a pass-through")
}

func TestIdempotency_SecondCallWithSameKeyReturnsCache(t *testing.T) {
	rdb := requireRedis(t)
	url, calls := newServer(t, idempotency.Config{Redis: rdb})

	key := uniqueKey(t)
	body := `{"k":1}`

	req1, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Idempotency-Key", key)
	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	raw1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	require.Equal(t, http.StatusCreated, resp1.StatusCode)

	req2, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Idempotency-Key", key)
	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	raw2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	assert.Equal(t, http.StatusCreated, resp2.StatusCode, "cached status replayed")
	assert.Equal(t, string(raw1), string(raw2), "cached body replayed verbatim")
	assert.Equal(t, "true", resp2.Header.Get("Idempotency-Replay"))
	assert.Equal(t, int32(1), calls.Load(),
		"handler ran exactly once across two requests with the same key")
}

func TestIdempotency_SameKeyDifferentRequestReturns422(t *testing.T) {
	rdb := requireRedis(t)
	var mismatches atomic.Int32
	url, _ := newServer(t, idempotency.Config{
		Redis:      rdb,
		OnMismatch: func() { mismatches.Add(1) },
	})

	key := uniqueKey(t)

	doPost := func(body string) int {
		req, _ := http.NewRequest("POST", url, strings.NewReader(body))
		req.Header.Set("Idempotency-Key", key)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusCreated, doPost(`{"a":1}`))
	assert.Equal(t, http.StatusUnprocessableEntity, doPost(`{"a":2}`),
		"same key + different body must yield 422 Unprocessable Entity")
	assert.Equal(t, int32(1), mismatches.Load())
}

func TestIdempotency_OversizeBodyReturns413(t *testing.T) {
	rdb := requireRedis(t)
	url, _ := newServer(t, idempotency.Config{Redis: rdb})

	big := strings.Repeat("x", idempotency.MaxBodyBytes+1)
	req, _ := http.NewRequest("POST", url, strings.NewReader(big))
	req.Header.Set("Idempotency-Key", uniqueKey(t))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestIdempotency_ConcurrentRequestsCollapseToOneExecution(t *testing.T) {
	rdb := requireRedis(t)
	url, calls := newServer(t, idempotency.Config{Redis: rdb})

	key := uniqueKey(t)
	body := `{"concurrent":true}`

	const N = 20
	var (
		wg            sync.WaitGroup
		pendingCount  atomic.Int32
		successCount  atomic.Int32
	)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", url, strings.NewReader(body))
			req.Header.Set("Idempotency-Key", key)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusCreated:
				successCount.Add(1)
			case http.StatusConflict:
				pendingCount.Add(1)
			}
		}()
	}
	wg.Wait()

	// Exactly one request executed the handler. The other 19 either
	// got the cached response or saw the pending sentinel (409). The
	// sum must be N, the handler must have run once.
	assert.Equal(t, int32(1), calls.Load(),
		"only one of %d concurrent requests should execute the handler", N)
	assert.Equal(t, int32(N), successCount.Load()+pendingCount.Load(),
		"every request must finish with either a cached 201 or a 409 pending")
}

func TestIdempotency_DegradesToPassThroughWhenRedisUnreachable(t *testing.T) {
	// A client pointed at a port nothing listens on. Every Redis call
	// fails; the middleware must let the handler run anyway.
	rdb := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
		MaxRetries:  -1,
	})
	t.Cleanup(func() { _ = rdb.Close() })

	var redisErrs atomic.Int32
	url, calls := newServer(t, idempotency.Config{
		Redis:        rdb,
		OnRedisError: func(error) { redisErrs.Add(1) },
	})

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest("POST", url, strings.NewReader(`{}`))
		req.Header.Set("Idempotency-Key", uniqueKey(t)+"-"+time.Now().Format("000000"))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusCreated, resp.StatusCode,
			"handler must run even when Redis is unreachable — fail-open is the right trade")
	}
	assert.Equal(t, int32(3), calls.Load())
	assert.Greater(t, redisErrs.Load(), int32(0),
		"OnRedisError must fire so operators can spot the outage in metrics")
}

func TestIdempotency_OverLongKeyRejected(t *testing.T) {
	rdb := requireRedis(t)
	url, _ := newServer(t, idempotency.Config{Redis: rdb})

	req, _ := http.NewRequest("POST", url, strings.NewReader(`{}`))
	req.Header.Set("Idempotency-Key", strings.Repeat("k", 256))
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
