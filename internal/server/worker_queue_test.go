package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server"
)

// ─── Worker / queue ──────────────────────────────────────────────────

func TestCheck_QueueFullReturns503(t *testing.T) {
	st := openStore(t)
	c, err := server.NewConcord(server.Options{
		ControlsDir: repoControlsDir(t), ConfigPath: filepath.Join(t.TempDir(), "x.yaml"),
		FixturesOnly: true, Store: st, OperatorToken: testOperatorToken, Version: "test",
		Worker: server.WorkerOpts{PoolSize: 1, QueueSize: 1},
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)

	ctx := context.Background()
	org, _ := st.CreateOrganization(ctx, "QFull", uniqueSlug("qfull"))
	_, tok, _ := st.CreateAPIToken(ctx, org.ID, "ci", nil)

	statuses := make(chan int, 5)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("POST", ts.URL+"/v1/orgs/"+org.Slug+"/check", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				statuses <- 0
				return
			}
			_ = resp.Body.Close()
			statuses <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	sawQF := false
	for s := range statuses {
		if s == http.StatusServiceUnavailable {
			sawQF = true
		}
	}
	assert.True(t, sawQF, "queue=1 + pool=1 with 5 concurrent requests must surface 503")
}
