package server_test

import (
	"bytes"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server"
)

// ─── Misc ────────────────────────────────────────────────────────────

func TestBearer_CaseInsensitive(t *testing.T) {
	h := newHarness(t)
	req, _ := http.NewRequest("GET",
		h.srv.URL+"/v1/orgs/"+h.org.Slug+"/frameworks", bytes.NewReader(nil))
	req.Header.Set("Authorization", "bearer "+h.apiToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestNewConcord_RequiresStore(t *testing.T) {
	_, err := server.NewConcord(server.Options{
		ControlsDir: repoControlsDir(t),
		ConfigPath:  filepath.Join(t.TempDir(), "x.yaml"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Store is required")
}
