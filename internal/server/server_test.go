package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// repoControlsDir resolves the bundled controls library from the package's
// test working directory (concord/internal/server) up to concord/controls.
func repoControlsDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../controls")
	require.NoError(t, err)
	return abs
}

func newTestServer(t *testing.T, fixturesOnly bool) (*httptest.Server, *server.Concord) {
	t.Helper()
	tmpOut := t.TempDir()
	c, err := server.NewConcord(server.Options{
		ControlsDir:  repoControlsDir(t),
		ConfigPath:   filepath.Join(tmpOut, "missing-concord.yaml"), // absent → empty Config
		OutputDir:    tmpOut,
		FixturesOnly: fixturesOnly,
		Version:      "test",
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)
	return ts, c
}

func get(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, body
}

func post(t *testing.T, url, contentType string, body io.Reader) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url, contentType, body)
	require.NoError(t, err)
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, out
}

func TestHealth(t *testing.T) {
	ts, _ := newTestServer(t, true)
	resp, body := get(t, ts.URL+"/healthz")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"status":"ok"}`, string(body))
}

func TestVersion_ExposesControlCount(t *testing.T) {
	ts, c := newTestServer(t, true)
	resp, body := get(t, ts.URL+"/version")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "test", got["version"])
	assert.EqualValues(t, len(c.Controls), got["controls"])
}

func TestFrameworks_GroupsAndSortsControls(t *testing.T) {
	ts, _ := newTestServer(t, true)
	resp, body := get(t, ts.URL+"/v1/frameworks")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got []map[string]any
	require.NoError(t, json.Unmarshal(body, &got))
	require.GreaterOrEqual(t, len(got), 4, "should expose at least 4 frameworks")

	// Result must be sorted alphabetically.
	for i := 1; i < len(got); i++ {
		assert.LessOrEqual(t, got[i-1]["framework"].(string), got[i]["framework"].(string),
			"frameworks should be sorted alphabetically")
	}
	// Every entry has a positive count.
	for _, e := range got {
		assert.Positive(t, int(e["controls"].(float64)))
	}
}

func TestControls_ListAndFilterByFramework(t *testing.T) {
	ts, _ := newTestServer(t, true)

	resp, body := get(t, ts.URL+"/v1/controls?framework=cis-aws")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got []apiv1.Control
	require.NoError(t, json.Unmarshal(body, &got))
	require.NotEmpty(t, got)
	for _, c := range got {
		assert.Equal(t, "cis-aws", c.Metadata.Framework)
	}
}

func TestControls_GetByID(t *testing.T) {
	ts, _ := newTestServer(t, true)

	resp, body := get(t, ts.URL+"/v1/controls/SOC2-CC8.1")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got apiv1.Control
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, "SOC2-CC8.1", got.Metadata.ID)
	assert.Equal(t, "soc2", got.Metadata.Framework)
}

func TestControls_GetByID_CaseInsensitive(t *testing.T) {
	ts, _ := newTestServer(t, true)
	resp, _ := get(t, ts.URL+"/v1/controls/soc2-cc8.1")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestControls_GetByID_NotFoundReturns404(t *testing.T) {
	ts, _ := newTestServer(t, true)
	resp, body := get(t, ts.URL+"/v1/controls/does-not-exist")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), "no control with id")
}

func TestCheck_RunsAllControlsAndPersists(t *testing.T) {
	ts, c := newTestServer(t, true)

	resp, body := post(t, ts.URL+"/v1/check", "application/json", nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var got struct {
		Summary  map[string]int    `json:"summary"`
		Findings []apiv1.Finding   `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	assert.Equal(t, len(c.Controls), len(got.Findings))
	assert.Equal(t, len(c.Controls), got.Summary["pass"], "fixtures-only run should be all-pass")
	assert.Equal(t, 0, got.Summary["fail"])

	// /v1/findings should now read back the same set.
	resp2, body2 := get(t, ts.URL+"/v1/findings")
	require.Equal(t, http.StatusOK, resp2.StatusCode)
	var second struct {
		Findings []apiv1.Finding `json:"findings"`
	}
	require.NoError(t, json.Unmarshal(body2, &second))
	assert.Equal(t, len(got.Findings), len(second.Findings))
}

func TestFindings_BeforeAnyCheckReturns404(t *testing.T) {
	ts, _ := newTestServer(t, true)
	resp, body := get(t, ts.URL+"/v1/findings")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), "POST /v1/check first")
}

func TestMethodMismatchReturns405(t *testing.T) {
	ts, _ := newTestServer(t, true)
	// PUT /healthz — not registered
	req, _ := http.NewRequest(http.MethodPut, ts.URL+"/healthz", nil)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

func TestNewConcord_EmptyControlsDirErrors(t *testing.T) {
	tmp := t.TempDir()
	_, err := server.NewConcord(server.Options{
		ControlsDir:  tmp,
		ConfigPath:   filepath.Join(tmp, "missing.yaml"),
		OutputDir:    tmp,
		FixturesOnly: true,
	})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "no controls"))
}
