package evidence_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const protectionResponseJSON = `{
  "required_status_checks": {
    "strict": true,
    "contexts": ["ci/build", "ci/test"]
  },
  "enforce_admins": {"enabled": true},
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "required_approving_review_count": 2
  },
  "required_linear_history": {"enabled": true},
  "allow_force_pushes": {"enabled": false},
  "allow_deletions": {"enabled": false},
  "required_conversation_resolution": {"enabled": true}
}`

func TestGitHubCollector_BranchProtection_Protected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/concord-dev/concord/branches/main", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"name":"main","protected":true}`)
	})
	mux.HandleFunc("/repos/concord-dev/concord/branches/main/protection", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, protectionResponseJSON)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("test-token").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		ID: "branch_protection", Source: "github", Type: "branch_protection",
		Params: map[string]any{"repo": "concord-dev/concord", "branch": "main"},
	})
	require.NoError(t, err)

	m, ok := v.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "concord-dev/concord", m["repo"])
	assert.Equal(t, "main", m["branch"])
	assert.Equal(t, true, m["protected"])

	p, ok := m["protection"].(map[string]any)
	require.True(t, ok)
	ppr := p["required_pull_request_reviews"].(map[string]any)
	assert.EqualValues(t, 2, ppr["required_approving_review_count"])
	enforceAdmins := p["enforce_admins"].(map[string]any)
	assert.Equal(t, true, enforceAdmins["enabled"])
}

func TestGitHubCollector_BranchProtection_NotProtected(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/concord-dev/concord/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"name":"main","protected":false}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("test-token").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "branch_protection",
		Params: map[string]any{"repo": "concord-dev/concord"},
	})
	require.NoError(t, err)

	m := v.(map[string]any)
	assert.Equal(t, false, m["protected"])
	assert.Nil(t, m["protection"])
}

func TestGitHubCollector_PropagatesUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/x/y/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"Bad credentials"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("bad").SetBaseURL(srv.URL)
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "branch_protection",
		Params: map[string]any{"repo": "x/y"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "Bad credentials")
}

func TestGitHubCollector_MissingRepoErrors(t *testing.T) {
	c := evidence.NewGitHubCollector("t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "branch_protection",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repo")
}

func TestGitHubCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := evidence.NewGitHubCollector("t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "weird",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType), "expected ErrUnsupportedType, got %v", err)
	assert.Contains(t, err.Error(), "weird")
}

func TestGitHubCollector_EmptyTypeErrors(t *testing.T) {
	c := evidence.NewGitHubCollector("t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

func TestGitHubCollector_EnvSubstitution(t *testing.T) {
	t.Setenv("CONCORD_TEST_REPO", "owner/repo")

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/branches/main", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"name":"main","protected":false}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("t").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "branch_protection",
		Params: map[string]any{"repo": "${env.CONCORD_TEST_REPO}"},
	})
	require.NoError(t, err)
	assert.Equal(t, "owner/repo", v.(map[string]any)["repo"])
}
