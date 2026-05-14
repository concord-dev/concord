package evidence_test

import (
	"encoding/base64"
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

// --- file_glob ---

const fraudDocMD = "---\n" +
	"model: fraud-detector\n" +
	"reviewer: \"alice@example.com\"\n" +
	"secondary_reviewer: \"bob@example.com\"\n" +
	"reviewed_at: \"2026-04-01T00:00:00Z\"\n" +
	"intended_use: \"Detect fraud in real time.\"\n" +
	"foreseeable_misuse: \"May discriminate.\"\n" +
	"affected_populations: \"Customers.\"\n" +
	"residual_risk: medium\n" +
	"eu_ai_act_tier: high\n" +
	"---\n\nBody.\n"

const spamDocMD = "---\n" +
	"model: spam-classifier\n" +
	"reviewer: \"carol@example.com\"\n" +
	"reviewed_at: \"2026-04-15T00:00:00Z\"\n" +
	"intended_use: \"Flag spam.\"\n" +
	"foreseeable_misuse: \"Over-block.\"\n" +
	"affected_populations: \"All users.\"\n" +
	"residual_risk: low\n" +
	"eu_ai_act_tier: limited\n" +
	"---\n"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func newFileGlobServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/docs/ai/risk-assessments", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[
			{"name":"fraud-detector.md","path":"docs/ai/risk-assessments/fraud-detector.md","type":"file"},
			{"name":"spam-classifier.md","path":"docs/ai/risk-assessments/spam-classifier.md","type":"file"},
			{"name":"README.txt","path":"docs/ai/risk-assessments/README.txt","type":"file"},
			{"name":"sub","path":"docs/ai/risk-assessments/sub","type":"dir"}
		]`)
	})
	mux.HandleFunc("/repos/owner/repo/contents/docs/ai/risk-assessments/fraud-detector.md", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"name":"fraud-detector.md","path":"docs/ai/risk-assessments/fraud-detector.md","content":"%s","encoding":"base64"}`, b64(fraudDocMD))
	})
	mux.HandleFunc("/repos/owner/repo/contents/docs/ai/risk-assessments/spam-classifier.md", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"name":"spam-classifier.md","path":"docs/ai/risk-assessments/spam-classifier.md","content":"%s","encoding":"base64"}`, b64(spamDocMD))
	})
	return httptest.NewServer(mux)
}

func TestGitHubCollector_FileGlob_FrontmatterParse(t *testing.T) {
	srv := newFileGlobServer(t)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("t").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "file_glob",
		Params: map[string]any{
			"repo":  "owner/repo",
			"paths": []any{"docs/ai/risk-assessments/*.md"},
			"parse": "frontmatter",
		},
	})
	require.NoError(t, err)

	m, ok := v.(map[string]any)
	require.True(t, ok)
	docs, ok := m["docs"].([]map[string]any)
	require.True(t, ok, "docs should be []map[string]any, got %T", m["docs"])
	require.Len(t, docs, 2, "expected only the two .md files; README.txt and sub/ filtered")

	// sorted alphabetically by path
	assert.Equal(t, "docs/ai/risk-assessments/fraud-detector.md", docs[0]["path"])
	assert.Equal(t, "fraud-detector", docs[0]["model"])
	assert.Equal(t, "alice@example.com", docs[0]["reviewer"])
	assert.Equal(t, "bob@example.com", docs[0]["secondary_reviewer"])
	assert.Equal(t, "high", docs[0]["eu_ai_act_tier"])
	assert.Equal(t, "2026-04-01T00:00:00Z", docs[0]["reviewed_at"])

	assert.Equal(t, "docs/ai/risk-assessments/spam-classifier.md", docs[1]["path"])
	assert.Equal(t, "spam-classifier", docs[1]["model"])
	assert.Equal(t, "limited", docs[1]["eu_ai_act_tier"])
}

func TestGitHubCollector_FileGlob_MissingPaths(t *testing.T) {
	c := evidence.NewGitHubCollector("t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "file_glob",
		Params: map[string]any{"repo": "owner/repo"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "paths")
}

func TestGitHubCollector_FileGlob_DirectoryNotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/nope", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("t").SetBaseURL(srv.URL)
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "file_glob",
		Params: map[string]any{
			"repo":  "owner/repo",
			"paths": []any{"nope/*.md"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestGitHubCollector_FileGlob_MalformedFrontmatter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/d", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"name":"x.md","path":"d/x.md","type":"file"}]`)
	})
	mux.HandleFunc("/repos/owner/repo/contents/d/x.md", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"name":"x.md","path":"d/x.md","content":"%s","encoding":"base64"}`, b64("no frontmatter here, just text"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("t").SetBaseURL(srv.URL)
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "file_glob",
		Params: map[string]any{
			"repo":  "owner/repo",
			"paths": []any{"d/*.md"},
			"parse": "frontmatter",
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "frontmatter")
}

func TestGitHubCollector_FileGlob_NoParse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo/contents/d", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"name":"x.txt","path":"d/x.txt","type":"file"}]`)
	})
	mux.HandleFunc("/repos/owner/repo/contents/d/x.txt", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"name":"x.txt","path":"d/x.txt","content":"%s","encoding":"base64"}`, b64("hello world"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("t").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "file_glob",
		Params: map[string]any{
			"repo":  "owner/repo",
			"paths": []any{"d/*.txt"},
		},
	})
	require.NoError(t, err)

	docs := v.(map[string]any)["docs"].([]map[string]any)
	require.Len(t, docs, 1)
	assert.Equal(t, "hello world", docs[0]["content"])
}

// --- org_security_policy ---

func TestGitHubCollector_OrgSecurityPolicy(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/concord-dev", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{
			"login": "concord-dev",
			"id": 42,
			"two_factor_requirement_enabled": true,
			"members_can_create_repositories": true,
			"default_repository_permission": "read",
			"web_commit_signoff_required": false,
			"advanced_security_enabled_for_new_repositories": true,
			"secret_scanning_enabled_for_new_repositories": true,
			"secret_scanning_push_protection_enabled_for_new_repositories": true,
			"dependabot_alerts_enabled_for_new_repositories": true
		}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewGitHubCollector("t").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "org_security_policy",
		Params: map[string]any{"org": "concord-dev"},
	})
	require.NoError(t, err)

	out := v.(map[string]any)
	assert.Equal(t, "concord-dev", out["org"])

	policy := out["policy"].(map[string]any)
	assert.Equal(t, true, policy["two_factor_requirement_enabled"])
	assert.Equal(t, "read", policy["default_repository_permission"])
	assert.Equal(t, true, policy["secret_scanning_enabled_for_new_repositories"])
	// id is not in the whitelist — should not appear.
	_, exists := policy["id"]
	assert.False(t, exists, "non-security fields should be filtered out")
}

func TestGitHubCollector_OrgSecurityPolicy_MissingOrgErrors(t *testing.T) {
	c := evidence.NewGitHubCollector("t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "github", Type: "org_security_policy",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org")
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
