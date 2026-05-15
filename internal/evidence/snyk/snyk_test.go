package snyk_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/evidence/snyk"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const snykPageOneJSON = `{
  "data": [
    {
      "id": "issue-1",
      "type": "issue",
      "attributes": {
        "key": "CVE-2024-1234",
        "title": "Prototype Pollution in lodash",
        "type": "package_vulnerability",
        "status": "open",
        "effective_severity_level": "critical",
        "created_at": "2026-04-01T00:00:00Z",
        "coordinates": [{
          "is_fixable_snyk": true,
          "is_upgradeable": true,
          "representations": [{
            "dependency": {"package_name": "lodash", "package_version": "4.17.10"}
          }]
        }]
      }
    },
    {
      "id": "issue-2",
      "type": "issue",
      "attributes": {
        "key": "CVE-2024-9999",
        "title": "ReDoS in regex-foo",
        "type": "package_vulnerability",
        "status": "open",
        "effective_severity_level": "high",
        "coordinates": [{
          "is_fixable_snyk": false,
          "is_fixable_manually": false,
          "representations": [{
            "dependency": {"package_name": "regex-foo", "package_version": "1.2.3"}
          }]
        }]
      }
    }
  ],
  "links": {"next": "%s/rest/orgs/test-org/issues?page=2&version=2024-10-15"}
}`

const snykPageTwoJSON = `{
  "data": [
    {
      "id": "issue-3",
      "type": "issue",
      "attributes": {
        "key": "CVE-2024-7777",
        "title": "XSS in old-jquery",
        "type": "package_vulnerability",
        "status": "open",
        "effective_severity_level": "medium",
        "coordinates": [{
          "is_fixable_snyk": true,
          "representations": [{
            "dependency": {"package_name": "old-jquery", "package_version": "1.0.0"}
          }]
        }]
      }
    }
  ],
  "links": {}
}`

func TestSnykCollector_OrgIssues_AggregatesAcrossPages(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/orgs/test-org/issues", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token tok-abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, snykPageTwoJSON)
			return
		}
		fmt.Fprintf(w, snykPageOneJSON, srv.URL)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := snyk.New("tok-abc").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "snyk", Type: "org_issues",
		Params: map[string]any{"org_id": "test-org"},
	})
	require.NoError(t, err)

	out := v.(map[string]any)
	assert.Equal(t, "test-org", out["org_id"])
	issues := out["issues"].([]map[string]any)
	require.Len(t, issues, 3, "should aggregate across paginated pages")

	first := issues[0]
	assert.Equal(t, "critical", first["severity"], "severity must be lower-cased")
	assert.Equal(t, "lodash", first["package_name"])
	assert.Equal(t, true, first["fixable"])

	second := issues[1]
	assert.Equal(t, false, second["fixable"], "no fix path → fixable=false")

	summary := out["summary"].(map[string]any)
	assert.Equal(t, 1, summary["critical"])
	assert.Equal(t, 1, summary["high"])
	assert.Equal(t, 1, summary["medium"])
	assert.Equal(t, 3, summary["total"])
}

const snykContainerProjectsJSON = `{
  "data": [
    {"id": "p1", "type": "project", "attributes": {"name": "concord-api:prod", "type": "container_image", "target_reference": "prod"}},
    {"id": "p2", "type": "project", "attributes": {"name": "concord-worker:prod", "type": "container_image", "target_reference": "prod"}}
  ],
  "links": {}
}`

const snykContainerIssuesP1JSON = `{
  "data": [
    {
      "id": "issue-1",
      "type": "issue",
      "attributes": {
        "key": "CVE-2024-12345",
        "title": "Heap overflow in libssl",
        "effective_severity_level": "critical",
        "status": "open",
        "coordinates": [{
          "is_fixable_snyk": true,
          "representations": [{"dependency": {"package_name": "openssl", "package_version": "1.1.1k"}}]
        }]
      }
    }
  ],
  "links": {}
}`

const snykContainerIssuesP2JSON = `{
  "data": [
    {
      "id": "issue-2",
      "type": "issue",
      "attributes": {
        "key": "CVE-2024-77777",
        "title": "Auth bypass in old-pkg",
        "effective_severity_level": "high",
        "status": "open",
        "coordinates": [{
          "is_fixable_snyk": true,
          "representations": [{"dependency": {"package_name": "old-pkg", "package_version": "3.0.0"}}]
        }]
      }
    }
  ],
  "links": {}
}`

func TestSnykCollector_ContainerIssues_AggregatesAcrossProjects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/orgs/test-org/projects", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "container_image", r.URL.Query().Get("types"))
		fmt.Fprint(w, snykContainerProjectsJSON)
	})
	mux.HandleFunc("/rest/orgs/test-org/issues", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("scan_item.id") {
		case "p1":
			fmt.Fprint(w, snykContainerIssuesP1JSON)
		case "p2":
			fmt.Fprint(w, snykContainerIssuesP2JSON)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := snyk.New("tok").SetBaseURL(srv.URL)
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "snyk", Type: "container_issues",
		Params: map[string]any{"org_id": "test-org"},
	})
	require.NoError(t, err)

	out := v.(map[string]any)
	assert.Equal(t, "container_image", out["project_type"])

	projects := out["projects"].([]map[string]any)
	require.Len(t, projects, 2)
	assert.Equal(t, 1, projects[0]["issue_count"])
	assert.Equal(t, 1, projects[1]["issue_count"])

	issues := out["issues"].([]map[string]any)
	require.Len(t, issues, 2)
	// Project metadata must be attached to each issue.
	assert.Equal(t, "p1", issues[0]["project_id"])
	assert.Equal(t, "concord-api:prod", issues[0]["project_name"])
	assert.Equal(t, "concord-worker:prod", issues[1]["project_name"])

	summary := out["summary"].(map[string]any)
	assert.Equal(t, 1, summary["critical"])
	assert.Equal(t, 1, summary["high"])
	assert.Equal(t, 2, summary["total"])
}

func TestSnykCollector_ContainerIssues_MissingOrgIDErrors(t *testing.T) {
	c := snyk.New("tok")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "snyk", Type: "container_issues"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org_id")
}

func TestSnykCollector_OrgIssues_MissingOrgIDErrors(t *testing.T) {
	c := snyk.New("tok")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "snyk", Type: "org_issues"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "org_id")
}

func TestSnykCollector_PropagatesAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/orgs/x/issues", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"detail":"invalid token"}]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := snyk.New("bad").SetBaseURL(srv.URL)
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "snyk", Type: "org_issues",
		Params: map[string]any{"org_id": "x"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "invalid token")
}

func TestSnykCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := snyk.New("tok")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "snyk", Type: "weird"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType))
}

func TestSnykCollector_Probe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token good" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"errors":[{"detail":"bad"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":{"id":"user-1","attributes":{}}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := snyk.New("good").SetBaseURL(srv.URL)
	info, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Contains(t, info, srv.URL)

	bad := snyk.New("nope").SetBaseURL(srv.URL)
	_, err = bad.Probe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}
