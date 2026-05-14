package evidence_test

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
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const hfModelsListResponse = `[
  {
    "id": "concord-dev/fraud-detector",
    "author": "concord-dev",
    "private": false,
    "gated": false,
    "downloads": 1234,
    "likes": 12,
    "pipeline_tag": "text-classification",
    "library_name": "transformers",
    "tags": ["pytorch", "text-classification", "safety:audited"],
    "lastModified": "2026-04-30T10:00:00.000Z",
    "cardData": {
      "license": "apache-2.0",
      "datasets": ["concord-dev/fraud-data"],
      "language": ["en"]
    }
  },
  {
    "id": "concord-dev/no-card",
    "author": "concord-dev",
    "private": true,
    "downloads": 0,
    "likes": 0,
    "tags": [],
    "lastModified": "2026-01-01T00:00:00.000Z"
  }
]`

func TestHuggingFaceCollector_OrgModels(t *testing.T) {
	var sawAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		assert.Equal(t, "concord-dev", r.URL.Query().Get("author"))
		fmt.Fprint(w, hfModelsListResponse)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewHuggingFaceCollector(srv.URL, "hf_token")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "huggingface", Type: "org_models",
		Params: map[string]any{"author": "concord-dev"},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer hf_token", sawAuth)

	out := v.(map[string]any)
	models := out["models"].([]map[string]any)
	require.Len(t, models, 2)

	fraud := models[0]
	assert.Equal(t, "concord-dev/fraud-detector", fraud["name"])
	assert.Equal(t, "apache-2.0", fraud["license"], "license should be lifted from cardData")
	assert.Equal(t, "text-classification", fraud["pipeline_tag"])
	assert.Contains(t, fraud["tags"], "safety:audited")

	noCard := models[1]
	assert.Equal(t, "concord-dev/no-card", noCard["name"])
	assert.Nil(t, noCard["license"], "no cardData → no license field")
	assert.Equal(t, true, noCard["private"])
}

func TestHuggingFaceCollector_OrgModels_RequiresAuthor(t *testing.T) {
	c := evidence.NewHuggingFaceCollector("", "")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "huggingface", Type: "org_models"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "author")
}

func TestHuggingFaceCollector_OrgModels_AnonymousRequestSendsNoAuthHeader(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `[]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewHuggingFaceCollector(srv.URL, "")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "huggingface", Type: "org_models",
		Params: map[string]any{"author": "x"},
	})
	require.NoError(t, err)
	assert.Empty(t, gotAuth, "no token → no Authorization header")
}

func TestHuggingFaceCollector_ModelCard(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/google/bert-base-uncased", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{
		  "id": "google/bert-base-uncased",
		  "author": "google",
		  "sha": "abc123",
		  "pipeline_tag": "fill-mask",
		  "tags": ["pytorch", "bert"],
		  "cardData": {"license": "apache-2.0", "model-index": [{"name": "bert"}]}
		}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewHuggingFaceCollector(srv.URL, "tok")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "huggingface", Type: "model_card",
		Params: map[string]any{"repo_id": "google/bert-base-uncased"},
	})
	require.NoError(t, err)
	m := v.(map[string]any)
	assert.Equal(t, "google/bert-base-uncased", m["name"])
	assert.Equal(t, "apache-2.0", m["license"])
	assert.Equal(t, "abc123", m["sha"])
	assert.NotEmpty(t, m["model_index"])
}

func TestHuggingFaceCollector_ModelCard_RequiresRepoID(t *testing.T) {
	c := evidence.NewHuggingFaceCollector("", "")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "huggingface", Type: "model_card"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repo_id")
}

func TestHuggingFaceCollector_PropagatesAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"Invalid credentials"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewHuggingFaceCollector(srv.URL, "bad")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "huggingface", Type: "org_models",
		Params: map[string]any{"author": "x"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestHuggingFaceCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := evidence.NewHuggingFaceCollector("", "")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "huggingface", Type: "weird"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType))
}

func TestHuggingFaceCollector_Probe_Anonymous(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewHuggingFaceCollector(srv.URL, "")
	info, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Contains(t, info, "anonymous")
}

func TestHuggingFaceCollector_Probe_Authenticated(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/whoami-v2", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		fmt.Fprint(w, `{"name":"alice","type":"user"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewHuggingFaceCollector(srv.URL, "good")
	info, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Contains(t, info, "alice")

	bad := evidence.NewHuggingFaceCollector(srv.URL, "nope")
	_, err = bad.Probe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}
