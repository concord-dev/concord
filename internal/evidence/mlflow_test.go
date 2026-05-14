package evidence_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const mlflowRegisteredModelsResponse = `{
  "registered_models": [
    {
      "name": "fraud-detector",
      "creation_timestamp": 1730000000000,
      "tags": [
        {"key": "owner", "value": "ml-platform"}
      ],
      "latest_versions": [
        {
          "name": "fraud-detector",
          "version": "5",
          "current_stage": "None",
          "run_id": "run-abc",
          "tags": [
            {"key": "eu_ai_act_tier", "value": "high"},
            {"key": "evaluation_report", "value": "s3://reports/fraud-v5.json"},
            {"key": "last_evaluated_at", "value": "2026-04-01T00:00:00Z"}
          ]
        },
        {
          "name": "fraud-detector",
          "version": "4",
          "current_stage": "Archived",
          "tags": []
        }
      ],
      "aliases": [
        {"alias": "production", "version": "5"}
      ]
    },
    {
      "name": "spam-classifier",
      "creation_timestamp": 1730000000000,
      "tags": [],
      "latest_versions": [
        {
          "name": "spam-classifier",
          "version": "2",
          "current_stage": "Production",
          "tags": [
            {"key": "eu_ai_act_tier", "value": "limited"}
          ]
        }
      ],
      "aliases": []
    },
    {
      "name": "experimental-rec",
      "latest_versions": [
        {"name": "experimental-rec", "version": "1", "current_stage": "Staging", "tags": []}
      ]
    }
  ]
}`

func TestMLflowCollector_ModelRegistry_AliasAndStage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dbx-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, mlflowRegisteredModelsResponse)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewMLflowCollector(srv.URL, "dbx-token")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "mlflow", Type: "model_registry",
	})
	require.NoError(t, err)

	out := v.(map[string]any)
	models := out["models"].([]map[string]any)
	require.Len(t, models, 3)

	// fraud-detector picked up via alias=production on version 5
	fraud := findModel(t, models, "fraud-detector")
	assert.Equal(t, true, fraud["production"])
	assert.Equal(t, "5", fraud["version"])
	assert.Equal(t, "high", fraud["eu_ai_act_tier"])
	assert.Equal(t, "s3://reports/fraud-v5.json", fraud["evaluation_report"])
	assert.Equal(t, "2026-04-01T00:00:00Z", fraud["last_evaluated_at"])
	assert.Equal(t, "ml-platform", fraud["owner"])

	// spam-classifier picked up via current_stage="Production"
	spam := findModel(t, models, "spam-classifier")
	assert.Equal(t, true, spam["production"])
	assert.Equal(t, "limited", spam["eu_ai_act_tier"])

	// experimental-rec has no production marker
	exp := findModel(t, models, "experimental-rec")
	assert.Equal(t, false, exp["production"])
}

func TestMLflowCollector_PropagatesUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error_code":"PERMISSION_DENIED"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewMLflowCollector(srv.URL, "bad")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "mlflow", Type: "model_registry"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestMLflowCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := evidence.NewMLflowCollector("http://localhost", "")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "mlflow", Type: "weird"})
	require.Error(t, err)
	// the registry will fall back to fixture; collector itself signals unsupported
}

func TestMLflowCollector_Probe(t *testing.T) {
	var calledPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, r *http.Request) {
		calledPath = r.URL.RequestURI()
		fmt.Fprint(w, `{"registered_models":[]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewMLflowCollector(srv.URL, "")
	info, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Contains(t, info, srv.URL)
	assert.Contains(t, calledPath, "max_results=1", "probe should pull one record only")
}

func TestMLflowCollector_Probe_PropagatesAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error_code":"PERMISSION_DENIED"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewMLflowCollector(srv.URL, "bad")
	_, err := c.Probe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestMLflowCollector_NoAuthHeaderWhenTokenEmpty(t *testing.T) {
	var sawAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/2.0/mlflow/registered-models/search", func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"registered_models":[]}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewMLflowCollector(srv.URL, "")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "mlflow", Type: "model_registry"})
	require.NoError(t, err)
	assert.Empty(t, sawAuth, "no token → no Authorization header")
}

func findModel(t *testing.T, models []map[string]any, name string) map[string]any {
	t.Helper()
	for _, m := range models {
		if m["name"] == name {
			return m
		}
	}
	t.Fatalf("model %q not found", name)
	return nil
}
