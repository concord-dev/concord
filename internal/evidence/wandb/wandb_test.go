package wandb_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/evidence/wandb"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// wandbRegistryFixture mimics a real W&B GraphQL response.
const wandbRegistryFixture = `{
  "data": {
    "entity": {
      "projects": {
        "edges": [
          {
            "node": {
              "name": "fraud",
              "artifactCollections": {
                "edges": [
                  {
                    "node": {
                      "name": "fraud-detector",
                      "typeName": "model",
                      "tags": {"edges": [{"node": {"name": "eu_ai_act_tier:high"}}]},
                      "artifacts": {
                        "edges": [
                          {
                            "node": {
                              "versionIndex": "v3",
                              "metadata": {"reviewer": "alice", "evaluation_report": "s3://reports/fraud-v3.json"},
                              "aliases": {"edges": [{"node": {"alias": "production"}}, {"node": {"alias": "v3"}}]}
                            }
                          },
                          {
                            "node": {
                              "versionIndex": "v2",
                              "metadata": {},
                              "aliases": {"edges": [{"node": {"alias": "v2"}}]}
                            }
                          }
                        ]
                      }
                    }
                  },
                  {
                    "node": {
                      "name": "fraud-dataset",
                      "typeName": "dataset",
                      "tags": {"edges": []},
                      "artifacts": {"edges": []}
                    }
                  }
                ]
              }
            }
          },
          {
            "node": {
              "name": "experiments",
              "artifactCollections": {
                "edges": [
                  {
                    "node": {
                      "name": "test-model",
                      "typeName": "model",
                      "tags": {"edges": []},
                      "artifacts": {
                        "edges": [
                          {
                            "node": {
                              "versionIndex": "v0",
                              "metadata": {},
                              "aliases": {"edges": [{"node": {"alias": "v0"}}]}
                            }
                          }
                        ]
                      }
                    }
                  }
                ]
              }
            }
          }
        ]
      }
    }
  }
}`

func TestWandbCollector_ModelRegistry_NormalizesProductionAndTags(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "api" || p != "key-abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		vars, _ := req["variables"].(map[string]any)
		assert.Equal(t, "concord-dev", vars["entityName"], "entity must be passed as graphql variable")
		fmt.Fprint(w, wandbRegistryFixture)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := wandb.New(srv.URL, "key-abc")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "wandb", Type: "model_registry",
		Params: map[string]any{"entity": "concord-dev"},
	})
	require.NoError(t, err)

	out := v.(map[string]any)
	assert.Equal(t, "concord-dev", out["entity"])

	models := out["models"].([]map[string]any)
	require.Len(t, models, 2, "two model collections across two projects; dataset must be filtered")

	fraud := findWandbModel(t, models, "fraud-detector")
	assert.Equal(t, "fraud", fraud["project"])
	assert.Equal(t, true, fraud["production"])
	assert.Equal(t, "v3", fraud["version"])
	assert.Contains(t, fraud["aliases"], "production")
	// Collection tag promoted as "true".
	assert.Equal(t, "true", fraud["eu_ai_act_tier:high"])
	// Production artifact metadata fields promoted.
	assert.Equal(t, "alice", fraud["reviewer"])
	assert.Equal(t, "s3://reports/fraud-v3.json", fraud["evaluation_report"])

	test := findWandbModel(t, models, "test-model")
	assert.Equal(t, false, test["production"], "no production alias on test-model")
}

func TestWandbCollector_ModelRegistry_ProjectFilter(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, wandbRegistryFixture)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := wandb.New(srv.URL, "k")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "wandb", Type: "model_registry",
		Params: map[string]any{"entity": "concord-dev", "project": "fraud"},
	})
	require.NoError(t, err)
	models := v.(map[string]any)["models"].([]map[string]any)
	require.Len(t, models, 1)
	assert.Equal(t, "fraud-detector", models[0]["name"])
}

func TestWandbCollector_MissingEntityErrors(t *testing.T) {
	c := wandb.New("https://api.wandb.ai", "k")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "wandb", Type: "model_registry"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entity")
}

func TestWandbCollector_PropagatesGraphQLErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"errors":[{"message":"permission denied"}],"data":null}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := wandb.New(srv.URL, "k")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "wandb", Type: "model_registry",
		Params: map[string]any{"entity": "x"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

func TestWandbCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := wandb.New("", "k")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "wandb", Type: "weird"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType))
}

func TestWandbCollector_Probe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		assert.True(t, strings.Contains(string(body), "viewer"))
		_, p, _ := r.BasicAuth()
		if p != "good" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `unauthorized`)
			return
		}
		fmt.Fprint(w, `{"data":{"viewer":{"username":"alice"}}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := wandb.New(srv.URL, "good")
	info, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Contains(t, info, "alice")

	bad := wandb.New(srv.URL, "nope")
	_, err = bad.Probe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func findWandbModel(t *testing.T, models []map[string]any, name string) map[string]any {
	t.Helper()
	for _, m := range models {
		if m["name"] == name {
			return m
		}
	}
	t.Fatalf("model %q not found", name)
	return nil
}
