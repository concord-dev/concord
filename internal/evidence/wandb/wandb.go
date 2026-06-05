package wandb

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/evidence"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type Collector struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

func New(baseURL, apiKey string) *Collector {
	if baseURL == "" {
		baseURL = "https://api.wandb.ai"
	}
	return &Collector{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var resp struct {
		Data struct {
			Viewer struct {
				Username string `json:"username"`
			} `json:"viewer"`
		} `json:"data"`
	}
	if err := c.graphql(ctx, "query { viewer { username } }", nil, &resp); err != nil {
		return "", err
	}
	if resp.Data.Viewer.Username != "" {
		return "authenticated as " + resp.Data.Viewer.Username, nil
	}
	return "authenticated", nil
}

func (c *Collector) Collect(cctx evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "model_registry":
		return c.collectModelRegistry(ref)
	case "":
		return nil, fmt.Errorf("wandb collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: wandb collector does not handle type %q", evidence.ErrUnsupportedType, ref.Type)
	}
}

func (c *Collector) collectModelRegistry(ref apiv1.EvidenceRef) (any, error) {
	entityName := evidence.StringParam(ref.Params, "entity", "")
	if entityName == "" {
		return nil, fmt.Errorf("missing required param %q", "entity")
	}
	projectFilter := evidence.StringParam(ref.Params, "project", "")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var resp wandbRegistryResp
	if err := c.graphql(ctx, wandbRegistryQuery, map[string]any{"entityName": entityName}, &resp); err != nil {
		return nil, fmt.Errorf("listing registered models: %w", err)
	}

	models := make([]map[string]any, 0)
	for _, projEdge := range resp.Data.Entity.Projects.Edges {
		project := projEdge.Node.Name
		if projectFilter != "" && project != projectFilter {
			continue
		}
		for _, collEdge := range projEdge.Node.ArtifactCollections.Edges {
			coll := collEdge.Node
			if coll.TypeName != "model" {
				continue
			}
			models = append(models, normalizeWandbCollection(project, coll))
		}
	}

	return map[string]any{
		"tracking_uri": c.baseURL,
		"entity":       entityName,
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
		"models":       models,
	}, nil
}

func normalizeWandbCollection(project string, coll wandbArtifactCollection) map[string]any {
	prod := pickWandbProductionArtifact(coll)
	tags := mergeWandbTags(coll.Tags.Edges, prod.metadata())

	model := map[string]any{
		"name":       coll.Name,
		"project":    project,
		"production": prod.VersionIndex != "",
	}
	if prod.VersionIndex != "" {
		model["version"] = prod.VersionIndex
		model["aliases"] = prod.aliasNames()
	}
	for k, v := range tags {
		if _, exists := model[k]; !exists {
			model[k] = v
		}
	}
	return model
}

func pickWandbProductionArtifact(coll wandbArtifactCollection) wandbArtifact {
	for _, edge := range coll.Artifacts.Edges {
		for _, aliasEdge := range edge.Node.Aliases.Edges {
			a := strings.ToLower(aliasEdge.Node.Alias)
			if a == "production" || a == "prod" {
				return edge.Node
			}
		}
	}
	return wandbArtifact{}
}

func mergeWandbTags(tagEdges []wandbTagEdge, metadata map[string]any) map[string]any {
	out := make(map[string]any, len(tagEdges)+len(metadata))
	for _, t := range tagEdges {
		out[t.Node.Name] = "true"
	}
	for k, v := range metadata {
		out[k] = v
	}
	return out
}

func (c *Collector) graphql(ctx context.Context, query string, vars map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": vars})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("api", c.apiKey)
	req.Header.Set("User-Agent", "concord-collector/0.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("wandb /graphql returned %d: %s", resp.StatusCode, string(raw))
	}

	var probe struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && len(probe.Errors) > 0 {
		return fmt.Errorf("wandb graphql error: %s", probe.Errors[0].Message)
	}

	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}


const wandbRegistryQuery = `query ConcordRegistry($entityName: String!) {
  entity(name: $entityName) {
    projects(first: 100) {
      edges {
        node {
          name
          artifactCollections(first: 200) {
            edges {
              node {
                name
                typeName
                tags { edges { node { name } } }
                artifacts(first: 100) {
                  edges {
                    node {
                      versionIndex
                      metadata
                      aliases { edges { node { alias } } }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}`

type wandbRegistryResp struct {
	Data struct {
		Entity struct {
			Projects struct {
				Edges []struct {
					Node struct {
						Name                string                      `json:"name"`
						ArtifactCollections wandbArtifactCollectionList `json:"artifactCollections"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"projects"`
		} `json:"entity"`
	} `json:"data"`
}

type wandbArtifactCollectionList struct {
	Edges []struct {
		Node wandbArtifactCollection `json:"node"`
	} `json:"edges"`
}

type wandbArtifactCollection struct {
	Name      string            `json:"name"`
	TypeName  string            `json:"typeName"`
	Tags      wandbTagList      `json:"tags"`
	Artifacts wandbArtifactList `json:"artifacts"`
}

type wandbTagList struct {
	Edges []wandbTagEdge `json:"edges"`
}

type wandbTagEdge struct {
	Node struct {
		Name string `json:"name"`
	} `json:"node"`
}

type wandbArtifactList struct {
	Edges []struct {
		Node wandbArtifact `json:"node"`
	} `json:"edges"`
}

type wandbArtifact struct {
	VersionIndex string          `json:"versionIndex"`
	Metadata     json.RawMessage `json:"metadata"`
	Aliases      wandbAliasList  `json:"aliases"`
}

type wandbAliasList struct {
	Edges []wandbAliasEdge `json:"edges"`
}

type wandbAliasEdge struct {
	Node struct {
		Alias string `json:"alias"`
	} `json:"node"`
}

func (a wandbArtifact) metadata() map[string]any {
	if len(a.Metadata) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(a.Metadata, &out); err != nil {
		var s string
		if err2 := json.Unmarshal(a.Metadata, &s); err2 == nil && s != "" {
			_ = json.Unmarshal([]byte(s), &out)
		}
	}
	return out
}

func (a wandbArtifact) aliasNames() []string {
	out := make([]string, 0, len(a.Aliases.Edges))
	for _, e := range a.Aliases.Edges {
		out = append(out, e.Node.Alias)
	}
	return out
}
