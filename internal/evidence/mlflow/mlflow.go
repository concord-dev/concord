package mlflow

import (
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
	token   string
	client  *http.Client
}

func New(baseURL, token string) *Collector {
	return &Collector{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := c.get(ctx, "/api/2.0/mlflow/registered-models/search?max_results=1"); err != nil {
		return "", err
	}
	return "tracking server reachable at " + c.baseURL, nil
}

func (c *Collector) Collect(cctx evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "model_registry", "query":
		return c.collectModelRegistry(ref)
	case "":
		return nil, fmt.Errorf("mlflow collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: mlflow collector does not handle type %q", evidence.ErrUnsupportedType, ref.Type)
	}
}

func (c *Collector) collectModelRegistry(ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	raw, err := c.get(ctx, "/api/2.0/mlflow/registered-models/search?max_results=1000")
	if err != nil {
		return nil, fmt.Errorf("listing registered models: %w", err)
	}

	var resp struct {
		RegisteredModels []mlflowRegisteredModel `json:"registered_models"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	models := make([]map[string]any, 0, len(resp.RegisteredModels))
	for _, rm := range resp.RegisteredModels {
		models = append(models, normalizeMLflowModel(rm))
	}

	return map[string]any{
		"tracking_uri": c.baseURL,
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
		"models":       models,
	}, nil
}

func normalizeMLflowModel(rm mlflowRegisteredModel) map[string]any {
	prodVersion := pickProductionVersion(rm)
	tags := mergeTagSlices(rm.Tags, prodVersion.Tags)

	model := map[string]any{
		"name":               rm.Name,
		"production":         prodVersion.Version != "",
		"creation_timestamp": rm.CreationTimestamp,
	}
	if prodVersion.Version != "" {
		model["version"] = prodVersion.Version
		if prodVersion.CurrentStage != "" {
			model["stage"] = prodVersion.CurrentStage
		}
		if prodVersion.RunID != "" {
			model["run_id"] = prodVersion.RunID
		}
	}
	for k, v := range tags {
		if _, exists := model[k]; !exists {
			model[k] = v
		}
	}
	return model
}

func pickProductionVersion(rm mlflowRegisteredModel) mlflowModelVersion {
	for _, alias := range rm.Aliases {
		if strings.EqualFold(alias.Alias, "production") {
			for _, v := range rm.LatestVersions {
				if v.Version == alias.Version {
					return v
				}
			}
		}
	}
	for _, v := range rm.LatestVersions {
		if strings.EqualFold(v.CurrentStage, "production") {
			return v
		}
	}
	return mlflowModelVersion{}
}

func mergeTagSlices(modelTags, versionTags []mlflowTag) map[string]string {
	out := make(map[string]string, len(modelTags)+len(versionTags))
	for _, t := range modelTags {
		out[t.Key] = t.Value
	}
	for _, t := range versionTags {
		out[t.Key] = t.Value
	}
	return out
}

func (c *Collector) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("User-Agent", "concord-collector/0.1")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("mlflow %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}


type mlflowRegisteredModel struct {
	Name              string               `json:"name"`
	CreationTimestamp int64                `json:"creation_timestamp"`
	Tags              []mlflowTag          `json:"tags"`
	LatestVersions    []mlflowModelVersion `json:"latest_versions"`
	Aliases           []mlflowAlias        `json:"aliases"`
}

type mlflowModelVersion struct {
	Name              string      `json:"name"`
	Version           string      `json:"version"`
	CreationTimestamp int64       `json:"creation_timestamp"`
	CurrentStage      string      `json:"current_stage"`
	RunID             string      `json:"run_id"`
	Tags              []mlflowTag `json:"tags"`
}

type mlflowTag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type mlflowAlias struct {
	Alias   string `json:"alias"`
	Version string `json:"version"`
}
