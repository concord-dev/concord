package huggingface

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	if baseURL == "" {
		baseURL = "https://huggingface.co"
	}
	return &Collector{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if c.token == "" {
		if _, err := c.get(ctx, "/api/models?limit=1"); err != nil {
			return "", err
		}
		return "reachable at " + c.baseURL + " (anonymous; set HUGGINGFACE_TOKEN to authenticate)", nil
	}
	raw, err := c.get(ctx, "/api/whoami-v2")
	if err != nil {
		return "", err
	}
	var who struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &who); err == nil && who.Name != "" {
		return "authenticated as " + who.Name, nil
	}
	return "authenticated", nil
}

func (c *Collector) Collect(cctx evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "org_models":
		return c.collectOrgModels(ref)
	case "model_card":
		return c.collectModelCard(ref)
	case "":
		return nil, fmt.Errorf("huggingface collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: huggingface collector does not handle type %q", evidence.ErrUnsupportedType, ref.Type)
	}
}

func (c *Collector) collectOrgModels(ref apiv1.EvidenceRef) (any, error) {
	author := evidence.StringParam(ref.Params, "author", "")
	if author == "" {
		return nil, fmt.Errorf("missing required param %q (org or user namespace)", "author")
	}
	limit := evidence.IntParam(ref.Params, "limit", 200)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	q := url.Values{}
	q.Set("author", author)
	q.Set("limit", fmt.Sprintf("%d", limit))
	q.Set("full", "true")
	raw, err := c.get(ctx, "/api/models?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("listing models for %s: %w", author, err)
	}
	var list []hfModelListEntry
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("parsing models list: %w", err)
	}

	models := make([]map[string]any, 0, len(list))
	for _, m := range list {
		models = append(models, normalizeHFModel(m))
	}
	return map[string]any{
		"tracking_uri": c.baseURL,
		"author":       author,
		"fetched_at":   time.Now().UTC().Format(time.RFC3339),
		"models":       models,
	}, nil
}

func (c *Collector) collectModelCard(ref apiv1.EvidenceRef) (any, error) {
	repoID := evidence.StringParam(ref.Params, "repo_id", "")
	if repoID == "" {
		return nil, fmt.Errorf("missing required param %q (e.g. %q)", "repo_id", "google/bert-base-uncased")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := c.get(ctx, "/api/models/"+repoID)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", repoID, err)
	}
	var m hfModelDetail
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing model: %w", err)
	}
	model := normalizeHFModelDetail(m)
	model["fetched_at"] = time.Now().UTC().Format(time.RFC3339)
	return model, nil
}

func normalizeHFModel(m hfModelListEntry) map[string]any {
	out := map[string]any{
		"name":          m.ID,
		"author":        m.Author,
		"private":       m.Private,
		"gated":         m.Gated,
		"downloads":     m.Downloads,
		"likes":         m.Likes,
		"pipeline_tag":  m.PipelineTag,
		"library_name":  m.LibraryName,
		"tags":          m.Tags,
		"last_modified": m.LastModified,
	}
	if m.CardData != nil {
		applyCardData(out, m.CardData)
	}
	return out
}

func normalizeHFModelDetail(m hfModelDetail) map[string]any {
	out := map[string]any{
		"name":          m.ID,
		"author":        m.Author,
		"private":       m.Private,
		"gated":         m.Gated,
		"downloads":     m.Downloads,
		"likes":         m.Likes,
		"pipeline_tag":  m.PipelineTag,
		"library_name":  m.LibraryName,
		"tags":          m.Tags,
		"last_modified": m.LastModified,
		"sha":           m.SHA,
	}
	if m.CardData != nil {
		applyCardData(out, m.CardData)
	}
	return out
}

func applyCardData(into map[string]any, card map[string]any) {
	if v, ok := card["license"]; ok {
		into["license"] = v
	}
	if v, ok := card["license_name"]; ok {
		into["license_name"] = v
	}
	if v, ok := card["datasets"]; ok {
		into["datasets"] = v
	}
	if v, ok := card["language"]; ok {
		into["language"] = v
	}
	if v, ok := card["model-index"]; ok {
		into["model_index"] = v
	}
	into["card"] = card
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
		return nil, fmt.Errorf("huggingface %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}


type hfModelListEntry struct {
	ID           string         `json:"id"`
	Author       string         `json:"author"`
	Private      bool           `json:"private"`
	Gated        any            `json:"gated"`
	Downloads    int            `json:"downloads"`
	Likes        int            `json:"likes"`
	PipelineTag  string         `json:"pipeline_tag"`
	LibraryName  string         `json:"library_name"`
	Tags         []string       `json:"tags"`
	LastModified string         `json:"lastModified"`
	CardData     map[string]any `json:"cardData"`
}

type hfModelDetail struct {
	hfModelListEntry
	SHA string `json:"sha"`
}
