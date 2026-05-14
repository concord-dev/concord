package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// GitHubCollector queries the GitHub REST API for repository evidence.
type GitHubCollector struct {
	token   string
	baseURL string
	client  *http.Client
}

// NewGitHubCollector returns a GitHubCollector configured with the given token.
func NewGitHubCollector(token string) *GitHubCollector {
	return &GitHubCollector{
		token:   token,
		baseURL: "https://api.github.com",
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBaseURL overrides the API base URL. Intended for tests.
func (c *GitHubCollector) SetBaseURL(url string) *GitHubCollector {
	c.baseURL = url
	return c
}

// Collect dispatches based on ref.Type.
func (c *GitHubCollector) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "branch_protection":
		return c.collectBranchProtection(ref)
	case "":
		return nil, fmt.Errorf("github collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: github collector does not handle type %q", ErrUnsupportedType, ref.Type)
	}
}

func (c *GitHubCollector) collectBranchProtection(ref apiv1.EvidenceRef) (any, error) {
	repo := StringParam(ref.Params, "repo", "")
	branch := StringParam(ref.Params, "branch", "main")
	if repo == "" {
		return nil, fmt.Errorf("missing required param %q", "repo")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info, err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/branches/%s", repo, branch))
	if err != nil {
		return nil, fmt.Errorf("branch lookup: %w", err)
	}
	bMap, ok := info.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("branch lookup: unexpected response shape")
	}
	protected, _ := bMap["protected"].(bool)

	result := map[string]any{
		"repo":      repo,
		"branch":    branch,
		"protected": protected,
		"protection": nil,
	}
	if !protected {
		return result, nil
	}

	full, err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/branches/%s/protection", repo, branch))
	if err != nil {
		return nil, fmt.Errorf("protection lookup: %w", err)
	}
	result["protection"] = full
	return result, nil
}

func (c *GitHubCollector) getJSON(ctx context.Context, path string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
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
		return nil, fmt.Errorf("github %s returned %d: %s", path, resp.StatusCode, string(body))
	}

	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return v, nil
}
