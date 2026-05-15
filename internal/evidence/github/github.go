package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/evidence"

	"sigs.k8s.io/yaml"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Collector queries the GitHub REST API for repository evidence.
type Collector struct {
	token   string
	baseURL string
	client  *http.Client
}

// New returns a Collector configured with the given token.
func New(token string) *Collector {
	return &Collector{
		token:   token,
		baseURL: "https://api.github.com",
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// SetBaseURL overrides the API base URL. Intended for tests.
func (c *Collector) SetBaseURL(url string) *Collector {
	c.baseURL = url
	return c
}

// Probe calls GET /user as a low-cost reachability + auth check. Returns the
// authenticated login (e.g. "octocat") or a wrapped error suitable for
// surfacing in `concord doctor`.
func (c *Collector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := c.getJSON(ctx, "/user")
	if err != nil {
		return "", err
	}
	if obj, ok := raw.(map[string]any); ok {
		if login, ok := obj["login"].(string); ok && login != "" {
			return "authenticated as " + login, nil
		}
	}
	return "authenticated", nil
}

// Collect dispatches based on ref.Type.
func (c *Collector) Collect(cctx evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "branch_protection":
		return c.collectBranchProtection(ref)
	case "file_glob":
		return c.collectFileGlob(ref)
	case "org_security_policy":
		return c.collectOrgSecurityPolicy(ref)
	case "":
		return nil, fmt.Errorf("github collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: github collector does not handle type %q", evidence.ErrUnsupportedType, ref.Type)
	}
}

func (c *Collector) collectBranchProtection(ref apiv1.EvidenceRef) (any, error) {
	repo := evidence.StringParam(ref.Params, "repo", "")
	branch := evidence.StringParam(ref.Params, "branch", "main")
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
		"repo":       repo,
		"branch":     branch,
		"protected":  protected,
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

func (c *Collector) collectOrgSecurityPolicy(ref apiv1.EvidenceRef) (any, error) {
	org := evidence.StringParam(ref.Params, "org", "")
	if org == "" {
		// Auto-derive from a "owner/repo" string if provided.
		repo := evidence.StringParam(ref.Params, "repo", "")
		if idx := strings.Index(repo, "/"); idx > 0 {
			org = repo[:idx]
		}
	}
	if org == "" {
		return nil, fmt.Errorf("missing required param %q (set explicitly or supply %q to auto-derive)", "org", "repo")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := c.getJSON(ctx, fmt.Sprintf("/orgs/%s", org))
	if err != nil {
		return nil, fmt.Errorf("fetching org %s: %w", org, err)
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected org response shape")
	}

	// Whitelist the security-relevant fields so policies have a stable, named surface.
	keys := []string{
		"two_factor_requirement_enabled",
		"members_can_create_repositories",
		"members_can_create_public_repositories",
		"members_can_fork_private_repositories",
		"default_repository_permission",
		"web_commit_signoff_required",
		"advanced_security_enabled_for_new_repositories",
		"secret_scanning_enabled_for_new_repositories",
		"secret_scanning_push_protection_enabled_for_new_repositories",
		"dependency_graph_enabled_for_new_repositories",
		"dependabot_alerts_enabled_for_new_repositories",
		"dependabot_security_updates_enabled_for_new_repositories",
	}
	policy := map[string]any{}
	for _, k := range keys {
		if v, ok := obj[k]; ok {
			policy[k] = v
		}
	}
	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"org":        org,
		"policy":     policy,
	}, nil
}

func (c *Collector) collectFileGlob(ref apiv1.EvidenceRef) (any, error) {
	repo := evidence.StringParam(ref.Params, "repo", "")
	if repo == "" {
		return nil, fmt.Errorf("missing required param %q", "repo")
	}
	globs := evidence.StringSliceParam(ref.Params, "paths")
	if len(globs) == 0 {
		return nil, fmt.Errorf("missing required param %q (expected list of globs)", "paths")
	}
	parse := evidence.StringParam(ref.Params, "parse", "")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	docs := []map[string]any{}
	scannedPaths := []string{}

	for _, glob := range globs {
		dir := path.Dir(glob)
		pattern := path.Base(glob)
		scannedPaths = append(scannedPaths, dir)

		listing, err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/contents/%s", repo, dir))
		if err != nil {
			// 404 on a doc directory means "no documents here yet" — fall
			// through with an empty listing so the policy's "no docs" deny
			// rule fires cleanly instead of surfacing a raw HTTP error.
			if isGitHubNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("listing %s: %w", dir, err)
		}
		entries, ok := listing.([]any)
		if !ok {
			return nil, fmt.Errorf("expected directory listing at %s; got non-array response", dir)
		}

		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := entry["type"].(string); t != "file" {
				continue
			}
			name, _ := entry["name"].(string)
			matched, _ := path.Match(pattern, name)
			if !matched {
				continue
			}
			filePath, _ := entry["path"].(string)

			doc, err := c.fetchAndParseFile(ctx, repo, filePath, parse)
			if err != nil {
				return nil, err
			}
			docs = append(docs, doc)
		}
	}

	sort.SliceStable(docs, func(i, j int) bool {
		pi, _ := docs[i]["path"].(string)
		pj, _ := docs[j]["path"].(string)
		return pi < pj
	})

	return map[string]any{
		"scanned_paths": scannedPaths,
		"docs":          docs,
	}, nil
}

func (c *Collector) fetchAndParseFile(ctx context.Context, repo, filePath, parse string) (map[string]any, error) {
	resp, err := c.getJSON(ctx, fmt.Sprintf("/repos/%s/contents/%s", repo, filePath))
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", filePath, err)
	}
	obj, ok := resp.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected file response shape for %s", filePath)
	}
	content, err := decodeContent(obj)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", filePath, err)
	}

	var doc map[string]any
	switch parse {
	case "frontmatter":
		doc, err = parseFrontmatter(content)
		if err != nil {
			return nil, fmt.Errorf("parsing frontmatter from %s: %w", filePath, err)
		}
	case "":
		doc = map[string]any{"content": string(content)}
	default:
		return nil, fmt.Errorf("unknown parse mode %q for %s", parse, filePath)
	}
	doc["path"] = filePath
	return doc, nil
}

func decodeContent(obj map[string]any) ([]byte, error) {
	enc, _ := obj["encoding"].(string)
	raw, _ := obj["content"].(string)
	if enc != "base64" {
		return nil, fmt.Errorf("unsupported content encoding %q (expected base64)", enc)
	}
	cleaned := strings.ReplaceAll(raw, "\n", "")
	return base64.StdEncoding.DecodeString(cleaned)
}

// isGitHubNotFound returns true when the error wraps a 404 from the GitHub API.
// Errors from getJSON include the response body which contains "returned 404" — we sniff that.
func isGitHubNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "returned 404")
}

func parseFrontmatter(content []byte) (map[string]any, error) {
	s := strings.ReplaceAll(string(content), "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return nil, fmt.Errorf("file does not start with frontmatter delimiter ---")
	}
	rest := s[4:]
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return nil, fmt.Errorf("no closing frontmatter delimiter ---")
	}
	fm := rest[:end]
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(fm), &doc); err != nil {
		return nil, fmt.Errorf("yaml: %w", err)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	return doc, nil
}

func (c *Collector) getJSON(ctx context.Context, apiPath string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+apiPath, nil)
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
		return nil, fmt.Errorf("github %s returned %d: %s", apiPath, resp.StatusCode, string(body))
	}

	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return v, nil
}
