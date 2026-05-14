package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// SnykCollector queries Snyk's REST API for organisation-scoped issue data.
// It speaks the versioned /rest API rather than the legacy /v1 surface.
type SnykCollector struct {
	baseURL    string
	token      string
	apiVersion string
	client     *http.Client
}

// NewSnykCollector returns a collector configured for the given API token.
// The default base URL is https://api.snyk.io; override via SetBaseURL for tests.
func NewSnykCollector(token string) *SnykCollector {
	return &SnykCollector{
		baseURL:    "https://api.snyk.io",
		token:      token,
		apiVersion: "2024-10-15",
		client:     &http.Client{Timeout: 60 * time.Second},
	}
}

// SetBaseURL overrides the API host. Intended for tests against httptest.
func (c *SnykCollector) SetBaseURL(u string) *SnykCollector { c.baseURL = u; return c }

// SetAPIVersion pins a specific Snyk REST API date version.
func (c *SnykCollector) SetAPIVersion(v string) *SnykCollector { c.apiVersion = v; return c }

// Probe lists at most one issue against the org as a reachability + auth check.
// Returns the org id on success.
func (c *SnykCollector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if _, err := c.get(ctx, "/rest/self?version="+c.apiVersion); err != nil {
		return "", err
	}
	return "authenticated against " + c.baseURL, nil
}

// Collect dispatches based on ref.Type.
func (c *SnykCollector) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "org_issues":
		return c.collectOrgIssues(ref)
	case "":
		return nil, fmt.Errorf("snyk collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: snyk collector does not handle type %q", ErrUnsupportedType, ref.Type)
	}
}

func (c *SnykCollector) collectOrgIssues(ref apiv1.EvidenceRef) (any, error) {
	orgID := StringParam(ref.Params, "org_id", "")
	if orgID == "" {
		return nil, fmt.Errorf("missing required param %q", "org_id")
	}
	severities := StringParam(ref.Params, "severities", "critical,high,medium,low")
	statusFilter := StringParam(ref.Params, "status", "open")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	q := url.Values{}
	q.Set("version", c.apiVersion)
	q.Set("limit", "100")
	q.Set("effective_severity_level", severities)
	q.Set("status", statusFilter)

	path := fmt.Sprintf("/rest/orgs/%s/issues?%s", url.PathEscape(orgID), q.Encode())

	var issues []map[string]any
	for path != "" {
		raw, err := c.get(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("listing issues: %w", err)
		}
		var page snykIssuesPage
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, fmt.Errorf("parsing issues page: %w", err)
		}
		for _, d := range page.Data {
			issues = append(issues, normalizeSnykIssue(d))
		}
		path = nextPath(page.Links.Next, c.baseURL)
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"org_id":     orgID,
		"issues":     issues,
		"summary":    summarizeSnykIssues(issues),
	}, nil
}

type snykIssuesPage struct {
	Data  []snykIssue `json:"data"`
	Links snykLinks   `json:"links"`
}

type snykLinks struct {
	Next string `json:"next"`
}

type snykIssue struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Attributes snykIssueAttrs `json:"attributes"`
}

type snykIssueAttrs struct {
	Key                    string                `json:"key"`
	Title                  string                `json:"title"`
	Type                   string                `json:"type"`
	Status                 string                `json:"status"`
	EffectiveSeverityLevel string                `json:"effective_severity_level"`
	Coordinates            []snykIssueCoordinate `json:"coordinates"`
	CreatedAt              string                `json:"created_at"`
	UpdatedAt              string                `json:"updated_at"`
}

type snykIssueCoordinate struct {
	IsFixableManually bool                  `json:"is_fixable_manually"`
	IsFixableSnyk     bool                  `json:"is_fixable_snyk"`
	IsFixableUpstream bool                  `json:"is_fixable_upstream"`
	IsPatchable       bool                  `json:"is_patchable"`
	IsPinnable        bool                  `json:"is_pinnable"`
	IsUpgradeable     bool                  `json:"is_upgradeable"`
	Representations   []snykIssueRepresent `json:"representations"`
}

type snykIssueRepresent struct {
	Dependency snykDependency `json:"dependency"`
}

type snykDependency struct {
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
}

func normalizeSnykIssue(d snykIssue) map[string]any {
	out := map[string]any{
		"id":         d.ID,
		"key":        d.Attributes.Key,
		"title":      d.Attributes.Title,
		"type":       d.Attributes.Type,
		"status":     d.Attributes.Status,
		"severity":   strings.ToLower(d.Attributes.EffectiveSeverityLevel),
		"created_at": d.Attributes.CreatedAt,
		"updated_at": d.Attributes.UpdatedAt,
	}
	if len(d.Attributes.Coordinates) > 0 {
		c := d.Attributes.Coordinates[0]
		out["fixable"] = c.IsFixableManually || c.IsFixableSnyk || c.IsFixableUpstream || c.IsUpgradeable || c.IsPatchable || c.IsPinnable
		if len(c.Representations) > 0 {
			dep := c.Representations[0].Dependency
			out["package_name"] = dep.PackageName
			out["package_version"] = dep.PackageVersion
		}
	} else {
		out["fixable"] = false
	}
	return out
}

func summarizeSnykIssues(issues []map[string]any) map[string]any {
	counts := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, i := range issues {
		s, _ := i["severity"].(string)
		if _, ok := counts[s]; ok {
			counts[s]++
		}
	}
	return map[string]any{
		"critical": counts["critical"],
		"high":     counts["high"],
		"medium":   counts["medium"],
		"low":      counts["low"],
		"total":    len(issues),
	}
}

// nextPath converts a fully-qualified or relative next-link into a path Snyk's
// get() can call. Returns "" when there is no next page. We strip baseURL so
// the get() helper can prepend it cleanly without producing host duplication.
func nextPath(next, baseURL string) string {
	if next == "" {
		return ""
	}
	if strings.HasPrefix(next, baseURL) {
		return strings.TrimPrefix(next, baseURL)
	}
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		if u, err := url.Parse(next); err == nil {
			if u.RawQuery != "" {
				return u.Path + "?" + u.RawQuery
			}
			return u.Path
		}
	}
	return next
}

func (c *SnykCollector) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.api+json")
	req.Header.Set("Authorization", "token "+c.token)
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
		return nil, fmt.Errorf("snyk %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}
