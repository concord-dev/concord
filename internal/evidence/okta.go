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

// OktaCollector queries an Okta org's REST API for identity evidence.
type OktaCollector struct {
	orgURL string
	token  string
	client *http.Client
}

// NewOktaCollector returns a collector configured against an Okta org.
// orgURL is the full org URL (e.g. "https://acme.okta.com"). token is an Okta API token.
func NewOktaCollector(orgURL, token string) *OktaCollector {
	return &OktaCollector{
		orgURL: strings.TrimRight(orgURL, "/"),
		token:  token,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// Collect dispatches based on ref.Type.
func (c *OktaCollector) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	switch ref.Type {
	case "users_mfa":
		return c.collectUsers(ref, `status eq "ACTIVE"`)
	case "users_offboarding":
		return c.collectUsers(ref, `status eq "SUSPENDED" or status eq "DEPROVISIONED"`)
	case "":
		return nil, fmt.Errorf("okta collector requires evidence type")
	default:
		return nil, fmt.Errorf("%w: okta collector does not handle type %q", ErrUnsupportedType, ref.Type)
	}
}

// weakFactorTypes are factors we consider too weak to satisfy "strong MFA".
// SMS/call are subject to SIM-swap; security questions to social engineering.
var weakFactorTypes = map[string]bool{
	"sms":               true,
	"call":              true,
	"email":             true,
	"security_question": true,
}

// collectUsers lists users matching the given Okta filter and fetches each
// user's MFA factors. Used by both users_mfa (active users) and
// users_offboarding (suspended/deprovisioned users).
func (c *OktaCollector) collectUsers(ref apiv1.EvidenceRef, filter string) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	users, err := c.listUsers(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}

	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		factors, err := c.listFactors(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("listing factors for %s: %w", u.Profile.Email, err)
		}
		normalized := normalizeFactors(factors)
		out = append(out, map[string]any{
			"id":             u.ID,
			"email":          u.Profile.Email,
			"name":           strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName),
			"login":          u.Profile.Login,
			"status":         u.Status,
			"factors":        normalized,
			"has_strong_mfa": hasStrongMFA(normalized),
		})
	}

	return map[string]any{
		"fetched_at": time.Now().UTC().Format(time.RFC3339),
		"org_url":    c.orgURL,
		"users":      out,
	}, nil
}

func (c *OktaCollector) listUsers(ctx context.Context, filter string) ([]oktaUser, error) {
	// Single-page (200 users) for v0. Pagination via Link header is a TODO.
	path := "/api/v1/users?limit=200&filter=" + url.QueryEscape(filter)
	raw, err := c.get(ctx, path)
	if err != nil {
		return nil, err
	}
	var users []oktaUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, fmt.Errorf("parsing users: %w", err)
	}
	return users, nil
}

func (c *OktaCollector) listFactors(ctx context.Context, userID string) ([]oktaFactor, error) {
	raw, err := c.get(ctx, "/api/v1/users/"+userID+"/factors")
	if err != nil {
		return nil, err
	}
	var factors []oktaFactor
	if err := json.Unmarshal(raw, &factors); err != nil {
		return nil, fmt.Errorf("parsing factors: %w", err)
	}
	return factors, nil
}

func (c *OktaCollector) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.orgURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "SSWS "+c.token)
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
		return nil, fmt.Errorf("okta %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

func normalizeFactors(factors []oktaFactor) []map[string]any {
	out := make([]map[string]any, 0, len(factors))
	for _, f := range factors {
		out = append(out, map[string]any{
			"type":     f.FactorType,
			"provider": f.Provider,
			"status":   f.Status,
		})
	}
	return out
}

func hasStrongMFA(factors []map[string]any) bool {
	for _, f := range factors {
		if s, _ := f["status"].(string); s != "ACTIVE" {
			continue
		}
		t, _ := f["type"].(string)
		if !weakFactorTypes[t] {
			return true
		}
	}
	return false
}

// --- Okta API types (subset we read) ---

type oktaUser struct {
	ID      string      `json:"id"`
	Status  string      `json:"status"`
	Profile oktaProfile `json:"profile"`
}

type oktaProfile struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Login     string `json:"login"`
}

type oktaFactor struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"`
	Provider   string `json:"provider"`
	Status     string `json:"status"`
}
