package openapi_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/concord-dev/concord/internal/server/openapi"
)

// spec is the lightweight shape we parse the YAML into. We don't ship a
// full OpenAPI library dep just for tests; YAML round-trip + targeted
// assertions are enough to catch drift.
type spec struct {
	OpenAPI    string                            `json:"openapi"`
	Info       map[string]any                    `json:"info"`
	Paths      map[string]map[string]operation   `json:"paths"`
	Components struct {
		SecuritySchemes map[string]any         `json:"securitySchemes"`
		Schemas         map[string]any         `json:"schemas"`
		Responses       map[string]any         `json:"responses"`
		Parameters      map[string]any         `json:"parameters"`
	} `json:"components"`
}

type operation struct {
	OperationID string `json:"operationId"`
	Summary     string `json:"summary"`
	Security    []map[string][]string `json:"security"`
}

func loadSpec(t *testing.T) spec {
	t.Helper()
	raw, err := openapi.SpecYAML()
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	var s spec
	require.NoError(t, yaml.Unmarshal(raw, &s))
	return s
}

func TestSpec_TopLevelStructure(t *testing.T) {
	s := loadSpec(t)
	assert.Equal(t, "3.0.3", s.OpenAPI)
	assert.NotEmpty(t, s.Info["title"])
	assert.NotEmpty(t, s.Info["version"])
	assert.NotEmpty(t, s.Paths, "must declare paths")
}

func TestSpec_SecuritySchemesPresent(t *testing.T) {
	s := loadSpec(t)
	for _, name := range []string{"operatorToken", "bearerAuth"} {
		_, ok := s.Components.SecuritySchemes[name]
		assert.True(t, ok, "spec must declare securityScheme %q", name)
	}
}

// TestSpec_CoversEveryExpectedRoute is the drift detector. Every path the
// server registers should appear in the spec; the test fails loudly when a
// route is added without updating the contract.
func TestSpec_CoversEveryExpectedRoute(t *testing.T) {
	s := loadSpec(t)

	wantRoutes := map[string][]string{
		// Public.
		"/healthz":      {"get"},
		"/readyz":       {"get"},
		"/metrics":      {"get"},
		"/version":      {"get"},
		// Auth.
		"/v1/auth/login":                        {"post"},
		"/v1/auth/login/mfa":                    {"post"},
		"/v1/auth/logout":                       {"post"},
		"/v1/auth/password-reset":               {"post"},
		"/v1/auth/password-reset/confirm":       {"post"},
		"/v1/invitations/accept":                {"get", "post"},
		// Session-scoped.
		"/v1/me":      {"get"},
		"/v1/me/orgs": {"get"},
		// MFA enrollment + management (session-scoped).
		"/v1/me/mfa":                                {"get"},
		"/v1/me/mfa/totp/enroll":                    {"post"},
		"/v1/me/mfa/totp/verify":                    {"post"},
		"/v1/me/mfa/disable":                        {"post"},
		"/v1/me/mfa/recovery-codes/regenerate":      {"post"},
		// Org API.
		"/v1/orgs/{slug}/me":                          {"get"},
		"/v1/orgs/{slug}/frameworks":                  {"get"},
		"/v1/orgs/{slug}/controls":                    {"get"},
		"/v1/orgs/{slug}/controls/{id}":               {"get"},
		"/v1/orgs/{slug}/findings":                {"get"},
		"/v1/orgs/{slug}/runs":                    {"get", "post"},
		"/v1/orgs/{slug}/runs/{id}":               {"get"},
		"/v1/orgs/{slug}/events":                  {"get"},
		"/v1/orgs/{slug}/drift":                   {"get"},
		"/v1/orgs/{slug}/overrides":               {"get"},
		"/v1/orgs/{slug}/controls/{id}/overrides": {"get", "put", "delete"},
		"/v1/orgs/{slug}/webhooks":                {"get", "post"},
		"/v1/orgs/{slug}/webhooks/{id}":           {"get", "put", "delete"},
		"/v1/orgs/{slug}/trust-portal":            {"get"},
		"/v1/orgs/{slug}/trust-portal/settings":   {"get", "put"},
		"/v1/orgs/{slug}/invitations":             {"get", "post"},
		"/v1/orgs/{slug}/invitations/{id}":        {"delete"},
		"/v1/orgs/{slug}/audit":                   {"get"},
		"/v1/orgs/{slug}/audit-package":           {"get"},
		// Operator (SaaS-operator back-door — gates CONCORD_OPERATOR_TOKEN).
		"/operator/v1/orgs":                         {"get", "post"},
		"/operator/v1/orgs/{slug}":                  {"get"},
		"/operator/v1/orgs/{slug}/tokens":           {"get", "post"},
		"/operator/v1/orgs/{slug}/tokens/{tokenID}": {"delete"},
		"/operator/v1/orgs/{slug}/members":          {"get", "post"},
		"/operator/v1/orgs/{slug}/members/{userID}": {"delete"},
		"/operator/v1/users":                        {"get", "post"},
		"/operator/v1/roles":                        {"get"},
		"/operator/v1/permissions":                  {"get"},
		"/operator/v1/auditors":                     {"get", "post", "delete"},
		"/operator/v1/dlq/events":                   {"get"},
		"/operator/v1/dlq/events/{id}":              {"get", "delete"},
		"/operator/v1/dlq/events/{id}/replay":       {"post"},
		"/operator/v1/dlq/deliveries":               {"get"},
		"/operator/v1/dlq/deliveries/{id}":          {"get", "delete"},
		"/operator/v1/dlq/deliveries/{id}/replay":   {"post"},
	}

	for path, methods := range wantRoutes {
		ops, ok := s.Paths[path]
		if !assert.True(t, ok, "missing path in spec: %s", path) {
			continue
		}
		for _, m := range methods {
			_, opOK := ops[m]
			assert.True(t, opOK, "missing %s on %s", m, path)
		}
	}
}

func TestSpec_EveryOperationHasOperationID(t *testing.T) {
	s := loadSpec(t)
	for path, ops := range s.Paths {
		for method, op := range ops {
			assert.NotEmptyf(t, op.OperationID,
				"%s %s must set operationId (used by codegen)", method, path)
		}
	}
}

// TestSpec_NoUnreferencedSchemas catches dead components. Every top-level
// schema should appear in at least one $ref or be declared as an `allOf`
// base for another schema.
//
// Implementation: serialize the parsed map back to YAML (bytes are easiest
// to grep) and check every schema name shows up at least twice (definition
// + one $ref reference).
func TestSpec_NoUnreferencedSchemas(t *testing.T) {
	raw, err := openapi.SpecYAML()
	require.NoError(t, err)
	s := loadSpec(t)

	names := make([]string, 0, len(s.Components.Schemas))
	for n := range s.Components.Schemas {
		names = append(names, n)
	}
	sort.Strings(names)

	body := string(raw)
	var unreferenced []string
	for _, n := range names {
		needle := "#/components/schemas/" + n
		// Schemas that exist only as `allOf` bases (RoleWithPermissions
		// references Role) still satisfy this rule via the needle above.
		if !contains(body, needle) {
			unreferenced = append(unreferenced, n)
		}
	}
	assert.Empty(t, unreferenced,
		"these schemas are defined but never referenced — delete or wire them up")
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
