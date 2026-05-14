package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const oktaUsersJSON = `[
  {"id": "alice-id", "status": "ACTIVE", "profile": {"firstName": "Alice", "lastName": "Anderson", "email": "alice@example.com", "login": "alice@example.com"}},
  {"id": "bob-id",   "status": "ACTIVE", "profile": {"firstName": "Bob",   "lastName": "Baker",    "email": "bob@example.com",   "login": "bob@example.com"}},
  {"id": "carol-id", "status": "ACTIVE", "profile": {"firstName": "Carol", "lastName": "Chen",     "email": "carol@example.com", "login": "carol@example.com"}}
]`

const aliceFactorsJSON = `[
  {"id": "f1", "factorType": "token:software:totp", "provider": "GOOGLE", "status": "ACTIVE"},
  {"id": "f2", "factorType": "push", "provider": "OKTA", "status": "ACTIVE"}
]`

const bobFactorsJSON = `[
  {"id": "f3", "factorType": "sms", "provider": "OKTA", "status": "ACTIVE"}
]`

const carolFactorsJSON = `[]`

func newOktaServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "SSWS test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, oktaUsersJSON)
	})
	mux.HandleFunc("/api/v1/users/alice-id/factors", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, aliceFactorsJSON)
	})
	mux.HandleFunc("/api/v1/users/bob-id/factors", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, bobFactorsJSON)
	})
	mux.HandleFunc("/api/v1/users/carol-id/factors", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, carolFactorsJSON)
	})
	return httptest.NewServer(mux)
}

func TestOktaCollector_UsersMFA_ClassifiesStrong(t *testing.T) {
	srv := newOktaServer(t)
	t.Cleanup(srv.Close)

	c := evidence.NewOktaCollector(srv.URL, "test-token")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "okta", Type: "users_mfa",
	})
	require.NoError(t, err)

	out := v.(map[string]any)
	users := out["users"].([]map[string]any)
	require.Len(t, users, 3)

	alice := findUser(t, users, "alice@example.com")
	assert.Equal(t, true, alice["has_strong_mfa"], "alice has TOTP + push → strong")
	assert.Equal(t, "Alice Anderson", alice["name"])

	bob := findUser(t, users, "bob@example.com")
	assert.Equal(t, false, bob["has_strong_mfa"], "bob has only SMS → not strong")

	carol := findUser(t, users, "carol@example.com")
	assert.Equal(t, false, carol["has_strong_mfa"], "carol has no factors at all")
}

func TestOktaCollector_Probe(t *testing.T) {
	var gotAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `[]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewOktaCollector(srv.URL, "test-token")
	info, err := c.Probe(context.Background())
	require.NoError(t, err)
	assert.Contains(t, info, srv.URL)
	assert.Equal(t, "SSWS test-token", gotAuth)
}

func TestOktaCollector_Probe_PropagatesAuthError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errorCode":"E0000011"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewOktaCollector(srv.URL, "bad")
	_, err := c.Probe(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestOktaCollector_PropagatesUnauthorized(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewOktaCollector(srv.URL, "bad")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "okta", Type: "users_mfa"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestOktaCollector_FactorFetchErrorPropagates(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"id":"u1","status":"ACTIVE","profile":{"email":"e@e.com"}}]`)
	})
	mux.HandleFunc("/api/v1/users/u1/factors", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"errorCode":"E0000999"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewOktaCollector(srv.URL, "t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "okta", Type: "users_mfa"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestOktaCollector_UnknownTypeReturnsUnsupported(t *testing.T) {
	c := evidence.NewOktaCollector("https://x.okta.com", "t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "okta", Type: "weird"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, evidence.ErrUnsupportedType))
}

func TestOktaCollector_EmptyTypeErrors(t *testing.T) {
	c := evidence.NewOktaCollector("https://x.okta.com", "t")
	_, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "okta"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type")
}

func TestOktaCollector_InactiveFactorsDoNotCount(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"id":"u1","status":"ACTIVE","profile":{"email":"e@e.com"}}]`)
	})
	mux.HandleFunc("/api/v1/users/u1/factors", func(w http.ResponseWriter, _ *http.Request) {
		// TOTP is strong BUT not active → must not satisfy strong-MFA
		fmt.Fprint(w, `[{"id":"f1","factorType":"token:software:totp","provider":"GOOGLE","status":"PENDING_ACTIVATION"}]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewOktaCollector(srv.URL, "t")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{Source: "okta", Type: "users_mfa"})
	require.NoError(t, err)
	user := v.(map[string]any)["users"].([]map[string]any)[0]
	assert.Equal(t, false, user["has_strong_mfa"])
}

func TestOktaCollector_UsersOffboarding_FiltersByStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("filter")
		if filter == "" || (!strings.Contains(filter, "SUSPENDED") && !strings.Contains(filter, "DEPROVISIONED")) {
			t.Errorf("unexpected filter %q", filter)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, `[
			{"id": "dave-id",  "status": "DEPROVISIONED", "profile": {"firstName": "Dave",  "lastName": "Davis", "email": "dave@example.com",  "login": "dave@example.com"}},
			{"id": "ellen-id", "status": "SUSPENDED",     "profile": {"firstName": "Ellen", "lastName": "Ellis", "email": "ellen@example.com", "login": "ellen@example.com"}}
		]`)
	})
	mux.HandleFunc("/api/v1/users/dave-id/factors", func(w http.ResponseWriter, _ *http.Request) {
		// Deprovisioned but still has an active TOTP — the leak we want to catch.
		fmt.Fprint(w, `[{"id":"f1","factorType":"token:software:totp","provider":"GOOGLE","status":"ACTIVE"}]`)
	})
	mux.HandleFunc("/api/v1/users/ellen-id/factors", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[]`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := evidence.NewOktaCollector(srv.URL, "t")
	v, err := c.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "okta", Type: "users_offboarding",
	})
	require.NoError(t, err)

	users := v.(map[string]any)["users"].([]map[string]any)
	require.Len(t, users, 2)

	dave := findUser(t, users, "dave@example.com")
	assert.Equal(t, "DEPROVISIONED", dave["status"])
	assert.Equal(t, true, dave["has_strong_mfa"], "active factor on deprovisioned user — should be detected")

	ellen := findUser(t, users, "ellen@example.com")
	assert.Equal(t, "SUSPENDED", ellen["status"])
	assert.Equal(t, false, ellen["has_strong_mfa"])
}

func findUser(t *testing.T, users []map[string]any, email string) map[string]any {
	t.Helper()
	for _, u := range users {
		if u["email"] == email {
			return u
		}
	}
	t.Fatalf("user %q not found in %v", email, users)
	return nil
}
