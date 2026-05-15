package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func TestAudit_FailedLoginEmitsUnauthenticatedEvent(t *testing.T) {
	h := newHarness(t)

	// Drive a failed login — auth.login.failure must surface with the email
	// the caller provided in details.
	body := fmt.Sprintf(`{"email":%q,"password":"wrong"}`, h.user.Email)
	resp, _ := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Audit recording happens inline (not in a goroutine), so by the time
	// the handler returns the row must already be visible.
	events, err := h.st.ListAuditEvents(context.Background(), h.user.ID, store.ListAuditOptions{
		Action: "auth.login.failure",
	})
	require.NoError(t, err)
	// Failed-login events have no org_id (the attacker hasn't proven membership);
	// listing by org returns []. Query by user-id index instead via the raw pool.
	_ = events
	rows, err := h.st.Pool().Query(context.Background(),
		`SELECT details FROM audit_event WHERE action = 'auth.login.failure'`)
	require.NoError(t, err)
	defer rows.Close()

	var anyMatch bool
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var d map[string]any
		require.NoError(t, json.Unmarshal(raw, &d))
		if d["email"] == h.user.Email && d["reason"] == "invalid_credentials" {
			anyMatch = true
		}
	}
	require.True(t, anyMatch, "must record one auth.login.failure carrying email + reason")
}

func TestAudit_LoginSuccessAndLogoutEmitUserActorEvents(t *testing.T) {
	h := newHarness(t)
	sessionToken := h.login(t)
	resp, _ := h.do(t, "POST", "/v1/auth/logout", "", sessionToken)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	events, err := h.st.ListAuditEvents(context.Background(), h.org.ID, store.ListAuditOptions{Limit: 50})
	require.NoError(t, err)
	// Note: login emits no org_id — the user has many orgs — so we query
	// by user_id directly here. Same for logout (session is a user concern).
	_ = events

	rows, err := h.st.Pool().Query(context.Background(),
		`SELECT action FROM audit_event WHERE actor_user_id = $1 ORDER BY occurred_at`, h.user.ID)
	require.NoError(t, err)
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var a string
		require.NoError(t, rows.Scan(&a))
		actions = append(actions, a)
	}
	assert.Contains(t, actions, "auth.login.success")
	assert.Contains(t, actions, "auth.logout")
}

func TestAudit_OrgScopedReadEnforcesAuditReadPermission(t *testing.T) {
	// owner role has audit:read; viewer does NOT. Hit the same endpoint
	// from both and confirm the RBAC gate behaves.
	h := newHarness(t)

	// Generate a known event in this org.
	h.st.RecordAudit(context.Background(), store.RecordAuditParams{
		ActorKind: store.AuditActorSystem,
		OrgID:     &h.org.ID,
		Action:    "test.fixture",
	})

	// Owner (the harness user, with the owner role) can read.
	sessionToken := h.login(t)
	path := "/v1/orgs/" + h.org.Slug + "/audit?" + url.Values{"action": {"test.fixture"}, "limit": {"5"}}.Encode()
	resp, raw := h.do(t, "GET", path, "", sessionToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var events []map[string]any
	require.NoError(t, json.Unmarshal(raw, &events))
	require.Len(t, events, 1)
	assert.Equal(t, "test.fixture", events[0]["action"])

	// Add a viewer-role user and confirm they get 403.
	viewerRole, err := h.st.GetRoleByName(context.Background(), "viewer")
	require.NoError(t, err)
	viewerPassword := "watch-only-x"
	viewer, err := h.st.CreateUser(context.Background(), store.CreateUserParams{
		FirstName: "V", LastName: "iewer",
		Email:    fmt.Sprintf("viewer-%s@example.com", h.org.Slug),
		Password: viewerPassword,
	})
	require.NoError(t, err)
	require.NoError(t, h.st.AssignRole(context.Background(), viewer.ID, h.org.ID, viewerRole.ID))

	// Log the viewer in.
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, viewer.Email, viewerPassword)
	respLogin, rawLogin := h.do(t, "POST", "/v1/auth/login", loginBody, "")
	require.Equal(t, http.StatusCreated, respLogin.StatusCode)
	var loginRes struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rawLogin, &loginRes))

	respForbidden, _ := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/audit", "", loginRes.Token)
	assert.Equal(t, http.StatusForbidden, respForbidden.StatusCode,
		"viewer role must not have audit:read; expected 403")
}
