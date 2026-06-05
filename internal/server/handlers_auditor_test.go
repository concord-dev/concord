package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func TestAuditor_GrantThenCrossOrgReadFlows(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	password := "audit-pass-" + h.org.Slug
	auditor, err := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Ex", LastName: "Auditor",
		Email:    "auditor-" + h.org.Slug + "@example.com",
		Password: password,
	})
	require.NoError(t, err)

	body := fmt.Sprintf(`{"user_id":%q}`, auditor.ID.String())
	resp, raw := h.do(t, "POST", "/operator/v1/auditors", body, testOperatorToken)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "grant: %s", raw)
	var granted store.User
	require.NoError(t, json.Unmarshal(raw, &granted))
	assert.True(t, granted.IsAuditor,
		"the grant response must carry the post-update row so the operator UI sees the new state immediately")

	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, auditor.Email, password)
	resp, raw = h.do(t, "POST", "/v1/auth/login", loginBody, "")
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "login: %s", raw)
	var loginRes struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &loginRes))

	resp, raw = h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/runs", "", loginRes.Token)
	assert.Equalf(t, http.StatusOK, resp.StatusCode,
		"auditor must read runs on an org they don't belong to: %s", raw)

	resp, _ = h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/audit", "", loginRes.Token)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"auditor must reach /audit on a non-member org — that's the headline use case for external auditors")

	submitBody := `{"agent":{"version":"x"},"started_at":"2026-06-04T00:00:00Z","completed_at":"2026-06-04T00:00:01Z","summary":{},"findings":[]}`
	resp, _ = h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs", submitBody, loginRes.Token)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"auditor must NOT be able to write (POST /runs requires runs:create which is not a *:read perm)")
}

func TestAuditor_RevokeRestoresStrictPerOrgGating(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	password := "revoke-pass-" + h.org.Slug
	auditor, err := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Ex", LastName: "Auditor",
		Email:    "auditor-rev-" + h.org.Slug + "@example.com",
		Password: password,
	})
	require.NoError(t, err)
	require.NoError(t, h.st.SetUserAuditor(ctx, auditor.ID, true))

	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, auditor.Email, password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", loginBody, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var loginRes struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &loginRes))

	resp, _ = h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/runs", "", loginRes.Token)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := fmt.Sprintf(`{"user_id":%q}`, auditor.ID.String())
	resp, _ = h.do(t, "DELETE", "/operator/v1/auditors", body, testOperatorToken)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)

	resp, _ = h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/runs", "", loginRes.Token)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"after revoke, the auditor's session must lose cross-org read access on the next request — proves HasPermission consults is_auditor live, not at session-mint time")
}

func TestAuditor_OperatorEndpointRejectsBadInput(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name string
		body string
		want int
	}{
		{"no body", `{}`, http.StatusBadRequest},
		{"bad UUID", `{"user_id":"not-a-uuid"}`, http.StatusBadRequest},
		{"unknown user", `{"email":"nobody-nowhere@example.test"}`, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := h.do(t, "POST", "/operator/v1/auditors", tc.body, testOperatorToken)
			assert.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

func TestAuditor_ListReturnsOnlyFlaggedUsersForOperator(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	auditor, _ := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "A", LastName: "u", Email: "auditor-list-" + h.org.Slug + "@example.com",
	})
	require.NoError(t, h.st.SetUserAuditor(ctx, auditor.ID, true))

	resp, raw := h.do(t, "GET", "/operator/v1/auditors", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got []store.User
	require.NoError(t, json.Unmarshal(raw, &got))
	require.NotEmpty(t, got)
	for _, u := range got {
		assert.Truef(t, u.IsAuditor, "ListAuditors must only return is_auditor=true rows (got %s)", u.Email)
	}
}

func TestAuditor_GrantEmitsAuditEvent(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	target, _ := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "T", LastName: "G", Email: "auditor-evt-" + h.org.Slug + "@example.com",
	})

	body := fmt.Sprintf(`{"user_id":%q}`, target.ID.String())
	resp, _ := h.do(t, "POST", "/operator/v1/auditors", body, testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	rows, err := h.st.Pool().Query(ctx,
		`SELECT actor_kind, action, target_id FROM audit_event
		 WHERE action = 'user.auditor.grant' AND target_id = $1`,
		target.ID)
	require.NoError(t, err)
	defer rows.Close()
	var hit bool
	for rows.Next() {
		hit = true
		var kind, action string
		var tid string
		require.NoError(t, rows.Scan(&kind, &action, &tid))
		assert.Equal(t, "operator", kind,
			"auditor grants must be attributed to the operator principal in the audit log — that's the privileged action's identity")
	}
	assert.True(t, hit, "user.auditor.grant audit event must be persisted on every grant for SOC 2 traceability")
}
