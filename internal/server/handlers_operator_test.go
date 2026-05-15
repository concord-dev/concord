package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── Operator (CONCORD_OPERATOR_TOKEN) ──────────────────────────────────────

func TestOperator_RequiresOperatorToken(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/operator/v1/orgs", "", h.apiToken)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "invalid operator token")
}

func TestOperator_CreateUserAndAssignRoles(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("invitee")
	body := fmt.Sprintf(`{"first_name":"Invite","last_name":"Pending","email":%q,"password":"pass-1234"}`, email)
	resp, raw := h.do(t, "POST", "/operator/v1/users", body, testOperatorToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	// Assign two roles in one call.
	addBody := fmt.Sprintf(`{"email":%q,"roles":["admin","viewer"]}`, email)
	resp2, raw2 := h.do(t, "POST", "/operator/v1/orgs/"+h.org.Slug+"/members",
		addBody, testOperatorToken)
	require.Equal(t, http.StatusCreated, resp2.StatusCode, string(raw2))

	// Verify via list members.
	respL, rawL := h.do(t, "GET", "/operator/v1/orgs/"+h.org.Slug+"/members",
		"", testOperatorToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var members []store.OrgMember
	require.NoError(t, json.Unmarshal(rawL, &members))
	// Harness preloaded an "owner" user; the new invitee is the second.
	var found *store.OrgMember
	for i := range members {
		if members[i].User.Email == email {
			found = &members[i]
		}
	}
	require.NotNil(t, found, "newly-invited user must appear in members list")
	assert.Len(t, found.Roles, 2)
}

func TestOperator_AddMember_UnknownRoleRejected(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("badrole")
	body := fmt.Sprintf(`{"first_name":"X","last_name":"Y","email":%q}`, email)
	resp, _ := h.do(t, "POST", "/operator/v1/users", body, testOperatorToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	addBody := fmt.Sprintf(`{"email":%q,"roles":["superuser"]}`, email)
	resp2, raw := h.do(t, "POST", "/operator/v1/orgs/"+h.org.Slug+"/members",
		addBody, testOperatorToken)
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)
	assert.Contains(t, string(raw), "unknown role superuser")
}

func TestOperator_RevokeToken_BlocksFutureUse(t *testing.T) {
	h := newHarness(t)
	// Mint a fresh token via the admin API.
	respC, rawC := h.do(t, "POST", "/operator/v1/orgs/"+h.org.Slug+"/tokens",
		`{"name":"ephemeral"}`, testOperatorToken)
	require.Equal(t, http.StatusCreated, respC.StatusCode)
	var tok struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rawC, &tok))

	respD, _ := h.do(t, "DELETE", "/operator/v1/orgs/"+h.org.Slug+"/tokens/"+tok.ID,
		"", testOperatorToken)
	assert.Equal(t, http.StatusNoContent, respD.StatusCode)

	resp, _ := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/frameworks", "", tok.Token)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestOperator_ListRoles_ShowsPermissionBundles(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do(t, "GET", "/operator/v1/roles", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var roles []struct {
		Name        string             `json:"name"`
		Permissions []store.Permission `json:"permissions"`
	}
	require.NoError(t, json.Unmarshal(raw, &roles))
	require.Len(t, roles, 4)
	for _, r := range roles {
		if r.Name == "owner" {
			assert.GreaterOrEqual(t, len(r.Permissions), 16,
				"owner should be bound to every seeded permission")
		}
		if r.Name == "viewer" {
			assert.LessOrEqual(t, len(r.Permissions), 6, "viewer is read-only")
		}
	}
}
