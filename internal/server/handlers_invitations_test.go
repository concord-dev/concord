package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── Org-side invitation CRUD ─────────────────────────────────────────

func TestInvitations_CreateReturnsTokenOnceAndIsListable(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("invitee")
	resp, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/invitations",
		fmt.Sprintf(`{"email":%q,"role":"member"}`, email), h.apiToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var created struct {
		Invitation map[string]any `json:"invitation"`
		Token      string         `json:"token"`
		AcceptURL  string         `json:"accept_url"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))
	assert.True(t, len(created.Token) > 30, "token must be present in create response")
	assert.Contains(t, created.AcceptURL, "/v1/invitations/accept?token=")
	assert.Equal(t, email, created.Invitation["email"])
	assert.Equal(t, "member", created.Invitation["role"])

	// List shows it, but without the plaintext token.
	respL, rawL := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/invitations", "", h.apiToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var listed []map[string]any
	require.NoError(t, json.Unmarshal(rawL, &listed))
	require.Len(t, listed, 1)
	assert.NotContains(t, string(rawL), "token", "list response must never contain the plaintext token")
	assert.NotContains(t, string(rawL), created.Token[:10], "list response must never contain even a prefix of the token")
}

func TestInvitations_ReinviteSupersedesPriorPending(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("dup")

	// Invite #1.
	_, raw1 := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/invitations",
		fmt.Sprintf(`{"email":%q,"role":"member"}`, email), h.apiToken)
	var c1 struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw1, &c1))

	// Invite #2 — same email, different role.
	resp2, raw2 := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/invitations",
		fmt.Sprintf(`{"email":%q,"role":"viewer"}`, email), h.apiToken)
	require.Equal(t, http.StatusCreated, resp2.StatusCode, string(raw2))

	// Exactly one pending invitation now; the first token must not resolve.
	respL, rawL := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/invitations", "", h.apiToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var listed []map[string]any
	require.NoError(t, json.Unmarshal(rawL, &listed))
	assert.Len(t, listed, 1, "re-invite must collapse to one pending row")
	assert.Equal(t, "viewer", listed[0]["role"], "the latest invite wins")

	// The superseded token must no longer resolve.
	respP, _ := http.Get(h.srv.URL + "/v1/invitations/accept?token=" + url.QueryEscape(c1.Token))
	defer respP.Body.Close()
	assert.Equal(t, http.StatusNotFound, respP.StatusCode,
		"first token must be invalid after the re-invite revoked it")
}

func TestInvitations_RevokePending(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("revoke")
	_, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/invitations",
		fmt.Sprintf(`{"email":%q,"role":"member"}`, email), h.apiToken)
	var created struct {
		Invitation struct{ ID uuid.UUID } `json:"invitation"`
		Token      string                 `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))

	respD, _ := h.do(t, "DELETE",
		"/v1/orgs/"+h.org.Slug+"/invitations/"+created.Invitation.ID.String(),
		"", h.apiToken)
	assert.Equal(t, http.StatusNoContent, respD.StatusCode)

	// Re-revoke is 404 (already revoked).
	respD2, _ := h.do(t, "DELETE",
		"/v1/orgs/"+h.org.Slug+"/invitations/"+created.Invitation.ID.String(),
		"", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respD2.StatusCode)
}

func TestInvitations_UnknownRoleReturns400(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/invitations",
		`{"email":"x@example.com","role":"god-emperor"}`, h.apiToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "unknown role")
}

// ─── Public accept flow ───────────────────────────────────────────────

func TestInvitations_AcceptFlowNewUser(t *testing.T) {
	h := newHarness(t)
	email := uniqueEmail("newbie")

	// Mint invite.
	_, raw := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/invitations",
		fmt.Sprintf(`{"email":%q,"role":"member"}`, email), h.apiToken)
	var created struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))

	// Preview: needs_account should be true.
	respP, rawP := h.do(t, "GET",
		"/v1/invitations/accept?token="+url.QueryEscape(created.Token), "", "")
	require.Equal(t, http.StatusOK, respP.StatusCode, string(rawP))
	var preview struct {
		Email        string `json:"email"`
		Role         string `json:"role"`
		NeedsAccount bool   `json:"needs_account"`
	}
	require.NoError(t, json.Unmarshal(rawP, &preview))
	assert.Equal(t, email, preview.Email)
	assert.Equal(t, "member", preview.Role)
	assert.True(t, preview.NeedsAccount, "brand-new email → needs_account=true")

	// Accept: must include first/last/password.
	pw := "newuser-pass-12345"
	respA, rawA := h.do(t, "POST", "/v1/invitations/accept",
		fmt.Sprintf(`{"token":%q,"first_name":"Newbie","last_name":"User","password":%q}`,
			created.Token, pw), "")
	require.Equal(t, http.StatusOK, respA.StatusCode, string(rawA))
	var accepted struct {
		Token        string `json:"token"`
		CreatedUser  bool   `json:"created_user"`
		AssignedRole bool   `json:"assigned_role"`
		Role         string `json:"role"`
	}
	require.NoError(t, json.Unmarshal(rawA, &accepted))
	assert.True(t, accepted.CreatedUser, "user did not exist → must have been created")
	assert.True(t, accepted.AssignedRole, "role must have been freshly attached")
	assert.NotEmpty(t, accepted.Token, "session token must be issued")
	assert.Equal(t, "member", accepted.Role)

	// The new user can log in with the password they just set.
	respLogin, _ := h.do(t, "POST", "/v1/auth/login",
		fmt.Sprintf(`{"email":%q,"password":%q}`, email, pw), "")
	assert.Equal(t, http.StatusCreated, respLogin.StatusCode,
		"the password set during accept must be valid for /auth/login")

	// Re-accepting the same token is now 404 (consumed).
	respA2, _ := h.do(t, "POST", "/v1/invitations/accept",
		fmt.Sprintf(`{"token":%q}`, created.Token), "")
	assert.Equal(t, http.StatusNotFound, respA2.StatusCode,
		"second accept of a consumed token must fail")
}

func TestInvitations_AcceptFlowExistingUserNoCredsNeeded(t *testing.T) {
	h := newHarness(t)
	// Use a brand new org so the existing harness user isn't already a member.
	other, _ := h.st.CreateOrganization(t.Context(), "Other Co", uniqueSlug("other"))
	// Mint an operator-driven owner+token for `other` so we can hit its
	// invitations endpoint.
	otherOwner, _ := h.st.CreateUser(t.Context(), store.CreateUserParams{
		FirstName: "Other", LastName: "Owner",
		Email: uniqueEmail("other-owner"), Password: "other-pw-1234",
	})
	role, _ := h.st.GetRoleByName(t.Context(), "owner")
	require.NoError(t, h.st.AssignRole(t.Context(), otherOwner.ID, other.ID, role.ID))
	_, otherTok, _ := h.st.CreateAPIToken(t.Context(), other.ID, "ci", nil)

	// Invite the *existing* harness user to the new org.
	_, raw := h.do(t, "POST", "/v1/orgs/"+other.Slug+"/invitations",
		fmt.Sprintf(`{"email":%q,"role":"viewer"}`, h.user.Email), otherTok)
	var created struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))

	// Preview should report needs_account=false.
	respP, rawP := h.do(t, "GET",
		"/v1/invitations/accept?token="+url.QueryEscape(created.Token), "", "")
	require.Equal(t, http.StatusOK, respP.StatusCode, string(rawP))
	var preview struct {
		NeedsAccount bool `json:"needs_account"`
	}
	require.NoError(t, json.Unmarshal(rawP, &preview))
	assert.False(t, preview.NeedsAccount,
		"existing user email → needs_account=false")

	// Accept body needs only the token — no first/last/password required.
	respA, rawA := h.do(t, "POST", "/v1/invitations/accept",
		fmt.Sprintf(`{"token":%q}`, created.Token), "")
	require.Equal(t, http.StatusOK, respA.StatusCode, string(rawA))
	var accepted struct {
		CreatedUser  bool `json:"created_user"`
		AssignedRole bool `json:"assigned_role"`
	}
	require.NoError(t, json.Unmarshal(rawA, &accepted))
	assert.False(t, accepted.CreatedUser, "existing user must NOT be re-created")
	assert.True(t, accepted.AssignedRole, "the new role must be attached")
}

func TestInvitations_UnknownTokenIs404(t *testing.T) {
	h := newHarness(t)
	resp, _ := http.Get(h.srv.URL + "/v1/invitations/accept?token=concord_inv_definitely-not-real")
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
