package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)


func TestLogin_HappyPath_ReturnsSessionToken(t *testing.T) {
	h := newHarness(t)
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var got struct {
		Token     string     `json:"token"`
		ExpiresAt time.Time  `json:"expires_at"`
		User      store.User `json:"user"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.True(t, strings.HasPrefix(got.Token, "concord_sess_"))
	assert.True(t, got.ExpiresAt.After(time.Now()))
	assert.Equal(t, h.user.Email, got.User.Email)
}

func TestLogin_BadPasswordReturnsGenericMessage(t *testing.T) {
	h := newHarness(t)
	body := fmt.Sprintf(`{"email":%q,"password":"wrong"}`, h.user.Email)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(raw), "invalid credentials")
	assert.NotContains(t, string(raw), h.user.Email,
		"error must not echo the email back (prevents enumeration)")
}

func TestLogin_UnknownEmailReturnsSameGenericMessage(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do(t, "POST", "/v1/auth/login",
		`{"email":"nobody@example.com","password":"x"}`, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(raw), "invalid credentials")
}

func TestLogout_RevokesSession(t *testing.T) {
	h := newHarness(t)
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	_, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	var got struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))

	respL, _ := h.do(t, "POST", "/v1/auth/logout", "", got.Token)
	assert.Equal(t, http.StatusNoContent, respL.StatusCode)

	respMe, _ := h.do(t, "GET", "/v1/me", "", got.Token)
	assert.Equal(t, http.StatusUnauthorized, respMe.StatusCode)
}


func TestSessionMe_ReturnsUser(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, raw := h.do(t, "GET", "/v1/me", "", sessTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var u store.User
	require.NoError(t, json.Unmarshal(raw, &u))
	assert.Equal(t, h.user.ID, u.ID)
}

func TestSessionOrgs_ListsUserMemberships(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, raw := h.do(t, "GET", "/v1/me/orgs", "", sessTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var orgs []store.UserOrg
	require.NoError(t, json.Unmarshal(raw, &orgs))
	require.Len(t, orgs, 1)
	assert.Equal(t, h.org.Slug, orgs[0].Organization.Slug)
	assert.Equal(t, "owner", orgs[0].Roles[0].Name)
}

func TestSessionRoute_RejectsAPIToken(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "GET", "/v1/me", "", h.apiToken)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Contains(t, string(body), "session token")
}
