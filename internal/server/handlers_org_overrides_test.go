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


func TestOverrides_PutGetListDelete(t *testing.T) {
	h := newHarness(t)
	base := "/v1/orgs/" + h.org.Slug + "/controls/SOC2-CC8.1/overrides"

	// No override yet → 404.
	respMiss, _ := h.do(t, "GET", base, "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respMiss.StatusCode)

	// PUT a value.
	respPut, raw := h.do(t, "PUT", base, `{"params":{"min_reviewers":4}}`, h.apiToken)
	require.Equal(t, http.StatusOK, respPut.StatusCode, string(raw))
	var env struct {
		ControlID string         `json:"control_id"`
		Params    map[string]any `json:"params"`
	}
	require.NoError(t, json.Unmarshal(raw, &env))
	assert.Equal(t, "SOC2-CC8.1", env.ControlID)
	assert.EqualValues(t, 4, env.Params["min_reviewers"])

	// GET returns the same envelope.
	respGet, rawGet := h.do(t, "GET", base, "", h.apiToken)
	require.Equal(t, http.StatusOK, respGet.StatusCode)
	require.NoError(t, json.Unmarshal(rawGet, &env))
	assert.EqualValues(t, 4, env.Params["min_reviewers"])

	// LIST contains exactly the one row.
	respList, rawList := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/overrides", "", h.apiToken)
	require.Equal(t, http.StatusOK, respList.StatusCode)
	var list []struct {
		ControlID string `json:"control_id"`
	}
	require.NoError(t, json.Unmarshal(rawList, &list))
	require.Len(t, list, 1)
	assert.Equal(t, "SOC2-CC8.1", list[0].ControlID)

	// DELETE removes it.
	respDel, _ := h.do(t, "DELETE", base, "", h.apiToken)
	assert.Equal(t, http.StatusNoContent, respDel.StatusCode)
	respGet2, _ := h.do(t, "GET", base, "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respGet2.StatusCode)
}

func TestOverrides_UnknownControlReturns404(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/MADE-UP/overrides",
		`{"params":{"x":1}}`, h.apiToken)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Contains(t, string(body), "no control with id")
	assert.Contains(t, string(body), "MADE-UP")
}

func TestOverrides_MissingParamsBodyReturns400(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/SOC2-CC8.1/overrides",
		`{"not_params":1}`, h.apiToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "`params` is required")
}

func TestOverrides_RequireOverridePermission(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Spin up a viewer (read-only) and login.
	email := uniqueEmail("viewer-ovr")
	pw := "v"
	v, _ := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "V", LastName: "V", Email: email, Password: pw,
	})
	viewer, _ := h.st.GetRoleByName(ctx, "viewer")
	require.NoError(t, h.st.AssignRole(ctx, v.ID, h.org.ID, viewer.ID))
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, pw)
	_, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	var got struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))

	// Viewer can GET (controls:read).
	respR, _ := h.do(t, "GET",
		"/v1/orgs/"+h.org.Slug+"/overrides", "", got.Token)
	assert.Equal(t, http.StatusOK, respR.StatusCode)

	// Viewer cannot PUT (controls:override).
	respW, bodyW := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/SOC2-CC8.1/overrides",
		`{"params":{"min_reviewers":99}}`, got.Token)
	assert.Equal(t, http.StatusForbidden, respW.StatusCode)
	assert.Contains(t, string(bodyW), "controls:override")
}

// Note: an older integration test asserted that overrides flipped a
// server-side run from pass→fail at runtime. In agent-push mode the agent
// fetches overrides from /v1/orgs/{slug}/overrides and applies them locally
// before running, so that runtime-coupling test no longer belongs here.
// Coverage of override *application* lives in the runner package's tests;
// this file owns the API surface only.
