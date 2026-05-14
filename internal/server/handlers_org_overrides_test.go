package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// ─── Per-org control overrides ────────────────────────────────────────

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

// TestOverrides_TightenedThresholdFlipsRunToFail is the integration test that
// proves the override actually reaches the runner. The harness fixture for
// SOC2-CC8.1 has required_approving_review_count == 2; an override of
// min_reviewers=3 should turn the pass into a fail.
func TestOverrides_TightenedThresholdFlipsRunToFail(t *testing.T) {
	h := newHarness(t)

	// Baseline: a run with no overrides → CC8.1 passes.
	resp1, body1 := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, resp1.StatusCode)
	var enq1 struct {
		PollURL string `json:"poll_url"`
	}
	require.NoError(t, json.Unmarshal(body1, &enq1))
	baseline := pollRunFindings(t, h, enq1.PollURL)
	assert.Equal(t, "pass", findingStatus(baseline, "SOC2-CC8.1"))

	// Install a stricter override.
	respPut, _ := h.do(t, "PUT",
		"/v1/orgs/"+h.org.Slug+"/controls/SOC2-CC8.1/overrides",
		`{"params":{"min_reviewers":3}}`, h.apiToken)
	require.Equal(t, http.StatusOK, respPut.StatusCode)

	// New run → CC8.1 now fails because the fixture only carries 2 reviewers.
	resp2, body2 := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", h.apiToken)
	require.Equal(t, http.StatusAccepted, resp2.StatusCode)
	var enq2 struct {
		PollURL string `json:"poll_url"`
	}
	require.NoError(t, json.Unmarshal(body2, &enq2))
	tightened := pollRunFindings(t, h, enq2.PollURL)
	assert.Equal(t, "fail", findingStatus(tightened, "SOC2-CC8.1"),
		"override of min_reviewers=3 should turn the run from pass to fail")
}

// pollRunFindings spins on GET /runs/{id} until the run reaches a terminal
// state, then returns the findings array.
func pollRunFindings(t *testing.T, h *harness, pollURL string) []apiv1.Finding {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, body := h.do(t, "GET", pollURL, "", h.apiToken)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var detail struct {
			Status   string          `json:"status"`
			Findings []apiv1.Finding `json:"findings"`
		}
		require.NoError(t, json.Unmarshal(body, &detail))
		if detail.Status == "succeeded" || detail.Status == "failed" {
			return detail.Findings
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("run %q never completed within 15s", pollURL)
	return nil
}

func findingStatus(findings []apiv1.Finding, controlID string) string {
	for _, f := range findings {
		if f.ControlID == controlID {
			return string(f.Status)
		}
	}
	return ""
}
