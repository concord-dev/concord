package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)


func TestOrgAPI_WithAPIToken_PermitsRead(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/frameworks", "", h.apiToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
}

func TestOrgAPI_TokenAgainstWrongOrgIsForbidden(t *testing.T) {
	h := newHarness(t)
	other, _ := h.st.CreateOrganization(context.Background(), "Other", uniqueSlug("other"))
	resp, body := h.do(t, "GET", "/v1/orgs/"+other.Slug+"/frameworks", "", h.apiToken)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Contains(t, string(body), "not scoped")
}

func TestOrgAPI_UnknownOrgReturns404(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "GET", "/v1/orgs/nope-"+uuid.NewString()[:8]+"/frameworks", "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}


func TestOrgAPI_OwnerSessionCanSubmitRun(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	runID := h.submitTestRun(t, sessTok, "[]")
	assert.NotEmpty(t, runID)
}

func TestOrgAPI_ViewerSessionForbiddenFromCreateRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	viewerEmail := uniqueEmail("viewer")
	viewerPass := "viewer-pass"
	viewer, _ := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "View", LastName: "Er", Email: viewerEmail, Password: viewerPass,
	})
	viewerRole, _ := h.st.GetRoleByName(ctx, "viewer")
	require.NoError(t, h.st.AssignRole(ctx, viewer.ID, h.org.ID, viewerRole.ID))

	body := fmt.Sprintf(`{"email":%q,"password":%q}`, viewerEmail, viewerPass)
	_, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	var got struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))

	respR, _ := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/frameworks", "", got.Token)
	assert.Equal(t, http.StatusOK, respR.StatusCode, "viewer holds controls:read")

	respC, bodyC := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/runs",
		`{"agent":{"version":"t"},"started_at":"2026-01-01T00:00:00Z","completed_at":"2026-01-01T00:00:00Z","summary":{},"findings":[]}`,
		got.Token)
	assert.Equal(t, http.StatusForbidden, respC.StatusCode)
	assert.Contains(t, string(bodyC), "runs:create")
}

func TestOrgMe_ReportsPermissionsForSessionUser(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, raw := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/me", "", sessTok)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got struct {
		Permissions []string `json:"permissions"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Contains(t, got.Permissions, "runs:create", "owner should hold runs:create")
	assert.Contains(t, got.Permissions, "org:delete", "owner should hold org:delete")
}
