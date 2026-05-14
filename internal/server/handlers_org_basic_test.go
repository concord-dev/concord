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

// ─── Org-scoped: API token path ───────────────────────────────────────

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

// ─── Org-scoped: session path with RBAC ───────────────────────────────

func TestOrgAPI_OwnerSessionCanCreateRun(t *testing.T) {
	h := newHarness(t)
	sessTok := h.login(t)
	resp, _ := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", sessTok)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode,
		"owner has runs:create — session-driven /check must succeed")
}

func TestOrgAPI_ViewerSessionForbiddenFromCreateRun(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Spin up a viewer user attached to the harness org.
	viewerEmail := uniqueEmail("viewer")
	viewerPass := "viewer-pass"
	viewer, _ := h.st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "View", LastName: "Er", Email: viewerEmail, Password: viewerPass,
	})
	viewerRole, _ := h.st.GetRoleByName(ctx, "viewer")
	require.NoError(t, h.st.AssignRole(ctx, viewer.ID, h.org.ID, viewerRole.ID))

	// Log the viewer in.
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, viewerEmail, viewerPass)
	_, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	var got struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))

	// Viewer can READ.
	respR, _ := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/frameworks", "", got.Token)
	assert.Equal(t, http.StatusOK, respR.StatusCode, "viewer holds controls:read")

	// Viewer cannot CREATE runs.
	respC, bodyC := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/check", "", got.Token)
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
