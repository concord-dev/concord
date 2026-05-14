package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server"
	"github.com/concord-dev/concord/internal/store"
)

const defaultTestDSN = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"
const testAdminToken = "test-admin-token-fixed"

func repoControlsDir(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../controls")
	require.NoError(t, err)
	return abs
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultTestDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Skipf("skipping: Postgres not reachable at %s: %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(s.Close)
	return s
}

// harness bundles a running httptest server with a pre-built tenant: one
// org, one API token, one user (with a known password and the owner role).
type harness struct {
	srv      *httptest.Server
	c        *server.Concord
	st       *store.Store
	org      store.Organization
	user     store.User
	password string
	apiToken string // plaintext concord_... token
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st := openStore(t)
	c, err := server.NewConcord(server.Options{
		ControlsDir:  repoControlsDir(t),
		ConfigPath:   filepath.Join(t.TempDir(), "missing-concord.yaml"),
		FixturesOnly: true,
		Store:        st,
		AdminToken:   testAdminToken,
		Version:      "test",
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)

	ctx := context.Background()
	org, err := st.CreateOrganization(ctx, "Test Org", "test-"+uuid.NewString()[:8])
	require.NoError(t, err)
	password := "hunter2-" + uuid.NewString()[:8]
	user, err := st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "Test", LastName: "User",
		Email:    fmt.Sprintf("u-%s@example.com", uuid.NewString()[:8]),
		Password: password,
	})
	require.NoError(t, err)
	owner, err := st.GetRoleByName(ctx, "owner")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, user.ID, org.ID, owner.ID))
	_, plain, err := st.CreateAPIToken(ctx, org.ID, "ci", &user.ID)
	require.NoError(t, err)

	return &harness{srv: ts, c: c, st: st, org: org, user: user,
		password: password, apiToken: plain}
}

func (h *harness) do(t *testing.T, method, path, body, auth string) (*http.Response, []byte) {
	t.Helper()
	var br io.Reader
	if body != "" {
		br = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, br)
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// ─── Helpers ────────────────────────────────────────────────────────

// login posts to /v1/auth/login with the harness credentials and returns
// the freshly-minted session token plaintext.
func (h *harness) login(t *testing.T) string {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
	var got struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	return got.Token
}

func uniqueSlug(p string) string  { return fmt.Sprintf("%s-%s", p, uuid.NewString()[:8]) }
func uniqueEmail(p string) string { return fmt.Sprintf("%s+%s@example.com", p, uuid.NewString()[:8]) }

type sseFrame struct {
	Event string
	Data  string
}

func readSSEFrames(r io.Reader, out chan<- sseFrame) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				idx := strings.Index(string(buf), "\n\n")
				if idx < 0 {
					break
				}
				raw := string(buf[:idx])
				buf = buf[idx+2:]
				var f sseFrame
				for _, line := range strings.Split(raw, "\n") {
					switch {
					case strings.HasPrefix(line, "event: "):
						f.Event = strings.TrimPrefix(line, "event: ")
					case strings.HasPrefix(line, "data: "):
						f.Data = strings.TrimPrefix(line, "data: ")
					}
				}
				if f.Event != "" {
					out <- f
				}
			}
		}
		if err != nil {
			return
		}
	}
}
