package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/cli/credentials"
	"github.com/concord-dev/concord/internal/server"
	"github.com/concord-dev/concord/internal/store"
)

type loginTestFixture struct {
	srv       *httptest.Server
	st        *store.Store
	orgSlug   string
	userEmail string
	password  string
}

func newLoginFixture(t *testing.T) *loginTestFixture {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := store.Open(ctx, dsn, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Skipf("skipping: Postgres not reachable at %s: %v", dsn, err)
	}
	require.NoError(t, st.Migrate(ctx))
	t.Cleanup(st.Close)

	controlsDir, err := filepath.Abs("../../controls")
	require.NoError(t, err)
	c, err := server.NewConcord(server.Options{
		ControlsDir: controlsDir,
		ConfigPath:  filepath.Join(t.TempDir(), "missing-concord.yaml"),
		Store:       st,
		Version:     "test",
	})
	require.NoError(t, err)
	ts := httptest.NewServer(c.Router())
	t.Cleanup(ts.Close)

	slug := "cli-test-" + uuid.NewString()[:8]
	org, err := st.CreateOrganization(ctx, "CLI Test", slug)
	require.NoError(t, err)
	email := "cli+" + uuid.NewString()[:8] + "@example.com"
	password := "hunter2-cli-" + uuid.NewString()[:8]
	user, err := st.CreateUser(ctx, store.CreateUserParams{
		FirstName: "CLI", LastName: "Test",
		Email: email, Password: password,
	})
	require.NoError(t, err)
	owner, err := st.GetRoleByName(ctx, "owner")
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, user.ID, org.ID, owner.ID))

	return &loginTestFixture{
		srv:       ts,
		st:        st,
		orgSlug:   slug,
		userEmail: email,
		password:  password,
	}
}

func runCmd(args []string, stdin string) (string, error) {
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return buf.String(), err
}

func TestLogin_WritesCredentialsFileAndPersistsSession(t *testing.T) {
	fx := newLoginFixture(t)
	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("CONCORD_CREDENTIALS_FILE", credsPath)

	out, err := runCmd(
		[]string{"login",
			"--server", fx.srv.URL,
			"--email", fx.userEmail,
			"--password-stdin"},
		fx.password+"\n",
	)
	require.NoError(t, err, out)
	assert.Contains(t, out, "logged in as "+fx.userEmail)

	info, err := os.Stat(credsPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"login must persist credentials at 0600 — anything looser leaks the session token")

	file, err := credentials.Load()
	require.NoError(t, err)
	p, err := file.CurrentProfile()
	require.NoError(t, err)
	assert.Equal(t, fx.srv.URL, p.Server)
	assert.NotEmpty(t, p.Token, "session token must be stored")
	assert.Equal(t, fx.userEmail, p.UserEmail)
	assert.Empty(t, p.DefaultOrg, "login must NOT auto-set DefaultOrg — `orgs use` is the explicit choice")
}

func TestLogin_WrongPasswordReturnsActionableError(t *testing.T) {
	fx := newLoginFixture(t)
	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("CONCORD_CREDENTIALS_FILE", credsPath)

	_, err := runCmd(
		[]string{"login",
			"--server", fx.srv.URL,
			"--email", fx.userEmail,
			"--password-stdin"},
		"wrong-password\n",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials",
		"server-side 401 must surface as a human-readable message, not a raw HTTP status")

	_, statErr := os.Stat(credsPath)
	assert.True(t, os.IsNotExist(statErr),
		"failed login must NOT touch the credentials file — half-written state is worse than no state")
}

func TestOrgsUse_RejectsUnknownSlugAndPinsValidOne(t *testing.T) {
	fx := newLoginFixture(t)
	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("CONCORD_CREDENTIALS_FILE", credsPath)

	_, err := runCmd(
		[]string{"login",
			"--server", fx.srv.URL,
			"--email", fx.userEmail,
			"--password-stdin"},
		fx.password+"\n",
	)
	require.NoError(t, err)

	_, err = runCmd([]string{"orgs", "use", "no-such-org-anywhere"}, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "don't appear to belong",
		"unknown / forbidden org must surface a single actionable message — not raw 403/404")
	file, _ := credentials.Load()
	p, _ := file.CurrentProfile()
	assert.Empty(t, p.DefaultOrg, "failed `orgs use` must leave DefaultOrg untouched")

	_, err = runCmd([]string{"orgs", "use", fx.orgSlug}, "")
	require.NoError(t, err)
	file, _ = credentials.Load()
	p, _ = file.CurrentProfile()
	assert.Equal(t, fx.orgSlug, p.DefaultOrg)
}

func TestWhoami_ReturnsActiveSessionAndOrgs(t *testing.T) {
	fx := newLoginFixture(t)
	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("CONCORD_CREDENTIALS_FILE", credsPath)

	_, err := runCmd(
		[]string{"login", "--server", fx.srv.URL,
			"--email", fx.userEmail, "--password-stdin"},
		fx.password+"\n",
	)
	require.NoError(t, err)

	out, err := runCmd([]string{"whoami", "--json"}, "")
	require.NoError(t, err, out)

	var got struct {
		Profile string `json:"profile"`
		Server  string `json:"server"`
		User    struct {
			Email string `json:"email"`
		} `json:"user"`
		Orgs []struct {
			Slug string `json:"slug"`
		} `json:"orgs"`
	}
	require.NoErrorf(t, json.Unmarshal([]byte(out), &got), "raw output: %q", out)
	assert.Equal(t, fx.userEmail, got.User.Email)
	assert.Equal(t, fx.srv.URL, got.Server)
	found := false
	for _, o := range got.Orgs {
		if o.Slug == fx.orgSlug {
			found = true
		}
	}
	assert.Truef(t, found, "whoami must list org %s; saw orgs=%+v, raw=%q", fx.orgSlug, got.Orgs, out)
}

func TestLogout_RemovesCredentialsFile(t *testing.T) {
	fx := newLoginFixture(t)
	credsPath := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("CONCORD_CREDENTIALS_FILE", credsPath)

	_, err := runCmd(
		[]string{"login", "--server", fx.srv.URL,
			"--email", fx.userEmail, "--password-stdin"},
		fx.password+"\n",
	)
	require.NoError(t, err)
	require.FileExists(t, credsPath)

	_, err = runCmd([]string{"logout"}, "")
	require.NoError(t, err)
	_, statErr := os.Stat(credsPath)
	assert.True(t, os.IsNotExist(statErr),
		"logout on the last profile must remove the credentials file entirely — leaving an empty file would be misleading")
}
