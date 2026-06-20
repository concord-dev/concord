package evidencetype_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/evidencetype"
)

const oktaUsersMFA = `
apiVersion: concord.dev/v1
kind: EvidenceType
metadata:
  id: okta/users_mfa
  version: v1.0.0
spec:
  source: okta
  description: Active Okta users with their enrolled MFA factors.
  schema:
    type: object
    required: [fetched_at, users]
    properties:
      fetched_at: {type: string, format: date-time}
      users:
        type: array
        items:
          type: object
          required: [id, email, status, has_strong_mfa]
          properties:
            id: {type: string}
            email: {type: string}
            status: {type: string}
            has_strong_mfa: {type: boolean}
            factors:
              type: array
              items:
                type: object
                properties:
                  type: {type: string}
                  provider: {type: string}
                  status: {type: string}
`

func TestParse_Valid(t *testing.T) {
	et, err := evidencetype.Parse([]byte(oktaUsersMFA))
	require.NoError(t, err)
	assert.Equal(t, "okta/users_mfa", et.Metadata.ID)
	assert.Equal(t, "v1.0.0", et.Metadata.Version)
	assert.Equal(t, "okta", et.Spec.Source)
}

func TestValidate_RejectsMissingFieldsAndBadKind(t *testing.T) {
	cases := map[string]apiv1.EvidenceType{
		"wrong kind":      {APIVersion: "concord.dev/v1", Kind: "Control", Metadata: apiv1.EvidenceTypeMetadata{ID: "a/b", Version: "v1.0.0"}, Spec: apiv1.EvidenceTypeSpec{Source: "a", Schema: []byte(`{"type":"object"}`)}},
		"missing id":      {APIVersion: "concord.dev/v1", Kind: "EvidenceType", Metadata: apiv1.EvidenceTypeMetadata{Version: "v1.0.0"}, Spec: apiv1.EvidenceTypeSpec{Source: "a", Schema: []byte(`{"type":"object"}`)}},
		"missing version": {APIVersion: "concord.dev/v1", Kind: "EvidenceType", Metadata: apiv1.EvidenceTypeMetadata{ID: "a/b"}, Spec: apiv1.EvidenceTypeSpec{Source: "a", Schema: []byte(`{"type":"object"}`)}},
		"bad version":     {APIVersion: "concord.dev/v1", Kind: "EvidenceType", Metadata: apiv1.EvidenceTypeMetadata{ID: "a/b", Version: "1.0"}, Spec: apiv1.EvidenceTypeSpec{Source: "a", Schema: []byte(`{"type":"object"}`)}},
		"missing source":  {APIVersion: "concord.dev/v1", Kind: "EvidenceType", Metadata: apiv1.EvidenceTypeMetadata{ID: "a/b", Version: "v1.0.0"}, Spec: apiv1.EvidenceTypeSpec{Schema: []byte(`{"type":"object"}`)}},
		"missing schema":  {APIVersion: "concord.dev/v1", Kind: "EvidenceType", Metadata: apiv1.EvidenceTypeMetadata{ID: "a/b", Version: "v1.0.0"}, Spec: apiv1.EvidenceTypeSpec{Source: "a"}},
		"bad compat":      {APIVersion: "concord.dev/v1", Kind: "EvidenceType", Metadata: apiv1.EvidenceTypeMetadata{ID: "a/b", Version: "v1.0.0"}, Spec: apiv1.EvidenceTypeSpec{Source: "a", Compatibility: "sideways", Schema: []byte(`{"type":"object"}`)}},
	}
	for name, et := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, evidencetype.Validate(et))
		})
	}
}

func TestValidate_RejectsUncompilableSchema(t *testing.T) {
	et := apiv1.EvidenceType{
		APIVersion: "concord.dev/v1", Kind: "EvidenceType",
		Metadata: apiv1.EvidenceTypeMetadata{ID: "a/b", Version: "v1.0.0"},
		Spec:     apiv1.EvidenceTypeSpec{Source: "a", Schema: []byte(`{"type": 123}`)},
	}
	assert.Error(t, evidencetype.Validate(et))
}

func TestRegistry_ValidatePayload(t *testing.T) {
	et, err := evidencetype.Parse([]byte(oktaUsersMFA))
	require.NoError(t, err)
	reg := evidencetype.New()
	require.NoError(t, reg.Add(et))

	good := map[string]any{
		"fetched_at": "2026-05-14T10:00:00Z",
		"users": []any{
			map[string]any{"id": "1", "email": "a@x.com", "status": "ACTIVE", "has_strong_mfa": true},
		},
	}
	require.NoError(t, reg.ValidatePayload("okta/users_mfa", good))

	missingRequired := map[string]any{"fetched_at": "2026-05-14T10:00:00Z"}
	assert.Error(t, reg.ValidatePayload("okta/users_mfa", missingRequired))

	wrongType := map[string]any{
		"fetched_at": "2026-05-14T10:00:00Z",
		"users": []any{
			map[string]any{"id": "1", "email": "a@x.com", "status": "ACTIVE", "has_strong_mfa": "yes"},
		},
	}
	assert.Error(t, reg.ValidatePayload("okta/users_mfa", wrongType))
}

func TestRegistry_DuplicateRejected(t *testing.T) {
	et, err := evidencetype.Parse([]byte(oktaUsersMFA))
	require.NoError(t, err)
	reg := evidencetype.New()
	require.NoError(t, reg.Add(et))
	assert.Error(t, reg.Add(et))
}

func TestRegistry_ResolveAndLatest(t *testing.T) {
	reg := evidencetype.New()
	for _, v := range []string{"v1.0.0", "v1.3.0", "v2.0.0"} {
		require.NoError(t, reg.Add(apiv1.EvidenceType{
			APIVersion: "concord.dev/v1", Kind: "EvidenceType",
			Metadata: apiv1.EvidenceTypeMetadata{ID: "okta/users_mfa", Version: v},
			Spec:     apiv1.EvidenceTypeSpec{Source: "okta", Schema: []byte(`{"type":"object"}`)},
		}))
	}

	latest, ok := reg.Latest("okta/users_mfa")
	require.True(t, ok)
	assert.Equal(t, "v2.0.0", latest.Metadata.Version)

	caret1, err := reg.Resolve("okta/users_mfa@^v1")
	require.NoError(t, err)
	assert.Equal(t, "v1.3.0", caret1.Metadata.Version, "^v1 picks the highest v1.x")

	exact, err := reg.Resolve("okta/users_mfa@v1.0.0")
	require.NoError(t, err)
	assert.Equal(t, "v1.0.0", exact.Metadata.Version)

	_, err = reg.Resolve("okta/users_mfa@^v3")
	assert.ErrorIs(t, err, evidencetype.ErrNotFound)

	_, err = reg.Resolve("nope/missing")
	assert.ErrorIs(t, err, evidencetype.ErrNotFound)
}

func TestLoadDir_FindsEvidenceTypesIgnoresOthers(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "et.yaml"), []byte(oktaUsersMFA), 0o644))
	// A control YAML in the same tree must be ignored, not error.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.yaml"), []byte(`
apiVersion: concord.dev/v1
kind: Control
metadata: {id: SOC2-CC6.1}
`), 0o644))
	// A non-concord YAML must be ignored too.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "random.yaml"), []byte("foo: bar\n"), 0o644))

	reg, err := evidencetype.LoadDir(dir)
	require.NoError(t, err)
	assert.Equal(t, 1, reg.Len())
	assert.True(t, reg.Has("okta/users_mfa"))
}

func TestLoadDir_MissingRootIsSkipped(t *testing.T) {
	reg, err := evidencetype.LoadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	require.NoError(t, err)
	assert.Equal(t, 0, reg.Len())
}

func TestParseRef(t *testing.T) {
	r, err := evidencetype.ParseRef("okta/users_mfa@^v1")
	require.NoError(t, err)
	assert.Equal(t, "okta/users_mfa", r.ID)
	assert.Equal(t, "^v1", r.Constraint)
	assert.True(t, r.Matches("v1.4.0"))
	assert.False(t, r.Matches("v2.0.0"))

	bare, err := evidencetype.ParseRef("okta/users_mfa")
	require.NoError(t, err)
	assert.Empty(t, bare.Constraint)
	assert.True(t, bare.Matches("v9.9.9"))

	_, err = evidencetype.ParseRef("okta/users_mfa@garbage")
	assert.Error(t, err)
	_, err = evidencetype.ParseRef("")
	assert.Error(t, err)
}

func TestRefFor(t *testing.T) {
	assert.Equal(t, "okta/users_mfa", evidencetype.RefFor("okta", "users_mfa"))
}
