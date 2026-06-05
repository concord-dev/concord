package ociart

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityRegexpForGitHubRepo_AnchorsAndEscapes(t *testing.T) {
	got := IdentityRegexpForGitHubRepo("concord-dev/concord-plugin-snyk")
	assert.Equal(t, `^https://github\.com/concord-dev/concord-plugin-snyk/\.github/workflows/.*@refs/tags/.*$`, got)
}

func TestAssertSignerContinuity(t *testing.T) {
	cases := []struct {
		name      string
		prev      string
		next      string
		wantError bool
	}{
		{"both empty allowed", "", "", false},
		{"prev empty (first install)", "", "X", false},
		{"next empty (no sig at upgrade)", "X", "", false},
		{"match", "X", "X", false},
		{"mismatch", "X", "Y", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AssertSignerContinuity(tc.prev, tc.next)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestVerify_MissingCosignBinary(t *testing.T) {
	_, err := Verify(context.Background(), "ghcr.io/example@v1", VerifyOptions{
		Identity:  "https://example",
		CosignBin: "definitely-not-on-path-" + t.Name(),
	})
	assert.ErrorIs(t, err, ErrCosignMissing)
}

func TestExtractIdentity_FromHumanOutput(t *testing.T) {
	out := "tlog index: 12345\nSubject: https://github.com/concord-dev/x/.github/workflows/r.yml@refs/tags/v1\nIssuer: https://token.actions.githubusercontent.com\n"
	assert.Equal(t, "https://github.com/concord-dev/x/.github/workflows/r.yml@refs/tags/v1", extractIdentity(out, ""))
}

func TestExtractIdentity_FromJSONUppercase(t *testing.T) {
	out := `[{"optional":{"Subject":"https://github.com/concord-dev/x/.github/workflows/r.yml@refs/tags/v1"}}]`
	assert.Equal(t, "https://github.com/concord-dev/x/.github/workflows/r.yml@refs/tags/v1", extractIdentity(out, ""))
}

func TestExtractIdentity_FromJSONLowercase(t *testing.T) {
	out := `[{"critical":{"identity":{"docker-reference":"ghcr.io/x"}},"optional":{"subject":"https://github.com/concord-dev/x/.github/workflows/r.yml@refs/tags/v1"}}]`
	assert.Equal(t, "https://github.com/concord-dev/x/.github/workflows/r.yml@refs/tags/v1", extractIdentity(out, ""))
}

func TestParseRef(t *testing.T) {
	cases := []struct {
		in      string
		host    string
		repo    string
		ref     string
		digest  bool
		wantErr bool
	}{
		{"ghcr.io/concord-dev/concord-plugin-snyk:v0.1.0", "ghcr.io", "concord-dev/concord-plugin-snyk", "v0.1.0", false, false},
		{"ghcr.io/x/y@sha256:abc", "ghcr.io", "x/y", "sha256:abc", true, false},
		{"missing-tag.example.com/x/y", "", "", "", false, true},
		{"", "", "", "", false, true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			r, err := ParseRef(c.in)
			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.host, r.Host)
			assert.Equal(t, c.repo, r.Repo)
			assert.Equal(t, c.ref, r.Reference)
			assert.Equal(t, c.digest, r.IsDigest)
		})
	}
}

func TestDefaultGitHubRepoFromArtifact(t *testing.T) {
	assert.Equal(t, "concord-dev/concord-plugin-snyk", DefaultGitHubRepoFromArtifact("ghcr.io/concord-dev/concord-plugin-snyk"))
	assert.Equal(t, "", DefaultGitHubRepoFromArtifact("quay.io/x/y"))
}
