package plugins

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityRegexpForGitHubRepo_AnchorsAndEscapes(t *testing.T) {
	re := IdentityRegexpForGitHubRepo("concord-dev/concord-plugin-snyk")
	assert.Equal(t, `^https://github\.com/concord-dev/concord-plugin-snyk/\.github/workflows/.*@refs/tags/.*$`, re)
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

func TestVerifySignature_MissingCosignBinary(t *testing.T) {
	_, err := VerifySignature(context.Background(), "ghcr.io/example@v1", VerifyOptions{
		Identity:  "https://example",
		CosignBin: "definitely-not-on-path-" + t.Name(),
	})
	assert.ErrorIs(t, err, ErrCosignMissing)
}

func TestExtractIdentity_FromHumanOutput(t *testing.T) {
	out := "tlog index: 12345\nSubject: https://github.com/concord-dev/concord-plugin-snyk/.github/workflows/release.yml@refs/tags/v0.1.0\nIssuer: https://token.actions.githubusercontent.com\n"
	assert.Equal(t, "https://github.com/concord-dev/concord-plugin-snyk/.github/workflows/release.yml@refs/tags/v0.1.0", extractIdentity(out, ""))
}

func TestExtractIdentity_FromJSON(t *testing.T) {
	out := `[{"critical":{"identity":{"docker-reference":"ghcr.io/x"}},"optional":{"subject":"https://github.com/concord-dev/concord-plugin-snyk/.github/workflows/release.yml@refs/tags/v0.1.0"}}]`
	assert.Equal(t, "https://github.com/concord-dev/concord-plugin-snyk/.github/workflows/release.yml@refs/tags/v0.1.0", extractIdentity(out, ""))
}
