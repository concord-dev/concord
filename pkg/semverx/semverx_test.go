package semverx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/concord-dev/concord/pkg/semverx"
)

func TestNewest(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"two-digit minor beats one-digit", []string{"v0.9.0", "v0.10.0"}, "v0.10.0"},
		{"two-digit patch", []string{"v1.2.9", "v1.2.10"}, "v1.2.10"},
		{"major ordering", []string{"v0.10.0", "v1.0.0", "v0.2.0"}, "v1.0.0"},
		{"no v prefix", []string{"0.9.0", "0.10.0"}, "0.10.0"},
		{"prerelease below release", []string{"v1.0.0-rc1", "v1.0.0"}, "v1.0.0"},
		{"single", []string{"v3.1.4"}, "v3.1.4"},
		{"empty", nil, ""},
		{"non-semver ranks below semver", []string{"nightly", "v0.1.0"}, "v0.1.0"},
		{"all non-semver falls back to lexical", []string{"alpha", "beta"}, "beta"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, semverx.Newest(tc.in))
		})
	}
}

// The input slice must not be reordered (callers may reuse it).
func TestNewest_DoesNotMutateInput(t *testing.T) {
	in := []string{"v0.9.0", "v0.10.0", "v0.2.0"}
	_ = semverx.Newest(in)
	assert.Equal(t, []string{"v0.9.0", "v0.10.0", "v0.2.0"}, in)
}
