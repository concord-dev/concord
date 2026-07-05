// Package semverx picks the newest version from a set of version strings using
// semantic-version ordering. It exists because lexical sorting is wrong for
// versions — "0.9.0" sorts after "0.10.0" — which would silently select an
// older pack or plugin once a project reaches a two-digit minor/patch.
package semverx

import (
	"sort"

	"github.com/Masterminds/semver/v3"
)

// Newest returns the highest version in versions by semantic-version ordering.
// A leading "v" is tolerated (semver.NewVersion handles it). Entries that are
// not valid semver sort below every valid one (and lexically among themselves),
// so a stray directory never wins over a real release. Returns "" for no input.
func Newest(versions []string) string {
	if len(versions) == 0 {
		return ""
	}
	sorted := append([]string(nil), versions...)
	sort.SliceStable(sorted, func(i, j int) bool {
		vi, ei := semver.NewVersion(sorted[i])
		vj, ej := semver.NewVersion(sorted[j])
		switch {
		case ei == nil && ej == nil:
			return vi.LessThan(vj) // both valid: ascending, so the max is last
		case ei == nil:
			return false // i is semver, j is not: i ranks higher
		case ej == nil:
			return true // j is semver, i is not: j ranks higher
		default:
			return sorted[i] < sorted[j] // neither valid: lexical
		}
	})
	return sorted[len(sorted)-1]
}
