package evidencetype

import (
	"fmt"
	"strings"

	"golang.org/x/mod/semver"
)

// Ref is a parsed evidence-type reference, e.g. "okta/users_mfa@^v1".
// An empty Constraint means "latest available version".
type Ref struct {
	ID         string
	Constraint string
}

// RefFor builds the canonical evidence-type id from a control's
// (source, type) pair.
func RefFor(source, typ string) string {
	return source + "/" + typ
}

// ParseRef splits an "id@constraint" string. The constraint is optional;
// when present it is an exact version (v1.2.0) or a caret range (^v1,
// ^v1.2.0) meaning "same major, at least this version".
func ParseRef(s string) (Ref, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Ref{}, fmt.Errorf("empty evidence-type reference")
	}
	id, constraint, hasConstraint := strings.Cut(s, "@")
	id = strings.TrimSpace(id)
	constraint = strings.TrimSpace(constraint)
	if id == "" {
		return Ref{}, fmt.Errorf("reference %q has no id", s)
	}
	if hasConstraint {
		if constraint == "" {
			return Ref{}, fmt.Errorf("reference %q has an empty constraint after @", s)
		}
		if err := validConstraint(constraint); err != nil {
			return Ref{}, fmt.Errorf("reference %q: %w", s, err)
		}
	}
	return Ref{ID: id, Constraint: constraint}, nil
}

// Matches reports whether a concrete version satisfies the ref's constraint.
// An empty constraint matches any version.
func (r Ref) Matches(version string) bool {
	if !validSemver(version) {
		return false
	}
	switch {
	case r.Constraint == "":
		return true
	case strings.HasPrefix(r.Constraint, "^"):
		base := strings.TrimPrefix(r.Constraint, "^")
		return semver.Major(version) == semver.Major(base) && semver.Compare(version, base) >= 0
	default:
		return semver.Compare(version, r.Constraint) == 0
	}
}

func validConstraint(c string) error {
	base := strings.TrimPrefix(c, "^")
	if !validSemver(base) {
		return fmt.Errorf("constraint %q is not a version or ^version (want v1, v1.2.0, ^v1)", c)
	}
	return nil
}

// validSemver accepts canonical-ish semver allowing major-only (v1) or
// major.minor (v1.2) shorthands, all requiring the leading "v".
func validSemver(v string) bool {
	return semver.IsValid(v)
}

// compareVersion orders two evidence-type versions; invalid versions sort
// before valid ones so a malformed entry never wins "latest".
func compareVersion(a, b string) int {
	av, bv := semver.IsValid(a), semver.IsValid(b)
	switch {
	case av && bv:
		return semver.Compare(a, b)
	case av:
		return 1
	case bv:
		return -1
	default:
		return strings.Compare(a, b)
	}
}
