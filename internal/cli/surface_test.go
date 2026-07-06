package cli

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

// wantVisibleTopLevel is the lean top-level command surface (assessment/36).
// The ~21 GRC-admin CRUD verbs are NOT here — they ship in the separate
// concord-admin bundle (NewAdminCmd) and are reached via `concord admin <verb>`
// through the extension dispatch. Adding a NEW visible top-level verb must be a
// deliberate act: prefer making it a concord-admin verb, a collector plugin, a
// content pack, or a CLI extension (doc 36 §6 rules 1–4). If a top-level verb
// genuinely belongs in the lean core, add it here AND update doc 36 — this
// guard (rule 5) fails the build so the surface never grows silently.
var wantVisibleTopLevel = []string{
	// Core — author & evaluate compliance as code (offline).
	"init", "check", "plan", "apply", "gate", "watch", "diff", "explain", "list",
	"control", "scaffold", "evidence-type", "doctor", "version",
	// Ecosystem — plugins, packs, frameworks, extensions.
	"plugin", "controlpack", "framework", "install", "add", "remove", "outdated", "oscal", "extension",
	// Account — connect to a server & read results.
	"login", "logout", "whoami", "orgs", "project", "runs", "findings", "score", "provenance", "agent",
}

func TestTopLevelSurfaceIsLean(t *testing.T) {
	root := NewConcordCmd()
	var got []string
	for _, c := range root.Commands() {
		if !c.Hidden {
			got = append(got, c.Name())
		}
	}
	sort.Strings(got)
	want := append([]string(nil), wantVisibleTopLevel...)
	sort.Strings(want)
	assert.Equal(t, want, got,
		"the lean top-level surface changed — a new verb should be an admin/plugin/pack/extension, "+
			"not core; if it truly belongs in core, update wantVisibleTopLevel AND assessment/36 (doc-36 rule 5)")
}
