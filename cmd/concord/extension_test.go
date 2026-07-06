package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFirstCommandToken(t *testing.T) {
	assert.Equal(t, "check", firstCommandToken([]string{"check", "--x"}))
	assert.Equal(t, "hello", firstCommandToken([]string{"--v", "hello", "arg"}))
	assert.Equal(t, "", firstCommandToken(nil))
	assert.Equal(t, "", firstCommandToken([]string{"--version"}))
}

func TestArgsAfter(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, argsAfter([]string{"hello", "a", "b"}, "hello"))
	assert.Empty(t, argsAfter([]string{"hello"}, "hello"))
	assert.Equal(t, []string{"x"}, argsAfter([]string{"--v", "hello", "x"}, "hello"))
}

func TestIsBuiltinCommand(t *testing.T) {
	root := newRootCmd()
	// Core commands and reserved verbs are builtins (never shadowed by PATH).
	for _, name := range []string{"check", "plan", "apply", "extension", "help", "completion"} {
		assert.Truef(t, isBuiltinCommand(root, name), "%q must be builtin", name)
	}
	// Hidden top-level admin aliases are still registered → still builtins.
	assert.True(t, isBuiltinCommand(root, "risk"), "hidden admin alias must not be shadowed")
	// An unknown verb is a candidate extension.
	assert.False(t, isBuiltinCommand(root, "definitely-not-a-command"))
}

func TestTryExtension_FallsThroughForBuiltinsAndFlags(t *testing.T) {
	root := newRootCmd()
	// Builtins and flag-led invocations are never treated as extensions.
	if _, handled := tryExtension(root, []string{"check", "--fixtures"}); handled {
		t.Fatal("builtin command must not dispatch to an extension")
	}
	if _, handled := tryExtension(root, []string{"--version"}); handled {
		t.Fatal("leading flag must not dispatch to an extension")
	}
	// Unknown command with no concord-<name> on PATH falls through to cobra.
	if _, handled := tryExtension(root, []string{"definitely-not-a-command-xyz"}); handled {
		t.Fatal("unknown command with no PATH binary must fall through")
	}
}
