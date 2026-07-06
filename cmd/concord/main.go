package main

import (
	"fmt"
	"os"
)

func main() {
	root := newRootCmd()
	// git/gh-style extension dispatch: an unknown command backed by a
	// concord-<name> binary on PATH is exec'd rather than erroring. Builtins,
	// flags, and unknown-with-no-binary fall through to cobra unchanged.
	if code, handled := tryExtension(root, os.Args[1:]); handled {
		os.Exit(code)
	}
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
