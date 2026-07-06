package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// extensionPrefix is the naming convention for CLI extensions: `concord <x>`
// dispatches to an executable named `concord-<x>` found on PATH (the git / gh /
// kubectl model). This is the escape valve that keeps the core lean — admin and
// community verbs ship as separate installable binaries rather than growing the
// core (assessment/36 §2 surface 3).
const extensionPrefix = "concord-"

// tryExtension dispatches to a PATH extension when args name a command the core
// doesn't know. It returns (exitCode, true) when it handled the invocation by
// exec-ing an extension; (0, false) means "not an extension — let cobra run",
// which covers builtins, flags, help/completion, and unknown names with no
// matching binary (so cobra still prints its normal unknown-command error).
func tryExtension(root *cobra.Command, args []string) (int, bool) {
	name := firstCommandToken(args)
	if name == "" || isBuiltinCommand(root, name) {
		return 0, false
	}
	bin, err := exec.LookPath(extensionPrefix + name)
	if err != nil {
		return 0, false
	}
	// Pass everything after the extension name straight through; env (incl.
	// CONCORD_SERVER_URL / CONCORD_API_TOKEN) is inherited so extensions reach
	// the same server as the core.
	cmd := exec.Command(bin, argsAfter(args, name)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), true
		}
		fmt.Fprintf(os.Stderr, "error: running extension %s%s: %v\n", extensionPrefix, name, err)
		return 1, true
	}
	return 0, true
}

// firstCommandToken returns the first non-flag argument — the command the user
// is invoking — or "" when there is none (bare `concord`, or a leading flag
// like `concord --version`).
func firstCommandToken(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

// argsAfter returns the arguments following the first occurrence of name.
func argsAfter(args []string, name string) []string {
	for i, a := range args {
		if a == name {
			return args[i+1:]
		}
	}
	return nil
}

// isBuiltinCommand reports whether name is a registered core command (including
// hidden aliases) or a reserved cobra verb, so it is never shadowed by a PATH
// binary of the same name.
func isBuiltinCommand(root *cobra.Command, name string) bool {
	switch name {
	case "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
		return true
	}
	for _, c := range root.Commands() {
		if c.Name() == name {
			return true
		}
		for _, alias := range c.Aliases {
			if alias == name {
				return true
			}
		}
	}
	return false
}

// discoveredExtension is one `concord-<name>` executable found on PATH.
type discoveredExtension struct {
	Name string // the verb (prefix stripped)
	Path string
}

// findExtensions scans PATH for `concord-*` executables. The first match for a
// name (earliest PATH entry) wins, mirroring normal shell resolution.
func findExtensions() []discoveredExtension {
	seen := map[string]string{}
	var order []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			base := e.Name()
			if !strings.HasPrefix(base, extensionPrefix) || e.IsDir() {
				continue
			}
			name := strings.TrimPrefix(base, extensionPrefix)
			if name == "" {
				continue
			}
			full := filepath.Join(dir, base)
			if !isExecutable(full) {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = full
				order = append(order, name)
			}
		}
	}
	sort.Strings(order)
	out := make([]discoveredExtension, 0, len(order))
	for _, n := range order {
		out = append(out, discoveredExtension{Name: n, Path: seen[n]})
	}
	return out
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}

func newExtensionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extension",
		Short: "Discover installed CLI extensions (concord-<name> on PATH)",
		Long: `Concord is extensible like git or gh: any executable named concord-<name> on
your PATH is invocable as ` + "`concord <name>`" + `. This keeps the core lean —
admin and community verbs install as separate binaries instead of growing the
core CLI. See assessment/36-lean-cli-and-plugin-ecosystem.md.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List concord-<name> extensions found on PATH",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			exts := findExtensions()
			if len(exts) == 0 {
				fmt.Fprintln(os.Stdout, "no extensions found on PATH (install an executable named concord-<name>)")
				return nil
			}
			for _, e := range exts {
				fmt.Fprintf(os.Stdout, "%-20s %s\n", e.Name, e.Path)
			}
			return nil
		},
	})
	return cmd
}
