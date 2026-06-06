package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/scaffold"
)

func newControlCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "control",
		Short: "Author + validate control packs (schema check, rego compile, fixture replay)",
	}
	cmd.AddCommand(newControlValidateCmd())
	cmd.AddCommand(newControlLintCmd())
	return cmd
}

func newControlValidateCmd() *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "validate <path-to-control.yaml> [...]",
		Short: "Schema-check + Rego compile + pass/fail fixture replay for one or more controls",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fail := 0
			for _, p := range args {
				rep, err := scaffold.ValidateControl(cmd.Context(), p)
				if err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s — %v\n", p, err)
					fail++
					continue
				}
				printValidationReport(rep, verbose)
				if !rep.AllGreen() {
					fail++
				}
			}
			if fail > 0 {
				return fmt.Errorf("%d control(s) failed validation", fail)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show every deny message from each fixture")
	return cmd
}

func newControlLintCmd() *cobra.Command {
	var verbose bool
	cmd := &cobra.Command{
		Use:   "lint <pack-root>",
		Short: "Validate every control under a pack root and surface orphaned rego/fixture files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fail := 0
			for _, root := range args {
				controlsDir := filepath.Join(root, "controls")
				if _, err := os.Stat(controlsDir); err != nil {
					return fmt.Errorf("%s: no controls/ directory", root)
				}
				err := filepath.Walk(controlsDir, func(p string, info os.FileInfo, err error) error {
					if err != nil || info.IsDir() {
						return err
					}
					if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
						return nil
					}
					rep, vErr := scaffold.ValidateControl(cmd.Context(), p)
					if vErr != nil {
						fmt.Fprintf(os.Stderr, "  ✗ %s — %v\n", p, vErr)
						fail++
						return nil
					}
					printValidationReport(rep, verbose)
					if !rep.AllGreen() {
						fail++
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
			if fail > 0 {
				return fmt.Errorf("%d control(s) failed lint", fail)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show every deny message from each fixture")
	return cmd
}

func printValidationReport(r scaffold.ValidationReport, verbose bool) {
	mark := "✓"
	if !r.AllGreen() {
		mark = "✗"
	}
	fmt.Fprintf(os.Stdout, "%s %s (%s)\n", mark, r.YAMLPath, r.ControlID)
	if r.RegoLoaded {
		fmt.Fprintf(os.Stdout, "    rego loaded   %s\n", r.RegoPath)
	}
	if r.PassResult != nil {
		describe := "expected PASS, got FAIL"
		if r.PassResult.Pass {
			describe = "PASS as expected"
		}
		fmt.Fprintf(os.Stdout, "    pass fixture  %s — %s\n", r.PassResult.Path, describe)
		if verbose {
			for _, d := range r.PassResult.Deny {
				fmt.Fprintf(os.Stdout, "                   deny: %s\n", d)
			}
		}
	}
	if r.FailResult != nil {
		describe := "expected FAIL, got PASS"
		if !r.FailResult.Pass {
			describe = "FAIL as expected"
		}
		fmt.Fprintf(os.Stdout, "    fail fixture  %s — %s\n", r.FailResult.Path, describe)
		if verbose {
			for _, d := range r.FailResult.Deny {
				fmt.Fprintf(os.Stdout, "                   deny: %s\n", d)
			}
		}
	}
	for _, e := range r.Errors {
		fmt.Fprintf(os.Stdout, "    error         %s\n", e)
	}
}
