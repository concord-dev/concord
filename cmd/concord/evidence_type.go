package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/pkg/evidencetype"
)

func newEvidenceTypeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence-type",
		Short: "Author + validate EvidenceType schemas (the plugin↔control evidence contract)",
	}
	cmd.AddCommand(newEvidenceTypeListCmd())
	cmd.AddCommand(newEvidenceTypeValidateCmd())
	cmd.AddCommand(newEvidenceTypeCheckCmd())
	return cmd
}

func newEvidenceTypeListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <dir> [...]",
		Short: "List every EvidenceType found under one or more directories",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			reg, err := evidencetype.LoadDir(args...)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if reg.Len() == 0 {
				fmt.Fprintln(out, "no evidence types found")
				return nil
			}
			for _, id := range reg.IDs() {
				if t, ok := reg.Latest(id); ok {
					fmt.Fprintf(out, "%s@%s  (source: %s)\n", t.Metadata.ID, t.Metadata.Version, t.Spec.Source)
				}
			}
			return nil
		},
	}
}

func newEvidenceTypeValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate <evidence-type.yaml> [...]",
		Short: "Structural + JSON Schema compile check for one or more EvidenceType files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
			fail := 0
			for _, p := range args {
				raw, err := os.ReadFile(p)
				if err != nil {
					fmt.Fprintf(errOut, "  ✗ %s — %v\n", p, err)
					fail++
					continue
				}
				t, err := evidencetype.Parse(raw)
				if err != nil {
					fmt.Fprintf(errOut, "  ✗ %s — %v\n", p, err)
					fail++
					continue
				}
				fmt.Fprintf(out, "  ✓ %s — %s@%s\n", p, t.Metadata.ID, t.Metadata.Version)
			}
			if fail > 0 {
				return fmt.Errorf("%d evidence type(s) failed validation", fail)
			}
			return nil
		},
	}
}

func newEvidenceTypeCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check <evidence-type.yaml> <payload.json>",
		Short: "Validate an evidence payload against an EvidenceType schema",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			typeRaw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			t, err := evidencetype.Parse(typeRaw)
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			payloadRaw, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			var payload any
			if err := json.Unmarshal(payloadRaw, &payload); err != nil {
				return fmt.Errorf("%s: parsing json: %w", args[1], err)
			}
			reg := evidencetype.New()
			if err := reg.Add(t); err != nil {
				return err
			}
			if err := reg.ValidatePayload(t.Metadata.ID, payload); err != nil {
				return fmt.Errorf("%s is INVALID against %s@%s:\n%w", args[1], t.Metadata.ID, t.Metadata.Version, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  ✓ %s is valid against %s@%s\n", args[1], t.Metadata.ID, t.Metadata.Version)
			return nil
		},
	}
}
