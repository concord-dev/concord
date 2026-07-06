package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

type permissionDTO struct {
	Name string `json:"name"`
}

type roleCLIDTO struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	IsSystem    bool            `json:"is_system"`
	Permissions []permissionDTO `json:"permissions"`
}

func roleBase(fs findingsServer) string { return "/v1/orgs/" + fs.orgSlug + "/roles" }

func newRoleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "role",
		Aliases: []string{"roles"},
		Short:   "Manage custom org roles and inspect the permission catalog",
	}
	cmd.AddCommand(newRoleListCmd())
	cmd.AddCommand(newRoleShowCmd())
	cmd.AddCommand(newRoleCreateCmd())
	cmd.AddCommand(newRoleSetPermsCmd())
	cmd.AddCommand(newRoleDeleteCmd())
	cmd.AddCommand(newRolePermissionsCmd())
	return cmd
}

func newRoleListCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List system + custom roles",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rows []roleCLIDTO
			if err := apiGet(cmd.Context(), fs, roleBase(fs), &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tKIND\tPERMS\tNAME")
			for _, r := range rows {
				kind := "custom"
				if r.IsSystem {
					kind = "system"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", r.ID, kind, len(r.Permissions), r.Name)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newRoleShowCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one role with its permissions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var r roleCLIDTO
			if err := apiGet(cmd.Context(), fs, roleBase(fs)+"/"+args[0], &r); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(r)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newRoleCreateCmd() *cobra.Command {
	var serverURL, orgSlug, token, name string
	var perms []string
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Define a custom role (you can only grant permissions you hold)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var r roleCLIDTO
			if err := apiSend(cmd.Context(), fs, "POST", roleBase(fs),
				map[string]any{"name": name, "permissions": perms}, &r); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%d permissions)\n", r.ID, r.Name, len(r.Permissions))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "Role name (required)")
	cmd.Flags().StringArrayVar(&perms, "perm", nil, "Permission to grant (repeatable), e.g. --perm risk:read")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newRoleSetPermsCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	var perms []string
	cmd := &cobra.Command{
		Use:   "set-perms <id>",
		Short: "Replace a custom role's permissions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var r roleCLIDTO
			if err := apiSend(cmd.Context(), fs, "PATCH", roleBase(fs)+"/"+args[0],
				map[string]any{"permissions": perms}, &r); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %d permissions\n", r.ID, len(r.Permissions))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringArrayVar(&perms, "perm", nil, "Permission (repeatable); replaces the full set")
	return cmd
}

func newRoleDeleteCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a custom role (must be unassigned)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiSend(cmd.Context(), fs, "DELETE", roleBase(fs)+"/"+args[0], nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "deleted %s\n", args[0])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newRolePermissionsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "permissions",
		Short: "List the assignable permission catalog",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var perms []permissionDTO
			if err := apiGet(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/permissions", &perms); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(perms)
			}
			for _, p := range perms {
				fmt.Fprintln(os.Stdout, p.Name)
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}
