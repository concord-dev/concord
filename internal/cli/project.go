package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type projectDTO struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func newProjectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Manage projects (scope unit for findings, runs, risks, evidence)",
	}
	cmd.AddCommand(newProjectListCmd())
	cmd.AddCommand(newProjectCreateCmd())
	cmd.AddCommand(newProjectShowCmd())
	cmd.AddCommand(newProjectUpdateCmd())
	return cmd
}

func newProjectListCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		includeArchived           bool
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List projects in the org",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path := "/v1/orgs/" + fs.orgSlug + "/projects"
			if includeArchived {
				path += "?include_archived=true"
			}
			var rows []projectDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			return printProjects(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().BoolVar(&includeArchived, "include-archived", false, "Also show archived projects")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newProjectCreateCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		slug, name, description   string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Open a new project in the org",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"slug": slug}
			if name != "" {
				body["name"] = name
			}
			if description != "" {
				body["description"] = description
			}
			var p projectDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				"/v1/orgs/"+fs.orgSlug+"/projects", body, &p); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s — %s (status=%s)\n", p.Slug, p.Name, p.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&slug, "slug", "", "Project slug (lowercase, [a-z0-9-]) (required)")
	cmd.Flags().StringVar(&name, "name", "", "Human-readable name")
	cmd.Flags().StringVar(&description, "description", "", "Description")
	_ = cmd.MarkFlagRequired("slug")
	return cmd
}

func newProjectShowCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "show <project-slug>",
		Short: "Show one project",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var p projectDTO
			if err := apiGet(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/projects/"+args[0], &p); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(p)
			}
			fmt.Fprintf(os.Stdout, "Project   : %s\n", p.Slug)
			fmt.Fprintf(os.Stdout, "Name      : %s\n", p.Name)
			fmt.Fprintf(os.Stdout, "Status    : %s\n", p.Status)
			if p.Description != "" {
				fmt.Fprintf(os.Stdout, "Detail    : %s\n", p.Description)
			}
			fmt.Fprintf(os.Stdout, "Created   : %s\n", p.CreatedAt.Format(time.RFC3339))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newProjectUpdateCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		name, description, status string
	)
	cmd := &cobra.Command{
		Use:   "update <project-slug>",
		Short: "Patch fields on a project (name, description, status)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{}
			if cmd.Flags().Changed("name") {
				body["name"] = name
			}
			if cmd.Flags().Changed("description") {
				body["description"] = description
			}
			if cmd.Flags().Changed("status") {
				body["status"] = status
			}
			if len(body) == 0 {
				return fmt.Errorf("no fields to update")
			}
			var p projectDTO
			if err := apiSend(cmd.Context(), fs, "PATCH",
				"/v1/orgs/"+fs.orgSlug+"/projects/"+args[0], body, &p); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s updated\n", p.Slug)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&description, "description", "", "New description")
	cmd.Flags().StringVar(&status, "status", "", "Status: active|archived")
	return cmd
}

func printProjects(w io.Writer, rows []projectDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no projects")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SLUG\tNAME\tSTATUS\tCREATED")
	for _, p := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			p.Slug, p.Name, p.Status, p.CreatedAt.Format(time.RFC3339))
	}
	return tw.Flush()
}
