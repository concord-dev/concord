package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/cli/credentials"
)

func newWhoamiCmd() *cobra.Command {
	var (
		profileName string
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Print the active session's user, server, and orgs",
		Long: `whoami resolves the stored session against the server. It checks that the
token is still valid (so an expired session surfaces here, not later
when you try to push), prints the user behind it, and lists the orgs
that user is a member of with their roles.

A typical flow before any real work:
  concord whoami            # confirm I'm pointed at the right server + identity
  concord orgs use <slug>   # pin the default org for push/check/watch
  concord push --findings ./findings.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := credentials.Load()
			if errors.Is(err, credentials.ErrNoCredentials) {
				return errors.New("no credentials file — run `concord login` first")
			}
			if err != nil {
				return err
			}
			if profileName == "" {
				profileName = file.Current
			}
			p, ok := file.Profiles[profileName]
			if !ok || p == nil {
				return fmt.Errorf("profile %q not found", profileName)
			}

			var me struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			}
			if err := callAPI(cmd.Context(), "GET", p.Server+"/v1/me", p.Token, nil, &me); err != nil {
				if isStatus(err, 401) {
					return errors.New("session is invalid or expired — run `concord login`")
				}
				return err
			}
			var orgsRaw []struct {
				Organization struct {
					Slug string `json:"slug"`
					Name string `json:"name"`
				} `json:"organization"`
				Roles []struct {
					Name string `json:"name"`
				} `json:"roles"`
			}
			if err := callAPI(cmd.Context(), "GET", p.Server+"/v1/me/orgs", p.Token, nil, &orgsRaw); err != nil {
				return err
			}
			type orgView struct {
				Slug  string   `json:"slug"`
				Name  string   `json:"name"`
				Roles []string `json:"roles"`
			}
			orgs := make([]orgView, 0, len(orgsRaw))
			for _, o := range orgsRaw {
				view := orgView{Slug: o.Organization.Slug, Name: o.Organization.Name}
				for _, r := range o.Roles {
					view.Roles = append(view.Roles, r.Name)
				}
				orgs = append(orgs, view)
			}

			if jsonOut {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"profile":     profileName,
					"server":      p.Server,
					"user":        me,
					"default_org": p.DefaultOrg,
					"orgs":        orgs,
					"expires_at":  p.ExpiresAt,
				})
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Profile:     %s\n", profileName)
			fmt.Fprintf(out, "Server:      %s\n", p.Server)
			fmt.Fprintf(out, "User:        %s  (id %s)\n", me.Email, me.ID)
			if !p.ExpiresAt.IsZero() {
				remaining := time.Until(p.ExpiresAt).Round(time.Minute)
				fmt.Fprintf(out, "Session ttl: %s\n", remaining)
			}
			if p.DefaultOrg != "" {
				fmt.Fprintf(out, "Default org: %s\n", p.DefaultOrg)
			}
			fmt.Fprintln(out, "Orgs:")
			if len(orgs) == 0 {
				fmt.Fprintln(out, "  (none — ask an operator to add you to an organization)")
			}
			for _, o := range orgs {
				fmt.Fprintf(out, "  · %-30s %s  roles=%v\n", o.Slug, o.Name, o.Roles)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "", "Profile to inspect (default: current)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit a machine-readable JSON envelope instead of the human view")
	return cmd
}
