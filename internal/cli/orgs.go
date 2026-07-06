package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/cli/credentials"
)

func newOrgsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "orgs",
		Short: "Manage org context (default org for push/check/watch, listing)",
	}
	cmd.AddCommand(newOrgsListCmd())
	cmd.AddCommand(newOrgsUseCmd())
	return cmd
}

func newOrgsListCmd() *cobra.Command {
	var profileName string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List orgs the current session is a member of",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := requireProfile(profileName)
			if err != nil {
				return err
			}
			var orgs []struct {
				Organization struct {
					Slug string `json:"slug"`
					Name string `json:"name"`
				} `json:"organization"`
				Roles []struct {
					Name string `json:"name"`
				} `json:"roles"`
			}
			if err := callAPI(cmd.Context(), "GET", p.Server+"/v1/me/orgs", p.Token, nil, &orgs); err != nil {
				if isStatus(err, 401) {
					return errors.New("session is invalid or expired — run `concord login`")
				}
				return err
			}
			out := cmd.OutOrStdout()
			if len(orgs) == 0 {
				fmt.Fprintln(out, "no orgs — ask an operator to add you to an organization")
				return nil
			}
			for _, o := range orgs {
				marker := " "
				if o.Organization.Slug == p.DefaultOrg {
					marker = "*"
				}
				roleNames := make([]string, 0, len(o.Roles))
				for _, r := range o.Roles {
					roleNames = append(roleNames, r.Name)
				}
				fmt.Fprintf(out, "%s %-30s %s  roles=%v\n", marker, o.Organization.Slug, o.Organization.Name, roleNames)
			}
			fmt.Fprintln(out, "  (asterisk = default org — change with `concord orgs use <slug>`)")
			return nil
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "", "Profile to query (default: current)")
	return cmd
}

func newOrgsUseCmd() *cobra.Command {
	var profileName string
	cmd := &cobra.Command{
		Use:   "use <slug>",
		Short: "Pin the default org slug used by push/check/watch when --org-slug is omitted",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			slug := args[0]
			file, err := credentials.Load()
			if errors.Is(err, credentials.ErrNoCredentials) {
				return errors.New("no credentials file — run `concord login` first")
			}
			if err != nil {
				return err
			}
			target := profileName
			if target == "" {
				target = file.Current
			}
			p, ok := file.Profiles[target]
			if !ok || p == nil {
				return fmt.Errorf("profile %q not found", target)
			}
			err = callAPI(cmd.Context(), "GET",
				p.Server+"/v1/orgs/"+slug+"/me", p.Token, nil, nil)
			if err != nil {
				if isStatus(err, 401) {
					return errors.New("session is invalid or expired — run `concord login`")
				}
				if isStatus(err, 403) || isStatus(err, 404) {
					return fmt.Errorf("you don't appear to belong to org %q (or it doesn't exist)", slug)
				}
				return err
			}
			p.DefaultOrg = slug
			if err := credentials.Save(file); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ default org set to %s\n", slug)
			return nil
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "", "Profile to update (default: current)")
	return cmd
}

func requireProfile(name string) (*credentials.Profile, error) {
	file, err := credentials.Load()
	if errors.Is(err, credentials.ErrNoCredentials) {
		return nil, errors.New("no credentials file — run `concord login` first")
	}
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = file.Current
	}
	p, ok := file.Profiles[name]
	if !ok || p == nil {
		return nil, fmt.Errorf("profile %q not found — run `concord login`", name)
	}
	return p, nil
}
