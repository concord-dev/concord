package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newSSOCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sso",
		Short: "Configure and inspect SSO (OIDC) for an org",
	}
	cmd.AddCommand(newSSOConfigCmd(), newSSOShowCmd(), newSSOTestCmd(), newSSODeleteCmd(),
		newSSOGroupsCmd())
	return cmd
}

func newSSOConfigCmd() *cobra.Command {
	var (
		flagServer, flagOrgSlug, flagToken string
		slug, displayName, issuer          string
		clientID, clientSecret             string
		defaultRole, groupsClaim           string
		scopes                             []string
		jit, disablePasswords              bool
	)
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Create or update the org's OIDC provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			if clientSecret == "" {
				clientSecret = os.Getenv("CONCORD_OIDC_CLIENT_SECRET")
			}
			if slug == "" || displayName == "" || issuer == "" || clientID == "" || clientSecret == "" {
				return errors.New("--slug, --display-name, --issuer, --client-id, and --client-secret are required (--client-secret may come from CONCORD_OIDC_CLIENT_SECRET)")
			}
			body := map[string]any{
				"slug":              slug,
				"display_name":      displayName,
				"issuer_url":        issuer,
				"client_id":         clientID,
				"client_secret":     clientSecret,
				"jit_provision":     jit,
				"disable_passwords": disablePasswords,
				"groups_claim":      groupsClaim,
			}
			if defaultRole != "" {
				body["default_role_id"] = defaultRole
			}
			if len(scopes) > 0 {
				body["scopes"] = scopes
			}
			raw, _ := json.Marshal(body)
			req, _ := http.NewRequest(http.MethodPut, fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/provider", bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer "+fs.token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			rawResp, _ := io.ReadAll(resp.Body)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("configure sso %d: %s", resp.StatusCode, rawResp)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "configured.")
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token")
	cmd.Flags().StringVar(&slug, "slug", "okta", "URL slug for this SSO provider")
	cmd.Flags().StringVar(&displayName, "display-name", "", "human-friendly name (e.g. Acme Okta)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL (e.g. https://acme.okta.com)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OIDC client id")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "OIDC client secret (or env CONCORD_OIDC_CLIENT_SECRET)")
	cmd.Flags().StringVar(&defaultRole, "default-role-id", "", "UUID of the role granted on first JIT login")
	cmd.Flags().StringSliceVar(&scopes, "scopes", nil, "OAuth scopes (default: openid,email,profile)")
	cmd.Flags().BoolVar(&jit, "jit-provision", true, "auto-create users on first login")
	cmd.Flags().BoolVar(&disablePasswords, "disable-passwords", false, "block /v1/auth/login (force SSO)")
	cmd.Flags().StringVar(&groupsClaim, "groups-claim", "groups", "ID-token claim that lists the user's groups")
	return cmd
}

func newSSOShowCmd() *cobra.Command {
	var flagServer, flagOrgSlug, flagToken string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Display the org's current SSO provider configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			req, _ := http.NewRequest(http.MethodGet, fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/provider", nil)
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			rawResp, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusNotFound {
				fmt.Fprintln(cmd.OutOrStdout(), "no SSO provider configured")
				return nil
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("show %d: %s", resp.StatusCode, rawResp)
			}
			var p map[string]any
			if err := json.Unmarshal(rawResp, &p); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			for _, k := range []string{"slug", "kind", "display_name", "issuer_url", "client_id", "jit_provision", "disable_passwords", "groups_claim"} {
				if v, ok := p[k]; ok {
					fmt.Fprintf(tw, "%s\t%v\n", k, v)
				}
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token")
	return cmd
}

func newSSOTestCmd() *cobra.Command {
	var flagServer, flagOrgSlug string
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Print the /v1/auth/sso/<slug>/start URL — open it in a browser to verify the flow",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", "anonymous")
			if err != nil {
				return err
			}
			u, _ := url.Parse(fs.url)
			u.Path = "/v1/auth/sso/" + fs.orgSlug + "/start"
			fmt.Fprintln(cmd.OutOrStdout(), u.String())
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	return cmd
}

func newSSODeleteCmd() *cobra.Command {
	var flagServer, flagOrgSlug, flagToken string
	var force bool
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Remove the org's SSO provider (re-enables password login)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return errors.New("re-run with --force to confirm")
			}
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			req, _ := http.NewRequest(http.MethodDelete, fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/provider", nil)
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				rawResp, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("delete %d: %s", resp.StatusCode, rawResp)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "deleted.")
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token")
	cmd.Flags().BoolVar(&force, "force", false, "confirm the destructive action")
	return cmd
}

func newSSOGroupsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "Manage SSO group → role mappings",
	}
	cmd.AddCommand(newSSOGroupsListCmd(), newSSOGroupsSetCmd())
	return cmd
}

func newSSOGroupsListCmd() *cobra.Command {
	var flagServer, flagOrgSlug, flagToken string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List current group → role mappings",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			req, _ := http.NewRequest(http.MethodGet, fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/group-mappings", nil)
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			rawResp, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("list %d: %s", resp.StatusCode, rawResp)
			}
			var rows []map[string]any
			if err := json.Unmarshal(rawResp, &rows); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "GROUP\tROLE_ID")
			for _, r := range rows {
				fmt.Fprintf(tw, "%v\t%v\n", r["group_name"], r["role_id"])
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token")
	return cmd
}

func newSSOGroupsSetCmd() *cobra.Command {
	var flagServer, flagOrgSlug, flagToken string
	var pairs []string
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Replace the full set of group → role mappings",
		Long: `Replaces (full replacement, not merge) the org's SSO group→role mappings.

Each --map argument has the form "group=role-uuid":
    concord sso groups set --map "engineering=11111111-...-..." --map "auditors=22222222-..."`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			mappings := []map[string]string{}
			for _, p := range pairs {
				kv := strings.SplitN(p, "=", 2)
				if len(kv) != 2 || strings.TrimSpace(kv[0]) == "" || strings.TrimSpace(kv[1]) == "" {
					return fmt.Errorf(`--map %q must be "group=role-uuid"`, p)
				}
				mappings = append(mappings, map[string]string{"group_name": kv[0], "role_id": kv[1]})
			}
			body := map[string]any{"mappings": mappings}
			raw, _ := json.Marshal(body)
			req, _ := http.NewRequest(http.MethodPut, fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/group-mappings", bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer "+fs.token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			rawResp, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("set %d: %s", resp.StatusCode, rawResp)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "updated.")
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token")
	cmd.Flags().StringArrayVar(&pairs, "map", nil, `group→role mapping, e.g. "engineering=11111111-...-..." (repeatable)`)
	return cmd
}
