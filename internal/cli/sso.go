package cli

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
		newSSOGroupsCmd(), newSSOSCIMCmd())
	return cmd
}

func newSSOConfigCmd() *cobra.Command {
	var (
		flagServer, flagOrgSlug, flagToken string
		kind                               string
		slug, displayName                  string
		defaultRole                        string
		jit, disablePasswords              bool

		// OIDC-specific
		issuer, clientID, clientSecret string
		scopes                         []string
		groupsClaim                    string

		// SAML-specific
		idpEntityID, idpSSOURL, idpCertPath string
		audienceURI, nameIDFormat           string
		samlGroupsAttribute                 string
	)
	cmd := &cobra.Command{
		Use:   "configure",
		Short: "Create or update the org's SSO provider (OIDC or SAML)",
		Long: `Configure the org's SSO provider.

For OIDC (default):
    concord sso configure --kind oidc
        --display-name "Acme Okta"
        --issuer https://acme.okta.com
        --client-id <id> --client-secret <secret>

For SAML:
    concord sso configure --kind saml
        --display-name "Acme Okta SAML"
        --idp-entity-id http://www.okta.com/exk-XXX
        --idp-sso-url https://acme.okta.com/app/.../sso/saml
        --idp-cert-file ./okta.cert.pem

The SP keypair for SAML is auto-generated server-side on first
configure. Download the resulting SP metadata XML at
    /v1/auth/sso/{slug}/saml/metadata
and upload it on the IdP side.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			if displayName == "" {
				return errors.New("--display-name is required")
			}
			if kind == "" {
				kind = "oidc"
			}
			body := map[string]any{
				"slug":              slug,
				"kind":              kind,
				"display_name":      displayName,
				"jit_provision":     jit,
				"disable_passwords": disablePasswords,
			}
			if defaultRole != "" {
				body["default_role_id"] = defaultRole
			}

			switch kind {
			case "oidc":
				if clientSecret == "" {
					clientSecret = os.Getenv("CONCORD_OIDC_CLIENT_SECRET")
				}
				if issuer == "" || clientID == "" || clientSecret == "" {
					return errors.New("--issuer, --client-id, and --client-secret are required for --kind oidc (or set CONCORD_OIDC_CLIENT_SECRET)")
				}
				body["issuer_url"] = issuer
				body["client_id"] = clientID
				body["client_secret"] = clientSecret
				body["groups_claim"] = groupsClaim
				if len(scopes) > 0 {
					body["scopes"] = scopes
				}
			case "saml":
				if idpEntityID == "" || idpSSOURL == "" || idpCertPath == "" {
					return errors.New("--idp-entity-id, --idp-sso-url, and --idp-cert-file are required for --kind saml")
				}
				certBytes, err := os.ReadFile(idpCertPath)
				if err != nil {
					return fmt.Errorf("read --idp-cert-file: %w", err)
				}
				body["idp_entity_id"] = idpEntityID
				body["idp_sso_url"] = idpSSOURL
				body["idp_x509_cert"] = string(certBytes)
				if audienceURI != "" {
					body["audience_uri"] = audienceURI
				}
				if nameIDFormat != "" {
					body["saml_name_id_format"] = nameIDFormat
				}
				if samlGroupsAttribute != "" {
					body["saml_groups_attribute"] = samlGroupsAttribute
				}
			default:
				return fmt.Errorf(`--kind must be "oidc" or "saml" (got %q)`, kind)
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
			if kind == "saml" {
				fmt.Fprintf(cmd.OutOrStdout(), "next: download metadata from %s/v1/auth/sso/%s/saml/metadata and upload it to your IdP\n",
					fs.url, fs.orgSlug)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token")
	cmd.Flags().StringVar(&kind, "kind", "oidc", `SSO protocol — "oidc" or "saml"`)
	cmd.Flags().StringVar(&slug, "slug", "okta", "URL slug for this SSO provider")
	cmd.Flags().StringVar(&displayName, "display-name", "", "human-friendly name (e.g. Acme Okta)")
	cmd.Flags().StringVar(&defaultRole, "default-role-id", "", "UUID of the role granted on first JIT login")
	cmd.Flags().BoolVar(&jit, "jit-provision", true, "auto-create users on first login")
	cmd.Flags().BoolVar(&disablePasswords, "disable-passwords", false, "block /v1/auth/login (force SSO)")
	// OIDC flags
	cmd.Flags().StringVar(&issuer, "issuer", "", "OIDC issuer URL (e.g. https://acme.okta.com)")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OIDC client id")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "OIDC client secret (or env CONCORD_OIDC_CLIENT_SECRET)")
	cmd.Flags().StringSliceVar(&scopes, "scopes", nil, "OAuth scopes (default: openid,email,profile)")
	cmd.Flags().StringVar(&groupsClaim, "groups-claim", "groups", "ID-token claim that lists the user's groups")
	// SAML flags
	cmd.Flags().StringVar(&idpEntityID, "idp-entity-id", "", "SAML IdP entity ID")
	cmd.Flags().StringVar(&idpSSOURL, "idp-sso-url", "", "SAML IdP SSO endpoint URL")
	cmd.Flags().StringVar(&idpCertPath, "idp-cert-file", "", "path to PEM-encoded IdP signing cert")
	cmd.Flags().StringVar(&audienceURI, "audience-uri", "", "SAML SP audience URI (defaults to the metadata URL)")
	cmd.Flags().StringVar(&nameIDFormat, "saml-name-id-format", "", "SAML NameID format (default: emailAddress)")
	cmd.Flags().StringVar(&samlGroupsAttribute, "saml-groups-attribute", "", "SAML attribute name carrying groups (default: groups)")
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

func newSSOSCIMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scim",
		Short: "Manage SCIM provisioning tokens for the org's SSO provider",
	}
	cmd.AddCommand(newSCIMTokenMintCmd(), newSCIMTokenListCmd(), newSCIMTokenRevokeCmd())
	return cmd
}

func newSCIMTokenMintCmd() *cobra.Command {
	var flagServer, flagOrgSlug, flagToken, name string
	cmd := &cobra.Command{
		Use:   "mint-token",
		Short: "Issue a new SCIM bearer token (shown once; paste into the IdP's SCIM app)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			if strings.TrimSpace(name) == "" {
				return errors.New("--name is required")
			}
			raw, _ := json.Marshal(map[string]any{"name": name})
			req, _ := http.NewRequest(http.MethodPost,
				fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/scim/tokens", bytes.NewReader(raw))
			req.Header.Set("Authorization", "Bearer "+fs.token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			rawResp, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusCreated {
				return fmt.Errorf("mint-token %d: %s", resp.StatusCode, rawResp)
			}
			var out struct {
				Token       string `json:"token"`
				ID          string `json:"id"`
				ScimBaseURL string `json:"scim_base_url"`
			}
			if err := json.Unmarshal(rawResp, &out); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "id\t%s\n", out.ID)
			fmt.Fprintf(tw, "scim_base_url\t%s\n", out.ScimBaseURL)
			fmt.Fprintf(tw, "token\t%s\n", out.Token)
			tw.Flush()
			fmt.Fprintln(cmd.OutOrStdout(),
				"\nThe token is shown only once. Paste it into your IdP's SCIM app under Authorization → Bearer.")
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token (org admin)")
	cmd.Flags().StringVar(&name, "name", "", `human-friendly label, e.g. "Okta prod"`)
	return cmd
}

func newSCIMTokenListCmd() *cobra.Command {
	var flagServer, flagOrgSlug, flagToken string
	cmd := &cobra.Command{
		Use:   "list-tokens",
		Short: "List SCIM tokens minted for the org's SSO provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			req, _ := http.NewRequest(http.MethodGet,
				fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/scim/tokens", nil)
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			rawResp, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("list-tokens %d: %s", resp.StatusCode, rawResp)
			}
			var rows []map[string]any
			if err := json.Unmarshal(rawResp, &rows); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tNAME\tPREFIX\tLAST USED\tREVOKED")
			for _, r := range rows {
				lastUsed := "-"
				if v, ok := r["last_used_at"]; ok && v != nil {
					lastUsed = fmt.Sprintf("%v", v)
				}
				revoked := "-"
				if v, ok := r["revoked_at"]; ok && v != nil {
					revoked = fmt.Sprintf("%v", v)
				}
				fmt.Fprintf(tw, "%v\t%v\t%v\t%s\t%s\n",
					r["id"], r["name"], r["token_prefix"], lastUsed, revoked)
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token (org admin)")
	return cmd
}

func newSCIMTokenRevokeCmd() *cobra.Command {
	var flagServer, flagOrgSlug, flagToken string
	cmd := &cobra.Command{
		Use:   "revoke-token <token-id>",
		Short: "Revoke an SCIM token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(flagServer, flagOrgSlug, "", flagToken)
			if err != nil {
				return err
			}
			req, _ := http.NewRequest(http.MethodDelete,
				fs.url+"/v1/orgs/"+fs.orgSlug+"/sso/scim/tokens/"+args[0], nil)
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNoContent {
				rawResp, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("revoke %d: %s", resp.StatusCode, rawResp)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "revoked.")
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagToken, "token", "", "API token (org admin)")
	return cmd
}
