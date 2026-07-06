package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type vendorDTO struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Tier           string          `json:"tier"`
	Status         string          `json:"status"`
	Notes          string          `json:"notes,omitempty"`
	Certifications []vendorCertDTO `json:"certifications,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type vendorCertDTO struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Issuer    string     `json:"issuer,omitempty"`
	IssuedAt  *time.Time `json:"issued_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type attachmentDTO struct {
	ID       string `json:"id"`
	SHA256   string `json:"sha256"`
	Filename string `json:"filename"`
	ByteSize int64  `json:"byte_size"`
}

func newVendorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vendor",
		Short: "Manage third-party vendors and their compliance certifications",
	}
	cmd.AddCommand(newVendorAddCmd())
	cmd.AddCommand(newVendorListCmd())
	cmd.AddCommand(newVendorShowCmd())
	cmd.AddCommand(newVendorUpdateCmd())
	cmd.AddCommand(newVendorAttachCmd())
	cmd.AddCommand(newVendorLinkCmd())
	return cmd
}

func newVendorAddCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token       string
		name, tier, notes               string
		certType, issuer, expiresStr    string
		soc2, iso, hipaa, pci, document string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Register a new vendor (optionally attach a certification document)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"name": name}
			if tier != "" {
				body["tier"] = tier
			}
			if notes != "" {
				body["notes"] = notes
			}
			var v vendorDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				"/v1/orgs/"+fs.orgSlug+"/vendors", body, &v); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s (%s) — tier=%s\n", v.ID, v.Name, v.Tier)

			cert, doc := pickCertFlag(certType, document, soc2, iso, hipaa, pci)
			if cert != "" {
				return attachCert(cmd, fs, v.ID, cert, issuer, expiresStr, doc)
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "Vendor name (required)")
	cmd.Flags().StringVar(&tier, "tier", "", "Tier: tier_1|tier_2|tier_3 (default tier_3)")
	cmd.Flags().StringVar(&notes, "notes", "", "Free-form notes")
	cmd.Flags().StringVar(&certType, "cert", "", "Add a certification at create time (soc2|iso27001|hipaa|pci|other)")
	cmd.Flags().StringVar(&soc2, "soc2", "", "Shortcut: --soc2 <path-to-pdf>")
	cmd.Flags().StringVar(&iso, "iso27001", "", "Shortcut: --iso27001 <path-to-pdf>")
	cmd.Flags().StringVar(&hipaa, "hipaa", "", "Shortcut: --hipaa <path-to-pdf>")
	cmd.Flags().StringVar(&pci, "pci", "", "Shortcut: --pci <path-to-pdf>")
	cmd.Flags().StringVar(&issuer, "issuer", "", "Certifying body (e.g. Schellman, BSI)")
	cmd.Flags().StringVar(&expiresStr, "expires", "", "Expiry date (RFC3339 or YYYY-MM-DD)")
	cmd.Flags().StringVar(&document, "document", "", "Override path to the cert document (used by --cert)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newVendorListCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List vendors registered for this org",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rows []vendorDTO
			if err := apiGet(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/vendors", &rows); err != nil {
				return err
			}
			return printVendors(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newVendorShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <vendor-id>",
		Short: "Show one vendor with its certifications",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var v vendorDTO
			if err := apiGet(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/vendors/"+args[0], &v); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(v)
			}
			fmt.Fprintf(os.Stdout, "%s — %s\nTier: %s\nStatus: %s\n", v.ID, v.Name, v.Tier, v.Status)
			if v.Notes != "" {
				fmt.Fprintf(os.Stdout, "Notes: %s\n", v.Notes)
			}
			if len(v.Certifications) > 0 {
				fmt.Fprintln(os.Stdout, "Certifications:")
				for _, c := range v.Certifications {
					expires := "—"
					if c.ExpiresAt != nil {
						expires = c.ExpiresAt.Format("2006-01-02")
					}
					fmt.Fprintf(os.Stdout, "  - %s (issuer=%s, expires=%s)\n", c.Type, c.Issuer, expires)
				}
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newVendorUpdateCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		name, tier, notes, status string
	)
	cmd := &cobra.Command{
		Use:   "update <vendor-id>",
		Short: "Patch fields on an existing vendor",
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
			if cmd.Flags().Changed("tier") {
				body["tier"] = tier
			}
			if cmd.Flags().Changed("notes") {
				body["notes"] = notes
			}
			if cmd.Flags().Changed("status") {
				body["status"] = status
			}
			if len(body) == 0 {
				return fmt.Errorf("no fields to update — pass at least one flag")
			}
			var v vendorDTO
			if err := apiSend(cmd.Context(), fs, "PATCH",
				"/v1/orgs/"+fs.orgSlug+"/vendors/"+args[0], body, &v); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s updated\n", v.ID)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&tier, "tier", "", "Tier: tier_1|tier_2|tier_3")
	cmd.Flags().StringVar(&notes, "notes", "", "New notes")
	cmd.Flags().StringVar(&status, "status", "", "Status: active|in_review|terminated")
	return cmd
}

func newVendorAttachCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token              string
		certType, issuer, expiresStr, document string
	)
	cmd := &cobra.Command{
		Use:   "attach <vendor-id>",
		Short: "Attach a certification (and optionally upload its document) to a vendor",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			return attachCert(cmd, fs, args[0], certType, issuer, expiresStr, document)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&certType, "cert", "", "Cert type: soc2|iso27001|hipaa|pci|other (required)")
	cmd.Flags().StringVar(&issuer, "issuer", "", "Certifying body")
	cmd.Flags().StringVar(&expiresStr, "expires", "", "Expiry (RFC3339 or YYYY-MM-DD)")
	cmd.Flags().StringVar(&document, "document", "", "Local path to the cert PDF (will be sha256-attached)")
	_ = cmd.MarkFlagRequired("cert")
	return cmd
}

func newVendorLinkCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "link <vendor-id> <finding-id>",
		Short: "Link a finding to a vendor",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiSend(cmd.Context(), fs, "POST",
				"/v1/orgs/"+fs.orgSlug+"/vendors/"+args[0]+"/links",
				map[string]any{"finding_id": args[1]}, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s ← %s\n", args[0], args[1])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func attachCert(cmd *cobra.Command, fs findingsServer, vendorID, certType, issuer, expiresStr, document string) error {
	if certType == "" {
		return fmt.Errorf("--cert is required")
	}
	body := map[string]any{"type": certType}
	if issuer != "" {
		body["issuer"] = issuer
	}
	if expiresStr != "" {
		t, err := parseCertDate(expiresStr)
		if err != nil {
			return err
		}
		body["expires_at"] = t.Format(time.RFC3339)
	}
	if document != "" {
		att, err := uploadAttachment(cmd, fs, document)
		if err != nil {
			return err
		}
		body["document_attachment"] = att.ID
	}
	var c vendorCertDTO
	if err := apiSend(cmd.Context(), fs, "POST",
		"/v1/orgs/"+fs.orgSlug+"/vendors/"+vendorID+"/certifications", body, &c); err != nil {
		return err
	}
	expires := "—"
	if c.ExpiresAt != nil {
		expires = c.ExpiresAt.Format("2006-01-02")
	}
	fmt.Fprintf(os.Stdout, "  + %s certification (expires %s)\n", c.Type, expires)
	return nil
}

func uploadAttachment(cmd *cobra.Command, fs findingsServer, path string) (attachmentDTO, error) {
	f, err := os.Open(path)
	if err != nil {
		return attachmentDTO{}, fmt.Errorf("open document: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return attachmentDTO{}, fmt.Errorf("hash document: %w", err)
	}
	body := map[string]any{
		"sha256":    hex.EncodeToString(h.Sum(nil)),
		"filename":  path,
		"byte_size": n,
	}
	var att attachmentDTO
	if err := apiSend(cmd.Context(), fs, "POST",
		"/v1/orgs/"+fs.orgSlug+"/evidence-attachments", body, &att); err != nil {
		return attachmentDTO{}, err
	}
	return att, nil
}

func parseCertDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("cannot parse %q (use RFC3339 or YYYY-MM-DD)", s)
}

func pickCertFlag(generic, genericDoc, soc2, iso, hipaa, pci string) (certType, document string) {
	switch {
	case soc2 != "":
		return "soc2", soc2
	case iso != "":
		return "iso27001", iso
	case hipaa != "":
		return "hipaa", hipaa
	case pci != "":
		return "pci", pci
	}
	return generic, genericDoc
}

func printVendors(w io.Writer, rows []vendorDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no vendors")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tTIER\tSTATUS\tCERTS")
	for _, v := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\n", v.ID, v.Name, v.Tier, v.Status, len(v.Certifications))
	}
	return tw.Flush()
}
