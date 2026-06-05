package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type evidenceCollectionDTO struct {
	Source          string     `json:"source"`
	LastStartedAt   time.Time  `json:"last_started_at"`
	LastSucceededAt *time.Time `json:"last_succeeded_at,omitempty"`
	LastAttemptAt   time.Time  `json:"last_attempt_at"`
	LastError       string     `json:"last_error,omitempty"`
	LastSHA256      string     `json:"last_sha256,omitempty"`
	AttemptCount    int        `json:"attempt_count"`
	SuccessCount    int        `json:"success_count"`
}

func newEvidenceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "evidence",
		Short: "Inspect evidence-collection state and attach evidence documents",
	}
	cmd.AddCommand(newEvidenceFreshnessCmd())
	cmd.AddCommand(newEvidenceAttachCmd())
	return cmd
}

func newEvidenceAttachCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		filePath, notes           string
	)
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Upload an evidence document (PDF, screenshot, runbook) as a sha256-addressed attachment",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			a, err := uploadEvidenceFile(cmd.Context(), fs, filePath, notes)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "attached %s (%d bytes, sha256=%s)\n",
				a.Filename, a.ByteSize, a.SHA256)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&filePath, "file", "", "Local path to the document (required)")
	cmd.Flags().StringVar(&notes, "notes", "", "Optional notes describing what this evidence proves")
	_ = cmd.MarkFlagRequired("file")
	return cmd
}

type evidenceAttachmentDTO struct {
	ID       string `json:"id"`
	SHA256   string `json:"sha256"`
	Filename string `json:"filename"`
	ByteSize int64  `json:"byte_size"`
}

func uploadEvidenceFile(ctx context.Context, fs findingsServer, path, notes string) (evidenceAttachmentDTO, error) {
	f, err := os.Open(path)
	if err != nil {
		return evidenceAttachmentDTO{}, fmt.Errorf("open document: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return evidenceAttachmentDTO{}, fmt.Errorf("hash document: %w", err)
	}
	body := map[string]any{
		"sha256":    hex.EncodeToString(h.Sum(nil)),
		"filename":  path,
		"byte_size": n,
	}
	if notes != "" {
		body["notes"] = notes
	}
	var a evidenceAttachmentDTO
	if err := apiSend(ctx, fs, "POST",
		"/v1/orgs/"+fs.orgSlug+"/evidence-attachments", body, &a); err != nil {
		return evidenceAttachmentDTO{}, err
	}
	return a, nil
}

func newEvidenceFreshnessCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "freshness",
		Short: "List per-source last-success / last-attempt times",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rows []evidenceCollectionDTO
			if err := apiGet(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/evidence-collections", &rows); err != nil {
				return err
			}
			return renderFreshness(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func renderFreshness(w io.Writer, rows []evidenceCollectionDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no evidence-collection rows yet (push a run first)")
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Source < rows[j].Source })
	now := time.Now().UTC()
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tLAST SUCCESS\tAGE\tLAST ATTEMPT\tATTEMPTS\tSUCCESSES\tLAST ERROR")
	for _, ec := range rows {
		age := "never"
		when := "—"
		if ec.LastSucceededAt != nil {
			when = ec.LastSucceededAt.Format(time.RFC3339)
			age = humanAge(now.Sub(*ec.LastSucceededAt))
		}
		errSnip := ec.LastError
		if len(errSnip) > 60 {
			errSnip = errSnip[:57] + "…"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			ec.Source, when, age, ec.LastAttemptAt.Format(time.RFC3339),
			ec.AttemptCount, ec.SuccessCount, errSnip,
		)
	}
	return tw.Flush()
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
