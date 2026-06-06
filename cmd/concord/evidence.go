package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		filePath, notes, finding  string
	)
	cmd := &cobra.Command{
		Use:   "attach",
		Short: "Upload an evidence document (PDF, screenshot, runbook) — streamed and sha256-verified",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			a, err := uploadEvidenceFile(cmd.Context(), fs, filePath, finding, notes)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "attached %s (%d bytes, sha256=%s, id=%s)\n",
				a.Filename, a.ByteSize, a.SHA256, a.ID)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&filePath, "file", "", "Local path to the document (required)")
	cmd.Flags().StringVar(&finding, "finding", "", "Optional finding id to attach the document to (FIND-abc...)")
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

// uploadEvidenceFile streams the file body to /v1/orgs/{slug}/attachments
// with the filename in the X-Concord-Filename header. The platform
// computes sha256 server-side and returns the attachment descriptor.
func uploadEvidenceFile(ctx context.Context, fs findingsServer, path, finding, notes string) (evidenceAttachmentDTO, error) {
	f, err := os.Open(path)
	if err != nil {
		return evidenceAttachmentDTO{}, fmt.Errorf("open document: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return evidenceAttachmentDTO{}, err
	}
	q := url.Values{}
	if finding != "" {
		q.Set("finding_id", finding)
	}
	if notes != "" {
		q.Set("notes", notes)
	}
	endpoint := fs.url + "/v1/orgs/" + fs.orgSlug + "/attachments"
	if len(q) > 0 {
		endpoint += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, f)
	if err != nil {
		return evidenceAttachmentDTO{}, err
	}
	req.ContentLength = st.Size()
	req.Header.Set("Authorization", "Bearer "+fs.token)
	req.Header.Set("X-Concord-Filename", filepath.Base(path))
	if ct := contentTypeFor(path); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return evidenceAttachmentDTO{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return evidenceAttachmentDTO{}, fmt.Errorf("upload %d: %s", resp.StatusCode, body)
	}
	var a evidenceAttachmentDTO
	if err := json.Unmarshal(body, &a); err != nil {
		return evidenceAttachmentDTO{}, err
	}
	return a, nil
}

func contentTypeFor(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".md":
		return "text/markdown"
	case ".txt":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	}
	return "application/octet-stream"
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
			if err := apiGet(cmd.Context(), fs, fs.projectBase()+"/evidence-collections", &rows); err != nil {
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
