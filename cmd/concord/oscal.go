package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/cli/credentials"
)

// oscalImportClient allows a generous timeout — catalogs (e.g. NIST 800-53)
// are multi-megabyte uploads.
var oscalImportClient = &http.Client{Timeout: 120 * time.Second}

type oscalOpts struct {
	serverURL     string
	operatorToken string
	frameworkKey  string
	baselineKey   string
	version       string
}

func newOSCALCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oscal",
		Short: "Import OSCAL catalogs and profiles into a Concord server (operator)",
		Long: `oscal imports OSCAL documents into a Concord server's requirement catalog.

These are operator actions — requirements and baselines are shared across all
tenants — so they authenticate with the server's operator token, not a user
API token.`,
	}
	cmd.AddCommand(newOSCALImportCatalogCmd())
	cmd.AddCommand(newOSCALImportProfileCmd())
	return cmd
}

func newOSCALImportCatalogCmd() *cobra.Command {
	var opts oscalOpts
	cmd := &cobra.Command{
		Use:   "import-catalog <catalog.json>",
		Short: "Import an OSCAL catalog as framework requirements",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOSCALImport(cmd.Context(), opts, "catalog", args[0])
		},
	}
	addOSCALFlags(cmd, &opts)
	return cmd
}

func newOSCALImportProfileCmd() *cobra.Command {
	var opts oscalOpts
	cmd := &cobra.Command{
		Use:   "import-profile <profile.json>",
		Short: "Import an OSCAL profile as a requirement baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.baselineKey == "" {
				return errors.New("--baseline-key is required for a profile")
			}
			return runOSCALImport(cmd.Context(), opts, "profile", args[0])
		},
	}
	addOSCALFlags(cmd, &opts)
	cmd.Flags().StringVar(&opts.baselineKey, "baseline-key", "", "Baseline slug to record (e.g. fedramp-moderate)")
	cmd.Flags().StringVar(&opts.version, "version", "", "Restrict to one framework version (else all imported versions)")
	return cmd
}

func addOSCALFlags(cmd *cobra.Command, opts *oscalOpts) {
	cmd.Flags().StringVar(&opts.serverURL, "to", os.Getenv("CONCORD_SERVER_URL"), "Concord server base URL (or CONCORD_SERVER_URL)")
	cmd.Flags().StringVar(&opts.operatorToken, "operator-token", os.Getenv("CONCORD_OPERATOR_TOKEN"), "Operator token (or CONCORD_OPERATOR_TOKEN)")
	cmd.Flags().StringVar(&opts.frameworkKey, "framework-key", "", "Canonical framework slug (e.g. nist-800-53)")
}

func runOSCALImport(ctx context.Context, opts oscalOpts, kind, path string) error {
	if opts.serverURL == "" {
		if p, err := credentials.Load(); err == nil {
			if prof, perr := p.CurrentProfile(); perr == nil {
				opts.serverURL = prof.Server
			}
		}
	}
	if opts.serverURL == "" {
		return errors.New("--to is required (or set CONCORD_SERVER_URL, or `concord login`)")
	}
	if opts.operatorToken == "" {
		return errors.New("--operator-token is required (or set CONCORD_OPERATOR_TOKEN)")
	}
	if opts.frameworkKey == "" {
		return errors.New("--framework-key is required")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	q := url.Values{}
	q.Set("framework_key", opts.frameworkKey)
	endpoint := "/operator/v1/oscal/catalog"
	if kind == "profile" {
		endpoint = "/operator/v1/oscal/profile"
		q.Set("baseline_key", opts.baselineKey)
		if opts.version != "" {
			q.Set("version", opts.version)
		}
	}
	dest := strings.TrimRight(opts.serverURL, "/") + endpoint + "?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opts.operatorToken)
	req.Header.Set("User-Agent", "concord-agent/"+versionString())

	resp, err := oscalImportClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", dest, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	fmt.Fprintf(os.Stderr, "✓ %s imported: %s\n", kind, strings.TrimSpace(string(respBody)))
	return nil
}
