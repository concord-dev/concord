package cli

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const provenancePayloadType = "application/vnd.in-toto+json"

func newProvenanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provenance",
		Short: "Download and verify Concord's signed evidence bundle",
	}
	cmd.AddCommand(newProvenanceDownloadCmd())
	cmd.AddCommand(newProvenanceVerifyCmd())
	return cmd
}

func newProvenanceDownloadCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		framework, since, until   string
		out                       string
	)
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download a sigstore-compatible provenance bundle (zip)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			if framework != "" {
				q.Add("framework", framework)
			}
			if since != "" {
				q.Add("since", since)
			}
			if until != "" {
				q.Add("until", until)
			}
			path := "/v1/orgs/" + fs.orgSlug + "/provenance-bundle"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			req, err := http.NewRequestWithContext(cmd.Context(),
				http.MethodGet, strings.TrimRight(fs.url, "/")+path, nil)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				return fmt.Errorf("download: %d: %s", resp.StatusCode, body)
			}
			if out == "" {
				out = "concord-provenance.zip"
			}
			f, err := os.Create(out)
			if err != nil {
				return err
			}
			defer f.Close()
			n, err := io.Copy(f, resp.Body)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "wrote %d bytes to %s\n", n, out)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&framework, "framework", "", "Filter by framework (e.g. soc2, iso27001)")
	cmd.Flags().StringVar(&since, "since", "", "RFC3339 lower bound on signed_at")
	cmd.Flags().StringVar(&until, "until", "", "RFC3339 upper bound on signed_at")
	cmd.Flags().StringVarP(&out, "out", "o", "", "Output path (default: concord-provenance.zip)")
	return cmd
}

func newProvenanceVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify <bundle.zip>",
		Short: "Offline verification of a provenance bundle's signatures",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				return fmt.Errorf("open zip: %w", err)
			}
			keys := map[string]ed25519.PublicKey{}
			var attestations [][2]string
			var manifest map[string]any
			for _, f := range zr.File {
				rc, err := f.Open()
				if err != nil {
					return err
				}
				body, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					return err
				}
				switch {
				case f.Name == "manifest.json":
					_ = json.Unmarshal(body, &manifest)
				case strings.HasPrefix(f.Name, "keys/"):
					id := strings.TrimSuffix(strings.TrimPrefix(f.Name, "keys/"), ".ed25519.pub")
					block, _ := pem.Decode(body)
					if block == nil {
						return fmt.Errorf("invalid PEM in %s", f.Name)
					}
					pub, err := x509.ParsePKIXPublicKey(block.Bytes)
					if err != nil {
						return fmt.Errorf("parse %s: %w", f.Name, err)
					}
					ed, ok := pub.(ed25519.PublicKey)
					if !ok {
						return fmt.Errorf("%s: not ed25519", f.Name)
					}
					keys[id] = ed
				case strings.HasPrefix(f.Name, "attestations/"):
					attestations = append(attestations, [2]string{f.Name, string(body)})
				}
			}
			if len(attestations) == 0 {
				return fmt.Errorf("bundle contains no attestations")
			}
			ok, fail := 0, 0
			for _, a := range attestations {
				if err := verifyDSSE(a[1], keys); err != nil {
					fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", a[0], err)
					fail++
					continue
				}
				ok++
			}
			fmt.Fprintf(os.Stdout, "verified %d of %d attestations using %d signing keys\n",
				ok, ok+fail, len(keys))
			if fail > 0 {
				return fmt.Errorf("%d attestations failed verification", fail)
			}
			return nil
		},
	}
	return cmd
}

func verifyDSSE(rawEnvelope string, keys map[string]ed25519.PublicKey) error {
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(rawEnvelope), &env); err != nil {
		return fmt.Errorf("parse envelope: %w", err)
	}
	if env.PayloadType != provenancePayloadType {
		return fmt.Errorf("unexpected payloadType %q", env.PayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	pae := []byte(fmt.Sprintf("DSSEv1 %d %s %d ", len(env.PayloadType), env.PayloadType, len(payload)))
	pae = append(pae, payload...)
	if len(env.Signatures) == 0 {
		return fmt.Errorf("no signatures")
	}
	for _, s := range env.Signatures {
		pub, ok := keys[s.KeyID]
		if !ok {
			return fmt.Errorf("no public key for keyid %s", s.KeyID)
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil {
			return fmt.Errorf("decode sig: %w", err)
		}
		if !ed25519.Verify(pub, pae, sig) {
			return fmt.Errorf("signature %s failed", s.KeyID)
		}
	}
	return nil
}
