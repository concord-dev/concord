package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 keypair for signing agent pushes",
		Long: `Generate a 32-byte Ed25519 keypair Concord uses to sign run submissions.

The private key is written to --out (mode 0600). The public key prints to
stdout — register it with the server via:

  curl -X POST $CONCORD_URL/v1/orgs/$SLUG/agent-keys \
       -H "Authorization: Bearer $CONCORD_API_TOKEN" \
       -H "Content-Type: application/json" \
       -d '{"name":"ci-prod","public_key":"<paste-stdout-here>"}'

The private key never leaves the agent. The server only ever knows the
public half. Lose the private key, the agent can no longer sign — but you
can always issue a new one without touching past runs.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generating Ed25519 keypair: %w", err)
			}

			// Write private key with restrictive permissions BEFORE printing
			// anything to stdout — fail fast if the file system rejects us.
			if err := os.WriteFile(outPath, priv, 0o600); err != nil {
				return fmt.Errorf("writing private key to %s: %w", outPath, err)
			}

			fmt.Fprintf(os.Stderr, "✓ private key → %s (mode 0600)\n", outPath)
			fmt.Fprintln(os.Stderr, "public key (base64) ↓ register with the server:")
			fmt.Println(base64.StdEncoding.EncodeToString(pub))
			return nil
		},
	}
	cmd.Flags().StringVar(&outPath, "out", "./concord-agent.key", "Path to write the private key (mode 0600)")
	return cmd
}
