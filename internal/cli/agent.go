package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// newAgentCmd groups agent-identity operations. Today: generating the ed25519
// keypair an agent uses to sign run submissions so the server can verify which
// agent produced a run (the trust seam). The private key never leaves the host.
func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Manage the agent identity used to sign run submissions",
	}
	cmd.AddCommand(newAgentKeygenCmd())
	return cmd
}

func newAgentKeygenCmd() *cobra.Command {
	var (
		out   string
		keyID string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an ed25519 signing key and print its public half for registration",
		Long: `keygen creates an ed25519 keypair for signing run submissions. The private
key is written to --out (0600) and never leaves this host; register the printed
public key with the server (operator: POST /operator/v1/orgs/{slug}/agent-keys),
then push with --key <file> --key-id <id>.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generating key: %w", err)
			}
			if keyID == "" {
				// Derive a stable id from the public key so it's unique + reproducible.
				sum := sha256.Sum256(pub)
				keyID = "agent-" + hex.EncodeToString(sum[:6])
			}
			if _, err := os.Stat(out); err == nil && !force {
				return fmt.Errorf("%s already exists (pass --force to overwrite)", out)
			}
			if err := os.WriteFile(out, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
				return fmt.Errorf("writing private key: %w", err)
			}
			pubHex := hex.EncodeToString(pub)
			fmt.Fprintf(os.Stdout, "Wrote private key to %s (keep it secret; do not commit)\n\n", out)
			fmt.Fprintf(os.Stdout, "key-id:         %s\n", keyID)
			fmt.Fprintf(os.Stdout, "public_key_hex: %s\n\n", pubHex)
			fmt.Fprintf(os.Stdout, "Register it (operator token required):\n")
			fmt.Fprintf(os.Stdout, "  curl -sf -X POST \"$SERVER/operator/v1/orgs/$ORG/agent-keys\" \\\n")
			fmt.Fprintf(os.Stdout, "    -H \"Authorization: Bearer $OPERATOR_TOKEN\" \\\n")
			fmt.Fprintf(os.Stdout, "    -d '{\"key_id\":%q,\"public_key_hex\":%q}'\n\n", keyID, pubHex)
			fmt.Fprintf(os.Stdout, "Then sign pushes with:  concord push ... --key %s --key-id %s\n", out, keyID)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "concord-agent.key", "Path to write the private key")
	cmd.Flags().StringVar(&keyID, "key-id", "", "Key id to register (default: derived from the public key)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing key file")
	return cmd
}

// signSubmission signs body with the ed25519 private key at keyPath and returns
// the hex signature for the X-Concord-Signature header.
func signSubmission(keyPath string, body []byte) (string, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("reading signing key: %w", err)
	}
	priv, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return "", fmt.Errorf("signing key is not valid hex: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("signing key must be a %d-byte ed25519 private key (got %d)", ed25519.PrivateKeySize, len(priv))
	}
	return hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(priv), body)), nil
}
