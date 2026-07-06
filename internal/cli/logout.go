package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/cli/credentials"
)

func newLogoutCmd() *cobra.Command {
	var (
		profileName string
		keepFile    bool
	)
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke the stored session and remove credentials",
		Long: `logout calls /v1/auth/logout to revoke the current session on the server,
then removes (or empties, with --keep-file) the local credentials file.
Subsequent commands will need a fresh ` + "`concord login`" + ` before they can talk
to the server.

The server-side revoke is best-effort: an offline server (or already-
expired token) does NOT block the local cleanup. The user's intent is
"be logged out" and we honor that even when we can't reach the server.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			file, err := credentials.Load()
			if errors.Is(err, credentials.ErrNoCredentials) {
				fmt.Fprintln(cmd.OutOrStdout(), "already logged out — no credentials file")
				return nil
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

			err = callAPI(cmd.Context(), "POST", p.Server+"/v1/auth/logout", p.Token, nil, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: server revoke failed (continuing with local logout): %v\n", err)
			}

			if keepFile {
				delete(file.Profiles, target)
				if file.Current == target {
					file.Current = ""
				}
				if err := credentials.Save(file); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ logged out of profile %q (file kept)\n", target)
				return nil
			}
			if len(file.Profiles) <= 1 {
				if err := credentials.Delete(); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "✓ logged out and removed credentials file\n")
				return nil
			}
			delete(file.Profiles, target)
			if file.Current == target {
				file.Current = ""
			}
			if err := credentials.Save(file); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "✓ logged out of profile %q\n", target)
			return nil
		},
	}
	cmd.Flags().StringVar(&profileName, "profile", "",
		"Profile to log out (default: the current profile)")
	cmd.Flags().BoolVar(&keepFile, "keep-file", false,
		"Keep the credentials file in place instead of removing it on the last profile")
	return cmd
}
