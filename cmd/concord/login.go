package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/concord-dev/concord/internal/cli/credentials"
)

type loginResult struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`

	SessionID string    `json:"session_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

func newLoginCmd() *cobra.Command {
	var (
		server        string
		profileName   string
		email         string
		passwordStdin bool
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate against a Concord server and store a session",
		Long: `login exchanges email + password (and, when enrolled, an MFA code) for a
session token, which is saved to ~/.config/concord/credentials.json with
mode 0600. Subsequent commands (push, check --to, watch --to, whoami,
orgs use, ...) read this file automatically so you don't have to juggle
API tokens in shell scripts or CI environment variables.

Use --profile to keep multiple deployments side by side (prod, staging,
local dev). The most recently used profile is the default.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if server == "" {
				return errors.New("--server is required (or set CONCORD_SERVER)")
			}
			server = strings.TrimRight(server, "/")
			if profileName == "" {
				profileName = credentials.DefaultProfileName
			}

			if email == "" {
				v, err := promptLine(cmd.OutOrStdout(), cmd.InOrStdin(), "Email: ")
				if err != nil {
					return err
				}
				email = strings.TrimSpace(v)
			}
			password, err := readPassword(cmd.OutOrStdout(), cmd.InOrStdin(), passwordStdin)
			if err != nil {
				return err
			}
			if email == "" || password == "" {
				return errors.New("email and password are required")
			}

			ctx := cmd.Context()
			var first loginResult
			err = callAPI(ctx, "POST", server+"/v1/auth/login", "",
				map[string]string{"email": email, "password": password},
				&first)
			if err != nil {
				if isStatus(err, 401) {
					return errors.New("invalid credentials")
				}
				if isStatus(err, 429) {
					return errors.New("rate-limited by the server — wait a minute and try again")
				}
				return err
			}

			finalSession := first
			if first.MFARequired {
				code, err := promptLine(cmd.OutOrStdout(), cmd.InOrStdin(),
					"MFA code (TOTP or recovery — prefix recovery with `r:`): ")
				if err != nil {
					return err
				}
				code = strings.TrimSpace(code)
				if code == "" {
					return errors.New("MFA code is required")
				}
				payload := map[string]string{"mfa_token": first.MFAToken}
				if strings.HasPrefix(code, "r:") {
					payload["recovery_code"] = strings.TrimPrefix(code, "r:")
				} else {
					payload["code"] = code
				}
				var second loginResult
				if err := callAPI(ctx, "POST", server+"/v1/auth/login/mfa", "", payload, &second); err != nil {
					if isStatus(err, 401) {
						return errors.New("MFA code did not validate")
					}
					if isStatus(err, 410) {
						return errors.New("MFA challenge expired — re-run `concord login`")
					}
					return err
				}
				finalSession = second
			}

			if finalSession.Token == "" {
				return errors.New("server did not return a session token — refusing to write credentials")
			}

			file, err := credentials.LoadOrInit()
			if err != nil {
				return err
			}
			file.SetCurrent(profileName)
			p := file.Profiles[profileName]
			p.Server = server
			p.Token = finalSession.Token
			p.UserID = finalSession.User.ID
			p.UserEmail = finalSession.User.Email
			p.ExpiresAt = finalSession.ExpiresAt

			if err := credentials.Save(file); err != nil {
				return fmt.Errorf("saving credentials: %w", err)
			}
			path, _ := credentials.Path()
			fmt.Fprintf(cmd.OutOrStdout(),
				"✓ logged in as %s (profile %q)\n  server:      %s\n  credentials: %s\n",
				p.UserEmail, profileName, p.Server, path)
			if p.DefaultOrg == "" {
				fmt.Fprintln(cmd.OutOrStdout(),
					"  next:        `concord orgs list` to see what's available, then `concord orgs use <slug>`")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "  default org: %s\n", p.DefaultOrg)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", os.Getenv("CONCORD_SERVER"),
		"Concord server base URL (or CONCORD_SERVER)")
	cmd.Flags().StringVar(&profileName, "profile", os.Getenv("CONCORD_PROFILE"),
		"Profile name to write under (default: \"default\")")
	cmd.Flags().StringVar(&email, "email", "", "Email (prompted if omitted)")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false,
		"Read password from stdin (one line). Required when running non-interactively.")
	return cmd
}

func promptLine(w io.Writer, r io.Reader, prompt string) (string, error) {
	fmt.Fprint(w, prompt)
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readPassword(w io.Writer, in io.Reader, passwordStdin bool) (string, error) {
	if passwordStdin {
		br := bufio.NewReader(in)
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("stdin is not a terminal; pass --password-stdin to read the password from a pipe")
	}
	fmt.Fprint(w, "Password: ")
	buf, err := term.ReadPassword(fd)
	fmt.Fprintln(w)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(buf), nil
}
