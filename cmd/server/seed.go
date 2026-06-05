package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/concord-dev/concord/internal/store"
)

func runSeedTenant(args []string) error {
	var (
		databaseURL   string
		email         string
		password      string
		passwordStdin bool
		firstName     string
		lastName      string
		orgName       string
		orgSlug       string
		tokenName     string
		skipMigrate   bool
	)
	fs := flag.NewFlagSet("seed-tenant", flag.ContinueOnError)
	fs.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"), "Postgres DSN (or set DATABASE_URL)")
	fs.StringVar(&email, "email", "", "Owner user email (required)")
	fs.StringVar(&password, "password", "", "Owner user password (or pass --password-stdin)")
	fs.BoolVar(&passwordStdin, "password-stdin", false, "Read password from stdin (one line, newline-terminated)")
	fs.StringVar(&firstName, "first-name", "Owner", "Owner user first name")
	fs.StringVar(&lastName, "last-name", "User", "Owner user last name")
	fs.StringVar(&orgName, "org-name", "", "Organization name (defaults to org slug)")
	fs.StringVar(&orgSlug, "org-slug", "", "Organization slug — URL-safe, lowercase (required)")
	fs.StringVar(&tokenName, "token-name", "bootstrap", "Display name for the minted API token")
	fs.BoolVar(&skipMigrate, "skip-migrate", false, "Skip running schema migrations before seeding")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: concord-server seed-tenant [flags]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Provisions a tenant: organization + owner user + API token.")
		fmt.Fprintln(fs.Output(), "Distinct from the SaaS-operator admin (CONCORD_OPERATOR_TOKEN).")
		fmt.Fprintln(fs.Output(), "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	if databaseURL == "" {
		return errors.New("DATABASE_URL is required (set the env var or pass --database-url)")
	}
	if email == "" || orgSlug == "" {
		return errors.New("--email and --org-slug are both required")
	}
	if orgName == "" {
		orgName = orgSlug
	}
	if passwordStdin {
		read, err := readPasswordFromStdin(os.Stdin)
		if err != nil {
			return fmt.Errorf("reading password from stdin: %w", err)
		}
		password = read
	}
	if password == "" {
		return errors.New("password is required (pass --password or --password-stdin)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.Open(ctx, databaseURL, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	if !skipMigrate {
		if err := st.Migrate(ctx); err != nil {
			return fmt.Errorf("migrating: %w", err)
		}
		fmt.Fprintln(os.Stdout, "✓ schema migrated")
	}

	org, err := st.CreateOrganization(ctx, orgName, orgSlug)
	if err != nil {
		return fmt.Errorf("creating organization %q: %w (slug may already exist — pick another)", orgSlug, err)
	}
	fmt.Fprintf(os.Stdout, "✓ organization created\n    id:   %s\n    slug: %s\n    name: %s\n", org.ID, org.Slug, org.Name)

	user, err := st.CreateUser(ctx, store.CreateUserParams{
		FirstName: firstName, LastName: lastName, Email: email, Password: password,
	})
	if err != nil {
		return fmt.Errorf("creating user %q: %w (email may already exist)", email, err)
	}
	fmt.Fprintf(os.Stdout, "✓ user created\n    id:    %s\n    email: %s\n", user.ID, user.Email)

	role, err := st.GetRoleByName(ctx, "owner")
	if err != nil {
		return fmt.Errorf("looking up owner role: %w (did migrations seed the role table?)", err)
	}
	if err := st.AssignRole(ctx, user.ID, org.ID, role.ID); err != nil {
		return fmt.Errorf("assigning owner role: %w", err)
	}
	fmt.Fprintln(os.Stdout, "✓ owner role assigned")

	tok, plain, err := st.CreateAPIToken(ctx, org.ID, tokenName, &user.ID)
	if err != nil {
		return fmt.Errorf("minting API token: %w", err)
	}
	fmt.Fprintf(os.Stdout, "✓ API token minted\n    id:    %s\n    name:  %s\n    token: %s\n",
		tok.ID, tok.Name, plain)
	fmt.Fprintln(os.Stdout, "    (save this token now — it cannot be retrieved later)")
	fmt.Fprintln(os.Stdout, "")
	fmt.Fprintln(os.Stdout, "Next steps:")
	fmt.Fprintf(os.Stdout, "  curl -H 'Authorization: Bearer %s' http://localhost:8080/v1/orgs/%s/me\n", plain, org.Slug)
	fmt.Fprintf(os.Stdout, "  curl -X POST http://localhost:8080/v1/auth/login \\\n")
	fmt.Fprintf(os.Stdout, "       -H 'Content-Type: application/json' \\\n")
	fmt.Fprintf(os.Stdout, "       -d '{\"email\":%q,\"password\":\"<your password>\"}'\n", email)
	return nil
}

func readPasswordFromStdin(r io.Reader) (string, error) {
	br := bufio.NewReader(r)
	line, err := br.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
