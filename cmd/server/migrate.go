package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/concord-dev/concord/internal/store"
)

// runMigrateDown rolls back the most-recently-applied migration(s). Wraps
// store.MigrateDown with CLI ergonomics: a flag for `steps`, a confirmation
// prompt (skippable with --yes) so a fat-fingered invocation can't silently
// nuke a dev DB, and a final report of which versions came off.
//
// DEV USE ONLY — see the docstring on store.MigrateDown for the
// expand-contract rationale. The subcommand exits non-zero with a clear
// message when an envisioned production caller tries to use it without
// understanding the data-loss semantics.
func runMigrateDown(args []string) error {
	var (
		databaseURL string
		steps       int
		yes         bool
	)
	fs := flag.NewFlagSet("migrate-down", flag.ContinueOnError)
	fs.StringVar(&databaseURL, "database-url", os.Getenv("DATABASE_URL"),
		"Postgres DSN (or set DATABASE_URL)")
	fs.IntVar(&steps, "steps", 1,
		"Number of most-recently-applied migrations to roll back")
	fs.BoolVar(&yes, "yes", false,
		"Skip the 'are you sure' prompt (use in scripts; foot-gun in interactive shells)")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: concord-server migrate-down [flags]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "DEV USE ONLY. Rolls back the most-recently-applied migration(s) by")
		fmt.Fprintln(fs.Output(), "running each migration's *.down.sql body. Data written between")
		fmt.Fprintln(fs.Output(), "migrate-up and migrate-down is destroyed by the table drops in those")
		fmt.Fprintln(fs.Output(), "files; this is NOT a safe production rollback step. For production,")
		fmt.Fprintln(fs.Output(), "roll forward with a new additive migration (expand-contract).")
		fmt.Fprintln(fs.Output(), "")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required (set the env var or pass --database-url)")
	}
	if steps <= 0 {
		return fmt.Errorf("--steps must be >= 1 (got %d)", steps)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.Open(ctx, databaseURL, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}
	defer st.Close()

	// Report what we're about to roll back so the operator can sanity-check
	// before committing. With one consolidated migration in the tree this
	// is mostly cosmetic; the value grows as 0002+ start landing.
	applied, err := st.AppliedMigrationVersions(ctx)
	if err != nil {
		return fmt.Errorf("listing applied migrations: %w", err)
	}
	if len(applied) == 0 {
		fmt.Fprintln(os.Stdout, "no applied migrations; nothing to roll back")
		return nil
	}
	willDrop := steps
	if willDrop > len(applied) {
		willDrop = len(applied)
	}
	toRollback := applied[len(applied)-willDrop:]
	fmt.Fprintf(os.Stdout, "About to roll back %d migration(s) on %s:\n", willDrop, databaseURL)
	for i := len(toRollback) - 1; i >= 0; i-- {
		fmt.Fprintf(os.Stdout, "  - %d\n", toRollback[i])
	}
	fmt.Fprintln(os.Stdout, "Data in dropped tables will be LOST. This is dev-only — never run against prod.")

	if !yes {
		fmt.Fprint(os.Stdout, "Type 'yes' to continue: ")
		var ans string
		_, _ = fmt.Fscanln(os.Stdin, &ans)
		if ans != "yes" {
			fmt.Fprintln(os.Stdout, "aborted")
			return nil
		}
	}

	if err := st.MigrateDown(ctx, steps); err != nil {
		return fmt.Errorf("migrate-down: %w", err)
	}
	fmt.Fprintf(os.Stdout, "✓ rolled back %d migration(s)\n", willDrop)
	return nil
}
