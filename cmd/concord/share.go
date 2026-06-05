package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type shareRoomDTO struct {
	ID             string     `json:"id"`
	AuditorEmail   string     `json:"auditor_email"`
	Framework      string     `json:"framework"`
	CreatedAt      time.Time  `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	LastAccessedAt *time.Time `json:"last_accessed_at,omitempty"`
	AccessCount    int64      `json:"access_count"`
	Token          string     `json:"token,omitempty"`
}

func newShareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Manage auditor share rooms (token-gated, scope-filtered read-only views)",
	}
	cmd.AddCommand(newShareCreateCmd())
	cmd.AddCommand(newShareListCmd())
	cmd.AddCommand(newShareRevokeCmd())
	return cmd
}

func newShareCreateCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		auditor, framework, until string
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Mint a new share room and print its one-time URL",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{
				"auditor_email": auditor,
				"framework":     framework,
			}
			if until != "" {
				t, err := parseUntil(until)
				if err != nil {
					return err
				}
				body["expires_at"] = t.Format(time.RFC3339)
			}
			var room shareRoomDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				fs.projectBase()+"/share-rooms", body, &room); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(room)
			}
			fmt.Fprintf(os.Stdout, "Share room created for %s (framework=%s)\n",
				room.AuditorEmail, room.Framework)
			fmt.Fprintf(os.Stdout, "URL: %s/v1/share/%s\n",
				strings.TrimRight(fs.url, "/"), room.Token)
			fmt.Fprintln(os.Stdout, "(This token is shown ONCE — copy it now.)")
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&auditor, "auditor", "", "Auditor email (required)")
	cmd.Flags().StringVar(&framework, "framework", "", "Framework to expose (required)")
	cmd.Flags().StringVar(&until, "until", "", "Optional expiry (RFC3339 or 30d / 8w / 6mo)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	_ = cmd.MarkFlagRequired("auditor")
	_ = cmd.MarkFlagRequired("framework")
	return cmd
}

func newShareListCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		includeRevoked            bool
		format                    string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List share rooms for the current org",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path :=  fs.projectBase() + "/share-rooms"
			if includeRevoked {
				path += "?include_revoked=true"
			}
			var rows []shareRoomDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			return printShareRooms(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().BoolVar(&includeRevoked, "include-revoked", false, "Also show revoked rooms")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newShareRevokeCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "revoke <room-id>",
		Short: "Revoke a share room by id",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiDelete(cmd.Context(), fs,
				fs.projectBase()+"/share-rooms/"+args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s revoked\n", args[0])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func printShareRooms(w io.Writer, rows []shareRoomDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no share rooms")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tAUDITOR\tFRAMEWORK\tCREATED\tEXPIRES\tLAST ACCESS\tACCESSES\tSTATUS")
	for _, r := range rows {
		status := "active"
		if r.RevokedAt != nil {
			status = "revoked"
		}
		expires := "—"
		if r.ExpiresAt != nil {
			expires = r.ExpiresAt.Format(time.RFC3339)
		}
		last := "—"
		if r.LastAccessedAt != nil {
			last = r.LastAccessedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			r.ID, r.AuditorEmail, r.Framework,
			r.CreatedAt.Format(time.RFC3339), expires, last,
			r.AccessCount, status)
	}
	return tw.Flush()
}
