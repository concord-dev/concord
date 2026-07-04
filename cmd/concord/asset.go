package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func assetBase(fs findingsServer) string { return "/v1/orgs/" + fs.orgSlug + "/assets" }

func newAssetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "asset",
		Short: "Bulk-import and export the asset inventory",
	}
	cmd.AddCommand(newAssetImportCmd())
	cmd.AddCommand(newAssetExportCmd())
	return cmd
}

func newAssetImportCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "import <file.csv>",
		Short: "Bulk-import assets from CSV (type,name,external_id,...); rows upsert by (source, external_id)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			out, err := apiUploadCSV(cmd.Context(), fs, assetBase(fs)+"/import", args[0])
			if err != nil {
				return err
			}
			var res struct {
				Created   int `json:"created"`
				Updated   int `json:"updated"`
				Unchanged int `json:"unchanged"`
			}
			if err := json.Unmarshal(out, &res); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "created %d · updated %d · unchanged %d\n", res.Created, res.Updated, res.Unchanged)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newAssetExportCmd() *cobra.Command {
	var serverURL, orgSlug, token, out string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the asset inventory as CSV",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			data, err := apiDownload(cmd.Context(), fs, assetBase(fs)+"/export")
			if err != nil {
				return err
			}
			return writeOutOrStdout(out, data)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&out, "out", "", "Write to file instead of stdout")
	return cmd
}
