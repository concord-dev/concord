package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

type customFieldDefDTO struct {
	ID         string   `json:"id"`
	EntityType string   `json:"entity_type"`
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	FieldType  string   `json:"field_type"`
	Required   bool     `json:"required"`
	Options    []string `json:"options,omitempty"`
}

func customFieldBase(fs findingsServer) string { return "/v1/orgs/" + fs.orgSlug + "/custom-fields" }
func customFieldValuesBase(fs findingsServer, entityType, entityID string) string {
	return "/v1/orgs/" + fs.orgSlug + "/custom-field-values/" + url.PathEscape(entityType) + "/" + url.PathEscape(entityID)
}

func newCustomFieldCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "custom-field",
		Aliases: []string{"cf"},
		Short:   "Define custom fields and set their values on entities",
	}
	cmd.AddCommand(newCustomFieldDefineCmd())
	cmd.AddCommand(newCustomFieldListCmd())
	cmd.AddCommand(newCustomFieldDeleteCmd())
	cmd.AddCommand(newCustomFieldValuesCmd())
	cmd.AddCommand(newCustomFieldSetCmd())
	return cmd
}

func newCustomFieldDefineCmd() *cobra.Command {
	var serverURL, orgSlug, token, entity, key, label, ftype string
	var options []string
	var required bool
	cmd := &cobra.Command{
		Use:   "define",
		Short: "Define a custom field (types: text|number|date|boolean|select)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{"entity_type": entity, "key": key, "label": label, "field_type": ftype, "required": required}
			if len(options) > 0 {
				payload["options"] = options
			}
			var d customFieldDefDTO
			if err := apiSend(cmd.Context(), fs, "POST", customFieldBase(fs), payload, &d); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s.%s (%s)\n", d.ID, d.EntityType, d.Key, d.FieldType)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&entity, "entity", "", "Entity type, e.g. risk, vendor, finding (required)")
	cmd.Flags().StringVar(&key, "key", "", "Field key (required)")
	cmd.Flags().StringVar(&label, "label", "", "Human label (required)")
	cmd.Flags().StringVar(&ftype, "type", "text", "Field type: text|number|date|boolean|select")
	cmd.Flags().StringArrayVar(&options, "option", nil, "Allowed option for a select field (repeatable)")
	cmd.Flags().BoolVar(&required, "required", false, "Mark the field required")
	_ = cmd.MarkFlagRequired("entity")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("label")
	return cmd
}

func newCustomFieldListCmd() *cobra.Command {
	var serverURL, orgSlug, token, entity, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List custom field definitions",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path := customFieldBase(fs)
			if entity != "" {
				path += "?entity_type=" + url.QueryEscape(entity)
			}
			var rows []customFieldDefDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no custom fields")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tENTITY\tKEY\tTYPE\tLABEL")
			for _, d := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.ID, d.EntityType, d.Key, d.FieldType, d.Label)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&entity, "entity", "", "Filter by entity type")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newCustomFieldDeleteCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a custom field definition (and its values)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiSend(cmd.Context(), fs, "DELETE", customFieldBase(fs)+"/"+args[0], nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "deleted %s\n", args[0])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newCustomFieldValuesCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "values <entity-type> <entity-id>",
		Short: "Show an entity's custom field values",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var out map[string]any
			if err := apiGet(cmd.Context(), fs, customFieldValuesBase(fs, args[0], args[1]), &out); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(out["values"])
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newCustomFieldSetCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	var sets []string
	cmd := &cobra.Command{
		Use:   "set <entity-type> <entity-id>",
		Short: "Set custom field values (--set key=value; value parsed as JSON, else string)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			values := map[string]any{}
			for _, kv := range sets {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("--set must be key=value, got %q", kv)
				}
				var parsed any
				if json.Unmarshal([]byte(v), &parsed) == nil {
					values[k] = parsed // typed (number/bool/null) when valid JSON
				} else {
					values[k] = v // otherwise a bare string
				}
			}
			var out map[string]any
			if err := apiSend(cmd.Context(), fs, "PUT", customFieldValuesBase(fs, args[0], args[1]),
				map[string]any{"values": values}, &out); err != nil {
				return err
			}
			return json.NewEncoder(os.Stdout).Encode(out["values"])
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringArrayVar(&sets, "set", nil, "key=value (repeatable); value parsed as JSON when valid, else a string")
	return cmd
}
