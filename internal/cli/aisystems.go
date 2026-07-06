package cli

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

// aiSystemInventory is the declarative ai-systems.yaml schema — a
// version-controlled inventory of AI systems that is applied to the platform's
// asset registry (type ai_model). It is independent of any live model
// registry, so it can declare systems MLflow doesn't know about and assign each
// an explicit EU AI Act risk classification that drives obligation scoping.
type aiSystemInventory struct {
	APIVersion string       `json:"apiVersion"`
	Kind       string       `json:"kind"`
	Spec       aiSystemSpec `json:"spec"`
}

type aiSystemSpec struct {
	Systems []aiSystem `json:"systems"`
}

type aiSystem struct {
	// ID is the stable inventory key (used as the asset external_id, and the
	// natural join key to a model of the same name in the registry).
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	RiskClass   string   `json:"risk_class"`
	Environment string   `json:"environment,omitempty"`
	Owner       string   `json:"owner,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// riskClasses are the EU AI Act risk classifications (Title II/III), highest to
// lowest. prohibited and high-risk are the ones that carry obligations.
var riskClasses = map[string]bool{
	"prohibited": true,
	"high-risk":  true,
	"limited":    true,
	"minimal":    true,
}

// tierForRiskClass maps a risk classification onto the eu_ai_act_tier tag value
// the control packs already scope on (e.g. Article controls fire only for
// tier "high"), so the declarative inventory and the model-registry evidence
// share one vocabulary.
func tierForRiskClass(rc string) string {
	switch rc {
	case "high-risk":
		return "high"
	default:
		return rc
	}
}

// criticalityForRiskClass maps a risk classification onto the asset criticality
// scale (1 = highest). prohibited/high-risk are top severity.
func criticalityForRiskClass(rc string) string {
	switch rc {
	case "prohibited", "high-risk":
		return "1"
	case "limited":
		return "2"
	default:
		return "3"
	}
}

func parseAISystems(raw []byte) (*aiSystemInventory, error) {
	var inv aiSystemInventory
	if err := yaml.Unmarshal(raw, &inv); err != nil {
		return nil, fmt.Errorf("parsing ai-systems inventory: %w", err)
	}
	if inv.Kind != "AISystemInventory" {
		return nil, fmt.Errorf("expected kind AISystemInventory, got %q", inv.Kind)
	}
	if len(inv.Spec.Systems) == 0 {
		return nil, fmt.Errorf("inventory declares no systems")
	}
	seen := map[string]bool{}
	for i, s := range inv.Spec.Systems {
		switch {
		case s.ID == "":
			return nil, fmt.Errorf("system[%d]: id is required", i)
		case s.Name == "":
			return nil, fmt.Errorf("system %q: name is required", s.ID)
		case !riskClasses[s.RiskClass]:
			return nil, fmt.Errorf("system %q: risk_class must be one of prohibited|high-risk|limited|minimal, got %q", s.ID, s.RiskClass)
		case seen[s.ID]:
			return nil, fmt.Errorf("duplicate system id %q", s.ID)
		}
		seen[s.ID] = true
	}
	return &inv, nil
}

// aiSystemsToAssetCSV renders the inventory into the asset-import CSV the
// platform already ingests (idempotent upsert by source+external_id). Each
// system becomes an ai_system asset tagged with its eu_ai_act_tier so the same
// risk vocabulary spans the inventory and the model-registry evidence.
func aiSystemsToAssetCSV(inv *aiSystemInventory) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	if err := w.Write([]string{"type", "name", "external_id", "source", "criticality", "environment", "tags"}); err != nil {
		return nil, err
	}
	for _, s := range inv.Spec.Systems {
		tags := []string{"ai-system", "eu_ai_act_tier:" + tierForRiskClass(s.RiskClass)}
		if s.Owner != "" {
			tags = append(tags, "owner:"+s.Owner)
		}
		tags = append(tags, s.Tags...)
		sort.Strings(tags)
		row := []string{
			"ai_model", s.Name, s.ID, "ai-systems",
			criticalityForRiskClass(s.RiskClass), s.Environment, joinTags(tags),
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// joinTags joins asset tags with the ';' separator the CSV import expects.
func joinTags(tags []string) string {
	out := ""
	for i, t := range tags {
		if i > 0 {
			out += ";"
		}
		out += t
	}
	return out
}

func newAssetApplyAISystemsCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "apply-ai-systems <file.yaml>",
		Short: "Apply a declarative ai-systems.yaml inventory as ai_model assets (idempotent upsert)",
		Long: `Apply a declarative AI-system inventory.

Reads an ai-systems.yaml (kind: AISystemInventory) and upserts each system into
the asset registry as an ai_model asset, tagged with its EU AI Act risk class
(eu_ai_act_tier). Idempotent: re-applying updates in place, keyed by system id.
This is the version-controlled AI-system inventory of the AI-governance
posture-as-code loop (assessment/33).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			inv, err := parseAISystems(raw)
			if err != nil {
				return err
			}
			csvBody, err := aiSystemsToAssetCSV(inv)
			if err != nil {
				return err
			}
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			out, err := apiUploadCSVBytes(cmd.Context(), fs, assetBase(fs)+"/import", csvBody)
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
			fmt.Fprintf(os.Stdout, "%d AI system(s): created %d · updated %d · unchanged %d\n",
				len(inv.Spec.Systems), res.Created, res.Updated, res.Unchanged)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}
