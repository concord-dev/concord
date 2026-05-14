package concord.iso42001.risk_assessment

import rego.v1

# ISO 42001 §6.1 — Risk Assessment.
# Inputs:
#   input.model_registry.models[]      — production AI inventory from MLflow/W&B/HF
#   input.risk_assessments.docs[]      — parsed risk-assessment documents

# Configurable: maximum age of a risk assessment in days.
# Override per-repo via concord.yaml: controls.params.ISO42001-6.1.max_age_days
max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 365

valid_tiers := {"minimal", "limited", "high", "prohibited"}
required_doc_fields := ["intended_use", "foreseeable_misuse", "affected_populations", "residual_risk"]
nanos_per_day := 86400000000000

# === Evidence presence ===

deny contains msg if {
    not input.model_registry
    msg := "no model registry evidence collected (expected MLflow / W&B / HF inventory)"
}

deny contains msg if {
    not input.risk_assessments
    msg := "no risk-assessment document evidence collected"
}

# === Per-model rules ===

deny contains msg if {
    some model in input.model_registry.models
    model.production == true
    not has_risk_doc(model.name)
    msg := sprintf("production model %q has no risk-assessment document", [model.name])
}

deny contains msg if {
    some model in input.model_registry.models
    model.production == true
    not has_tier(model)
    msg := sprintf("production model %q has no EU AI Act risk tier", [model.name])
}

deny contains msg if {
    some model in input.model_registry.models
    has_tier(model)
    not model.eu_ai_act_tier in valid_tiers
    msg := sprintf("model %q has invalid EU AI Act tier %q (must be one of minimal|limited|high|prohibited)", [model.name, model.eu_ai_act_tier])
}

deny contains msg if {
    some model in input.model_registry.models
    model.production == true
    model.eu_ai_act_tier == "prohibited"
    msg := sprintf("model %q is classified prohibited under EU AI Act but is running in production", [model.name])
}

# === Per-document rules ===

deny contains msg if {
    some doc in input.risk_assessments.docs
    not has_reviewer(doc)
    msg := sprintf("risk doc %q has no human reviewer", [doc.path])
}

deny contains msg if {
    some doc in input.risk_assessments.docs
    some field in required_doc_fields
    not has_field(doc, field)
    msg := sprintf("risk doc %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
    some doc in input.risk_assessments.docs
    doc.reviewed_at
    reviewed_ns := time.parse_rfc3339_ns(doc.reviewed_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("risk doc %q has not been reviewed in over %d days", [doc.path, max_age_days])
}

# === Warnings ===

warn contains msg if {
    some model in input.model_registry.models
    model.eu_ai_act_tier == "high"
    not model.evaluation_report
    msg := sprintf("high-risk model %q has no linked evaluation report", [model.name])
}

warn contains msg if {
    some doc in input.risk_assessments.docs
    doc.eu_ai_act_tier == "high"
    not doc.secondary_reviewer
    msg := sprintf("high-risk risk doc %q has only one reviewer (two recommended)", [doc.path])
}

# === Helpers ===

has_risk_doc(name) if {
    some doc in input.risk_assessments.docs
    doc.model == name
}

has_tier(model) if {
    model.eu_ai_act_tier
    model.eu_ai_act_tier != ""
}

has_reviewer(doc) if {
    doc.reviewer
    doc.reviewer != ""
}

has_field(doc, name) if {
    val := doc[name]
    val != ""
}
