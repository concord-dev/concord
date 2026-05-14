package concord.eu_ai_act.article_11

import rego.v1

# EU AI Act Article 11 — technical documentation for high-risk AI systems.
# Inputs:
#   input.model_registry.models[]   — production AI inventory
#   input.technical_docs.docs[]     — parsed *.md files with frontmatter

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 180

nanos_per_day := 86400000000000

required_frontmatter := ["model", "version", "reviewer", "reviewed_at"]

deny contains msg if {
    not input.model_registry
    msg := "no model registry evidence collected"
}

deny contains msg if {
    not input.technical_docs
    msg := "no technical-documentation evidence collected"
}

# Every high-risk production model must have at least one tech-doc file.
deny contains msg if {
    some model in input.model_registry.models
    is_high_risk_prod(model)
    not has_doc(model.name)
    msg := sprintf("high-risk model %q has no technical documentation under docs/ai/technical-documentation/", [model.name])
}

# Every present doc must declare the required frontmatter fields.
deny contains msg if {
    some doc in input.technical_docs.docs
    some field in required_frontmatter
    not has_value(doc, field)
    msg := sprintf("technical doc %q is missing required frontmatter field %q", [doc.path, field])
}

# Docs must be fresh.
deny contains msg if {
    some doc in input.technical_docs.docs
    doc.reviewed_at
    reviewed_ns := time.parse_rfc3339_ns(doc.reviewed_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("technical doc %q has not been reviewed in over %d days", [doc.path, max_age_days])
}

# Non-mandatory but recommended: tier=high models should also document
# accuracy + cybersecurity sections per Annex IV §3 and §5.
warn contains msg if {
    some doc in input.technical_docs.docs
    not has_value(doc, "accuracy_metrics")
    msg := sprintf("technical doc %q has no accuracy_metrics field (recommended by Annex IV §3)", [doc.path])
}

is_high_risk_prod(model) if {
    model.production == true
    model.eu_ai_act_tier == "high"
}

has_doc(name) if {
    some doc in input.technical_docs.docs
    doc.model == name
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
