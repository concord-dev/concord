package concord.iso42001.model_evaluation

import rego.v1

# ISO 42001 §7.4 — every production AI model has a fresh evaluation record.

# Configurable: maximum age of an evaluation report in days.
# Override per-repo via concord.yaml: controls.params.ISO42001-7.4.max_age_days
max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 90

nanos_per_day := 86400000000000

deny contains msg if {
    not input.model_registry
    msg := "no model registry evidence collected"
}

deny contains msg if {
    some model in input.model_registry.models
    model.production == true
    not has_eval_report(model)
    msg := sprintf("production model %q has no evaluation_report tag", [model.name])
}

deny contains msg if {
    some model in input.model_registry.models
    model.production == true
    not has_eval_timestamp(model)
    msg := sprintf("production model %q has no last_evaluated_at tag", [model.name])
}

deny contains msg if {
    some model in input.model_registry.models
    model.production == true
    has_eval_timestamp(model)
    reviewed_ns := time.parse_rfc3339_ns(model.last_evaluated_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("production model %q was last evaluated over %d days ago", [model.name, max_age_days])
}

# High-tier models should also have an explicit owner tag for accountability.
warn contains msg if {
    some model in input.model_registry.models
    model.production == true
    model.eu_ai_act_tier == "high"
    not model.owner
    msg := sprintf("high-risk model %q has no owner tag", [model.name])
}

has_eval_report(model) if {
    model.evaluation_report
    model.evaluation_report != ""
}

has_eval_timestamp(model) if {
    model.last_evaluated_at
    model.last_evaluated_at != ""
}
