package concord.soc2.cc3_1

import rego.v1

# SOC 2 CC3.1 — documented risk-assessment methodology.

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 365

nanos_per_day := 86400000000000

required_fields := ["process_owner", "methodology", "review_cadence", "last_reviewed_at"]
valid_methodologies := {"qualitative", "quantitative", "hybrid"}

deny contains msg if {
    not input.risk_process
    msg := "no risk-assessment-process evidence collected"
}

deny contains msg if {
    count(input.risk_process.docs) == 0
    msg := "no risk-assessment process documented at docs/policies/risk-assessment-process.md"
}

deny contains msg if {
    some doc in input.risk_process.docs
    some field in required_fields
    not has_value(doc, field)
    msg := sprintf("risk-assessment process %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
    some doc in input.risk_process.docs
    doc.methodology
    not doc.methodology in valid_methodologies
    msg := sprintf("risk-assessment process %q declares invalid methodology %q (must be qualitative|quantitative|hybrid)", [doc.path, doc.methodology])
}

deny contains msg if {
    some doc in input.risk_process.docs
    doc.last_reviewed_at
    reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("risk-assessment process %q has not been reviewed in over %d days", [doc.path, max_age_days])
}

# Recommend a defined risk-rating scale so register entries are comparable.
warn contains msg if {
    some doc in input.risk_process.docs
    not has_value(doc, "rating_scale")
    msg := sprintf("risk-assessment process %q has no rating_scale field (recommended for consistent severity scoring)", [doc.path])
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
