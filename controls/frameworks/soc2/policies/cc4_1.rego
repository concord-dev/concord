package concord.soc2.cc4_1

import rego.v1

# SOC 2 CC4.1 — monitoring strategy is documented and current.

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 365

nanos_per_day := 86400000000000

required_fields := ["scope", "alert_owner", "review_cadence", "last_reviewed_at"]

deny contains msg if {
    not input.monitoring_strategy
    msg := "no monitoring-strategy evidence collected"
}

deny contains msg if {
    count(input.monitoring_strategy.docs) == 0
    msg := "no monitoring strategy doc found under docs/monitoring/"
}

deny contains msg if {
    some doc in input.monitoring_strategy.docs
    some field in required_fields
    not has_value(doc, field)
    msg := sprintf("monitoring strategy %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
    some doc in input.monitoring_strategy.docs
    doc.last_reviewed_at
    reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("monitoring strategy %q has not been reviewed in over %d days", [doc.path, max_age_days])
}

# Recommend an alert-quality metric so the strategy stays effective.
warn contains msg if {
    some doc in input.monitoring_strategy.docs
    not has_value(doc, "alert_quality_review")
    msg := sprintf("monitoring strategy %q has no alert_quality_review field — recommend tracking FP rate and MTTA", [doc.path])
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
