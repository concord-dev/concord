package concord.soc2.cc5_1

import rego.v1

# SOC 2 CC5.1 — control activities register: each implemented control
# documented with owner, status, and audit date.

min_entries := n if {
    n := input._concord.params.min_entries
} else := 5

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 365

nanos_per_day := 86400000000000

required_fields := ["control_id", "owner", "status", "last_audited_at"]
valid_statuses := {"implemented", "planned", "ad_hoc", "deprecated"}

deny contains msg if {
    not input.control_register
    msg := "no control-activities register evidence collected"
}

deny contains msg if {
    count(input.control_register.docs) < min_entries
    msg := sprintf("control-activities register has %d entries; minimum is %d", [count(input.control_register.docs), min_entries])
}

deny contains msg if {
    some doc in input.control_register.docs
    some field in required_fields
    not has_value(doc, field)
    msg := sprintf("control register entry %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
    some doc in input.control_register.docs
    doc.status
    not doc.status in valid_statuses
    msg := sprintf("control register entry %q has invalid status %q (must be implemented|planned|ad_hoc|deprecated)", [doc.path, doc.status])
}

deny contains msg if {
    some doc in input.control_register.docs
    doc.last_audited_at
    audited_ns := time.parse_rfc3339_ns(doc.last_audited_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    audited_ns < cutoff_ns
    msg := sprintf("control register entry %q was last audited over %d days ago", [doc.path, max_age_days])
}

# Warn when an entry is still "planned" — needs an implementation timeline.
warn contains msg if {
    some doc in input.control_register.docs
    doc.status == "planned"
    msg := sprintf("control register entry %q is still planned (not implemented) — confirm a target date", [doc.path])
}

# Warn when ad_hoc status is used — these should be formalized.
warn contains msg if {
    some doc in input.control_register.docs
    doc.status == "ad_hoc"
    msg := sprintf("control register entry %q is ad_hoc — consider formalizing for audit", [doc.path])
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
