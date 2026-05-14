package concord.soc2.cc7_2

import rego.v1

# SOC 2 CC7.2 — incident response runbook present, current, names on-call owner.

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 365

nanos_per_day := 86400000000000

required_fields := ["title", "severity_levels", "escalation_path", "on_call_owner", "reviewed_at"]

deny contains msg if {
    not input.ir_runbooks
    msg := "no incident-response runbook evidence collected"
}

deny contains msg if {
    count(input.ir_runbooks.docs) == 0
    msg := "no incident-response runbook found under docs/incident-response/"
}

deny contains msg if {
    some doc in input.ir_runbooks.docs
    some field in required_fields
    not has_value(doc, field)
    msg := sprintf("IR runbook %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
    some doc in input.ir_runbooks.docs
    doc.reviewed_at
    reviewed_ns := time.parse_rfc3339_ns(doc.reviewed_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("IR runbook %q has not been reviewed in over %d days", [doc.path, max_age_days])
}

warn contains msg if {
    some doc in input.ir_runbooks.docs
    not has_value(doc, "communication_plan")
    msg := sprintf("IR runbook %q has no communication_plan section (recommended for customer notification)", [doc.path])
}

warn contains msg if {
    some doc in input.ir_runbooks.docs
    not has_value(doc, "post_mortem_template")
    msg := sprintf("IR runbook %q has no post_mortem_template reference (recommended)", [doc.path])
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
