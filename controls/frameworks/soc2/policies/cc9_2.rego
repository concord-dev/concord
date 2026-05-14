package concord.soc2.cc9_2

import rego.v1

# SOC 2 CC9.2 — risk register is current and well-formed.

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 90

nanos_per_day := 86400000000000

required_fields := ["title", "severity", "owner", "mitigation_status", "reviewed_at"]
valid_statuses := {"open", "mitigated", "accepted", "transferred"}
valid_severities := {"critical", "high", "medium", "low"}

deny contains msg if {
    not input.risk_register
    msg := "no risk register evidence collected"
}

deny contains msg if {
    count(input.risk_register.docs) == 0
    msg := "risk register is empty — at least one identified risk required for SOC 2 CC9.2 evidence"
}

deny contains msg if {
    some doc in input.risk_register.docs
    some field in required_fields
    not has_value(doc, field)
    msg := sprintf("risk register entry %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
    some doc in input.risk_register.docs
    doc.mitigation_status
    not doc.mitigation_status in valid_statuses
    msg := sprintf("risk register entry %q has invalid mitigation_status %q (must be open|mitigated|accepted|transferred)", [doc.path, doc.mitigation_status])
}

deny contains msg if {
    some doc in input.risk_register.docs
    doc.severity
    not doc.severity in valid_severities
    msg := sprintf("risk register entry %q has invalid severity %q", [doc.path, doc.severity])
}

deny contains msg if {
    some doc in input.risk_register.docs
    doc.reviewed_at
    reviewed_ns := time.parse_rfc3339_ns(doc.reviewed_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("risk register entry %q has not been reviewed in over %d days", [doc.path, max_age_days])
}

# Warn when critical/high risks are still 'open' after declared review.
warn contains msg if {
    some doc in input.risk_register.docs
    doc.severity in {"critical", "high"}
    doc.mitigation_status == "open"
    msg := sprintf("risk register entry %q is %s severity and still open — schedule treatment", [doc.path, doc.severity])
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
