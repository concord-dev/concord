package concord.soc2.cc7_1_snyk

import rego.v1

# SOC 2 CC7.1 (Snyk variant) — open CRITICAL/HIGH vulnerabilities tracked
# by Snyk are within the declared threshold.
# Input: input.snyk_issues is the org_issues evidence (summary + issues).

default max_critical := 0

max_critical := n if {
    n := input._concord.params.max_critical
}

default max_high := 0

max_high := n if {
    n := input._concord.params.max_high
}

deny contains msg if {
    not input.snyk_issues
    msg := "no Snyk org_issues evidence collected"
}

deny contains msg if {
    input.snyk_issues.summary.critical > max_critical
    msg := sprintf("%d CRITICAL Snyk issue(s) open (threshold: %d) — see warnings for fix paths", [input.snyk_issues.summary.critical, max_critical])
}

deny contains msg if {
    input.snyk_issues.summary.high > max_high
    msg := sprintf("%d HIGH Snyk issue(s) open (threshold: %d)", [input.snyk_issues.summary.high, max_high])
}

# Warn per-issue when Snyk has identified a fix path — these are
# immediately actionable.
warn contains msg if {
    some i in input.snyk_issues.issues
    i.severity in {"critical", "high"}
    i.fixable == true
    msg := sprintf("[%s] %s in %s@%s — fix available via Snyk", [upper(i.severity), i.key, i.package_name, i.package_version])
}

# Warn separately when no fix path exists yet — these need a documented
# exception or workaround.
warn contains msg if {
    some i in input.snyk_issues.issues
    i.severity in {"critical", "high"}
    i.fixable == false
    msg := sprintf("[%s] %s in %s has no fix yet — document exception or apply workaround", [upper(i.severity), i.key, i.package_name])
}
