package concord.soc2.cc7_1_containers

import rego.v1

# SOC 2 CC7.1 (container variant) — open CRITICAL/HIGH issues in Snyk-scanned
# container images are within threshold.
# Input: input.container_issues is the container_issues evidence
# (projects + issues, with each issue tagged with project metadata).

default max_critical := 0

max_critical := n if {
    n := input._concord.params.max_critical
}

default max_high := 0

max_high := n if {
    n := input._concord.params.max_high
}

deny contains msg if {
    not input.container_issues
    msg := "no Snyk container_issues evidence collected"
}

deny contains msg if {
    input.container_issues.summary.critical > max_critical
    msg := sprintf("%d CRITICAL container issue(s) open (threshold: %d) — see warnings for affected images", [input.container_issues.summary.critical, max_critical])
}

deny contains msg if {
    input.container_issues.summary.high > max_high
    msg := sprintf("%d HIGH container issue(s) open (threshold: %d)", [input.container_issues.summary.high, max_high])
}

# Per-image, per-issue warnings — surface the image identity so the
# on-call engineer knows what to rebuild.
warn contains msg if {
    some i in input.container_issues.issues
    i.severity in {"critical", "high"}
    i.fixable == true
    msg := sprintf("[%s] %s in image %q (%s) — rebuild with patched base", [upper(i.severity), i.key, i.project_name, i.package_name])
}

warn contains msg if {
    some i in input.container_issues.issues
    i.severity in {"critical", "high"}
    i.fixable == false
    msg := sprintf("[%s] %s in image %q has no fix yet — pin a workaround or accept the risk", [upper(i.severity), i.key, i.project_name])
}
