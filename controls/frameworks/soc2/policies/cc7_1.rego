package concord.soc2.cc7_1

import rego.v1

# SOC 2 CC7.1 — vulnerability management via Trivy.
# Input: input.trivy_report is the raw Trivy JSON output (Schema 2),
# with PascalCase keys (Results, Vulnerabilities, Severity, etc.).

# Configurable thresholds.
max_critical := n if {
    n := input._concord.params.max_critical
} else := 0

max_high := n if {
    n := input._concord.params.max_high
} else := 0

deny contains msg if {
    not input.trivy_report
    msg := "no Trivy scan evidence collected"
}

deny contains msg if {
    not input.trivy_report.Results
    msg := "Trivy report has no Results array — scan likely failed or produced empty output"
}

deny contains msg if {
    count(critical_vulns) > max_critical
    msg := sprintf("%d CRITICAL vulnerabilities present (threshold: %d) — see warnings for fix paths", [count(critical_vulns), max_critical])
}

deny contains msg if {
    count(high_vulns) > max_high
    msg := sprintf("%d HIGH vulnerabilities present (threshold: %d)", [count(high_vulns), max_high])
}

# Warn per-vuln when a fix is available — these are immediately actionable.
warn contains msg if {
    some result in input.trivy_report.Results
    some v in result.Vulnerabilities
    v.Severity in {"CRITICAL", "HIGH"}
    v.FixedVersion != ""
    msg := sprintf("[%s] %s in %s@%s — upgrade to %s", [v.Severity, v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.FixedVersion])
}

# Warn when ANY HIGH or CRITICAL vuln has no fix yet — these need a
# documented exception or workaround.
warn contains msg if {
    some result in input.trivy_report.Results
    some v in result.Vulnerabilities
    v.Severity in {"CRITICAL", "HIGH"}
    v.FixedVersion == ""
    msg := sprintf("[%s] %s in %s has no fix available yet — document exception or apply workaround", [v.Severity, v.VulnerabilityID, v.PkgName])
}

critical_vulns := [v |
    some result in input.trivy_report.Results
    some v in result.Vulnerabilities
    v.Severity == "CRITICAL"
]

high_vulns := [v |
    some result in input.trivy_report.Results
    some v in result.Vulnerabilities
    v.Severity == "HIGH"
]
