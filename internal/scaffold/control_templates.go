package scaffold

import (
	"fmt"
	"strings"
)

// ControlTemplate names the runtime shape of evidence + Rego scaffolding to emit.
type ControlTemplate string

const (
	TemplateGeneric           ControlTemplate = "generic"
	TemplateAWSResource       ControlTemplate = "aws-resource"
	TemplateGCPResource       ControlTemplate = "gcp-resource"
	TemplateAzureResource     ControlTemplate = "azure-resource"
	TemplateK8sResource       ControlTemplate = "k8s-resource"
	TemplateGitHubPolicy      ControlTemplate = "github-policy"
	TemplatePolicyAttestation ControlTemplate = "policy-attestation"
	TemplateVendorCert        ControlTemplate = "vendor-cert"
	TemplateComposite         ControlTemplate = "composite"
)

// AllTemplates returns every supported template in sorted demo order.
func AllTemplates() []ControlTemplate {
	return []ControlTemplate{
		TemplateGeneric, TemplateAWSResource, TemplateGCPResource,
		TemplateAzureResource, TemplateK8sResource, TemplateGitHubPolicy,
		TemplatePolicyAttestation, TemplateVendorCert, TemplateComposite,
	}
}

// ParseTemplate maps a CLI flag value to a known ControlTemplate.
func ParseTemplate(s string) (ControlTemplate, error) {
	switch ControlTemplate(strings.TrimSpace(s)) {
	case "", TemplateGeneric:
		return TemplateGeneric, nil
	case TemplateAWSResource:
		return TemplateAWSResource, nil
	case TemplateGCPResource:
		return TemplateGCPResource, nil
	case TemplateAzureResource:
		return TemplateAzureResource, nil
	case TemplateK8sResource:
		return TemplateK8sResource, nil
	case TemplateGitHubPolicy:
		return TemplateGitHubPolicy, nil
	case TemplatePolicyAttestation:
		return TemplatePolicyAttestation, nil
	case TemplateVendorCert:
		return TemplateVendorCert, nil
	case TemplateComposite:
		return TemplateComposite, nil
	}
	return "", fmt.Errorf("unknown control template %q (try one of: %v)", s, AllTemplates())
}

type templateParts struct {
	evidenceID     string
	evidenceSrc    string
	evidenceType   string
	evidenceParams string
	passBody       string
	failBody       string
	regoBody       string
}

func partsFor(tmpl ControlTemplate, pkg, controlID, evidenceKey string) templateParts {
	switch tmpl {
	case TemplateAWSResource:
		return awsResourceParts(pkg, controlID, evidenceKey)
	case TemplateGCPResource:
		return gcpResourceParts(pkg, controlID, evidenceKey)
	case TemplateAzureResource:
		return azureResourceParts(pkg, controlID, evidenceKey)
	case TemplateK8sResource:
		return k8sResourceParts(pkg, controlID, evidenceKey)
	case TemplateGitHubPolicy:
		return githubPolicyParts(pkg, controlID, evidenceKey)
	case TemplatePolicyAttestation:
		return policyAttestationParts(pkg, controlID, evidenceKey)
	case TemplateVendorCert:
		return vendorCertParts(pkg, controlID, evidenceKey)
	case TemplateComposite:
		return compositeParts(pkg, controlID, evidenceKey)
	default:
		return genericParts(pkg, controlID, evidenceKey)
	}
}

func genericParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "no evidence collected for %s"
}

deny contains msg if {
	items := input.%s.items
	bad := collection.non_compliant_ids(items)
	count(bad) > 0
	msg := sprintf("%s: non-compliant items %%v", [bad])
}
`, pkg, key, controlID, key, controlID)

	return templateParts{
		evidenceID:   key,
		evidenceSrc:  "TODO",
		evidenceType: "TODO",
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "items": [
      { "id": "example-1", "compliant": true }
    ]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "items": [
      { "id": "example-1", "compliant": false }
    ]
  }
}
`, key),
		regoBody: rego,
	}
}

func awsResourceParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: aws evidence missing"
}

deny contains msg if {
	some r in input.%s.resources
	not r.compliant
	msg := sprintf("%s: resource %%q is non-compliant (reason: %%s)", [r.arn, r.reason])
}
`, pkg, key, controlID, key, controlID)

	return templateParts{
		evidenceID:     key,
		evidenceSrc:    "aws",
		evidenceType:   "aws_resource_inventory",
		evidenceParams: "      service: TODO  # e.g. s3, iam, kms\n      region: us-east-1",
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "arn": "arn:aws:s3:::acme-logs", "compliant": true, "reason": "" }
    ]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "arn": "arn:aws:s3:::acme-logs", "compliant": false, "reason": "public access block disabled" }
    ]
  }
}
`, key),
		regoBody: rego,
	}
}

func gcpResourceParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: gcp evidence missing"
}

deny contains msg if {
	some r in input.%s.resources
	not r.compliant
	msg := sprintf("%s: %%s is non-compliant (%%s)", [r.full_name, r.reason])
}
`, pkg, key, controlID, key, controlID)

	return templateParts{
		evidenceID:     key,
		evidenceSrc:    "gcp",
		evidenceType:   "gcp_resource_inventory",
		evidenceParams: "      kind: TODO  # e.g. storage_bucket, iam_binding, kms_key\n      project: my-project",
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "full_name": "projects/x/buckets/logs", "compliant": true, "reason": "" }
    ]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "full_name": "projects/x/buckets/logs", "compliant": false, "reason": "public-access prevention not enforced" }
    ]
  }
}
`, key),
		regoBody: rego,
	}
}

func azureResourceParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: azure evidence missing"
}

deny contains msg if {
	some r in input.%s.resources
	not r.compliant
	msg := sprintf("%s: %%s is non-compliant (%%s)", [r.resource_id, r.reason])
}
`, pkg, key, controlID, key, controlID)

	return templateParts{
		evidenceID:     key,
		evidenceSrc:    "azure",
		evidenceType:   "azure_resource_inventory",
		evidenceParams: "      kind: TODO  # e.g. storage_account, key_vault, rbac_assignment\n      subscription: TODO",
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "resource_id": "/subscriptions/x/resourceGroups/y/.../sa", "compliant": true, "reason": "" }
    ]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "resource_id": "/subscriptions/x/resourceGroups/y/.../sa", "compliant": false, "reason": "blob public access enabled" }
    ]
  }
}
`, key),
		regoBody: rego,
	}
}

func k8sResourceParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: k8s evidence missing"
}

deny contains msg if {
	some r in input.%s.resources
	not r.compliant
	msg := sprintf("%s: %%s/%%s is non-compliant (%%s)", [r.namespace, r.name, r.reason])
}
`, pkg, key, controlID, key, controlID)

	return templateParts{
		evidenceID:     key,
		evidenceSrc:    "kubernetes",
		evidenceType:   "k8s_resource_inventory",
		evidenceParams: "      kind: TODO  # e.g. role_binding, network_policy, namespace\n      cluster: production",
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "namespace": "prod", "name": "frontend", "compliant": true, "reason": "" }
    ]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "resources": [
      { "namespace": "prod", "name": "frontend", "compliant": false, "reason": "no NetworkPolicy selects this pod" }
    ]
  }
}
`, key),
		regoBody: rego,
	}
}

func githubPolicyParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: github evidence missing"
}

deny contains msg if {
	some r in input.%s.repos
	not r.protected_default_branch
	msg := sprintf("%s: %%q default branch has no protection rule", [r.full_name])
}
`, pkg, key, controlID, key, controlID)

	return templateParts{
		evidenceID:     key,
		evidenceSrc:    "github",
		evidenceType:   "github_branch_protection",
		evidenceParams: "      org: acme",
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "repos": [
      { "full_name": "acme/api", "protected_default_branch": true, "required_status_checks": true }
    ]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "repos": [
      { "full_name": "acme/api", "protected_default_branch": false, "required_status_checks": false }
    ]
  }
}
`, key),
		regoBody: rego,
	}
}

func policyAttestationParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.%s)
	msg := sprintf("%s: attestation expired (expires_at=%%s)", [input.%s.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.%s, 365)
	msg := sprintf("%s: attestation not reviewed in 365 days (last_review_at=%%s)", [input.%s.last_review_at])
}
`, pkg, key, controlID, key, controlID, key, key, controlID, key)

	return templateParts{
		evidenceID:   key,
		evidenceSrc:  "attestation",
		evidenceType: "policy_attestation",
		evidenceParams: `      schema: TODO  # e.g. ropa-v1, dpia-v1, dpa-v1, ism-v1
      signers:
        - dpo@acme.com
      max_age_days: 365`,
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "version": "1",
    "owner": "dpo@acme.com",
    "signers": ["dpo@acme.com"],
    "last_review_at": "2026-01-01T00:00:00Z",
    "expires_at": "2027-01-01T00:00:00Z",
    "attested_fields": ["scope", "lawful_basis", "retention"]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "version": "1",
    "owner": "dpo@acme.com",
    "signers": ["dpo@acme.com"],
    "last_review_at": "2023-01-01T00:00:00Z",
    "expires_at": "2024-06-01T00:00:00Z",
    "attested_fields": ["scope"]
  }
}
`, key),
		regoBody: rego,
	}
}

func vendorCertParts(pkg, controlID, key string) templateParts {
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: vendor evidence missing"
}

deny contains msg if {
	some v in input.%s.vendors
	v.tier in {"tier_1", "tier_2"}
	not v.current_cert
	msg := sprintf("%s: %%s has no current cert in scope", [v.name])
}
`, pkg, key, controlID, key, controlID)

	return templateParts{
		evidenceID:     key,
		evidenceSrc:    "concord",
		evidenceType:   "vendor_inventory",
		evidenceParams: "      required_types: [\"soc2\", \"iso27001\"]",
		passBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "vendors": [
      { "name": "Datadog", "tier": "tier_1", "current_cert": true, "cert_type": "soc2" }
    ]
  }
}
`, key),
		failBody: fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "vendors": [
      { "name": "Datadog", "tier": "tier_1", "current_cert": false, "cert_type": "" }
    ]
  }
}
`, key),
		regoBody: rego,
	}
}

func compositeParts(pkg, controlID, key string) templateParts {
	secondary := key + "_secondary"
	rego := fmt.Sprintf(`package %s

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: primary evidence missing"
}

deny contains msg if {
	not evidence.present(input, "%s")
	msg := "%s: secondary evidence missing"
}

deny contains msg if {
	some r in input.%s.items
	not r.compliant
	msg := sprintf("%s: primary item %%q failed (%%s)", [r.id, r.reason])
}

deny contains msg if {
	some r in input.%s.items
	not r.compliant
	msg := sprintf("%s: secondary item %%q failed (%%s)", [r.id, r.reason])
}
`, pkg, key, controlID, secondary, controlID, key, controlID, secondary, controlID)

	return templateParts{
		evidenceID:   key,
		evidenceSrc:  "TODO",
		evidenceType: "TODO",
		evidenceParams: fmt.Sprintf(`      # composite control: also reference a second evidence id below
    - id: %s
      source: TODO
      type: TODO`, secondary),
		passBody: fmt.Sprintf(`{
  "%s": { "fetched_at": "2026-01-01T00:00:00Z", "items": [{"id":"a","compliant":true,"reason":""}] },
  "%s": { "fetched_at": "2026-01-01T00:00:00Z", "items": [{"id":"b","compliant":true,"reason":""}] }
}
`, key, secondary),
		failBody: fmt.Sprintf(`{
  "%s": { "fetched_at": "2026-01-01T00:00:00Z", "items": [{"id":"a","compliant":false,"reason":"bad"}] },
  "%s": { "fetched_at": "2026-01-01T00:00:00Z", "items": [{"id":"b","compliant":true,"reason":""}] }
}
`, key, secondary),
		regoBody: rego,
	}
}
