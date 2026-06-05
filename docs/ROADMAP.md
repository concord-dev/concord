# Concord — roadmap

Concord is **GRC-as-code for cloud-native + AI systems** — a Terraform-style
declarative compliance platform. Phases 1-6 built a production-grade
**runtime** (rate limiting, durable events, worker, DLQ, hardening, ops).
Phases 7+ build the **content + integration breadth** that makes Concord
useful to a real GRC buyer.

## Guiding principles

**Don't reinvent the wheel.** Where mature, well-licensed OSS exists for
a problem (cloud config querying, security scanning, secret detection,
SBOM, CIS benchmarks), we **adapt** rather than re-implement. The OSS
ecosystem in this space is unusually rich — leveraging it lets us go
from 7 integrations to 140+ overnight.

**Strategic OSS dependencies:**

| Tool | License | Role in Concord | Plugin/check count |
|---|---|---|---|
| [Steampipe](https://steampipe.io) | Apache 2.0 | Universal evidence collector via SQL FDW | 140+ data sources (AWS, GCP, Azure, K8s, M365, Okta, GitHub, Postgres, Snowflake, …) |
| [Prowler](https://github.com/prowler-cloud/prowler) | Apache 2.0 | Pre-built cloud security checks with framework mappings | 500+ checks across AWS/Azure/GCP/K8s with GDPR/HIPAA/PCI/CIS/NIST/ISO/SOC2 mappings |
| [OPA / Rego](https://www.openpolicyagent.org/) | Apache 2.0 | Custom policy engine for cross-domain controls (already used) | — |
| [Trivy](https://trivy.dev/) | Apache 2.0 | Container + IaC + SBOM scanning | covers Dockerfile/K8s/Terraform/Helm |
| [Microsoft Presidio](https://microsoft.github.io/presidio/) | MIT | PII detection in data (for DSAR / data classification) | 50+ entity types |
| [Conftest](https://www.conftest.dev/) | Apache 2.0 | Wraps OPA for config-file checks | Dockerfile, K8s YAML, Terraform plan |
| [OpenSCAP](https://www.open-scap.org/) | LGPL | OS-level CIS benchmark scanning | for host-level evidence |

**The architectural shift:** Concord's `internal/evidence/` becomes a thin
*adapter layer* — most new "collectors" are just translators between
Concord's evidence contract and the output format of an upstream tool.

**Concord's defensible value-add** (not delegatable to OSS):
- GRC workflow: orgs, RBAC, auditor flag, audit-package export
- Drift detection between runs
- Durable event pipeline (outbox → Kafka → worker → webhook)
- Multi-framework crosswalks
- Trust portal
- Operator endpoints (DLQ, partition rotation)
- The orchestration glue: scheduling, retention, audit log, policy override

---

## Strategic positioning

**Wedge:** Cloud-native + AI-first organizations who want GRC-as-code
instead of clicking through Vanta / Drata / Secureframe. Specifically:

- **AI/ML companies** under EU AI Act + ISO 42001 — we already have stubs
  for these and they're a young, defensible niche.
- **K8s-native** companies who need CIS Kubernetes Benchmark + custom
  cluster policies.
- **Multi-cloud** with strong Postgres/data infrastructure where Vanta's
  data-platform coverage is weak.

**Anti-positioning:** We are NOT trying to compete with Vanta on
integration count for typical SaaS startups. They have a 10-year head
start. Instead, lean on OSS (Steampipe, Prowler) for breadth and put
Concord's energy into:

1. Code-first authoring (controls + Rego live in git, reviewed in PRs)
2. Multi-framework crosswalks (one control satisfies SOC2-CC6.1 +
   ISO27001-A.9.4.2 + NIST AC-2 + GDPR-Art-32)
3. AI / K8s / data-platform depth
4. Drift detection + change-driven audit (Concord knows what changed
   between runs, traditional GRC tools don't)

---

## Phase coverage matrix (where we go from sparse to covering)

```
Framework         Phase 6   Phase 7   Phase 8   Phase 9   Phase 10  Phase 11
                  (today)   GDPR/PG   GCP/Az    K8s/Id    Remed.    HR/Vendors
SOC 2             14        +5        +5        +10       —          +5
NIST 800-53       11        +10       +20       +30       —          +10
CIS AWS           8         —         —         —         —          —
CIS GCP           0         —         +30       —         —          —
CIS Azure         0         —         +30       —         —          —
CIS K8s           0         —         —         +30       —          —
ISO 42001         3         +5        +5        —         —          +5
EU AI Act         3         +5        —         —         —          +3
GDPR              0         +35       +5        —         —          —
HIPAA             0         +20       +10       —         —          +5
PCI-DSS v4        0         —         +15       —         —          +10
ISO 27001:2022    0         +30       +20       +10       —          +15
FedRAMP Mod       0         —         —         +20       —          —
─────────────────────────────────────────────────────────────────────
running total     39        129       247       347       347        383
```

(numbers are rough; the point is the trajectory)

---

## Phase 7 — GDPR foundations + universal collectors (8-10 weeks)

**Goal:** Concord can support a real GDPR audit. Three deliverables.

### 7a. Steampipe adapter — `internal/evidence/steampipe/`

Single Go adapter that runs `steampipe query --output json` and returns
evidence as Rego-compatible JSON. Customer installs Steampipe + plugins
once; Concord can then collect from any of the 140+ Steampipe data
sources by writing a SQL query in the control YAML:

```yaml
evidence:
  - id: rds_encryption
    source: steampipe
    params:
      query: |
        SELECT db_instance_identifier, storage_encrypted, kms_key_id, engine
        FROM aws_rds_db_instance
        WHERE engine IN ('postgres','mysql','aurora-postgresql')
```

This single adapter unlocks: AWS (all services), GCP, Azure, K8s, Okta,
GitHub, M365, Google Workspace, Postgres, MySQL, Snowflake, BigQuery,
Slack, Jira, Linear, Salesforce, HubSpot, …

### 7b. Prowler adapter — `internal/evidence/prowler/`

Adapter that runs Prowler against the customer's cloud account and
parses ASFF (AWS Security Finding Format) JSON. Prowler ships with
GDPR/HIPAA/PCI/CIS/NIST/ISO/SOC2 compliance mappings built in:

```yaml
evidence:
  - id: prowler_gdpr_aws
    source: prowler
    params:
      provider: aws
      compliance: gdpr_eu
      services: [rds, s3, kms, cloudtrail, iam]
```

Output: structured findings with `check_id`, `status`, `resource_arn`,
`severity`, `compliance_mappings`. Concord's Rego policies reason over
these instead of re-deriving them.

### 7c. GDPR control pack — `controls/frameworks/gdpr/`

35-40 controls covering the technical/organisational measures
GDPR's Articles 5, 17, 25, 30, 32, 33, 35, 44 require. Most leverage
Prowler output; a handful need custom Steampipe queries (e.g.,
"Postgres pg_audit is enabled on all PII-bearing databases").

Examples:
- `gdpr-art-32-encryption-at-rest.yaml` — RDS/Cloud SQL/Azure SQL all encrypted (Prowler)
- `gdpr-art-32-encryption-in-transit.yaml` — TLS 1.2+ enforced on all load balancers (Prowler)
- `gdpr-art-32-access-logging.yaml` — CloudTrail / Cloud Audit / Azure Activity Log enabled (Prowler)
- `gdpr-art-5-storage-limitation.yaml` — log retention policy ≤ documented period (Steampipe)
- `gdpr-art-25-default-deny.yaml` — no S3/GCS/Blob containers world-readable (Prowler)
- `gdpr-art-30-ropa-current.yaml` — RoPA document exists and was updated in last 365 days (manual evidence)
- `gdpr-art-44-data-residency.yaml` — no resources in non-adequate regions (Steampipe)

Each control YAML declares its multi-framework crosswalk so the same
evidence claims coverage of GDPR-Art-32 + SOC2-CC6.7 + ISO27001-A.10.1
simultaneously.

### 7d. Crosswalk metadata + renderer

Add a `crosswalks:` block to the control YAML schema. Update the
markdown + trust-portal renderers to show "this control satisfies N
framework sections". A GDPR auditor and a SOC 2 auditor can request
different views of the same underlying control set.

### 7e. Postgres native collector (via Steampipe `postgres` plugin)

Customer points Steampipe's Postgres plugin at their primary DB.
Concord controls then query for: TLS in use, `pg_audit` extension
installed, RLS policies on tables tagged as PII, role grants reviewed,
default tablespace encryption.

---

## Phase 8 — Multi-cloud parity (6-8 weeks)

**Goal:** GCP + Azure first-class.

Both providers are now collected via the Steampipe adapter from
Phase 7 — no new Concord code needed. Phase 8's work is:

8a. **CIS GCP Foundations** — 30+ controls in `controls/frameworks/cis-gcp/`
8b. **CIS Azure Foundations** — 30+ controls in `controls/frameworks/cis-azure/`
8c. **Prowler integration upgrade** — invoke `prowler gcp --compliance gdpr_eu` and `prowler azure --compliance gdpr_eu`
8d. **Cross-cloud crosswalks** — e.g., `gdpr-art-32-encryption-at-rest` claims coverage of AWS-RDS + GCP-CloudSQL + Azure-SQL simultaneously
8e. **NIST 800-53 expansion** — bring up to ~30 controls covering AC, AU, CM families
8f. **ISO 27001:2022** — 30 starter controls

---

## Phase 9 — Kubernetes + Identity (6 weeks)

**Goal:** Cover the container + identity compliance surface.

9a. **Steampipe K8s plugin wiring** — `kubernetes_pod`, `kubernetes_role`, etc. are queryable via 7a
9b. **CIS Kubernetes Benchmark** — 30 starter controls in `controls/frameworks/cis-k8s/`
9c. **Trivy adapter** — `internal/evidence/trivy/` — image vuln + IaC scanning. Returns SARIF; Concord's Rego reasons over findings.
9d. **Conftest integration** — for K8s manifest / Terraform plan static analysis. Conftest already uses Rego, so the integration is a binary-shell-out.
9e. **Identity providers via Steampipe** — Okta, Entra ID, Google Workspace, Auth0, JumpCloud all have Steampipe plugins
9f. **Off-boarding control suite** — combine identity provider data + HRIS (Phase 11) to verify access revocation within 24h of termination

---

## Phase 10 — Remediation lane (6 weeks)

**Goal:** Concord moves from detect-only to detect + plan + (optionally) apply.

10a. **Remediation hint per control** — Rego policy returns a `remediation` block: which API call / IaC change would close the finding
10b. **`POST /v1/orgs/{slug}/runs/{id}/plan`** — derive remediation plan
10c. **Ticketing outbound** — Jira, Linear, GitHub Issues, ServiceNow
10d. **Auto-remediation (opt-in per control, narrow scope)** — Concord executes via customer-provided least-privilege IAM role:
   - "Disable IAM user inactive >90d"
   - "Enable S3 bucket versioning"
   - "Expire invitations older than 14d"
10e. **Approval workflow** — risky auto-remediations require human approval routed via the ticketing integration

---

## Phase 11 — HR + vendors + access reviews (8 weeks)

**Goal:** Cover the human / organizational compliance surface.

11a. **HRIS collectors via Steampipe** — Workday, BambooHR, Rippling (Steampipe plugins exist for some; native collectors for the rest)
11b. **Access review automation** — quarterly report of who has access to what, approvals routed via ticketing
11c. **Vendor inventory + DPA tracking** — `vendor` table + sub-processor management; each vendor links to evidence (DPA upload, sub-processor list, last SOC 2)
11d. **Background check tracking** — integration with Checkr / HireRight
11e. **Training tracking** — KnowBe4 / SANS / customer-managed

---

## Phase 12 — Platform polish (6 weeks)

**Goal:** Concord operates the way Terraform users expect.

12a. **Module / control-pack registry** — versioned, signed control bundles. `concord pull cncf/k8s@2.3.0` semantics.
12b. **Workspaces** — prod/staging/dev compliance posture per org
12c. **Risk register + scoring** — finding → risk score → top-10 view
12d. **Trust portal v2** — proper SOC 3-style report generation, badge embed
12e. **SDKs** — Go + Python + TypeScript client libs published

---

## Beyond — opportunistic, customer-pull driven

- **HIPAA framework + healthcare collectors** (AWS HealthLake, FHIR servers)
- **PCI-DSS v4** + cardholder data scoping (tokenisation evidence)
- **FedRAMP Moderate** + boundary visualization
- **SBOM ingestion** (cyclonedx, spdx) + supply-chain controls
- **EU AI Act expansion** — high-risk system documentation requirements
- **ISO 42001 expansion** — AI management system controls
- **Custom DSL** — higher-level YAML schema that compiles to Rego for non-engineer authors

---

## Open-source we explicitly chose NOT to depend on

| Tool | Reason |
|---|---|
| Cloud Custodian | Heavier than Prowler for our read-only use; better suited to Phase 10 (remediation) |
| Goss / InSpec | Host-level only; OpenSCAP covers this niche better |
| OSCAL tooling (NIST) | Format-only; we already render OSCAL output; ingestion not yet needed |
| Falco | Runtime security; orthogonal to point-in-time compliance posture |
| Wazuh / OSSEC | Same — runtime/SIEM |
| Vault directly | Customer's secret store, not our data; Steampipe has a Vault plugin |

---

## Success criteria per phase

Concrete deliverables to ship a phase:

- All controls in the framework directory have a fixture-based test
  (so CI runs without real cloud creds)
- `make lint && make test-race` pass clean
- Live smoke against at least one real customer-shaped environment
  (recorded in `examples/`)
- Operator runbook entry for any new failure modes
- ARCHITECTURE.md + ROADMAP.md updated
- Single rebase-clean PR per sub-phase
