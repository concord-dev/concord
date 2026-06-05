# Concord — GDPR control pack

This pack expresses GDPR's technical and organisational measures
(Articles 5, 17, 25, 30, 32, 33, 35, 44) as Concord controls.

## How it works

Most controls in this pack lean on the **Prowler** evidence adapter
(`source: prowler`). Prowler ships with first-party GDPR compliance
mappings for AWS, Azure, and GCP — running it produces ASFF JSON that
already classifies findings against `gdpr_eu`. Concord's Rego
policies then reduce those findings to pass/fail decisions and
expose them in the standard control surface (drift, audit-package,
trust portal).

A handful of controls use the **Steampipe** adapter (`source:
steampipe`) for queries Prowler doesn't cover — pg_audit extension
status, Postgres TLS, retention policy on log groups.

## Prerequisites

- Customer environment has [Prowler](https://github.com/prowler-cloud/prowler) installed: `pip install prowler` or via container
- For Postgres-bearing controls, [Steampipe](https://steampipe.io)
  with the relevant plugins installed
- The Concord agent runs with credentials that let Prowler/Steampipe
  reach the customer's accounts (read-only IAM is sufficient)

## Coverage snapshot

| GDPR Article | Subject | Concord control |
|---|---|---|
| 5(1)(c) — data minimisation | retention on log groups | gdpr-art-5-log-retention |
| 5(1)(f) — confidentiality | encryption at rest | gdpr-art-32-encryption-at-rest |
| 5(1)(f) — confidentiality | encryption in transit | gdpr-art-32-encryption-in-transit |
| 25 — privacy by design | no public storage | gdpr-art-25-no-public-storage |
| 30 — records of processing | audit logging enabled | gdpr-art-30-audit-logging |
| 32 — security of processing | MFA on privileged accounts | gdpr-art-32-mfa-privileged |
| 32 — security of processing | KMS key rotation enabled | gdpr-art-32-kms-key-rotation |
| 32 — security of processing | backup retention configured | gdpr-art-32-backup-retention |

This is the **starter** pack. Phase 8 (multi-cloud) and Phase 9
(K8s + identity) will expand it.

## Authoring more controls

To add a Prowler-backed control:

1. Find the Prowler check IDs that map to the GDPR article via
   [Prowler's compliance YAML](https://github.com/prowler-cloud/prowler/tree/master/prowler/compliance).
2. Add a YAML in this directory referencing the relevant Prowler
   `services:` slice. Set `source: prowler` + `params.compliance: gdpr_eu`.
3. Re-use `policies/prowler.rego` (the generic "no FAIL findings for
   this set of checks" policy). Override only when the control needs
   custom logic.

To add a Steampipe-backed control: drop a SQL query into the YAML's
`evidence.params.query` field and a Rego file under `policies/`.
