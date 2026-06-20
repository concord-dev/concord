# EvidenceType — the evidence payload contract

An **EvidenceType** is the versioned JSON Schema for one evidence payload
shape. It is the contract between a plugin (which *produces* the payload)
and the controls + Rego policies (which *consume* it). Before
EvidenceTypes the `type` on a control's evidence reference was an
unvalidated string, so a fixture or a plugin's output could drift from
what a policy expected with nothing to catch it.

## The kind

```yaml
apiVersion: concord.dev/v1
kind: EvidenceType
metadata:
  id: okta/users_mfa        # "source/type"
  version: v1.0.0           # semver; minor bumps must stay additive
spec:
  source: okta
  description: Active Okta users with their enrolled MFA factors.
  compatibility: backward   # backward | backward_transitive | none
  schema:                   # JSON Schema, draft 2020-12
    type: object
    required: [fetched_at, users]
    properties:
      fetched_at: {type: string, format: date-time}
      users:
        type: array
        items:
          type: object
          required: [id, email, status, has_strong_mfa]
          properties:
            has_strong_mfa: {type: boolean}
  examples:
    - ../frameworks/soc2/tests/fixtures/cc6.1-okta-pass.json
```

- **id** is `source/type`. A control's `evidence[].source` +
  `evidence[].type` resolve to it (`okta` + `users_mfa` → `okta/users_mfa`).
- **schema** is standard JSON Schema (draft 2020-12 by default), validated
  with [`santhosh-tekuri/jsonschema/v6`](https://github.com/santhosh-tekuri/jsonschema).
- YAML caveat: avoid bare keys/values like `n`, `y`, `on`, `off` in the
  schema — the YAML parser coerces them to booleans. `concord
  evidence-type validate` catches the resulting malformed schema.

## Versioned references

A reference is `id` optionally followed by `@constraint`:

| Reference | Resolves to |
|---|---|
| `okta/users_mfa` | the latest registered version |
| `okta/users_mfa@v1.2.0` | exactly v1.2.0 |
| `okta/users_mfa@^v1` | the highest `v1.x` (same major) |

Version comparison uses `golang.org/x/mod/semver`.

## Where they live

EvidenceTypes are loaded from an `evidence-types/` directory at a pack
root. The control loader skips that directory and any co-located
`kind: EvidenceType` document, so a pack can hold both. A plugin should
ship the EvidenceTypes for the evidence it produces.

## Authoring + CI

```
concord evidence-type validate evidence-types/okta_users_mfa.yaml
concord evidence-type check    evidence-types/okta_users_mfa.yaml payload.json
concord evidence-type list     evidence-types/
```

`concord control validate` (and `control lint`) load the pack's
`evidence-types/` and validate every pass/fail fixture's evidence payload
against the matching schema. A fixture that has drifted from the declared
shape fails validation. The check is opt-in: a control whose evidence
`type` has no registered EvidenceType is left untouched, so existing
packs keep working until they adopt one.

## Implementation

- `pkg/api/v1/evidencetype.go` — the kind's Go types.
- `pkg/evidencetype/` — `Parse`/`Validate`, the `Registry` (load, index by
  id+version, resolve refs, validate payloads), and ref parsing.
- `internal/scaffold/validate.go` — the `concord control validate` wiring.
- `cmd/concord/evidence_type.go` — the CLI.
