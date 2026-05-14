# Concord

Compliance as code. Declare controls in YAML, evaluate with Open Policy Agent, collect evidence from your stack.

## Quick start

```bash
make tidy        # fetch deps
make test        # run unit + integration tests
make check       # build CLI and run all controls
```

## Repository layout

```
cmd/concord/         CLI entrypoint (cobra)
internal/
  controls/          YAML loader + validator
  policy/            OPA / Rego engine wrapper
  evidence/          collectors (file-based today; GitHub/AWS later)
  runner/            orchestrates load → collect → evaluate → finding
  report/            CLI rendering of findings
pkg/api/v1/          public types (Control, Evidence, Finding)
controls/            content library
  frameworks/
    soc2/            first framework live
      *.yaml         control definitions
      policies/      .rego files
      tests/         fixtures + golden expectations
```

## Implemented controls

| ID | Title | Framework |
|---|---|---|
| SOC2-CC8.1 | Default branch is protected and requires reviewed changes | SOC 2 |

More land one at a time. See [../02-repo-structure.md](../02-repo-structure.md) for the schema and roadmap.

## Running a single control with a custom fixture

```bash
./bin/concord check --controls ./controls
```

The control's `spec.evidence[].fixture` path resolves relative to the control YAML file. Swap the fixture to flip a control between pass/fail without touching policy code.
