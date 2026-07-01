# Concord

Compliance as code. Declare controls in YAML, evaluate with Open Policy Agent, collect evidence from your stack.

## Quick start

```bash
make tidy        # fetch deps
make test        # run unit + integration tests
make check       # build CLI and smoke-test the check engine
```

In a project:

```bash
concord init                 # scaffold concord.yaml
concord add soc2             # install a framework's control pack (+ plugin deps)
concord check                # evaluate installed controls against collected evidence
```

## Repository layout

```
cmd/concord/         CLI entrypoint (cobra)
internal/
  policy/            OPA / Rego engine wrapper
  evidence/          evidence registry + file collector + plugin wiring
  runner/            orchestrates load → collect → evaluate → finding
  controlpacks/      install / verify OCI control packs
  plugins/           discover / spawn collector plugins
pkg/
  controls/          control YAML loader + validator
  report/            CLI rendering of findings
  api/v1/            public types (Control, Evidence, Finding)
controls/
  evidence-types/    EvidenceType schemas (control content ships as OCI control packs)
testdata/smoke-pack/ a single control exercised by `make check` and CI smoke
```

## Controls and evidence

Control content and collectors are distributed as signed OCI artifacts, not
bundled in this repo:

- **Control packs** (`concord-controlpack-*`) — installed with `concord add <framework>` or `concord controlpack install`.
- **Collector plugins** (`concord-plugin-*`) — installed with `concord plugin install`.

See [docs/migration.md](docs/migration.md) for the in-tree → OCI history.

## Running a control with a custom fixture

```bash
concord check --fixtures --controls testdata/smoke-pack
```

A control's `spec.evidence[].fixture` path resolves relative to the control
YAML file. Swap the fixture to flip a control between pass/fail without
touching policy code.
