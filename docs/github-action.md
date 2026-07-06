# Concord GitHub Action — compliance gate on every PR

`concord-dev/concord` ships a composite Action that runs `concord gate` in CI,
blocks the merge on any failing control, and publishes results to **GitHub code
scanning** so failing controls appear as inline PR annotations and Security-tab
alerts. This is the adoption wedge: compliance-as-code reviewed in the PR, like
any other check.

## Usage

```yaml
# .github/workflows/compliance.yml
name: compliance
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # required to upload SARIF to code scanning

jobs:
  concord:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: concord-dev/concord@v1
        with:
          controls: controls
          config: concord.yaml
          # framework: soc2        # optional: gate a single framework
          # fixtures: "true"       # optional: offline eval (no live collectors)
          # fail-on-warnings: "true"
```

The job fails (blocking the PR) whenever a control fails or errors; with
`fail-on-warnings: true`, warnings block too.

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `version` | `latest` | Concord release to install (git tag, or `latest`). |
| `controls` | `controls` | Controls directory. |
| `config` | `concord.yaml` | Path to `concord.yaml`. |
| `framework` | _(all)_ | Restrict evaluation to one framework id. |
| `fixtures` | `false` | Fixtures-only (offline) evaluation. |
| `fail-on-warnings` | `false` | Fail the gate on warnings, not just failures. |
| `sarif-file` | `concord.sarif` | Where the SARIF report is written. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. |
| `working-directory` | `.` | Directory to run in. |

## What shows up in the PR

- **Inline annotations** on the file the SARIF points at (`--sarif-location`,
  default `concord.yaml`), one per failing control.
- **Security → Code scanning alerts** listing each failing control with its
  severity (from the control's `severity`), framework tags, and the specific
  failure message.

## Without the Action

The Action just wraps the CLI, so any CI can do the same:

```bash
concord gate --controls controls --config concord.yaml --sarif concord.sarif
# exits non-zero on failure; upload concord.sarif with your platform's SARIF step
```
