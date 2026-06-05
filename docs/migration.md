# In-tree → plugin migration timeline

All 9 collectors and 6 framework control packs that previously shipped
inside this repo are now published as standalone, signed OCI artifacts.
The in-tree implementations are kept temporarily to give users a
predictable migration window.

## Replacements

| In-tree path | OCI artifact | Status |
|---|---|---|
| `internal/evidence/aws/` | `ghcr.io/concord-dev/concord-plugin-aws` | published v0.1.0 |
| `internal/evidence/github/` | `ghcr.io/concord-dev/concord-plugin-github` | published v0.1.0 |
| `internal/evidence/huggingface/` | `ghcr.io/concord-dev/concord-plugin-huggingface` | published v0.1.0 |
| `internal/evidence/mlflow/` | `ghcr.io/concord-dev/concord-plugin-mlflow` | published v0.1.0 |
| `internal/evidence/okta/` | `ghcr.io/concord-dev/concord-plugin-okta` | published v0.1.0 |
| `internal/evidence/prowler/` | `ghcr.io/concord-dev/concord-plugin-prowler` | published v0.1.0 |
| `internal/evidence/snyk/` | `ghcr.io/concord-dev/concord-plugin-snyk` | published v0.1.0 |
| `internal/evidence/steampipe/` | `ghcr.io/concord-dev/concord-plugin-steampipe` | published v0.1.0 |
| `internal/evidence/wandb/` | `ghcr.io/concord-dev/concord-plugin-wandb` | published v0.1.0 |
| `controls/frameworks/cis-aws/` | `ghcr.io/concord-dev/concord-controlpack-cis-aws` | published v0.1.0 |
| `controls/frameworks/eu-ai-act/` | `ghcr.io/concord-dev/concord-controlpack-eu-ai-act` | published v0.1.0 |
| `controls/frameworks/gdpr/` | `ghcr.io/concord-dev/concord-controlpack-gdpr` | published v0.1.1 |
| `controls/frameworks/iso42001/` | `ghcr.io/concord-dev/concord-controlpack-iso42001` | published v0.1.0 |
| `controls/frameworks/nist-800-53/` | `ghcr.io/concord-dev/concord-controlpack-nist-800-53` | published v0.1.0 |
| `controls/frameworks/soc2/` | `ghcr.io/concord-dev/concord-controlpack-soc2` | published v0.1.0 |

## Timeline

| Date | Action |
|---|---|
| 2026-06-05 | First release. All artifacts live; in-tree path remains the default. |
| 2026-07-05 (T + 30 days) | `CONCORD_PREFER_PLUGINS=1` becomes the default. In-tree path stays available via `CONCORD_USE_IN_TREE=1` opt-in. |
| 2026-08-04 (T + 60 days) | `concord doctor` emits a loud warning for any in-tree collector still in use. |
| 2026-09-03 (T + 90 days) | `internal/evidence/{aws,github,huggingface,mlflow,okta,prowler,snyk,steampipe,wandb}/` deleted. `controls/frameworks/*` deleted. Wiring shrinks to roughly the file collector + plugin manager. |

## Migrating

For every framework you previously evaluated via in-tree code:

```sh
# one-time
concord init

# install the framework + transitive plugin/control-pack deps
concord add gdpr soc2 iso-27001     # space-separated

# install the matching plugin if you used `--source=<x>` directly
concord plugin install ghcr.io/concord-dev/concord-plugin-aws@v0.1.0
```

After the install, `concord check` will find the installed pack's
controls automatically (alongside any in `--controls`), and the
plugin manager will lazy-spawn the matching plugin for every
needed evidence source.

## Why a window

A clean cut on day one would have left users with broken `concord
check` runs until they manually installed every dependency. The 30/60/90
window lets CI pipelines and Helm charts roll forward at their own
cadence, gated by the `concord outdated` command.
