# In-tree → plugin migration (complete)

The 9 evidence collectors and 6 framework control packs that once shipped
inside this repo now exist only as standalone, signed OCI artifacts. The
in-tree implementations have been removed: the plugin manager and the
control-pack installer are the sole path to collectors and controls.

## Replacements

| Removed in-tree path | OCI artifact |
|---|---|
| `internal/evidence/aws/` | `ghcr.io/concord-dev/concord-plugin-aws` |
| `internal/evidence/github/` | `ghcr.io/concord-dev/concord-plugin-github` |
| `internal/evidence/huggingface/` | `ghcr.io/concord-dev/concord-plugin-huggingface` |
| `internal/evidence/mlflow/` | `ghcr.io/concord-dev/concord-plugin-mlflow` |
| `internal/evidence/okta/` | `ghcr.io/concord-dev/concord-plugin-okta` |
| `internal/evidence/prowler/` | `ghcr.io/concord-dev/concord-plugin-prowler` |
| `internal/evidence/snyk/` | `ghcr.io/concord-dev/concord-plugin-snyk` |
| `internal/evidence/steampipe/` | `ghcr.io/concord-dev/concord-plugin-steampipe` |
| `internal/evidence/wandb/` | `ghcr.io/concord-dev/concord-plugin-wandb` |
| `controls/frameworks/cis-aws/` | `ghcr.io/concord-dev/concord-controlpack-cis-aws` |
| `controls/frameworks/eu-ai-act/` | `ghcr.io/concord-dev/concord-controlpack-eu-ai-act` |
| `controls/frameworks/gdpr/` | `ghcr.io/concord-dev/concord-controlpack-gdpr` |
| `controls/frameworks/iso42001/` | `ghcr.io/concord-dev/concord-controlpack-iso42001` |
| `controls/frameworks/nist-800-53/` | `ghcr.io/concord-dev/concord-controlpack-nist-800-53` |
| `controls/frameworks/soc2/` | `ghcr.io/concord-dev/concord-controlpack-soc2` |

## Using a framework

```sh
# scaffold concord.yaml
concord init

# install the framework's control pack + transitive plugin deps
concord add gdpr soc2 iso-27001     # space-separated

# install the matching collector plugin
concord plugin install ghcr.io/concord-dev/concord-plugin-aws@v0.1.0
```

After the install, `concord check` finds the installed pack's controls
automatically (alongside any passed via `--controls`), and the plugin
manager lazy-spawns the matching collector for every evidence source it
needs.

## History

| Date | Action |
|---|---|
| 2026-06-05 | First release. All OCI artifacts live; the in-tree path shipped as the default. |
| 2026-07-01 | In-tree collectors (`internal/evidence/{aws,github,huggingface,mlflow,okta,prowler,snyk,steampipe,wandb}/`) and the bundled control library (`controls/frameworks/*`) removed. `concord init` no longer scaffolds a bundled library and `concord upgrade` was retired — controls now come from `concord add`. The `CONCORD_PREFER_PLUGINS` / `CONCORD_USE_IN_TREE` switches were dropped: with no in-tree path left, plugins are always the source. |
