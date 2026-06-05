# Plugin security model

Installing a Concord plugin is equivalent to running an arbitrary binary
on your machine with your credentials. The defences below shrink the
attack surface, but **trust is the primary control** — only install
plugins whose source you have a reason to trust.

## Layers in place today

### 1. Signed OCI distribution
Every published artifact (plugin, control pack, framework manifest) is
signed with Cosign keyless against the GitHub Actions OIDC token of its
release workflow. `concord ... install --require-signature` refuses
unsigned artifacts; the default behaviour verifies when cosign is on
PATH and warns when it is not.

### 2. Lockfile digest pinning
`concord.lock` records the resolved sha256 digest of every installed
artifact. CI workflows running `concord install` against a checked-in
lockfile re-pull and verify those exact digests — a registry that
serves a different blob for the same tag fails.

### 3. Identity continuity
Each lockfile entry also records the keyless signer identity (the
publishing workflow URI). An upgrade that resolves to an artifact
signed by a *different* workflow identity is refused unless the
operator passes `--allow-signer-change`.

### 4. Environment scoping
At install time, Concord queries the plugin's `Capabilities` response
and persists the union of `RequiredEnv ∪ OptionalEnv` to
`~/.concord/plugins/<source>/<version>/capabilities.json`. On every
subsequent spawn the plugin process receives only those variables plus
a small set of essentials (`PATH`, `HOME`, locale, time zone). A
malicious `pagerduty` plugin cannot read `AWS_SECRET_ACCESS_KEY` unless
its manifest explicitly lists it — and that listing is visible at
install time.

### 5. Process isolation
Plugins run in separate processes over gRPC. A panic or crash maps to
a `gRPC UNAVAILABLE` instead of taking down the host. The
hashicorp/go-plugin handshake (magic cookie) prevents an unrelated
binary from accidentally talking to the host.

### 6. Per-call timeouts
Every Collect call has a deadline (`120s` by default, overridable per
plugin via `NewPluginCollector`). `DEADLINE_EXCEEDED` only fails the
single evidence ref, not the rest of the run.

### 7. OCI tarball extraction safety
Control-pack tarballs are validated before extraction. Entries
containing `..`, absolute paths, NUL bytes, or symlinks/hardlinks are
rejected. Atomic install via temp dir + rename means a partial
extraction never leaves a half-installed pack on disk.

## Threat model

| Threat | Mitigation |
|---|---|
| Malicious upload to a public registry | M1 signing + M3 identity continuity |
| Compromised tag pointing to a new blob | M2 lockfile digest pinning |
| Plugin exfiltrating unrelated env vars | M4 env scoping |
| Plugin crash taking down the run | M5 process isolation |
| Slow plugin hanging the run | M6 per-call timeouts |
| Pack tarball with `../etc/passwd` payload | M7 tar extractor safety |

## Future hardening (Phase Π-12+)

These are not implemented today; they are documented design choices
for the next iteration.

### Stronger network egress filtering
Plugins declare their permitted destinations in
`Capabilities.Permissions.Network` (e.g. `["*.amazonaws.com"]`). Today
this list is advisory. A future iteration will route the plugin's
outbound DNS + TCP through a host-side proxy that enforces the
allowlist — initially via a userspace proxy (no kernel changes), later
via eBPF on Linux.

### OS-level sandboxing
- **Linux**: a seccomp filter restricting syscalls to the read/write/network
  set a Go binary actually needs, plus Landlock to restrict filesystem
  access to the plugin's own version dir + `$HOME/.aws` (if declared).
- **macOS**: `sandbox-exec` with a profile derived from the plugin's
  declared `Permissions.Filesystem`.
- **Windows**: AppContainer integrity level low + restricted token.

These are intentionally NOT in the v1 cut because each requires a
non-trivial portability story (different per-OS), and the existing
layers already raise the cost of attack significantly.

### Plugin index / discovery
A `plugins.concord.dev` site will list signed, trusted plugins with
audit trails (who pushed which version, when). `concord search` will
query this index; `concord plugin install <name>` may dispatch through
it for canonical sources.

## What we do NOT defend against

- A plugin that you explicitly granted credentials to (e.g. `AWS_*`)
  misusing those credentials within their declared scope. This is the
  Terraform model: providers receive your credentials and the security
  model assumes they will use them honestly.
- An attacker with write access to your `concord.lock`. The lockfile is
  source-of-truth for digests; if it is tampered with, all bets are
  off. Treat it as a CI artifact.
- An attacker with root on the machine running Concord. Defence in
  depth ends at the OS boundary.
