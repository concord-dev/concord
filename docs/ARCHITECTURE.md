# Concord — architecture (as of Phase 0 cleanup, pre-Kafka/Redis)

This document captures the **current** shape of the codebase so contributors
have a single map of the major pieces, why they exist, and where the seams
are. It is descriptive, not aspirational — the next-phase work (Kafka,
Redis, split worker binary) will land its own updates.

## 30-second overview

Concord is a multi-tenant compliance-as-code platform. Customers run an
**agent** (the `concord` CLI) on their own infrastructure with their own
cloud credentials; it evaluates Rego-based controls against collected
evidence and **pushes** finalized run results to the SaaS server. The
server never holds customer cloud credentials.

Two binaries today:

- `cmd/concord-server` — the multi-tenant HTTP API
- `cmd/concord` — the agent CLI (controls library, runners, push, login)

A third (`cmd/concord-worker`) is planned in Phase 3.

## Repository layout

```
cmd/
  concord/         CLI: check, watch, push, login, orgs, ...
  server/          concord-server entry point + subcommands (seed-tenant, migrate-down)
controls/          Rego control library + fixtures
deploy/
  helm/concord/    production Helm chart
docs/              this file, future runbooks
internal/
  auditpackage/    streaming ZIP export of compliance evidence
  auth/            password hashing (argon2id) + secret minting/hashing
  cli/credentials/ CLI on-disk session credentials (0600 JSON)
  config/          concord.yaml parsing
  controls/        controls library loader
  evidence/        per-source evidence collectors (AWS, GitHub, Okta, ...)
  logx/            slog wrapper + request-id context plumbing
  notify/          watcher-side notify Sinks + server-side mail/
  otelx/           OpenTelemetry SDK wiring (no-op default)
  policy/          OPA/Rego evaluator
  report/          renderers (text, json, oscal, markdown, trust-portal)
  runner/          orchestrates evidence × policy per control
  scaffold/        `concord init` templates
  server/          HTTP API
    authctx/         request-scoped principal context
    bg/              tracked-goroutine helper (Runner)
    bus/             in-process SSE fan-out (NOT durable)
    cors/            CORS middleware
    drift/           pass↔fail transition detector (pure)
    handlers/        request handlers split by route group
      auth/            /v1/auth/* + /v1/me/mfa/*
      operator/        /operator/v1/* (CONCORD_OPERATOR_TOKEN gate)
      org/             /v1/orgs/{slug}/*
      public/          unauthenticated routes (/healthz, /readyz, /metrics, ...)
    httpx/           JSON/Error helpers + access-log middleware + ClientIP
    limiter/         keyed token-bucket rate limiter (in-memory)
    metrics/         Prometheus collectors
    middleware/      auth + security-headers + request-id middleware
    openapi/         embedded OpenAPI 3.0.3 spec
  store/           Postgres store layer + migrations
  watcher/         CLI long-poll watcher
pkg/api/v1/        public types shared with the CLI
```

## Request lifecycle

```
client request
    │
    ▼
otelhttp.NewHandler             ── creates server span
    │
    ▼
renameSpanFromPattern           ── inside mux, deferred SetName(r.Pattern)
    │  (only on matched routes)
    │
    ▼
middleware.RequestID            ── X-Request-ID echo + ctx plumb
    │
    ▼
httpx.Logging                   ── slog access record (level by status class)
    │
    ▼
metrics.Middleware              ── concord_http_* counters + histogram
    │
    ▼
middleware.SecurityHeaders      ── nosniff, X-Frame-Options, Referrer-Policy,
    │                              HSTS when r.TLS or X-Forwarded-Proto=https
    ▼
cors.New                        ── exact-origin allowlist, preflight 204
    │
    ▼
http.ServeMux                   ── routes registered in router.go
    │
    ▼
RequireSession / RequireOrgPerm ── auth/RBAC gates
    │                              (HasPermission honours auditor flag for *:read)
    ▼
handler                         ── business logic
```

## Identity & access

| Principal       | Auth surface                            | Where the check lives |
|---|---|---|
| Session user    | `Authorization: Bearer concord_sess_…`  | `middleware.RequireSession` → `Store.ResolveSession` |
| API token       | `Authorization: Bearer concord_…`       | `middleware.RequireOrgPerm` → `Store.ResolveAPIToken` |
| Operator        | `Authorization: Bearer <CONCORD_OPERATOR_TOKEN>` | `middleware.RequireOperator` (constant-time compare) |
| Auditor         | session, with `user.is_auditor = true`  | `Store.HasPermission` short-circuits any `*:read` perm cross-org |

Permissions are `<resource>:<verb>` strings stored in `permission`. Roles
map to permissions via `role_permission`. `user_org_role` binds users to
roles per org. The `is_auditor` flag is the only cross-org grant.

MFA: TOTP (RFC 6238) + recovery codes. Login flow returns a short-lived
`mfa_challenge` token when enrolled; the second leg at `/v1/auth/login/mfa`
mints the real session.

## Storage

Single Postgres database, pgxpool. Schema lives in
`internal/store/migrations/0001_init.up.sql` as a single consolidated
file (pre-launch, no data to preserve; future migrations land as 0002+).

Auth tokens (api_token, user_session, invitation, password_reset,
mfa_challenge) all follow the same pattern: plaintext is shown ONCE at
mint time, the DB only holds `sha256(plaintext)` for lookup. Passwords
use argon2id (PHC string format). Recovery codes use argon2id too —
trying the stored hash list one-by-one is bounded at 10 attempts per
submit thanks to the recovery-code count cap.

CASCADE semantics:
- Org delete CASCADEs every per-org row (api_token, user_session not
  directly — but invitation, run, control_override, webhook,
  audit_event, drift_event, mfa_challenge are all org-scoped).
- User delete: tokens / sessions cascade; audit_event.actor_user_id is
  SET NULL so the forensic trail survives.
- Run delete: drift_event.prior_run_id is SET NULL so the drift history
  survives run pruning.

## Background work

The current model is in-process via `internal/server/bg.Runner`:

```
Concord.Broadcast       ─→ bus.Publish (SSE subscribers)
                         ─→ bg.Go(fireWebhooks)
                              ─→ bg.Go(deliverOne)×N

Concord.BroadcastDrift  ─→ bus.Publish
                         ─→ bg.Go(fireWebhooks)

password_reset / invitation email  ─→ h.goAsync(send)
                                       (h.goAsync == h.bg.Go when wired,
                                        plain `go` in tests with nil runner)
```

All `bg.Go` goroutines are tracked by a shared `sync.WaitGroup`.
`Concord.Shutdown(ctx)` blocks until they finish or ctx expires.
`cmd/server`'s SIGTERM handler runs `http.Server.Shutdown` first
(stops accepting + drains in-flight HTTP) then `Concord.Shutdown` under
a single `CONCORD_SHUTDOWN_TIMEOUT` budget.

**Limitations** — this model is the central target of Phase 2/3:

- Process kill / panic / OOM = lost notifications.
- No retries, no backoff, no DLQ.
- Each replica processes its own dispatch — N replicas don't share work.
- Rate limiter (`limiter.Bucket`) is in-memory per-pod; budgets multiply
  by replica count.

## Observability

Three pillars wired:

1. **Logs** — `logx` wraps `slog`. Request-id flows in context.
   Default JSON; `--log-format=text` for dev.
2. **Metrics** — `internal/server/metrics`. Private `*prometheus.Registry`,
   served at `/metrics`. Routes labeled by `r.Pattern` (bounded cardinality).
3. **Traces** — `internal/otelx`. OTLP exporter (http or grpc). No-op when
   `--otel-endpoint` empty. W3C tracecontext propagators always installed.

Drift detection adds a custom `drift.detect_and_persist` span; webhook
delivery uses `otelhttp.NewTransport` for client-side spans and
`traceparent` propagation to the receiver.

## Audit log

Every security-sensitive operation writes to `audit_event` via
`Store.RecordAudit`. Actor kinds: `user`, `token`, `operator`,
`unauthenticated`, `system`. Forensic columns: ip, user_agent,
request_id, details (JSONB). Best-effort: failures slog at ERROR, never
fail the originating request.

`GET /v1/orgs/{slug}/audit` exposes per-org events. The audit-package
export bundle (`/v1/orgs/{slug}/audit-package`) wraps audit + runs +
findings + drift into one ZIP.

## Helm deploy

Single chart at `deploy/helm/concord/`. Deployment uses
`RollingUpdate maxUnavailable: 0` for strict zero-downtime, restricted
PSS (non-root + RO root FS + drop ALL caps), and
`terminationGracePeriodSeconds: 35` > `config.shutdownTimeout: 30s`
so the drain has time before kubelet SIGKILL.

Postgres is **not** managed by the chart — point at an external
instance via a Secret. The chart adds a `concord-postgres` service
in docker-compose for local dev only.

## CI gates

`.github/workflows/ci.yml` runs five jobs in parallel:

| Job   | Purpose |
|---|---|
| lint  | go vet + staticcheck + deadcode + gofmt |
| vuln  | govulncheck against module + stdlib CVEs |
| test  | go test -race against real Postgres in a service container |
| build | builds both binaries, runs `concord check --fixtures` smoke |
| helm  | helm lint + helm template against the chart |

Run locally with `make lint && make test-race && make vuln`.

## Pending work (mapped to phases)

| Phase | Scope |
|---|---|
| 1     | Redis-backed rate limiter (interface + impl + fallback) |
| 2     | Kafka producer for `concord.events` (idempotency via event_id) |
| 3     | `cmd/concord-worker` binary + Kafka consumer + per-attempt webhook delivery table |
| 4     | DLQ inspection + replay endpoints |
| 5     | Idempotency-Key for POST mutations, circuit breakers, audit partitioning, PII redaction |
| 6     | Operator runbook + Grafana dashboards + Prometheus alerts |
