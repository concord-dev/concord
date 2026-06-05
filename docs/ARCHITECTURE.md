# Concord — architecture

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

Three binaries today:

- `cmd/server` — the multi-tenant HTTP API (concord-server)
- `cmd/concord` — the agent CLI (controls library, runners, push, login)
- `cmd/concord-worker` — Kafka consumer + outbound webhook delivery

## Repository layout

```
cmd/
  concord/         CLI: check, watch, push, login, orgs, ...
  concord-worker/  Kafka consumer + webhook delivery (Phase 3)
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
  eventbus/        durable Outbox + Dispatcher; ships event_outbox rows to Kafka
  kafkax/          segmentio/kafka-go writer factory (TLS + SASL + compression)
  redisx/          go-redis client factory (single + Sentinel modes)
  worker/          concord-worker domain: Executor + Consumer + Retrier
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
    limiter/         keyed token-bucket rate limiter (memory + redis + failover)
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

## Durable events

Domain events (`run.completed`, `drift.detected`, …) flow through a
**transactional outbox** so a process crash never loses an event. The
flow is:

```
handler          eventbus.Outbox       Postgres            eventbus.Dispatcher        Kafka
   │                  │                  │                       │                      │
   ├─ Enqueue(evt)───▶│                  │                       │                      │
   │                  ├─ INSERT row ────▶│                       │                      │
   │                  │   (in same tx    │                       │                      │
   │                  │    as state)     │                       │                      │
   │                  │                  │                       │                      │
   │                  │                  │   poll (200ms tick) ◀─┤                      │
   │                  │                  │   FOR UPDATE          │                      │
   │                  │                  │   SKIP LOCKED ───────▶│                      │
   │                  │                  │                       ├─ Publish(env) ──────▶│
   │                  │                  │   UPDATE published_at◀┤                      │
   │                  │                  │                       │                      │
```

- **At-least-once delivery** — failed publishes bump `attempt_count` +
  `last_error` and reschedule via jittered exponential backoff
  (1s → 5min, capped at MaxAttempts=20).
- **Multi-replica safe** — `SELECT FOR UPDATE SKIP LOCKED` shards
  pending rows across dispatcher replicas without coordination. Tested
  with two dispatchers + 100 enqueued events → exactly 100 publishes.
- **Phase 2 boundary** — the in-process bus + webhook delivery still
  runs for SSE + immediate webhook fan-out; the outbox is the durable
  parallel path the Phase 3 worker will consume. Kafka is *optional* —
  when unconfigured, the no-op publisher marks rows shipped so the
  queue drains; configure brokers later and in-flight rows resume.
- **Dead-letter** — rows that hit MaxAttempts stay un-published and
  visible to operators. Phase 4 will add `/operator/v1/dlq` for
  inspect + replay.

Wire shape on the topic:
- Topic: `concord.events` (configurable)
- Partition key: `org_id` (per-tenant ordering preserved)
- Body: `{version, event_id, org_id, kind, occurred_at, data}` JSON
- Headers: `event-id`, `event-kind`, `org-id`, `traceparent`

## Webhook delivery (Phase 3)

`cmd/concord-worker` is the consumer-side counterpart to the Phase 2
outbox dispatcher. It reads `concord.events` via a Kafka consumer
group, dedupes incoming `event_id`s through Redis SETNX (24h TTL), and
drives the first delivery attempt for every matching webhook. A
sibling `Retrier` goroutine polls `webhook_delivery` for failed rows
whose backoff has elapsed and re-runs the same `Executor`.

```
Kafka topic concord.events
        │
        ▼  (kafka-go ConsumerGroup, partition key = org_id)
Consumer.processOne
        │
        ├─ dedupe (Redis SETNX event_id, TTL 24h)
        │     (DB-side UNIQUE (webhook_id, event_id) is the second line)
        │
        ├─ parse envelope → resolve enabled webhooks for org
        │
        └─ for each webhook:
              UpsertDelivery (status='delivering')
              Executor.Attempt → POST + HMAC sign + status update
              commit Kafka offset only AFTER every row is persisted

Retrier.tick (every PollInterval)
        │
        ├─ ClaimPendingDeliveries (FOR UPDATE SKIP LOCKED, batch ≤ N)
        │
        └─ for each row:
              Executor.Attempt (retry=true)
              MarkSucceeded | MarkFailed (+ backoff) | MarkDead
```

- **Idempotency**: two layers — Redis SETNX fast-path + DB-level UNIQUE
  `(webhook_id, event_id)`. A re-delivered Kafka message becomes a
  no-op UPSERT on the existing row.
- **At-least-once**: Kafka offsets commit only AFTER each row is
  persisted. A crash mid-batch re-delivers; dedupe makes it safe.
- **Bounded retries**: 5 attempts × jittered exponential backoff
  (1s → 60s capped). After max attempts, the row is `status='dead'` and
  stops being claimed; Phase 4 surfaces an operator endpoint.
- **Per-tenant ordering**: partition key = `org_id`, so all of an
  org's events land on one partition and one consumer processes them
  in order.
- **Horizontal scale**: Kafka rebalances partitions across worker
  pods; SKIP LOCKED shards the retrier across replicas.

The server-side `Concord.Broadcast` / `BroadcastDrift` keep publishing
on the in-process bus (for SSE) and enqueue an outbox row — webhook
fan-out happens **only** in the worker now. Deploying the worker is a
prerequisite for any webhook to fire.

## Reliability hardening (Phase 5)

Three production-grade upgrades shipped together:

**Idempotency-Key.** `internal/server/idempotency` is a Redis-backed
middleware mounted in front of the high-leverage POST routes
(`/v1/orgs/{slug}/runs`, `/v1/orgs/{slug}/invitations`,
`/v1/orgs/{slug}/webhooks`). Callers opt in via the
`Idempotency-Key: <uuid>` header. SETNX claims a `idem:<scope>:<key>`
slot with a 24h TTL; the handler's response is captured via a
buffering ResponseWriter and stored under the same key. A re-send
with the same key returns the cached body verbatim with
`Idempotency-Replay: true`; a same-key-different-body returns 422; a
same-key-while-pending returns 409. Cluster-safe via the shared Redis
client. A Redis outage degrades the middleware to pass-through
(strictly preferred over 503'ing every POST) with
`concord_idempotency_redis_errors_total` bumped so the outage is
visible.

**Circuit breakers.** `internal/worker.Breakers` is a per-host pool of
`sony/gobreaker` instances wrapping every outbound webhook POST.
Default policy: 5 consecutive failures → open, 30s cooldown, 1
half-open probe. A wedged receiver trips its breaker once and
subsequent attempts fail fast with `ErrCircuitOpen` until the
half-open probe succeeds. State is per-pod in-memory — load-shedding,
not a correctness guarantee. The breaker treats non-2xx and network
errors as failures uniformly, so a receiver returning 500 for
everything trips the same way a DNS-failing host does.
`concord_worker_breaker_state_changes_total{state}` counts
transitions.

**PII redaction.** `logx.RedactingHandler` wraps the JSON/text slog
handler installed by `logx.Init`. Attribute names matching the
curated sensitive set (`password`, `secret`, `token`, `authorization`,
`api_key`, `session_token`, `recovery_code`, `x-concord-signature`, …
substring + case-insensitive) have their values replaced with
`***REDACTED***` before reaching stderr. `WithAttrs` / `WithGroup`
propagate the redactor through pre-bound loggers, and the descent
into `slog.Group` catches nested structures. Message text is
deliberately not scanned — handlers must keep secrets out of the
`slog.Info("...")` first argument; the redactor is a last line of
defence, not a free pass.

## Dead-letter handling (Phase 4)

Two dead-letter populations need operator attention:

- **`event_outbox`** rows where `attempt_count >= 20` AND
  `published_at IS NULL` — Kafka was unreachable too long for the
  dispatcher's retry budget.
- **`webhook_delivery`** rows where `status='dead'` — a specific
  receiver stayed broken past the retrier's `MaxAttempts` (default 5).

Both surfaces expose the same shape under `/operator/v1/dlq/*`:

```
GET    /events            list  (filters: org_id, kind, limit, offset)
GET    /events/{id}       inspect  (full payload + last_error + attempt_count)
POST   /events/{id}/replay reset attempt_count=0, clear abandoned_at,
                          schedule for the next dispatcher tick
DELETE /events/{id}       abandon (set abandoned_at = now())
```

`/deliveries` mirrors `/events`. Migration 0004 adds an
`abandoned_at TIMESTAMPTZ NULL` column to both tables; dispatcher /
retrier claim queries gain `AND abandoned_at IS NULL`. Replay clears
the flag so abandon is reversible — operators that change their mind
can put a row back in flight without losing forensic columns
(`attempts_log`, `last_error`, `payload`).

Every mutating call writes to `audit_event` with `actor_kind=operator`,
`action ∈ {dlq.event.replay, dlq.event.abandon, dlq.delivery.replay,
dlq.delivery.abandon}` and the target row id — so a compliance auditor
can reconstruct every operator intervention.

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

## Rate limiting

`internal/server/limiter` is the gate in front of every unauthenticated
endpoint where a caller can burn compute (login, password-reset request)
or guess a secret (invitation accept, password-reset confirm). `Bucket`
is the interface every handler depends on; three impls ship:

- **MemoryBucket** — per-pod token bucket via `golang.org/x/time/rate`.
  Zero dependency, correct on a single replica; with N replicas the
  effective limit is N× the configured rate.
- **RedisBucket** — fleet-wide token bucket implemented atomically via
  a Lua script. Stores `{tokens, last_refill_ns}` as a HASH per key
  with an EXPIRE so eviction is automatic. Every call runs against a
  ~50ms per-call timeout — a sick or failing-over Redis returns
  context.DeadlineExceeded promptly.
- **FailoverBucket** — wraps a primary (RedisBucket) and a fallback
  (tightened MemoryBucket). Primary errors route to the fallback, which
  enforces a fraction (default 0.33) of the original rate so a Redis
  outage can't be used to amplify an attack to N× across pods.
  `concord_limiter_primary_errors_total{gate}` records each route.

`cmd/server` picks the wiring via `--rate-limiter=memory|redis`. The
Helm chart exposes `redis.rateLimiter`, `redis.mode`, `redis.addr`,
`redis.sentinelMaster`, `redis.sentinelAddrs`, TLS knobs, timeouts, and
`redis.fallbackRatio`. AUTH credentials live in a Secret referenced via
`redis.credentialsSecretName`.

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
| 1     | Redis-backed rate limiter (interface + impl + fallback) — DONE |
| 2     | Transactional outbox + Kafka producer for `concord.events` — DONE |
| 3     | `cmd/concord-worker` binary + Kafka consumer + `webhook_delivery` table — DONE |
| 4     | DLQ inspection + replay endpoints under `/operator/v1/dlq/*` — DONE |
| 5     | Idempotency-Key, circuit breakers, PII redaction — DONE |
| 5     | Idempotency-Key for POST mutations, circuit breakers, audit partitioning, PII redaction |
| 6     | Operator runbook + Grafana dashboards + Prometheus alerts |
