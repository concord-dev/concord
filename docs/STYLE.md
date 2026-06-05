# Concord — Go style guide

This is the project's authoritative style guide. It is **opinionated**,
**concrete**, and grounded in (a) the established canonical sources and
(b) the patterns this codebase already enforces across `cmd/`,
`internal/`, and `pkg/`.

For anything not stated here, follow the priority order below. When
the canonical sources disagree, this document wins — but only because
it picked one of them; we don't invent new conventions.

## Source of truth

1. **[Effective Go](https://go.dev/doc/effective_go)** — foundational idioms.
2. **[Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)** — the unofficial-official linter-in-prose.
3. **[Google Go Style Guide](https://google.github.io/styleguide/go/)** — normative when foundational sources are silent.
4. **[Uber Go Style Guide](https://github.com/uber-go/guide/blob/master/style.md)** — concrete Do/Don't pairs; the basis for our linter ruleset.
5. **This document** — Concord-specific decisions and codebase conventions.

`gofmt` and `goimports` are non-negotiable. CI fails on unformatted code.

---

## 1. Project layout

```
cmd/                    main packages — one binary per subdirectory
  concord/              agent CLI
  concord-worker/       Kafka consumer + webhook delivery
  server/               concord-server HTTP API
controls/               Rego control library + fixtures (non-Go assets)
deploy/                 Helm chart, Grafana, Prometheus rules
docs/                   ARCHITECTURE.md, runbook.md, STYLE.md (this file)
internal/               application code; not importable from outside the module
  auth/, config/, controls/, eventbus/, kafkax/, logx/, notify/, ...
  server/               HTTP API
    handlers/<group>/   per-domain handler subpackages
    middleware/         RequireOperator / RequireSession / RequireOrgPerm / RequestID / SecurityHeaders
    httpx/              JSON / Error / Logging helpers + ClientIP
    bus/                in-process event bus (SSE fan-out)
    idempotency/        Redis-backed Idempotency-Key middleware
    limiter/            rate limiter (memory + Redis + failover)
    metrics/            Prometheus collectors
    auditpart/          audit_event partition rotator
  store/                Postgres store layer + numbered migrations
  worker/               concord-worker domain (Consumer + Executor + Retrier + Breakers)
pkg/api/v1/             public types shared with external consumers (CLI, customers)
scripts/                one-off operator scripts (psql, smoke tests)
examples/               runnable examples and demo data
```

### Where new code goes

| New thing | Goes in |
|---|---|
| HTTP handler for an existing route group | `internal/server/handlers/<group>/` |
| New domain-event kind | `internal/eventbus/event.go` + a handler that enqueues it |
| New external-system client | dedicated `internal/<system>x` package (`kafkax`, `redisx`, `otelx`) |
| New CLI subcommand | `cmd/concord/cli/<name>.go` |
| New binary | `cmd/<name>/` |
| Public type used by both server and `concord` CLI | `pkg/api/v1` |
| Operator psql one-liner | `docs/runbook.md` §9 |
| New SQL schema | numbered migration in `internal/store/migrations/` |

### When to create a new package

Create a directory only when one of these is true:

- It will be **imported by more than one caller**, OR
- It has **a clear, documentable single responsibility** that doesn't fit an existing package, OR
- It needs to be **independently testable** (with its own test harness).

Do **not** create packages purely for cosmetic neatness. A 200-line
file in `internal/server/server.go` is fine; a 200-line file split
into five packages because "it felt cleaner" is not.

### Forbidden package names

`util`, `utils`, `common`, `shared`, `lib`, `helpers`, `misc`,
`base`. Per Uber + Alex Edwards: these become trash bins. Pick a name
that **describes what's inside**, not where it sits.

If the helper is genuinely cross-cutting, it lives in the package
closest to its first caller — e.g. `httpx.ClientIP` (used by every
handler) lives in `httpx`, not `utils`.

---

## 2. Naming

### Packages
- All lower-case, no underscores, no plurals: `store` not `stores`.
- Short and meaningful: `kafkax` (kafka eXtras), not `kafkahelpers`.
- The "x" suffix is reserved for thin wrappers around external SDKs
  whose own package would otherwise collide (`redisx`, `kafkax`,
  `otelx`, `httpx`, `logx`).

### Files
- Domain noun, lowercase, underscores between words:
  `webhook_delivery.go`, `audit_partition.go`.
- Test files mirror the source: `webhook_delivery_test.go`.
- An `export_test.go` exposes package internals to tests in the
  `_test` companion package.

### Functions, methods, types
- `MixedCaps` for exported, `mixedCaps` for unexported.
- Method receivers: short (`s *Store`, `c *Concord`, `h *Handlers`).
  Pick one letter and stay consistent across the type's methods.
- Single-method interfaces use the `-er` suffix: `Reader`, `Publisher`,
  `Bucket` (where `Bucket` is itself a noun, the verb-noun convention
  bends — that's fine).

### Test functions
- `TestXxx` for plain tests.
- `TestXxx_WhatIsBeingTested` for the second axis when the name
  alone is ambiguous: `TestDLQEvents_AbandonHidesFromDispatcher`.

### Constants and variables
- `MaxBodyBytes`, `CachedTTL` — descriptive, no Hungarian prefixes.
- Sentinel errors: `ErrXxx` exported, `errXxx` unexported.
  `store.ErrNotFound` is the canonical example.

---

## 3. Comments

**Project rule:** one-line godoc on exports only. **No narrative blocks. No section dividers.**

Existing files in this repo carry heavier comments than this rule
prescribes — that's legacy and will be pruned during normal edits.
New code follows the rule.

### Do

```go
// Open dials Postgres via pgxpool. Returns an error on misconfigured DSN
// or unreachable database.
func Open(ctx context.Context, dsn string, opts PoolOptions) (*Store, error) { ... }

// ErrNotFound is returned when a lookup finds no matching row.
var ErrNotFound = errors.New("not found")
```

### Don't

```go
// ─── Public accept flow ──────────────────────────────────────────────  // ← section divider
// Open dials Postgres via pgxpool. dsn is a libpq URL. The pool is       // ← narrative
// health-checked before returning so misconfiguration surfaces immediately.
//
// Lifecycle:
//   1. ParseConfig validates the DSN.
//   2. NewWithConfig allocates connections.                              // ← too much
//   3. Ping verifies reachability.
```

### When a comment IS warranted

- A subtle invariant that isn't obvious from the code.
- A workaround for a known external bug (link the issue).
- A non-trivial performance or security trade-off.

Keep them short, single-paragraph, no ASCII art.

### `TODO` discipline

`// TODO(handle): description` with the GitHub handle of the person
responsible. A `TODO` without an owner is a wish, not a task — and
the linter rejects it.

---

## 4. Errors

### Wrapping
- Wrap with `%w` to preserve the chain:
  ```go
  if err := pool.Ping(ctx); err != nil {
      return fmt.Errorf("pinging db: %w", err)
  }
  ```
- The wrapping prefix is a **verb phrase** describing what was being
  done. Never include the underlying error message in your prefix —
  `%w` already does that.

### Sentinel vs typed
- Sentinels (`store.ErrNotFound`) for the common "not found / not
  applicable" branches. Compare with `errors.Is`.
- Typed errors (`*ValidationError`) only when callers need to
  programmatically extract structured fields.

### Boundary handling
- Internal code returns wrapped errors freely.
- HTTP handlers convert to HTTP status via `httpx.Error`, mapping
  `store.ErrNotFound → 404`, validation → 400, the rest → 500.
- Background tasks log at the boundary (`slog.Error`) and decide
  whether to retry/abandon based on type, not message.

### Don't
- Don't `fmt.Errorf("%v", err)` — strips the chain.
- Don't `return errors.New(err.Error())` — same.
- Don't `_ = err` to silence the linter — handle it or comment why
  the discard is intentional (e.g., best-effort audit write).

---

## 5. Logging (`slog`)

### Use `logx.FromContext(ctx)` in handlers

`request_id` is attached to the context by `middleware.RequestID`.
`FromContext` returns a logger pre-bound with that ID so every log
line correlates with the inflight HTTP request:

```go
func (h *Handlers) SubmitRun(w http.ResponseWriter, r *http.Request) {
    log := logx.FromContext(r.Context())
    log.Info("run submitted", slog.String("org_id", p.Org.ID.String()))
    ...
}
```

### Levels
- `Debug` — verbose, off by default.
- `Info` — normal operations, audit-adjacent ("session created", "webhook delivered").
- `Warn` — recoverable degradations ("limiter primary down, using fallback").
- `Error` — must be **actionable**. If reading this in production at 3am wouldn't change what an on-call does, it's not Error.

Per Google: `Error` is expensive (often pages). Don't use it for
"unexpected but harmless".

### Structure
- Keys are lower_snake_case strings: `slog.String("org_id", ...)`.
- One concept per attr: `slog.String("err", err.Error())` not
  `"err: foo"`. Slog renders structured.
- PII is redacted by `logx.RedactingHandler` (Phase 5); don't rely on
  it — keep secrets out of attrs altogether.

---

## 6. Database access

### Single Store
Every Postgres call goes through `internal/store/Store`. Handlers
never reach for `pgxpool` directly. The Store enforces:

- DSN validation + pool lifecycle.
- `pgx.ErrNoRows` → `store.ErrNotFound` translation.
- Transaction helpers (`ClaimPendingDeliveries`, etc.).

### Method shape
- `Get*` / `List*` / `Create*` / `Update*` / `Delete*` for CRUD.
- Tx-scoped variants take a `pgx.Tx` first: `EnqueueTx(ctx, tx, ...)`.
- Returns: `(value, error)` for single rows; `([]value, error)` for
  lists; `error` for mutations.

### Migrations
- Numbered: `NNNN_short_name.up.sql` + `NNNN_short_name.down.sql`.
- Forward-only in production; `down.sql` exists for dev rollback.
- Idempotent helpers (`CREATE INDEX IF NOT EXISTS`, PL/pgSQL
  functions checking `pg_class` first) are preferred over conditional
  application logic.
- Pre-launch: structural changes may drop + recreate. Post-launch:
  data-preserving migrations only.

### Indexing
- Add an index when a query's `EXPLAIN` shows a sequential scan AND
  the table will grow unbounded.
- Prefer **partial indexes** for predicate-restricted queries (e.g.,
  `WHERE status = 'failed'`).
- The partition key must be in the PK on partitioned tables.

---

## 7. HTTP handlers

### Layout
- One file per resource: `handlers_invitations.go`, `handlers_runs.go`.
- Helpers in `httpx`: `JSON`, `Error`, `ClientIP`, `Logging`.
- Authentication and authorization happen **in middleware**, not in
  the handler. Handlers assume `authctx.PrincipalFrom(ctx)` succeeds.

### Response shape
- JSON via `httpx.JSON(w, status, payload)`.
- Errors via `httpx.Error(w, status, message)`. Message is human-readable;
  no internal stack traces.
- 204 No Content for successful mutations that have no body.

### Middleware composition
The router applies, from outermost to innermost:

```
otelhttp → RequestID → Logging → Metrics → SecurityHeaders → CORS → mux
                                                                  └→ per-route gate (Auth + RBAC)
                                                                                └→ Idempotency-Key (mutating routes)
                                                                                              └→ handler
```

Inner middleware can see request_id (context) and the matched route
pattern (`r.Pattern`).

### Validation
- Reject early with 400 before doing real work.
- Body size caps on every POST (see `internal/server/handlers/org/submit_run.go::maxSubmissionBytes`).
- Use `io.LimitReader` not just `r.Body.Read` — the former enforces
  the cap.

---

## 8. Background tasks

### Lifecycle anchored to `Concord`
Every long-running goroutine is:
1. **Constructed** in `NewConcord` (or wired in via `Options`).
2. **Started** with a `context.Context` derived from a fresh
   `context.Background()` — NOT the request context.
3. **Stopped** in `Concord.Shutdown` by cancelling its context.

The dispatcher, retrier, and audit partition rotator all follow this
pattern. So should new tasks.

### Tracked goroutines
For per-request fan-out (webhook delivery, async email), use
`internal/server/bg.Runner`. Its `WaitGroup` is consulted by
`Concord.Shutdown` so SIGTERM drains in-flight work.

### Don't
- Don't spawn untracked `go func()` from a handler. The graceful
  shutdown guarantee is the whole point of `bg.Runner`.
- Don't tie a background task's context to a request. The request
  ends; the task must outlive it.

---

## 9. Testing

### Test layout: alongside the code, partitioned by build tag
Go convention puts `*_test.go` next to the source file it exercises.
We stick with that — moving tests to a separate tree loses access to
unexported identifiers (`package foo` white-box tests), breaks
`go test ./...` ergonomics, and pulls every contributor away from the
shape every other Go project uses.

What we *do* use to keep `go test ./...` fast and the suite organised
is **build tags**. Three tiers:

| Tier | Build tag | Where it lives | What it touches |
|---|---|---|---|
| **unit** | none (default) | next to source | pure Go; no Postgres / Redis / Kafka / network / external binary |
| **integration** | `//go:build integration` | next to source | one or more real backends; spawns child processes; hits the registry |
| **e2e** | `//go:build e2e` | dedicated top-level `e2e/` module (own `go.mod`) | spans multiple Concord binaries (CLI → server → worker) and asserts on DB state |

Commands:

```
go test ./...                         # unit only (every CI PR)
go test -tags integration ./...       # unit + integration (CI integration job)
go test -tags e2e ./e2e/...           # cross-binary scenarios (concord-platform only)
go test -race -tags integration ./... # the race-detector gate
```

Why the `e2e/` module is separate: it builds the production binaries
via `go build` and execs them, so it depends on real Postgres + the
sibling concord checkout. Keeping it in its own `go.mod` keeps those
heavy deps out of the platform's main module graph.

### Race detector by default
`go test -race -tags integration ./...` is the CI gate. Locally, use
the same invocation. We have hit dozens of races during this project's
development — the detector is non-negotiable.

### Real backends, not mocks
Integration tests run against real Postgres / Redis / Kafka:

```
CONCORD_TEST_DATABASE_URL  → real Postgres (concord/concord-dev)
CONCORD_TEST_REDIS_ADDR    → real Redis
CONCORD_TEST_KAFKA_BROKERS → real Redpanda
```

Tests skip cleanly when the backend isn't reachable (so a developer
without Kafka running can still iterate on non-Kafka code), but CI
provides all three. Reason: mocked DBs have repeatedly hidden bugs
that surfaced in production. Postgres semantics differ enough
(JSONB whitespace, isolation levels, partial indexes) that mocking
is a false economy.

### Table tests
Use them for matrix-of-inputs cases:

```go
for _, c := range []struct {
    in   string
    want int
}{
    {"a", 1},
    {"b", 2},
} {
    t.Run(c.in, func(t *testing.T) { ... })
}
```

But don't force every test into a table — single-case tests are fine
when the case is the whole point.

### Test helpers
- `openTestStore(t)` / `openIsolatedStore(t)` for DB-backed tests.
- `newHarness(t)` for the full server stack.
- `requireRedis(t)` / `requireRedis(t)` for backend-dependent tests.

### Assertions
- `github.com/stretchr/testify/assert` for soft assertions (test
  continues on failure).
- `github.com/stretchr/testify/require` for hard ones (test stops).
- Reach for `require` when subsequent assertions would all fail too —
  it makes the failure log readable.

### Coverage isn't a goal
Coverage is a side-effect of good tests. Don't chase a percentage.
Cover the **happy path**, the **canonical error paths**, and the
**security-critical edges** (auth, rate-limit, idempotency). Skip
trivial getters.

---

## 10. Concurrency

### Goroutines are owned
Every goroutine must have an identifiable owner that knows how to
stop it: a `context.CancelFunc`, a closed channel, or
`bg.Runner.Wait`. Anonymous `go func()` with no shutdown path is a
review-blocker.

### Locks
- Prefer immutable values + channels over `sync.Mutex` when feasible.
- When a mutex is needed: name the lock `mu`, group it with the fields
  it protects, comment which fields are guarded only when it's not
  obvious.

### Shared state
- `atomic.Int64` / `atomic.Bool` for counters and flags.
- `sync.Map` only when benchmarks show it beats `map + mutex`. Usually
  the latter is faster and clearer.

---

## 11. Dependencies

### When to add one
- **Add** when the alternative is "non-trivial code we'd have to
  maintain" AND the dep has: > 1k stars, recent commits, a maintained
  release process, no transitive surprises.
- **Don't add** for one-line helpers or things `stdlib` already does.

### Version pinning
- `go.mod` carries the exact versions. CI runs `go mod tidy` and
  fails on diffs.
- `govulncheck` runs in CI. CVE-flagged versions block merges.

### Current Concord deps
We standardize on:
- `github.com/jackc/pgx/v5` — Postgres
- `github.com/redis/go-redis/v9` — Redis
- `github.com/segmentio/kafka-go` — Kafka (pure Go, no CGO)
- `github.com/sony/gobreaker` — circuit breaker
- `github.com/google/uuid` — UUIDs
- `github.com/stretchr/testify` — test assertions
- `go.opentelemetry.io/otel/*` — tracing
- `github.com/prometheus/client_golang` — metrics
- `golang.org/x/time/rate` — token bucket (in-memory limiter)
- `github.com/spf13/cobra` — CLI

Adding a dep means: updating `go.mod`, `go.sum`, AND mentioning it
in the relevant ARCHITECTURE.md / STYLE.md section so the next reader
knows what role it plays.

---

## 12. Configuration

### Three layers, in precedence order
1. **Command-line flags** — highest priority, used in dev.
2. **Environment variables** — `CONCORD_*` prefix, the prod default.
3. **Defaults baked into the binary** — last resort.

Every flag should have an env-var equivalent. Pattern:

```go
fs.StringVar(&kafkaTopic, "kafka-topic",
    envOr("CONCORD_KAFKA_TOPIC", "concord.events"),
    "Topic the outbox dispatcher publishes to.")
```

### Helm / k8s
`deploy/helm/concord/values.yaml` exposes every operationally-relevant
knob. The chart's ConfigMap carries non-secrets; Secrets carry
credentials.

### Don't
- Don't read env vars deep in the call stack. Resolve in `cmd/*` and
  pass through.
- Don't bake URLs or hostnames into the binary. Even the OTel
  endpoint is a flag.

---

## 13. Security defaults

### Authentication
- `Authorization: Bearer concord_...` for API tokens.
- `Authorization: Bearer concord_sess_...` for user sessions.
- `Authorization: Bearer <CONCORD_OPERATOR_TOKEN>` for operator routes.
- Operator token is constant-time-compared.

### Secrets in the DB
- `argon2id` for passwords (PHC string format).
- `sha256(plaintext)` for API tokens, sessions, invitation tokens,
  password-reset tokens. Plaintext shown ONCE at mint time.
- Recovery codes: `argon2id`, count-capped at 10 per user.

### Outbound
- `httpx.ClientIP` is the canonical client-IP extractor. Don't
  re-implement.
- HMAC-SHA256 for webhook signing; `sha256=<hex>` envelope.
- Circuit breakers in front of every webhook POST (Phase 5).

### Logging
- `logx.RedactingHandler` filters sensitive attrs (Phase 5). Don't
  put secrets in slog calls in the first place — the redactor is a
  last line of defence.

### Migrations
- New tables get explicit `ON DELETE CASCADE` / `SET NULL` per FK.
  The decision is documented in the migration comment.

---

## 14. Tooling & CI

Local development:

```
make lint       # vet + staticcheck + deadcode (must pass)
make test       # full test sweep
make test-race  # full sweep with -race
make vuln       # govulncheck against module + stdlib CVEs
make tools      # install pinned analyzer versions
```

CI runs five jobs in parallel: lint, vuln, test, build, helm. All
must pass to merge. CI provisions Postgres, Redis, and Redpanda as
service containers so the integration tests run for real.

### Lint config
- `go vet` — built-in.
- `staticcheck v0.7.0` — pinned. Bumping is a deliberate PR.
- `deadcode v0.45.0` — pinned. Unreachable funcs fail the build.
- `govulncheck v1.3.0` — pinned. Stdlib + dep CVEs block merges.

### Pre-commit
There's no enforced pre-commit hook. The Makefile targets are the
authoritative gates. Many of us alias `make lint && make test-race`
to a local hook.

---

## 15. Anti-patterns we've already burned on

These are calibration points — the project has hit each at least
once during development, and the fix is now codified above.

| Anti-pattern | Where it bit us | Codified rule |
|---|---|---|
| Reaching for `pgxpool` directly from a handler | early prototype, leaked locks on rollback | §6: Store is the only DB surface |
| `// utils.go` of unrelated helpers | early phase, became a trash bin | §1: forbidden package names |
| Anonymous `go func()` in handler | webhook fan-out, lost on SIGTERM | §8: tracked goroutines via `bg.Runner` |
| Mocking Postgres in unit tests | JSONB whitespace divergence wasted hours | §9: real backends, not mocks |
| `// section divider` ASCII boxes | accumulated cruft, hard to grep | §3: no section dividers |
| `if err != nil { return err }` without context | error chains lost the operation | §4: wrap with `%w` and a verb phrase |
| Untracked goroutines for "fire and forget" | shutdown lost in-flight webhook deliveries | §8: lifecycle anchored to `Concord` |

---

## 16. Adoption notes

This guide describes the **target** state. The codebase as of the
Phase 6 commit (`d6e334d`) is broadly compliant but carries heavier
comment density than §3 prescribes — that's intentional legacy from
the early phases. Future PRs prune opportunistically; we don't open
churn-only PRs.

When in doubt: search for an existing example in the repo that does
the same thing, copy its shape, and link the file in your PR
description so the reviewer can confirm the choice.
