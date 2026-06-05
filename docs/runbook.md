# Concord — operator runbook

This is the on-call playbook for `concord-server` and `concord-worker`.
Every entry follows the same shape: **symptom → triage queries →
remediation**. The "remediation" sections name the exact Store method
or operator endpoint to use; `psql -d concord` snippets are the
escape hatch when the API is wedged.

Conventions:
- `$OP_TOKEN` is the `CONCORD_OPERATOR_TOKEN` value for the cluster.
- `$BASE` is the server's external URL (e.g. `https://api.concord.example`).
- Time fields are UTC unless otherwise noted.

---

## 1. The dispatcher is falling behind

**Symptom:** `concord_outbox_lag_seconds` climbs above 60s and stays
there for > 5 minutes. Downstream consumers (the worker, any external
subscriber) see stale events.

**Triage:**

```bash
# Count outbox rows by state. The "dead" cohort is Phase 4 DLQ
# territory; the "pending" cohort is what the dispatcher should be
# chewing through.
psql -c "
  SELECT
    CASE
      WHEN published_at IS NOT NULL THEN 'published'
      WHEN abandoned_at IS NOT NULL THEN 'abandoned'
      WHEN attempt_count >= 20      THEN 'dead'
      ELSE 'pending'
    END AS state,
    count(*)
  FROM event_outbox
  GROUP BY 1 ORDER BY 1;"

# Inspect the oldest pending row.
psql -c "
  SELECT id, kind, attempt_count, last_error, next_attempt_at
  FROM event_outbox
  WHERE published_at IS NULL AND abandoned_at IS NULL
    AND attempt_count < 20
  ORDER BY created_at LIMIT 5;"
```

**Common causes & fixes:**

| Diagnosis | Signal | Fix |
|---|---|---|
| Kafka unreachable | `last_error` mentions `dial tcp` or `EOF` | check broker health; the dispatcher auto-recovers when Kafka returns |
| Postgres slow | dispatcher logs `tick failed` with `context deadline exceeded` | check `concord_db_pool_*` saturation; scale up pool or DB |
| Schema drift | `last_error` mentions unknown column | verify migrations applied; `concord-server --skip-migrate=false` |
| Dispatcher not running | `concord_outbox_published_total` is flat | check pod readiness; dispatcher only runs in `concord-server` |

**If you must abandon a stuck batch:** use the Phase 4 DLQ replay /
abandon endpoints (`POST /operator/v1/dlq/events/{id}/replay`,
`DELETE /operator/v1/dlq/events/{id}`). Bulk abandon is a SQL
workaround:

```sql
UPDATE event_outbox SET abandoned_at = now()
WHERE published_at IS NULL AND abandoned_at IS NULL
  AND created_at < now() - interval '24 hours';
```

---

## 2. A webhook receiver is wedged

**Symptom:** `concord_worker_dead_total` climbs for one kind; one
webhook URL accumulates `status='dead'` rows.

**Triage:**

```bash
curl -H "Authorization: Bearer $OP_TOKEN" \
  "$BASE/operator/v1/dlq/deliveries?limit=20" | jq .

# Or directly via psql, grouped by webhook so you see the bad receiver:
psql -c "
  SELECT w.url, count(*) AS dead, max(d.last_attempted_at) AS last
  FROM webhook_delivery d JOIN webhook w ON w.id = d.webhook_id
  WHERE d.status = 'dead' AND d.abandoned_at IS NULL
  GROUP BY w.url ORDER BY dead DESC LIMIT 10;"
```

**Fix:**

1. Confirm the receiver is recovered (curl it from a worker pod's host
   network or check `concord_worker_breaker_state_changes_total{state="closed"}`).
2. Bulk replay:

   ```bash
   for id in $(psql -tAc "
       SELECT id FROM webhook_delivery
       WHERE status='dead' AND webhook_id = '<id>' AND abandoned_at IS NULL"); do
     curl -X POST -H "Authorization: Bearer $OP_TOKEN" \
       "$BASE/operator/v1/dlq/deliveries/$id/replay"
   done
   ```

3. If the receiver is gone for good, abandon en masse:

   ```sql
   UPDATE webhook_delivery
   SET abandoned_at = now()
   WHERE status = 'dead' AND webhook_id = '<id>' AND abandoned_at IS NULL;
   ```

---

## 3. The circuit breaker won't stop tripping

**Symptom:** `concord_worker_breaker_state_changes_total{state="open"}`
keeps incrementing for one host; deliveries see `last_error =
"circuit_open: ..."`.

**Diagnosis:** the receiver is consistently failing. The breaker is
*doing its job* — the underlying receiver needs fixing. Use the
worker logs (`circuit breaker state change`) to find the offending
host; treat it as runbook §2.

**Tuning knobs** (env vars on the worker Deployment):

| Var | Default | When to change |
|---|---|---|
| `CONCORD_WORKER_BREAKER_MAX_FAILS` | 5 | raise if your retry budget already accepts more failures |
| `CONCORD_WORKER_BREAKER_OPEN_TIMEOUT` | 30s | raise on noisy receivers to give them more cooldown |
| `CONCORD_WORKER_BREAKER_HALF_OPEN_MAX` | 1 | raise to recover faster on high-throughput receivers |

---

## 4. Audit-partition rotator is failing

**Symptom:** `concord_audit_partition_rotator_errors_total` is
non-zero, or `concord_audit_partitions_created_total` has been flat
for too long.

**Triage:**

```bash
psql -c "
  SELECT c.relname, pg_get_expr(c.relpartbound, c.oid)
  FROM pg_inherits i
  JOIN pg_class c       ON c.oid = i.inhrelid
  JOIN pg_class parent  ON parent.oid = i.inhparent
  WHERE parent.relname = 'audit_event'
  ORDER BY c.relname;"
```

**Fix (manual rotation):**

```sql
-- Create next month's partition if missing. Idempotent.
SELECT * FROM concord_ensure_audit_partition(
  date_trunc('month', now() + interval '1 month')
);
```

This is the same code path the background task uses. After the
manual run, the rotator will resume normally on its next tick.

**Recovery from a missed rollover** (audit inserts started failing
because no partition matches the row's `occurred_at`):

```sql
SELECT * FROM concord_ensure_audit_partition(now());
```

Then re-issue the failed audit writes (the audit handler is
best-effort, so they're already logged but not persisted).

---

## 5. Idempotency cache is stale or wedged

**Symptom:** `concord_idempotency_redis_errors_total` is climbing and
the middleware has degraded to pass-through (duplicate POSTs creating
duplicate rows).

**Triage:**

```bash
redis-cli -h <host> PING
redis-cli -h <host> INFO memory | head -10
redis-cli -h <host> --scan --pattern "idem:*" | wc -l
```

**Fix:**

- Restart the Redis pod / failover the Sentinel cluster.
- If a specific key is poisoned (e.g. a stuck "pending" sentinel from
  a crashed handler), delete it:

  ```bash
  redis-cli DEL "idem:org:<slug>:<key>"
  ```

- The Pending TTL is 5 minutes, so a stuck slot self-heals within
  that window without intervention.

---

## 6. Rate limiter is over- or under-permissive

**Symptom:** Either users are getting 429s when they shouldn't, OR
brute-force traffic is sneaking through.

**Triage:**

```bash
# Recent 429s by route — quick "are we limiting the right thing?"
psql -c "
  SELECT a.action, count(*)
  FROM audit_event a
  WHERE occurred_at > now() - interval '15 minutes'
    AND a.action LIKE '%.failure'
  GROUP BY 1 ORDER BY 2 DESC;"

# Per-pod fallback hits — non-zero means Redis is failing over
curl -s $BASE/metrics | grep concord_limiter_primary_errors_total
```

**Fix:**

- If Redis is the problem: see Phase 1 — the failover bucket is
  carrying load. Restore Redis and the primary path resumes.
- If the limit values are wrong: edit `defaultAuthLimits` /
  `defaultPublicLimits` in `internal/server/server.go` and redeploy.
  Per-route customization is via the chart's `redis.fallbackRatio`
  for the tightening factor.

---

## 7. Rotating the operator token

The `CONCORD_OPERATOR_TOKEN` is a single shared secret across all
operator endpoints. Rotation flow:

1. Generate a new token (≥ 32 random bytes, base64url):
   ```bash
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
   ```
2. Update the Secret backing `config.operatorTokenSecretName`:
   ```bash
   kubectl -n concord create secret generic concord-operator-token \
     --from-literal=token=$NEW_TOKEN \
     --dry-run=client -o yaml | kubectl apply -f -
   ```
3. Restart `concord-server` so it picks up the new env:
   ```bash
   kubectl -n concord rollout restart deploy/concord-server
   ```
4. Existing `/operator/v1/*` clients must update their bearer header.

There's no overlap window — the token is constant-time-compared
in-process, so the new value is the only authoritative one after the
restart. Plan downtime for the operator surface accordingly (the
SaaS API itself stays up; only `/operator/v1/*` rejects until the
client catches up).

---

## 8. Reading the metrics

| Metric | What it tells you |
|---|---|
| `concord_http_request_duration_seconds` | API latency by route + method |
| `concord_outbox_lag_seconds` | producer-side dispatch lag (gauge) |
| `concord_outbox_published_total` / `_failed_total` / `_dead_total` | dispatcher outcomes by kind |
| `concord_worker_consumed_total` | Kafka messages the worker chewed through |
| `concord_worker_attempts_total{outcome}` | webhook delivery outcomes (succeeded\|non_2xx\|network_error) |
| `concord_worker_dead_total{kind}` | deliveries that hit max-attempts (DLQ candidates) |
| `concord_worker_breaker_state_changes_total{state}` | circuit breaker transitions |
| `concord_limiter_primary_errors_total{gate}` | Redis-backed rate limiter failovers |
| `concord_idempotency_hits_total` / `_mismatch_total` / `_pending_total` | dedupe outcomes |
| `concord_audit_partition_rotator_errors_total` | partition rotation health |

A Grafana dashboard with these panels pre-built lives at
`deploy/grafana/concord.json`; Prometheus alerting rules at
`deploy/prometheus/alerts.yml`.

---

## 9. Common psql one-liners

```sql
-- "How many runs were submitted in the last hour, by org?"
SELECT o.slug, count(*) FROM run r JOIN organization o ON o.id = r.org_id
WHERE r.started_at > now() - interval '1 hour' GROUP BY 1 ORDER BY 2 DESC;

-- "What's the oldest pending outbox row?"
SELECT id, kind, age(now(), created_at) FROM event_outbox
WHERE published_at IS NULL AND abandoned_at IS NULL
ORDER BY created_at LIMIT 1;

-- "Show me dead webhook deliveries grouped by URL"
SELECT w.url, count(*) FROM webhook_delivery d JOIN webhook w ON w.id = d.webhook_id
WHERE d.status = 'dead' AND d.abandoned_at IS NULL GROUP BY 1 ORDER BY 2 DESC;

-- "What audit-event partitions exist?"
SELECT c.relname, pg_get_expr(c.relpartbound, c.oid)
FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
WHERE p.relname = 'audit_event' ORDER BY c.relname;
```
