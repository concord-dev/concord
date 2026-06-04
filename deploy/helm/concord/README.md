# concord Helm chart

Deploys the Concord API server into Kubernetes. Single Deployment +
ServiceAccount + Service, optional Ingress / HPA / PDB.

Postgres is **not** managed by this chart — point at an external
instance (managed RDS / Cloud SQL / CrunchyData operator / your own
StatefulSet).

## Install

```bash
# Required: a Secret holding the Postgres DSN.
kubectl create secret generic concord-db \
  --from-literal=DATABASE_URL='postgres://concord:...@db.internal:5432/concord?sslmode=require'

# Optional: SaaS-operator token for /operator/v1/*.
kubectl create secret generic concord-operator \
  --from-literal=token=$(openssl rand -hex 32)

# Optional: SMTP creds.
kubectl create secret generic concord-smtp \
  --from-literal=username=apikey \
  --from-literal=password=$SENDGRID_KEY

helm install concord deploy/helm/concord \
  --set image.tag=$(git rev-parse --short HEAD) \
  --set database.databaseUrlSecret.name=concord-db \
  --set config.operatorTokenSecretName=concord-operator \
  --set smtp.host=smtp.sendgrid.net \
  --set smtp.from='Concord <noreply@your.org>' \
  --set smtp.credentialsSecretName=concord-smtp \
  --set replicaCount=3 \
  --set autoscaling.enabled=true
```

## Production checklist

- [ ] `image.digest` pinned, not `tag` — immutable deploys
- [ ] `database.databaseUrlSecret.name` set; DSN uses TLS (`sslmode=require`)
- [ ] `config.operatorTokenSecretName` set (otherwise tenant provisioning is impossible)
- [ ] `smtp.host` set (otherwise reset/invite emails just log)
- [ ] `replicaCount >= 2` AND `autoscaling.enabled=true` OR you accept the planned HPA off path
- [ ] `ingress.enabled=true` with TLS via cert-manager
- [ ] cluster has a `NetworkPolicy` allow-list (this chart doesn't ship one — it would conflict with org-wide policy stacks)
- [ ] Prometheus is scraping `/metrics` (the chart sets the standard
      `prometheus.io/scrape` annotations; a ServiceMonitor isn't shipped
      to avoid forcing an Operator-pattern stack)

## Probes

| Endpoint   | Purpose                          | Failure action          |
|------------|----------------------------------|-------------------------|
| `/healthz` | process is up                    | Pod restart (liveness)  |
| `/readyz`  | deps (Postgres) reachable        | Service drain (readiness) — no restart |

Splitting the two probes is deliberate: a Postgres blip should drain
traffic from the Pod (so the load balancer routes around it) but NOT
restart the process (which can't fix a downed DB anyway and only adds
crash-loop pain).

## Graceful shutdown

`terminationGracePeriodSeconds: 35` + `config.shutdownTimeout: 30s`
gives the in-flight webhook + email drain a 30-second budget with 5s
headroom before kubelet sends SIGKILL. Tune both together — keep the
grace period **strictly greater** than the shutdown timeout.

## What's intentionally NOT here

- **Database provisioning** — the chart wires Concord at an existing
  Postgres. Run a managed instance or use the postgres-operator chart
  separately; mixing those into this chart would force opinionated
  defaults that production deploys end up overriding anyway.
- **NetworkPolicy** — cluster-wide policy stacks (Calico/Cilium global
  rules) generally drive this. Add a `NetworkPolicy` Resource manually
  if your stack expects per-app policies.
- **ServiceMonitor** — depends on whether you run kube-prometheus
  (CRD-based) or a self-hosted Prometheus (annotation-based). The
  chart sets the annotation-based discovery; add a ServiceMonitor in
  your own values overlay if you use the CRD path.
