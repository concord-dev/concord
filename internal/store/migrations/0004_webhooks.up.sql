-- 0004_webhooks.up.sql
-- Per-org outbound webhooks. The server fires HMAC-signed POSTs to every
-- enabled webhook whenever a run lifecycle event publishes on the bus.
--
-- event_kinds is an empty array by default, meaning "deliver every kind".
-- A non-empty array restricts delivery to those specific kinds (e.g.
-- {'run.completed', 'run.failed'} for an alerting-only sink).

CREATE TABLE webhook (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    secret        TEXT NOT NULL,
    event_kinds   TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT true,
    last_fired_at TIMESTAMPTZ,
    last_status   INT,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webhook_org ON webhook(org_id) WHERE enabled;

-- Webhook permissions. Read is wide (any org member should see what's
-- configured); create/delete are admin-shaped.
INSERT INTO permission (name) VALUES
    ('webhooks:read'),
    ('webhooks:create'),
    ('webhooks:delete')
ON CONFLICT (name) DO NOTHING;

-- Grant all three to owner + admin; grant read to member + viewer.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name IN ('owner', 'admin')
  AND p.name IN ('webhooks:read', 'webhooks:create', 'webhooks:delete')
ON CONFLICT DO NOTHING;

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name IN ('member', 'viewer')
  AND p.name = 'webhooks:read'
ON CONFLICT DO NOTHING;
