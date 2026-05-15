-- Agent push mode: customers run the OSS collector ("concord agent") on their
-- own infrastructure and POST findings back. Concord-the-SaaS never receives
-- their AWS/GitHub/Snyk credentials.
--
-- Agents may optionally register an Ed25519 public key. When a push carries
-- both X-Concord-Agent-Key-Id + X-Concord-Agent-Signature headers, the server
-- verifies the signature and records the agent_key_id on the run row. Pushes
-- without those headers are still accepted (API token auth alone) but recorded
-- as source='unsigned' so operators can see the difference.

CREATE TABLE agent_key (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    -- 32-byte Ed25519 public key, stored raw. base64 only used on the wire.
    public_key          BYTEA NOT NULL,
    created_by_user_id  UUID REFERENCES "user"(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ
);

CREATE INDEX idx_agent_key_org ON agent_key(org_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX idx_agent_key_org_name ON agent_key(org_id, name) WHERE revoked_at IS NULL;

-- Per-org sanity: at most one active key with a given name. Revoked keys keep
-- the name they had so audit trails stay readable.

-- Extend run to capture provenance for agent-submitted rows. NULL on every
-- existing (server-side worker) row.
ALTER TABLE run
    ADD COLUMN source              TEXT NOT NULL DEFAULT 'server'
        CHECK (source IN ('server', 'agent', 'unsigned')),
    ADD COLUMN agent_id            UUID REFERENCES agent_key(id) ON DELETE SET NULL,
    ADD COLUMN agent_version       TEXT,
    ADD COLUMN signature_verified  BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX idx_run_org_source ON run(org_id, source);

-- New permission for managing agent keys. Owner + admin only — adding a key
-- is a privileged action because it grants future runs the ability to assert
-- "this is a verified agent".
INSERT INTO permission (name) VALUES ('agent_keys:manage')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name IN ('owner', 'admin')
  AND p.name = 'agent_keys:manage'
ON CONFLICT DO NOTHING;
