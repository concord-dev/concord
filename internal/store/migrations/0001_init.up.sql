-- 0001_init.up.sql — Concord SaaS schema, dev snapshot.
--
-- Single migration covering the full schema. We're still pre-launch with no
-- production data, so consolidating the iterative history (10 files of churn
-- adding then removing scheduler / agent-key signing tables) into one clean
-- snapshot is the right move. Future schema changes ship as additive
-- migrations starting at 0002.
--
-- Sections, top to bottom:
--   1. Extensions
--   2. Identity & access (organization, user, role, permission, RBAC join
--      tables, api_token, user_session)
--   3. Domain (run, control_override, webhook)
--   4. Auth flows (invitation, password_reset)
--   5. Seed (roles + permissions + role-permission bindings)

-- ── 1. Extensions ────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;    -- case-insensitive email columns

-- ── 2. Identity & access ─────────────────────────────────────────────────

CREATE TABLE organization (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT        NOT NULL,
    slug                  TEXT        NOT NULL UNIQUE,
    -- Opt-in flag for the public /v1/orgs/{slug}/trust-portal route. Off by
    -- default — when false the route returns 404 indistinguishably from a
    -- non-existent org so the endpoint can't be used to enumerate slugs.
    trust_portal_enabled  BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- "user" is a reserved word in SQL; quoting keeps the table name human while
-- forcing every reference site to quote consistently.
CREATE TABLE "user" (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name        TEXT        NOT NULL,
    last_name         TEXT        NOT NULL,
    email             TEXT        NOT NULL UNIQUE,
    password_hash     TEXT,                       -- NULL for SSO-only or invite-pending users
    email_verified_at TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Case-insensitive email lookup; the unique constraint above is case-sensitive,
-- so this covers the actual login path.
CREATE UNIQUE INDEX idx_user_email_lower ON "user" (lower(email));

CREATE TABLE role (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permission (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL UNIQUE,       -- "<resource>:<verb>"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role_permission (
    role_id       UUID NOT NULL REFERENCES role(id)       ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permission(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

-- A user can hold multiple roles inside the same org (e.g. "admin" plus
-- "compliance-officer"). The PK enforces uniqueness per (user, org, role).
CREATE TABLE user_org_role (
    user_id    UUID NOT NULL REFERENCES "user"(id)     ON DELETE CASCADE,
    org_id     UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES role(id)        ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id, role_id)
);
CREATE INDEX idx_user_org_role_org  ON user_org_role(org_id);
CREATE INDEX idx_user_org_role_user ON user_org_role(user_id);

-- API tokens: long-lived programmatic credentials. token_hash is the sha256
-- of the plaintext; the raw secret is shown ONCE at create time and lost.
CREATE TABLE api_token (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    token_hash          TEXT        NOT NULL UNIQUE,
    name                TEXT        NOT NULL,
    created_by_user_id  UUID                 REFERENCES "user"(id) ON DELETE SET NULL,
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_token_org ON api_token(org_id);

-- User sessions: short-lived web-dashboard credentials. Same hash pattern as
-- api_token; ip + user_agent recorded for audit.
CREATE TABLE user_session (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token_hash   TEXT        NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    ip           INET,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_user_session_user    ON user_session(user_id);
CREATE INDEX idx_user_session_expires ON user_session(expires_at);

-- ── 3. Domain ────────────────────────────────────────────────────────────

-- Run rows are inserted by agents via POST /v1/orgs/{slug}/runs already in
-- terminal state. The status enum keeps `failed` so agents can report a
-- crashed scan; today every successful submission writes `succeeded`.
CREATE TABLE run (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    status              TEXT        NOT NULL CHECK (status IN ('succeeded', 'failed')),
    -- `agent` today; the column is kept so a future "operator upload" or
    -- "federated run" provenance lands without a column add.
    source              TEXT        NOT NULL DEFAULT 'agent'
        CHECK (source IN ('agent')),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    error_message       TEXT,
    summary             JSONB,
    findings            JSONB,
    -- Agent CLI version string ("0.5.2" or "0.5.2/ci-prod"); informational.
    agent_version       TEXT,
    triggered_by_token  UUID        REFERENCES api_token(id) ON DELETE SET NULL,
    triggered_by_user   UUID        REFERENCES "user"(id)    ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_run_org_started ON run(org_id, started_at DESC);
CREATE INDEX idx_run_org_source  ON run(org_id, source);

-- Per-org Rego parameter overrides. Agents fetch via GET /v1/orgs/{slug}/overrides
-- and apply locally before running.
CREATE TABLE control_override (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    control_id TEXT        NOT NULL,
    params     JSONB       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, control_id)
);
CREATE INDEX idx_control_override_org ON control_override(org_id);

-- Per-org outbound webhooks. event_kinds is an empty array by default,
-- meaning "deliver every kind". A non-empty array restricts delivery.
CREATE TABLE webhook (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    url           TEXT        NOT NULL,
    secret        TEXT        NOT NULL,                -- HMAC secret, sha256-signed body
    event_kinds   TEXT[]      NOT NULL DEFAULT '{}',
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    last_fired_at TIMESTAMPTZ,
    last_status   INT,
    last_error    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_webhook_org ON webhook(org_id) WHERE enabled;

-- ── 4. Auth flows ────────────────────────────────────────────────────────

-- Invitations: org owners + admins invite teammates by email. The plaintext
-- token is shown ONCE in the create response (and to the eventual email-
-- delivery flow); the DB only holds sha256(token).
--
-- Lifecycle states (a row is in exactly one):
--   pending     accepted_at IS NULL AND revoked_at IS NULL AND now() < expires_at
--   expired     accepted_at IS NULL AND revoked_at IS NULL AND now() >= expires_at
--   accepted    accepted_at IS NOT NULL
--   revoked     revoked_at  IS NOT NULL
CREATE TABLE invitation (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    email       CITEXT      NOT NULL,
    role_id     UUID        NOT NULL REFERENCES role(id),
    invited_by  UUID                 REFERENCES "user"(id) ON DELETE SET NULL,
    token_hash  BYTEA       NOT NULL,                  -- raw sha256(token)
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID                 REFERENCES "user"(id) ON DELETE SET NULL,
    revoked_at  TIMESTAMPTZ,
    revoked_by  UUID                 REFERENCES "user"(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Lookup pending invitations by token. Partial index keeps the structure tight.
CREATE UNIQUE INDEX idx_invitation_token_pending
    ON invitation(token_hash)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
-- List pending invitations for an org.
CREATE INDEX idx_invitation_org_pending
    ON invitation(org_id)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
-- At most one pending invitation per (org, email). Re-invites supersede the
-- prior pending row in code (a transaction inside the store).
CREATE UNIQUE INDEX idx_invitation_org_email_pending
    ON invitation(org_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- Forgot-password tokens. Single-use; consuming one revokes every session
-- for the user. API tokens are intentionally left alone.
CREATE TABLE password_reset (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token_hash    BYTEA       NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    requester_ip  TEXT,                                -- audit only
    requester_ua  TEXT,                                -- audit only
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_password_reset_token_live
    ON password_reset(token_hash)
    WHERE used_at IS NULL;
CREATE INDEX idx_password_reset_user_recent
    ON password_reset(user_id, created_at DESC);

-- ── 4a-bis. Multi-factor auth ────────────────────────────────────────────

-- Per-user TOTP enrollment. At most one secret per user — re-enrolling
-- requires explicit disable first (so an attacker who briefly has session
-- access can't silently swap the second factor out from under the owner).
-- enrolled_at NULL means the user has scanned the QR but not yet typed a
-- valid code; the secret is unused until that step succeeds.
CREATE TABLE user_totp (
    user_id       UUID        PRIMARY KEY REFERENCES "user"(id) ON DELETE CASCADE,
    secret        TEXT        NOT NULL,      -- base32, hot — DO NOT LOG
    enrolled_at   TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time recovery codes for users who lose their authenticator. Hashed
-- with argon2id (same PHC encoding as password_hash) so a read replica
-- compromise can't enumerate codes. used_at marks consumed entries; we
-- keep the row so dashboards can show "N of M codes remaining".
CREATE TABLE user_recovery_code (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    code_hash  TEXT        NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_user_recovery_code_user ON user_recovery_code(user_id)
    WHERE used_at IS NULL;

-- Short-lived challenge token issued by /v1/auth/login when the caller has
-- MFA enrolled. The plaintext is returned ONCE; the DB holds raw sha256
-- (same pattern as invitation / password_reset). Bound to IP + UA so the
-- second step has to come from the same client.
CREATE TABLE mfa_challenge (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token_hash  BYTEA       NOT NULL,
    ip          INET,
    user_agent  TEXT,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_mfa_challenge_token_live
    ON mfa_challenge(token_hash)
    WHERE consumed_at IS NULL;
CREATE INDEX idx_mfa_challenge_user ON mfa_challenge(user_id);

-- ── 4a-ter. Control drift events ─────────────────────────────────────────

-- Drift events: per-run record of every control whose pass/fail status
-- changed relative to the previous run. Powers webhook delivery
-- ("page on regression") and the GET /v1/orgs/{slug}/drift inbox.
--
-- One row per (control_id, transition); a single run that regresses 20
-- controls writes 20 rows. The cardinality is bounded by the size of the
-- control library, not the volume of runs — runs that don't drift write
-- no rows. The (org_id, control_id) index supports the most common UI
-- query: "show me the history of control X in this org."
--
-- prior_run_id can be NULL: when an org's very first run is submitted
-- there's no prior to compare to, so no drift events are written; this
-- column is only NULL when a prior run existed but was later DELETEd
-- (the FK is ON DELETE SET NULL so history survives run pruning).
CREATE TABLE drift_event (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    run_id       UUID        NOT NULL REFERENCES run(id)          ON DELETE CASCADE,
    prior_run_id UUID                 REFERENCES run(id)          ON DELETE SET NULL,
    control_id   TEXT        NOT NULL,
    from_status  TEXT        NOT NULL,
    to_status    TEXT        NOT NULL,
    rationale    TEXT,
    occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_drift_event_org_occurred ON drift_event(org_id, occurred_at DESC);
CREATE INDEX idx_drift_event_run          ON drift_event(run_id);
CREATE INDEX idx_drift_event_control      ON drift_event(org_id, control_id, occurred_at DESC);

-- ── 4b. Audit log ────────────────────────────────────────────────────────

-- Security-sensitive actions land here so compliance teams can answer "who
-- did what, when, from where". Actor identity is split across columns:
-- exactly one of (actor_user_id, actor_token_id) is set for authenticated
-- events; actor_kind disambiguates ('user', 'token', 'operator',
-- 'unauthenticated', 'system'). Operator events (CONCORD_OPERATOR_TOKEN)
-- carry actor_kind='operator' with both ID columns NULL — the operator is
-- a SaaS-platform principal, not a user row.
--
-- ON DELETE behavior:
--   org_id      CASCADE        — org deletion wipes its audit trail
--   actor_user_id  SET NULL    — keep history when a user is deleted
--   actor_token_id SET NULL    — keep history when a token is revoked
-- The SET NULLs intentionally preserve "what happened" even after the
-- subject row is gone.
CREATE TABLE audit_event (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_kind      TEXT        NOT NULL
        CHECK (actor_kind IN ('user', 'token', 'operator', 'unauthenticated', 'system')),
    actor_user_id   UUID                 REFERENCES "user"(id)     ON DELETE SET NULL,
    actor_token_id  UUID                 REFERENCES api_token(id)  ON DELETE SET NULL,
    org_id          UUID                 REFERENCES organization(id) ON DELETE CASCADE,
    action          TEXT        NOT NULL,
    target_type     TEXT,
    target_id       UUID,
    ip              INET,
    user_agent      TEXT,
    request_id      TEXT,
    details         JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_audit_event_org_occurred  ON audit_event(org_id, occurred_at DESC)
    WHERE org_id IS NOT NULL;
CREATE INDEX idx_audit_event_actor_user    ON audit_event(actor_user_id, occurred_at DESC)
    WHERE actor_user_id IS NOT NULL;
CREATE INDEX idx_audit_event_action        ON audit_event(action, occurred_at DESC);

-- ── 5. Seed: canonical roles + permissions ───────────────────────────────

INSERT INTO role (name) VALUES
    ('owner'), ('admin'), ('member'), ('viewer');

-- Permission names follow "<resource>:<verb>". Future migrations APPEND
-- permissions; never rename an existing one or the role bindings break.
INSERT INTO permission (name) VALUES
    -- Org admin surface.
    ('org:read'),
    ('org:update'),
    ('org:delete'),
    -- Members + roles.
    ('members:list'),
    ('members:invite'),
    ('members:remove'),
    ('roles:assign'),
    -- API tokens.
    ('tokens:list'),
    ('tokens:create'),
    ('tokens:revoke'),
    -- Runs + controls (agents POST runs via runs:create).
    ('runs:read'),
    ('runs:create'),
    ('runs:delete'),
    ('controls:read'),
    ('controls:override'),
    -- Outbound webhooks.
    ('webhooks:read'),
    ('webhooks:create'),
    ('webhooks:delete'),
    -- Public trust portal toggle.
    ('trust_portal:manage'),
    -- Org-scoped audit log read (org admins + owners; no write — events are
    -- emitted by the server inline, never user-authored).
    ('audit:read'),
    -- Billing (placeholder for the SaaS commercial layer).
    ('billing:manage');

-- ── Role-permission bindings ─────────────────────────────────────────────

-- owner: every permission.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r CROSS JOIN permission p
WHERE r.name = 'owner';

-- admin: every permission except org:delete and billing:manage.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r CROSS JOIN permission p
WHERE r.name = 'admin'
  AND p.name NOT IN ('org:delete', 'billing:manage');

-- member: can submit runs and read most things; no destructive verbs and no
-- write access to webhooks / overrides / portal settings.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r CROSS JOIN permission p
WHERE r.name = 'member'
  AND p.name IN (
      'org:read', 'members:list', 'tokens:list',
      'runs:read', 'runs:create', 'controls:read',
      'webhooks:read'
  );

-- viewer: pure read-only.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id FROM role r CROSS JOIN permission p
WHERE r.name = 'viewer'
  AND p.name IN (
      'org:read', 'members:list',
      'runs:read', 'controls:read',
      'webhooks:read'
  );
