-- 0001_init.up.sql
-- Concord SaaS schema, v1 (RBAC).
--
-- Identity & access:
--   organization        one row per customer org (slug used in URLs)
--   "user"              one row per human; password_hash optional (web login)
--   role                bundle of permissions; data, not enum, so new roles
--                       can be added without code changes
--   permission          atomic capability, named "<resource>:<verb>"
--   role_permission     M:N role <-> permission
--   user_org_role       a user holds zero or more roles inside each org
--   api_token           long-lived programmatic credential, scoped to an org
--   user_session        short-lived browser session for the web dashboard
--
-- Domain:
--   run                 every compliance evaluation, scoped to an org
--
-- Pre-launch seed (at the bottom of this file) installs four canonical roles
-- (owner / admin / member / viewer) and binds them to a starter permission
-- set. Permissions are append-only across future migrations.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ── Organizations ────────────────────────────────────────────────────────

CREATE TABLE organization (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Users ────────────────────────────────────────────────────────────────
-- "user" is a reserved word in SQL; quoting keeps the table name human while
-- forcing every reference site to quote consistently.

CREATE TABLE "user" (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name        TEXT NOT NULL,
    last_name         TEXT NOT NULL,
    email             TEXT NOT NULL UNIQUE,
    password_hash     TEXT,            -- NULL for SSO-only or invite-pending users
    email_verified_at TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Case-insensitive email lookup; the unique constraint above is case-sensitive,
-- so this covers the actual login path.
CREATE UNIQUE INDEX idx_user_email_lower ON "user" (lower(email));

-- ── Roles + permissions (RBAC) ───────────────────────────────────────────

CREATE TABLE role (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permission (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL UNIQUE,   -- "<resource>:<verb>", e.g. "runs:create"
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role_permission (
    role_id       UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permission(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

-- A user can hold multiple roles inside the same org (e.g. "admin" plus
-- "compliance-officer"). The PK enforces uniqueness per (user, org, role).
CREATE TABLE user_org_role (
    user_id    UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    org_id     UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES role(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id, role_id)
);
CREATE INDEX idx_user_org_role_org ON user_org_role(org_id);
CREATE INDEX idx_user_org_role_user ON user_org_role(user_id);

-- ── API tokens (programmatic auth, long-lived) ───────────────────────────

CREATE TABLE api_token (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    token_hash          TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    created_by_user_id  UUID REFERENCES "user"(id) ON DELETE SET NULL,
    last_used_at        TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_api_token_org ON api_token(org_id);

-- ── User sessions (web dashboard, short-lived) ───────────────────────────

CREATE TABLE user_session (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    ip           INET,
    user_agent   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_user_session_user ON user_session(user_id);
CREATE INDEX idx_user_session_expires ON user_session(expires_at);

-- ── Runs (domain) ────────────────────────────────────────────────────────

CREATE TABLE run (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    status              TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed')),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at        TIMESTAMPTZ,
    error_message       TEXT,
    summary             JSONB,
    findings            JSONB,
    triggered_by_token  UUID REFERENCES api_token(id) ON DELETE SET NULL,
    triggered_by_user   UUID REFERENCES "user"(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_run_org_started ON run(org_id, started_at DESC);

-- ── Seed: canonical roles + permissions ──────────────────────────────────

INSERT INTO role (name) VALUES
    ('owner'), ('admin'), ('member'), ('viewer')
ON CONFLICT (name) DO NOTHING;

-- Permission names follow "<resource>:<verb>". New permissions land in
-- additive migrations; never rename an existing one (the role bindings
-- would break).
INSERT INTO permission (name) VALUES
    ('org:read'),
    ('org:update'),
    ('org:delete'),
    ('members:list'),
    ('members:invite'),
    ('members:remove'),
    ('roles:assign'),
    ('tokens:list'),
    ('tokens:create'),
    ('tokens:revoke'),
    ('runs:read'),
    ('runs:create'),
    ('runs:delete'),
    ('controls:read'),
    ('controls:override'),
    ('billing:manage')
ON CONFLICT (name) DO NOTHING;

-- owner: every permission.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name = 'owner'
ON CONFLICT DO NOTHING;

-- admin: every permission except org:delete and billing:manage.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name = 'admin'
  AND p.name NOT IN ('org:delete', 'billing:manage')
ON CONFLICT DO NOTHING;

-- member: can run checks and read most things; no destructive verbs.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name = 'member'
  AND p.name IN (
      'org:read', 'members:list', 'tokens:list',
      'runs:read', 'runs:create', 'controls:read'
  )
ON CONFLICT DO NOTHING;

-- viewer: pure read-only.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name = 'viewer'
  AND p.name IN ('org:read', 'members:list', 'runs:read', 'controls:read')
ON CONFLICT DO NOTHING;
