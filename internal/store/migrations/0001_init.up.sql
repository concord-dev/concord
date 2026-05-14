-- 0001_init.up.sql
-- Concord SaaS schema, v1.
--
-- Hierarchy:
--   organizations  one row per customer org
--   users          one row per human (no auth yet; web login lands later)
--   memberships    M:N between users and organizations, with role
--   api_tokens     belong to an organization (used by CI / CLI)
--   runs           every compliance evaluation, scoped to an organization
--
-- Schema_migrations is created up-front by the migrator itself so the
-- version-tracking row inserted at the end of this file has a place to land.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Case-insensitive email lookup; the unique constraint above is case-sensitive
-- so this index covers the lookup path users actually take.
CREATE UNIQUE INDEX idx_users_email_lower ON users (lower(email));

-- Memberships are the join table. Role constraints are enforced in the DB
-- so an application bug can't grant a fictional role.
CREATE TABLE memberships (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id)
);
CREATE INDEX idx_memberships_org ON memberships(org_id);

-- API tokens belong to an organization. The created_by column attributes
-- the token to a user when one is known (web dashboard), and is NULL when
-- minted via admin-bootstrap (env-token operator path).
CREATE TABLE api_tokens (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);
CREATE INDEX idx_api_tokens_org ON api_tokens(org_id);

CREATE TABLE runs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status        TEXT NOT NULL CHECK (status IN ('pending','running','succeeded','failed')),
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ,
    error_message TEXT,
    summary       JSONB,
    findings      JSONB,
    triggered_by_token UUID REFERENCES api_tokens(id) ON DELETE SET NULL
);
CREATE INDEX idx_runs_org_started ON runs(org_id, started_at DESC);
