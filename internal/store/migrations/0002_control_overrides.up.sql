-- 0002_control_overrides.up.sql
-- Per-org Rego parameter overrides. One row per (org, control) pair.
--
-- The params JSONB matches the shape that goes into the runner's
-- input._concord.params: a flat string-keyed object. Example for SOC2-CC8.1:
--   {"min_reviewers": 3, "block_force_pushes": true}
--
-- A NULL row simply means "use the control's built-in defaults".

CREATE TABLE control_override (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    params     JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, control_id)
);
CREATE INDEX idx_control_override_org ON control_override(org_id);
