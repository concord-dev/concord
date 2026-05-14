-- 0003_schedules.up.sql
-- Per-org check schedule. One row per organization (the UNIQUE on org_id
-- enforces this). The scheduler claims due rows with SELECT ... FOR UPDATE
-- SKIP LOCKED so a future multi-instance deployment doesn't double-fire.
--
-- cron_expr accepts standard 5-field expressions ("0 */6 * * *") plus
-- robfig/cron descriptors (@hourly, @daily, @every 30m).

CREATE TABLE schedule (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL UNIQUE REFERENCES organization(id) ON DELETE CASCADE,
    cron_expr     TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    last_fired_at TIMESTAMPTZ,
    next_fire_at  TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The hot lookup is "every enabled schedule due before NOW". The partial
-- index keeps it cheap even at millions of orgs.
CREATE INDEX idx_schedule_due ON schedule(next_fire_at) WHERE enabled;
