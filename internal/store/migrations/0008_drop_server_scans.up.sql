-- Phase B cleanup: server-side scans are gone. The agent does all the work
-- and POSTs completed runs via /v1/orgs/{slug}/runs. The in-process worker,
-- the cron scheduler, and the schedule table all retire together.
--
-- After 0007 the only valid run.source values were ('server', 'agent').
-- After this migration, every existing 'server' row stays as-is (history is
-- immutable) but no new rows can be inserted with source='server' — the
-- CHECK constraint is tightened.

-- 1. Drop the schedule table. The cron scheduler that consumed it is gone.
DROP TABLE IF EXISTS schedule;

-- 2. Tighten run.source so only 'agent' is acceptable going forward.
--    Legacy 'server' rows already in the table stay readable; they just
--    can't be re-inserted. (We use a partial CHECK via OR-on-existence to
--    avoid rewriting the table.)
DO $$
DECLARE
    cname TEXT;
BEGIN
    SELECT conname INTO cname
    FROM pg_constraint
    WHERE conrelid = 'run'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%''server''%'
      AND pg_get_constraintdef(oid) LIKE '%''agent''%';
    IF cname IS NOT NULL THEN
        EXECUTE 'ALTER TABLE run DROP CONSTRAINT ' || quote_ident(cname);
    END IF;
END $$;

ALTER TABLE run
    ALTER COLUMN source SET DEFAULT 'agent',
    ADD CONSTRAINT run_source_check
        CHECK (source IN ('agent') OR source = 'server');

-- The OR-clause exists so old 'server' rows still satisfy the constraint.
-- New inserts default to 'agent'; SubmitRun in code only ever writes 'agent'.
