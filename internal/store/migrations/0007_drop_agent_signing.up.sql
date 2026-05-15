-- Phase A cleanup: Ed25519 signing was removed. API token auth (which already
-- carries identity + org scope + revocation) is the sole authentication
-- mechanism for agent pushes. The agent_key table, the FK from run.agent_id,
-- and the signature_verified column all go away.
--
-- Existing rows with source='unsigned' are reclassified as 'agent' — they
-- were always agent pushes, just unsigned ones. After this migration the
-- only valid sources are 'server' (legacy worker, removed in 0008) and
-- 'agent' (the only path going forward).

UPDATE run SET source = 'agent' WHERE source = 'unsigned';

-- Drop the auto-named CHECK constraint that allowed 'unsigned'. Look it up
-- by signature rather than by guessed name so the migration is stable.
DO $$
DECLARE
    cname TEXT;
BEGIN
    SELECT conname INTO cname
    FROM pg_constraint
    WHERE conrelid = 'run'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%unsigned%';
    IF cname IS NOT NULL THEN
        EXECUTE 'ALTER TABLE run DROP CONSTRAINT ' || quote_ident(cname);
    END IF;
END $$;

ALTER TABLE run ADD CONSTRAINT run_source_check
    CHECK (source IN ('server', 'agent'));

ALTER TABLE run DROP COLUMN agent_id;
ALTER TABLE run DROP COLUMN signature_verified;

DROP TABLE agent_key;

-- Permission 'agent_keys:manage' is left in place: cascading its removal
-- through role_permission rows is more risk than the row itself costs.
-- Future migration may sweep it if we ever audit dead permissions.
