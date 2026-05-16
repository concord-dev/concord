-- 0001_init.down.sql — reverse the consolidated dev-snapshot schema.
--
-- DEV USE ONLY. This file exists so a developer iterating on the next
-- migration (0002+) can `migrate-down` to a clean slate without dropping
-- the whole database. It is NOT a safe production rollback step: any
-- data Concord has written between `migrate up` and `migrate down` is
-- destroyed by the table drops below.
--
-- For production, never run this. Always roll forward with a new
-- additive migration (expand-contract).
--
-- Order: drop tables from leaf to root so foreign-key dependencies
-- unwind cleanly even without CASCADE — though CASCADE is included as
-- belt-and-braces against partial state from a half-failed up migration.

-- Auth flows (leaves of the FK tree).
DROP TABLE IF EXISTS mfa_challenge      CASCADE;
DROP TABLE IF EXISTS user_recovery_code CASCADE;
DROP TABLE IF EXISTS user_totp          CASCADE;
DROP TABLE IF EXISTS password_reset     CASCADE;
DROP TABLE IF EXISTS invitation         CASCADE;

-- Audit log (references org + user + token).
DROP TABLE IF EXISTS audit_event        CASCADE;

-- Drift events (references run, which is dropped below — order doesn't
-- matter with CASCADE but keep this near audit_event for readability).
DROP TABLE IF EXISTS drift_event        CASCADE;

-- Domain tables.
DROP TABLE IF EXISTS webhook            CASCADE;
DROP TABLE IF EXISTS control_override   CASCADE;
DROP TABLE IF EXISTS run                CASCADE;

-- Identity & access (RBAC + credentials + tenancy).
DROP TABLE IF EXISTS user_session       CASCADE;
DROP TABLE IF EXISTS api_token          CASCADE;
DROP TABLE IF EXISTS user_org_role      CASCADE;
DROP TABLE IF EXISTS role_permission    CASCADE;
DROP TABLE IF EXISTS permission         CASCADE;
DROP TABLE IF EXISTS role               CASCADE;
DROP TABLE IF EXISTS "user"             CASCADE;
DROP TABLE IF EXISTS organization       CASCADE;

-- Extensions are intentionally NOT dropped — they're cheap to leave
-- installed and other databases on the same cluster may rely on them.
