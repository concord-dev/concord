-- Forgot-password flow: an unauthenticated request from an end user that
-- (if their email is on file) mints a single-use reset token. The plaintext
-- is delivered out-of-band; only sha256(token) lands here.
--
-- Lifecycle:
--   live    used_at IS NULL AND now() < expires_at
--   used    used_at IS NOT NULL
--   expired used_at IS NULL AND now() >= expires_at
--
-- Confirming a reset:
--   1. Look up by sha256(token).
--   2. Reject if used_at IS NOT NULL or expires_at < now().
--   3. In one txn: update the password hash, set used_at, revoke all of the
--      user's existing sessions. API tokens are left alone — they're the
--      automation surface and the user may not even know they exist.
--
-- Audit fields capture who asked. Helpful when investigating a string of
-- reset requests against a single account.

CREATE TABLE password_reset (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    -- sha256 of the plaintext token, raw bytes.
    token_hash    BYTEA       NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    requester_ip  TEXT,
    requester_ua  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Token lookup MUST be unique among live rows. Reused tokens (used_at set)
-- keep their old hash in place for audit but no longer participate.
CREATE UNIQUE INDEX idx_password_reset_token_live
    ON password_reset(token_hash)
    WHERE used_at IS NULL;

-- For "this user has $n outstanding reset requests" / abuse signals.
CREATE INDEX idx_password_reset_user_recent
    ON password_reset(user_id, created_at DESC);
