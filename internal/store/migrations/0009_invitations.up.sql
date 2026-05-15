-- Invitations: org owners + admins invite teammates by email. The system
-- mints a one-time token, hashes it, and stores it here. Acceptance attaches
-- the new user to the org with the role declared at invite time.
--
-- The plaintext token is shown ONCE to the inviter (returned by the create
-- endpoint) and to the eventual email-delivery flow. The DB only holds
-- sha256(token), same pattern as api_token + user_session.
--
-- Lifecycle states (a row is in exactly one):
--   pending     accepted_at IS NULL AND revoked_at IS NULL AND now() < expires_at
--   expired     accepted_at IS NULL AND revoked_at IS NULL AND now() >= expires_at
--   accepted    accepted_at IS NOT NULL
--   revoked     revoked_at  IS NOT NULL

-- CITEXT lets us match emails case-insensitively without lower()ing on every
-- read. Already used by `user.email`; extension is a no-op if already loaded.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE invitation (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    email       CITEXT      NOT NULL,
    role_id     UUID        NOT NULL REFERENCES role(id),
    invited_by  UUID                 REFERENCES "user"(id) ON DELETE SET NULL,
    -- sha256 of the plaintext token, raw bytes; lookup is indexed.
    token_hash  BYTEA       NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID                 REFERENCES "user"(id) ON DELETE SET NULL,
    revoked_at  TIMESTAMPTZ,
    revoked_by  UUID                 REFERENCES "user"(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Look up a pending invitation by token. Partial index keeps the structure
-- tight: accepted/revoked/expired rows don't participate in resolution.
CREATE UNIQUE INDEX idx_invitation_token_pending
    ON invitation(token_hash)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- List pending invitations for an org (the inviter's view).
CREATE INDEX idx_invitation_org_pending
    ON invitation(org_id)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- At most one pending invitation per (org, email). New invites for an email
-- with an existing pending row should supersede the previous one — the store
-- handles that in a transaction by revoking the prior pending row first.
CREATE UNIQUE INDEX idx_invitation_org_email_pending
    ON invitation(org_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
