-- Trust portal: opt-in public-facing compliance snapshot per org.
--
-- Off by default. Owners (and admins, via trust_portal:manage) toggle it on.
-- When disabled the public endpoint returns 404 — no signal that the org
-- exists, no signal about its compliance state.

ALTER TABLE organization
    ADD COLUMN trust_portal_enabled BOOLEAN NOT NULL DEFAULT FALSE;

INSERT INTO permission (name) VALUES ('trust_portal:manage')
ON CONFLICT (name) DO NOTHING;

-- owner + admin can toggle; member/viewer cannot.
INSERT INTO role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM role r CROSS JOIN permission p
WHERE r.name IN ('owner', 'admin')
  AND p.name = 'trust_portal:manage'
ON CONFLICT DO NOTHING;
