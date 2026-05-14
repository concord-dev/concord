package store

import (
	"context"

	"github.com/google/uuid"
)

// OrgMember is one (user, org) pair with the roles the user holds in that org.
type OrgMember struct {
	User  User   `json:"user"`
	Roles []Role `json:"roles"`
}

// UserOrg is one org a user belongs to, with the roles they hold there.
type UserOrg struct {
	Organization Organization `json:"organization"`
	Roles        []Role       `json:"roles"`
}

// AssignRole grants a role to a user inside an org. Idempotent — re-assigning
// the same triple is a no-op (the PK collides and ON CONFLICT skips).
func (s *Store) AssignRole(ctx context.Context, userID, orgID, roleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_org_role(user_id, org_id, role_id)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		userID, orgID, roleID)
	return err
}

// RevokeRole removes one specific role grant.
func (s *Store) RevokeRole(ctx context.Context, userID, orgID, roleID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM user_org_role WHERE user_id = $1 AND org_id = $2 AND role_id = $3`,
		userID, orgID, roleID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveUserFromOrg drops every role grant for (userID, orgID).
func (s *Store) RemoveUserFromOrg(ctx context.Context, userID, orgID uuid.UUID) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM user_org_role WHERE user_id = $1 AND org_id = $2`, userID, orgID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListOrgMembers returns every member of orgID, grouped by user so the
// multiple roles a user holds appear together.
func (s *Store) ListOrgMembers(ctx context.Context, orgID uuid.UUID) ([]OrgMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT u.id, u.first_name, u.last_name, u.email, u.email_verified_at,
		        u.created_at, u.updated_at,
		        r.id, r.name, r.created_at, r.updated_at
		 FROM user_org_role uor
		 JOIN "user" u ON u.id = uor.user_id
		 JOIN role r ON r.id = uor.role_id
		 WHERE uor.org_id = $1
		 ORDER BY lower(u.email), r.name`,
		orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byUser := make(map[uuid.UUID]*OrgMember)
	order := []uuid.UUID{}
	for rows.Next() {
		var u User
		var r Role
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.EmailVerifiedAt,
			&u.CreatedAt, &u.UpdatedAt,
			&r.ID, &r.Name, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		m, ok := byUser[u.ID]
		if !ok {
			m = &OrgMember{User: u}
			byUser[u.ID] = m
			order = append(order, u.ID)
		}
		m.Roles = append(m.Roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]OrgMember, 0, len(order))
	for _, id := range order {
		out = append(out, *byUser[id])
	}
	return out, nil
}

// ListUserOrgs returns every org the user belongs to with the roles they hold.
func (s *Store) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]UserOrg, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT o.id, o.name, o.slug, o.created_at, o.updated_at,
		        r.id, r.name, r.created_at, r.updated_at
		 FROM user_org_role uor
		 JOIN organization o ON o.id = uor.org_id
		 JOIN role r ON r.id = uor.role_id
		 WHERE uor.user_id = $1
		 ORDER BY o.created_at, r.name`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byOrg := make(map[uuid.UUID]*UserOrg)
	order := []uuid.UUID{}
	for rows.Next() {
		var o Organization
		var r Role
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt,
			&r.ID, &r.Name, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		entry, ok := byOrg[o.ID]
		if !ok {
			entry = &UserOrg{Organization: o}
			byOrg[o.ID] = entry
			order = append(order, o.ID)
		}
		entry.Roles = append(entry.Roles, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]UserOrg, 0, len(order))
	for _, id := range order {
		out = append(out, *byOrg[id])
	}
	return out, nil
}

// HasPermission reports whether the user holds any role in the org that
// grants the named permission. Returns false (no error) when the user has
// no membership in the org.
func (s *Store) HasPermission(ctx context.Context, userID, orgID uuid.UUID, permission string) (bool, error) {
	var got bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
		    SELECT 1
		    FROM user_org_role uor
		    JOIN role_permission rp ON rp.role_id = uor.role_id
		    JOIN permission p       ON p.id = rp.permission_id
		    WHERE uor.user_id = $1 AND uor.org_id = $2 AND p.name = $3
		 )`,
		userID, orgID, permission,
	).Scan(&got)
	return got, err
}

// UserPermissions returns the distinct permission names the user holds in
// the org. Useful for "what can this user do here?" UI prompts.
func (s *Store) UserPermissions(ctx context.Context, userID, orgID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT p.name
		 FROM user_org_role uor
		 JOIN role_permission rp ON rp.role_id = uor.role_id
		 JOIN permission p       ON p.id = rp.permission_id
		 WHERE uor.user_id = $1 AND uor.org_id = $2
		 ORDER BY p.name`,
		userID, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
