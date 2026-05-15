package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/concord-dev/concord/internal/auth"
)

// Invitation is a pending or terminal invite for one (org, email). Token is
// never echoed by the store — the plaintext is returned only by
// CreateInvitation (mirroring the API-token pattern).
type Invitation struct {
	ID         uuid.UUID  `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	Email      string     `json:"email"`
	RoleID     uuid.UUID  `json:"role_id"`
	RoleName   string     `json:"role"` // joined from role table for convenience
	InvitedBy  *uuid.UUID `json:"invited_by,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
	AcceptedAt *time.Time `json:"accepted_at,omitempty"`
	AcceptedBy *uuid.UUID `json:"accepted_by,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  *uuid.UUID `json:"revoked_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// CreateInvitationParams is the shape callers pass to CreateInvitation.
type CreateInvitationParams struct {
	OrgID     uuid.UUID
	Email     string
	RoleID    uuid.UUID
	InvitedBy *uuid.UUID
	TTL       time.Duration // defaults to 7 days when zero
}

// CreateInvitation mints a new pending invitation. Any existing pending row
// for the same (org_id, email) is revoked in the same transaction — the
// partial-unique index requires this, and it gives operators a clean
// "re-invite" UX without unique-violation errors.
//
// Returns the persisted row + the plaintext token. The plaintext is the only
// thing the caller can use to share the link; the store retains only its
// sha256.
func (s *Store) CreateInvitation(ctx context.Context, p CreateInvitationParams) (Invitation, string, error) {
	if p.Email = strings.TrimSpace(p.Email); p.Email == "" {
		return Invitation{}, "", errors.New("email is required")
	}
	if p.TTL <= 0 {
		p.TTL = 7 * 24 * time.Hour
	}

	plain, err := auth.GenerateSecret(auth.InvitationPrefix, 32)
	if err != nil {
		return Invitation{}, "", err
	}
	hashHex := auth.HashSecret(plain)
	hashBytes, err := hexToBytes(hashHex)
	if err != nil {
		return Invitation{}, "", err
	}
	expiresAt := time.Now().Add(p.TTL)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Invitation{}, "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck — explicit Commit below

	// Supersede any prior pending invite for the same (org, email).
	if _, err := tx.Exec(ctx,
		`UPDATE invitation
		 SET revoked_at = now(), revoked_by = $1
		 WHERE org_id = $2 AND email = $3
		   AND accepted_at IS NULL AND revoked_at IS NULL`,
		p.InvitedBy, p.OrgID, p.Email,
	); err != nil {
		return Invitation{}, "", fmt.Errorf("revoking prior pending invite: %w", err)
	}

	var inv Invitation
	err = tx.QueryRow(ctx,
		`INSERT INTO invitation(org_id, email, role_id, invited_by, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, org_id, email, role_id, invited_by,
		           expires_at, accepted_at, accepted_by, revoked_at, revoked_by, created_at`,
		p.OrgID, p.Email, p.RoleID, p.InvitedBy, hashBytes, expiresAt,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.InvitedBy,
		&inv.ExpiresAt, &inv.AcceptedAt, &inv.AcceptedBy,
		&inv.RevokedAt, &inv.RevokedBy, &inv.CreatedAt)
	if err != nil {
		return Invitation{}, "", fmt.Errorf("inserting invitation: %w", err)
	}

	// Join role name for the returned view (saves the handler a round trip).
	if err := tx.QueryRow(ctx,
		`SELECT name FROM role WHERE id = $1`, inv.RoleID,
	).Scan(&inv.RoleName); err != nil {
		return Invitation{}, "", fmt.Errorf("looking up role: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Invitation{}, "", err
	}
	return inv, plain, nil
}

// ListPendingInvitations returns active (not accepted, not revoked, not yet
// expired) invitations for an org, oldest first.
func (s *Store) ListPendingInvitations(ctx context.Context, orgID uuid.UUID) ([]Invitation, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT i.id, i.org_id, i.email, i.role_id, r.name, i.invited_by,
		        i.expires_at, i.accepted_at, i.accepted_by,
		        i.revoked_at, i.revoked_by, i.created_at
		 FROM invitation i JOIN role r ON r.id = i.role_id
		 WHERE i.org_id = $1
		   AND i.accepted_at IS NULL
		   AND i.revoked_at IS NULL
		   AND i.expires_at > now()
		 ORDER BY i.created_at ASC`,
		orgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invitation
	for rows.Next() {
		var inv Invitation
		if err := rows.Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.RoleName,
			&inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.AcceptedBy,
			&inv.RevokedAt, &inv.RevokedBy, &inv.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// GetInvitationByToken looks up an invitation by its plaintext token. Only
// pending (not accepted, not revoked) rows match; expiry is reported
// separately so the caller can produce a useful error message.
//
// The returned Invitation always has RoleName populated.
func (s *Store) GetInvitationByToken(ctx context.Context, plaintext string) (Invitation, error) {
	hashBytes, err := hexToBytes(auth.HashSecret(plaintext))
	if err != nil {
		return Invitation{}, err
	}
	var inv Invitation
	err = s.pool.QueryRow(ctx,
		`SELECT i.id, i.org_id, i.email, i.role_id, r.name, i.invited_by,
		        i.expires_at, i.accepted_at, i.accepted_by,
		        i.revoked_at, i.revoked_by, i.created_at
		 FROM invitation i JOIN role r ON r.id = i.role_id
		 WHERE i.token_hash = $1
		   AND i.accepted_at IS NULL
		   AND i.revoked_at IS NULL`,
		hashBytes,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.RoleName,
		&inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.AcceptedBy,
		&inv.RevokedAt, &inv.RevokedBy, &inv.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	return inv, err
}

// RevokeInvitation soft-deletes a pending invitation. ErrNotFound when the
// id isn't in this org or is already accepted/revoked.
func (s *Store) RevokeInvitation(ctx context.Context, orgID, invID uuid.UUID, revokedBy *uuid.UUID) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE invitation
		 SET revoked_at = now(), revoked_by = $1
		 WHERE id = $2 AND org_id = $3
		   AND accepted_at IS NULL AND revoked_at IS NULL`,
		revokedBy, invID, orgID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// AcceptInvitationParams carries everything an /invitations/accept handler
// needs to commit the user side of the flow.
type AcceptInvitationParams struct {
	// Plaintext token from the URL. Hashed before lookup.
	Token string
	// New-user fields. Ignored when the invitation's email already maps to
	// an existing user.
	FirstName string
	LastName  string
	Password  string
}

// AcceptInvitationResult tells the caller what just happened so the handler
// can shape the response (and decide whether to issue a session token).
type AcceptInvitationResult struct {
	Invitation    Invitation
	User          User
	CreatedUser   bool // true when the accept flow inserted a new user row
	AssignedRole  bool // true when AssignRole inserted (false on idempotent re-accept of the same user/org/role)
}

// AcceptInvitation completes the flow: optionally creates the user, attaches
// them to the org with the invited role, and marks the invitation accepted —
// all in one transaction so a partial failure leaves no zombie state.
//
// Token validation rules:
//   - Unknown / accepted / revoked → ErrNotFound
//   - Expired → returns a sentinel error so the handler can 410 it cleanly
//
// Idempotency: re-accepting a token that's already accepted returns
// ErrNotFound (it's no longer pending). Callers that need to verify acceptance
// after the fact should query the row by id, not re-submit the token.
func (s *Store) AcceptInvitation(ctx context.Context, p AcceptInvitationParams) (AcceptInvitationResult, error) {
	if strings.TrimSpace(p.Token) == "" {
		return AcceptInvitationResult{}, errors.New("token is required")
	}
	hashBytes, err := hexToBytes(auth.HashSecret(p.Token))
	if err != nil {
		return AcceptInvitationResult{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AcceptInvitationResult{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// SELECT FOR UPDATE so two concurrent accepts of the same token can't both
	// win. The loser gets a "no rows" on its second pass and returns ErrNotFound.
	var inv Invitation
	err = tx.QueryRow(ctx,
		`SELECT i.id, i.org_id, i.email, i.role_id, r.name, i.invited_by,
		        i.expires_at, i.accepted_at, i.accepted_by,
		        i.revoked_at, i.revoked_by, i.created_at
		 FROM invitation i JOIN role r ON r.id = i.role_id
		 WHERE i.token_hash = $1
		   AND i.accepted_at IS NULL
		   AND i.revoked_at IS NULL
		 FOR UPDATE OF i`,
		hashBytes,
	).Scan(&inv.ID, &inv.OrgID, &inv.Email, &inv.RoleID, &inv.RoleName,
		&inv.InvitedBy, &inv.ExpiresAt, &inv.AcceptedAt, &inv.AcceptedBy,
		&inv.RevokedAt, &inv.RevokedBy, &inv.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AcceptInvitationResult{}, ErrNotFound
	}
	if err != nil {
		return AcceptInvitationResult{}, err
	}

	if time.Now().After(inv.ExpiresAt) {
		return AcceptInvitationResult{}, ErrInvitationExpired
	}

	// Resolve the user: existing-by-email, or create from p.{FirstName, LastName, Password}.
	result := AcceptInvitationResult{Invitation: inv}
	var u User
	err = tx.QueryRow(ctx,
		`SELECT `+userColumns+` FROM "user" WHERE email = $1`, inv.Email,
	).Scan(userScanArgs(&u)...)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if p.Password == "" || p.FirstName == "" || p.LastName == "" {
			return AcceptInvitationResult{},
				fmt.Errorf("first_name, last_name, and password are required for a new account")
		}
		hash, err := auth.HashPassword(p.Password)
		if err != nil {
			return AcceptInvitationResult{}, fmt.Errorf("hashing password: %w", err)
		}
		err = tx.QueryRow(ctx,
			`INSERT INTO "user"(first_name, last_name, email, password_hash, email_verified_at)
			 VALUES ($1, $2, $3, $4, now())
			 RETURNING `+userColumns,
			p.FirstName, p.LastName, inv.Email, hash,
		).Scan(userScanArgs(&u)...)
		if err != nil {
			return AcceptInvitationResult{}, fmt.Errorf("creating user: %w", err)
		}
		result.CreatedUser = true
	case err != nil:
		return AcceptInvitationResult{}, err
	}
	result.User = u

	// AssignRole equivalent inside the txn (ON CONFLICT DO NOTHING so a
	// re-invite of an already-attached user is harmless).
	ct, err := tx.Exec(ctx,
		`INSERT INTO user_org_role(user_id, org_id, role_id)
		 VALUES ($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		u.ID, inv.OrgID, inv.RoleID)
	if err != nil {
		return AcceptInvitationResult{}, fmt.Errorf("assigning role: %w", err)
	}
	result.AssignedRole = ct.RowsAffected() > 0

	// Mark the invitation accepted.
	if _, err := tx.Exec(ctx,
		`UPDATE invitation SET accepted_at = now(), accepted_by = $1
		 WHERE id = $2`,
		u.ID, inv.ID,
	); err != nil {
		return AcceptInvitationResult{}, fmt.Errorf("marking invitation accepted: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return AcceptInvitationResult{}, err
	}
	// Reflect the freshly-set timestamps in the returned struct for the caller.
	now := time.Now()
	result.Invitation.AcceptedAt = &now
	result.Invitation.AcceptedBy = &u.ID
	return result, nil
}

// ErrInvitationExpired is returned by AcceptInvitation when the token exists
// but its expires_at has passed. Distinct from ErrNotFound so the handler can
// produce a meaningful "this link expired, ask for a fresh one" message
// rather than the generic "invalid invitation" we use for unknown / revoked
// / already-accepted (we collapse those to ErrNotFound deliberately — they
// shouldn't be distinguishable from an attacker's perspective).
var ErrInvitationExpired = errors.New("invitation expired")
