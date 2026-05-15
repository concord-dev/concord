package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func TestUserTOTP_EnrollFlow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "M", LastName: "FA", Email: uniqueEmail("totp"),
	})

	// New user → not enrolled.
	enrolled, err := s.IsUserMFAEnrolled(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, enrolled)

	// Begin enrollment → row exists but enrolled_at is NULL.
	require.NoError(t, s.BeginUserTOTPEnrollment(ctx, u.ID, "JBSWY3DPEHPK3PXP"))
	enrolled, err = s.IsUserMFAEnrolled(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, enrolled, "pending enrollment must NOT count as enrolled")

	// Mark enrolled.
	require.NoError(t, s.MarkUserTOTPEnrolled(ctx, u.ID))
	enrolled, err = s.IsUserMFAEnrolled(ctx, u.ID)
	require.NoError(t, err)
	assert.True(t, enrolled)

	// Re-enroll on an already-enrolled user must fail loudly.
	err = s.BeginUserTOTPEnrollment(ctx, u.ID, "NEWSECRET")
	assert.ErrorIs(t, err, store.ErrMFAAlreadyEnrolled,
		"re-enrolling without disable first must error — silent overwrite would let a session hijack swap the second factor")
}

func TestDisableUserMFA_WipesSecretAndCodes(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "M", LastName: "FA", Email: uniqueEmail("disable"),
	})

	require.NoError(t, s.BeginUserTOTPEnrollment(ctx, u.ID, "JBSWY3DPEHPK3PXP"))
	require.NoError(t, s.MarkUserTOTPEnrolled(ctx, u.ID))
	require.NoError(t, s.ReplaceRecoveryCodes(ctx, u.ID,
		[]string{"abcd-efgh", "ijkl-mnop", "qrst-uvwx"}))

	require.NoError(t, s.DisableUserMFA(ctx, u.ID))

	enrolled, _ := s.IsUserMFAEnrolled(ctx, u.ID)
	assert.False(t, enrolled, "secret row must be deleted on disable")
	n, _ := s.CountUnusedRecoveryCodes(ctx, u.ID)
	assert.Equal(t, 0, n, "all recovery codes must be wiped on disable")
}

func TestRecoveryCodes_NormalizationAndOneTimeUse(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "R", LastName: "ec", Email: uniqueEmail("recovery"),
	})

	require.NoError(t, s.ReplaceRecoveryCodes(ctx, u.ID, []string{"ABCD-EFGH"}))
	n, _ := s.CountUnusedRecoveryCodes(ctx, u.ID)
	assert.Equal(t, 1, n)

	// Different formatting must match (case-insensitive, dashes optional).
	ok, err := s.ConsumeRecoveryCode(ctx, u.ID, "abcdefgh")
	require.NoError(t, err)
	assert.True(t, ok, "code must match regardless of case or dash formatting")

	n, _ = s.CountUnusedRecoveryCodes(ctx, u.ID)
	assert.Equal(t, 0, n, "consumed code must be marked used")

	// Second submission of the same code now fails.
	ok, err = s.ConsumeRecoveryCode(ctx, u.ID, "abcdefgh")
	require.NoError(t, err)
	assert.False(t, ok, "second use of the same recovery code must fail — one-time semantics")
}

func TestMFAChallenge_HappyPath(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "C", LastName: "h", Email: uniqueEmail("challenge"),
	})

	ch, plain, err := s.CreateMFAChallenge(ctx, u.ID, "127.0.0.1", "test-ua", 5*time.Minute)
	require.NoError(t, err)
	assert.NotEmpty(t, plain)
	assert.True(t, ch.ExpiresAt.After(time.Now()))

	gotUser, err := s.ConsumeMFAChallenge(ctx, plain)
	require.NoError(t, err)
	assert.Equal(t, u.ID, gotUser)

	// Replay must fail (consumed_at is set).
	_, err = s.ConsumeMFAChallenge(ctx, plain)
	assert.ErrorIs(t, err, store.ErrNotFound,
		"a consumed challenge must not be reusable")
}

func TestMFAChallenge_ExpiryIsEnforced(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "E", LastName: "x", Email: uniqueEmail("expire"),
	})

	_, plain, err := s.CreateMFAChallenge(ctx, u.ID, "127.0.0.1", "ua", -1*time.Second)
	require.NoError(t, err)

	_, err = s.ConsumeMFAChallenge(ctx, plain)
	assert.ErrorIs(t, err, store.ErrMFAChallengeExpired,
		"a challenge past its expires_at must surface as ErrMFAChallengeExpired, not be silently consumed")
}
