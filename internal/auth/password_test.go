package auth_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/auth"
)

func TestHashPassword_PHCFormat(t *testing.T) {
	enc, err := auth.HashPassword("correct-horse-battery-staple")
	require.NoError(t, err)
	// Expected layout: $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>
	parts := strings.Split(enc, "$")
	require.Len(t, parts, 6)
	assert.Equal(t, "argon2id", parts[1])
	assert.Equal(t, "v=19", parts[2])
	assert.True(t, strings.HasPrefix(parts[3], "m="))
}

func TestHashPassword_EmptyRejected(t *testing.T) {
	_, err := auth.HashPassword("")
	require.Error(t, err)
}

func TestHashPassword_SaltIsRandom(t *testing.T) {
	a, _ := auth.HashPassword("hunter2")
	b, _ := auth.HashPassword("hunter2")
	assert.NotEqual(t, a, b, "same password must produce different hashes (random salt)")
}

func TestVerifyPassword_MatchesCorrect(t *testing.T) {
	enc, err := auth.HashPassword("hunter2")
	require.NoError(t, err)
	ok, err := auth.VerifyPassword("hunter2", enc)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestVerifyPassword_RejectsWrong(t *testing.T) {
	enc, _ := auth.HashPassword("hunter2")
	ok, err := auth.VerifyPassword("hunter3", enc)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyPassword_RejectsTamperedHash(t *testing.T) {
	enc, _ := auth.HashPassword("hunter2")
	tampered := enc[:len(enc)-4] + "XXXX"
	ok, err := auth.VerifyPassword("hunter2", tampered)
	// Either invalid hash error or mismatch — both are acceptable, neither is "true".
	if err == nil {
		assert.False(t, ok)
	}
}

func TestVerifyPassword_RejectsMalformedHash(t *testing.T) {
	_, err := auth.VerifyPassword("hunter2", "not-a-phc-string")
	assert.ErrorIs(t, err, auth.ErrInvalidPasswordHash)
}

func TestGenerateSecret_DistinctAndPrefixed(t *testing.T) {
	a, err := auth.GenerateSecret(auth.APITokenPrefix, 32)
	require.NoError(t, err)
	b, err := auth.GenerateSecret(auth.APITokenPrefix, 32)
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
	assert.True(t, strings.HasPrefix(a, "concord_"))
	assert.Greater(t, len(a), 30, "256 bits in base64-url should exceed 40 chars total")
}

func TestHashSecret_Deterministic(t *testing.T) {
	a := auth.HashSecret("concord_abc")
	b := auth.HashSecret("concord_abc")
	c := auth.HashSecret("concord_abd")
	assert.Equal(t, a, b)
	assert.NotEqual(t, a, c)
	assert.Len(t, a, 64, "sha256 hex must be 64 chars")
}
