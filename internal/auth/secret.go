package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Prefixes for the two kinds of secrets we mint. Distinct prefixes mean a
// leaked secret can be triaged at a glance (API tokens may be safe to rotate
// quietly, session tokens always trigger an immediate revoke).
const (
	APITokenPrefix       = "concord_"
	SessionTokenPrefix   = "concord_sess_"
	InvitationPrefix     = "concord_inv_"
	PasswordResetPrefix  = "concord_reset_"
	// MFAChallengePrefix tags the short-lived token returned by /v1/auth/login
	// when the user has MFA enrolled. The caller submits it on the second leg
	// (/v1/auth/login/mfa) alongside their TOTP or recovery code.
	MFAChallengePrefix   = "concord_mfa_"
)

// GenerateSecret returns a URL-safe random secret of the requested byte
// length, prefixed with `prefix`. 32 bytes (256 bits) is the default for
// our minted secrets — effectively unguessable.
func GenerateSecret(prefix string, byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 32
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating secret: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashSecret returns the hex-encoded SHA-256 of a plaintext secret. Used as
// the lookup key for both api_token.token_hash and user_session.token_hash —
// the database never stores the plaintext.
func HashSecret(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
