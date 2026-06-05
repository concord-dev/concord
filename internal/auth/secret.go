package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	APITokenPrefix       = "concord_"
	SessionTokenPrefix   = "concord_sess_"
	InvitationPrefix     = "concord_inv_"
	PasswordResetPrefix  = "concord_reset_"
	MFAChallengePrefix   = "concord_mfa_"
)

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

func HashSecret(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
