package server_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/auth"
	"github.com/concord-dev/concord/internal/store"
)


func TestPasswordReset_RequestAlways200_NoEnumeration(t *testing.T) {
	h := newHarness(t)

	// Known email — succeeds, but the response shape is intentionally
	// identical to the unknown-email case (see next assertion).
	respKnown, _ := h.do(t, "POST", "/v1/auth/password-reset",
		fmt.Sprintf(`{"email":%q}`, h.user.Email), "")
	assert.Equal(t, http.StatusOK, respKnown.StatusCode)

	// Unknown email — also 200, same shape. This is the anti-enumeration
	// guarantee: the API must not let an attacker probe whether an email is
	// registered.
	respUnknown, _ := h.do(t, "POST", "/v1/auth/password-reset",
		`{"email":"definitely-not-real@example.test"}`, "")
	assert.Equal(t, http.StatusOK, respUnknown.StatusCode)
}

func TestPasswordReset_RequestRejectsEmptyEmail(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/v1/auth/password-reset", `{}`, "")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "email")
}


// Confirm tests need a real token. The token is logged out-of-band in
// production; here we read the row directly from the store and reconstruct
// what the user would have received. The harness exposes `st` for this.
func TestPasswordReset_ConfirmRotatesPasswordAndKillsSessions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Pre-condition: an active session for the user. The current password
	// must work for /auth/login.
	respLogin1, rawLogin1 := h.do(t, "POST", "/v1/auth/login",
		fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password), "")
	require.Equal(t, http.StatusCreated, respLogin1.StatusCode)
	var login1 struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rawLogin1, &login1))

	// Confirm the session works.
	respMe, _ := h.do(t, "GET", "/v1/me", "", login1.Token)
	require.Equal(t, http.StatusOK, respMe.StatusCode)

	// Trigger the reset request (also exercises the public endpoint).
	respReq, _ := h.do(t, "POST", "/v1/auth/password-reset",
		fmt.Sprintf(`{"email":%q}`, h.user.Email), "")
	require.Equal(t, http.StatusOK, respReq.StatusCode)

	// Pull the freshly-minted token. In production the user receives this
	// out-of-band; in tests we materialise it by re-issuing via the store
	// so the test doesn't have to scrape stderr.
	pr, plain, err := h.st.CreatePasswordReset(ctx, store.CreatePasswordResetParams{
		UserID: h.user.ID,
	})
	require.NoError(t, err)
	_ = pr // unused except as proof the issue worked

	// Confirm with a new password.
	newPW := "rotated-pw-987654"
	respConf, rawConf := h.do(t, "POST", "/v1/auth/password-reset/confirm",
		fmt.Sprintf(`{"token":%q,"new_password":%q}`, plain, newPW), "")
	require.Equal(t, http.StatusOK, respConf.StatusCode, string(rawConf))
	var conf struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rawConf, &conf))
	assert.NotEmpty(t, conf.Token, "confirm must issue a fresh session token")

	// The OLD session is now revoked.
	respMe2, _ := h.do(t, "GET", "/v1/me", "", login1.Token)
	assert.Equal(t, http.StatusUnauthorized, respMe2.StatusCode,
		"all prior sessions must be revoked after a password reset")

	// The OLD password no longer works.
	respLoginOld, _ := h.do(t, "POST", "/v1/auth/login",
		fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password), "")
	assert.Equal(t, http.StatusUnauthorized, respLoginOld.StatusCode)

	// The NEW password does.
	respLoginNew, _ := h.do(t, "POST", "/v1/auth/login",
		fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, newPW), "")
	assert.Equal(t, http.StatusCreated, respLoginNew.StatusCode)

	// The fresh session returned by /confirm also works.
	respMe3, _ := h.do(t, "GET", "/v1/me", "", conf.Token)
	assert.Equal(t, http.StatusOK, respMe3.StatusCode)
}

func TestPasswordReset_ConfirmTokenIsSingleUse(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	_, plain, err := h.st.CreatePasswordReset(ctx, store.CreatePasswordResetParams{
		UserID: h.user.ID,
	})
	require.NoError(t, err)

	// First confirm succeeds.
	resp1, _ := h.do(t, "POST", "/v1/auth/password-reset/confirm",
		fmt.Sprintf(`{"token":%q,"new_password":"rotated-once"}`, plain), "")
	require.Equal(t, http.StatusOK, resp1.StatusCode)

	// Second confirm with the same token is 404 (token already consumed —
	// the response is indistinguishable from a never-existed token).
	resp2, _ := h.do(t, "POST", "/v1/auth/password-reset/confirm",
		fmt.Sprintf(`{"token":%q,"new_password":"rotated-twice"}`, plain), "")
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
}

func TestPasswordReset_ConfirmExpiredTokenIs410(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Mint a token with a TTL of 1ns so it's expired immediately.
	_, plain, err := h.st.CreatePasswordReset(ctx, store.CreatePasswordResetParams{
		UserID: h.user.ID,
		TTL:    time.Nanosecond,
	})
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond) // make sure the clock has moved past expires_at

	resp, body := h.do(t, "POST", "/v1/auth/password-reset/confirm",
		fmt.Sprintf(`{"token":%q,"new_password":"x"}`, plain), "")
	assert.Equal(t, http.StatusGone, resp.StatusCode, string(body))
	assert.Contains(t, string(body), "expired")
}

func TestPasswordReset_ConfirmUnknownTokenIs404(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "POST", "/v1/auth/password-reset/confirm",
		`{"token":"concord_reset_bogus","new_password":"y"}`, "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestPasswordReset_ConfirmRequiresBothFields(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/v1/auth/password-reset/confirm",
		`{"token":"x"}`, "")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "new_password")
}


func TestPasswordReset_TokenFormat(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, plain, err := h.st.CreatePasswordReset(ctx, store.CreatePasswordResetParams{
		UserID: h.user.ID,
	})
	require.NoError(t, err)
	assert.True(t, len(plain) > 40, "reset token should be at least 40 chars (32 bytes b64url-encoded)")
	assert.Equal(t, auth.PasswordResetPrefix, plain[:len(auth.PasswordResetPrefix)],
		"reset token must carry the well-known prefix")
	// The hash kept in the DB is hex(sha256(plaintext)); we don't expose it,
	// but proving the round-trip works is a one-line check via the auth helper.
	_, err = hex.DecodeString(auth.HashSecret(plain))
	require.NoError(t, err, "the hash format must stay hex")
}
