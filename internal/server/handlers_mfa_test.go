package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fullMFAEnroll(t *testing.T, h *harness) (string, []string) {
	t.Helper()
	sessionToken := h.login(t)

	resp, raw := h.do(t, "POST", "/v1/me/mfa/totp/enroll", "", sessionToken)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "enroll: %s", raw)
	var enrollRes struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(raw, &enrollRes))
	require.NotEmpty(t, enrollRes.Secret)

	code, err := totp.GenerateCode(enrollRes.Secret, time.Now())
	require.NoError(t, err)

	verifyBody := fmt.Sprintf(`{"code":%q}`, code)
	resp, raw = h.do(t, "POST", "/v1/me/mfa/totp/verify", verifyBody, sessionToken)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "verify: %s", raw)
	var verifyRes struct {
		Enrolled      bool     `json:"enrolled"`
		RecoveryCodes []string `json:"recovery_codes"`
	}
	require.NoError(t, json.Unmarshal(raw, &verifyRes))
	assert.True(t, verifyRes.Enrolled)
	require.Len(t, verifyRes.RecoveryCodes, 10,
		"verify must return exactly 10 recovery codes")
	return enrollRes.Secret, verifyRes.RecoveryCodes
}

func TestMFA_EnrollVerifyAndLoginEndToEnd(t *testing.T) {
	h := newHarness(t)
	secret, _ := fullMFAEnroll(t, h)

	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var first struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
	}
	require.NoError(t, json.Unmarshal(raw, &first))
	assert.True(t, first.MFARequired, "post-enrollment login must short-circuit into MFA branch")
	assert.NotEmpty(t, first.MFAToken)

	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	second := fmt.Sprintf(`{"mfa_token":%q,"code":%q}`, first.MFAToken, code)
	resp, raw = h.do(t, "POST", "/v1/auth/login/mfa", second, "")
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "second-leg: %s", raw)
	var sessionRes struct {
		Token            string `json:"token"`
		UsedRecoveryCode bool   `json:"used_recovery_code"`
	}
	require.NoError(t, json.Unmarshal(raw, &sessionRes))
	assert.NotEmpty(t, sessionRes.Token, "second-leg must mint a session token")
	assert.False(t, sessionRes.UsedRecoveryCode)
}

func TestMFA_LoginWithRecoveryCodeConsumesIt(t *testing.T) {
	h := newHarness(t)
	_, codes := fullMFAEnroll(t, h)

	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var first struct {
		MFAToken string `json:"mfa_token"`
	}
	require.NoError(t, json.Unmarshal(raw, &first))

	second := fmt.Sprintf(`{"mfa_token":%q,"recovery_code":%q}`, first.MFAToken, codes[0])
	resp, raw = h.do(t, "POST", "/v1/auth/login/mfa", second, "")
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "recovery login: %s", raw)
	var sessionRes struct {
		UsedRecoveryCode bool `json:"used_recovery_code"`
	}
	require.NoError(t, json.Unmarshal(raw, &sessionRes))
	assert.True(t, sessionRes.UsedRecoveryCode, "response must flag that a recovery code was consumed")

	body2 := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw = h.do(t, "POST", "/v1/auth/login", body2, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var second2 struct {
		MFAToken string `json:"mfa_token"`
	}
	require.NoError(t, json.Unmarshal(raw, &second2))
	body3 := fmt.Sprintf(`{"mfa_token":%q,"recovery_code":%q}`, second2.MFAToken, codes[0])
	resp, _ = h.do(t, "POST", "/v1/auth/login/mfa", body3, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
		"re-use of an already-consumed recovery code must be rejected")

	n, err := h.st.CountUnusedRecoveryCodes(context.Background(), h.user.ID)
	require.NoError(t, err)
	assert.Equal(t, 9, n)
}

func TestMFA_WrongTOTPCodeFailsAndDoesNotMintSession(t *testing.T) {
	h := newHarness(t)
	_, _ = fullMFAEnroll(t, h)

	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var first struct {
		MFAToken string `json:"mfa_token"`
	}
	require.NoError(t, json.Unmarshal(raw, &first))

	bad := fmt.Sprintf(`{"mfa_token":%q,"code":"000000"}`, first.MFAToken)
	resp, _ = h.do(t, "POST", "/v1/auth/login/mfa", bad, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestMFA_DisableRequiresPassword(t *testing.T) {
	h := newHarness(t)
	secret, _ := fullMFAEnroll(t, h)
	_ = secret

	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", loginBody, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var first struct {
		MFAToken string `json:"mfa_token"`
	}
	require.NoError(t, json.Unmarshal(raw, &first))
	code, _ := totp.GenerateCode(secret, time.Now())
	second := fmt.Sprintf(`{"mfa_token":%q,"code":%q}`, first.MFAToken, code)
	resp, raw = h.do(t, "POST", "/v1/auth/login/mfa", second, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var sess struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &sess))

	resp, _ = h.do(t, "POST", "/v1/me/mfa/disable", `{"password":"nope"}`, sess.Token)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	enrolled, _ := h.st.IsUserMFAEnrolled(context.Background(), h.user.ID)
	assert.True(t, enrolled, "wrong password must NOT disable MFA")

	disableBody := fmt.Sprintf(`{"password":%q}`, h.password)
	resp, _ = h.do(t, "POST", "/v1/me/mfa/disable", disableBody, sess.Token)
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	enrolled, _ = h.st.IsUserMFAEnrolled(context.Background(), h.user.ID)
	assert.False(t, enrolled, "successful disable must wipe enrollment")

	resp, raw = h.do(t, "POST", "/v1/auth/login", loginBody, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
}
