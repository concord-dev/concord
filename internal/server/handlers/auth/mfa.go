// MFA endpoints — TOTP (RFC 6238) enrollment plus one-time recovery codes.
//
// Routes wired by the router:
//
//	POST /v1/auth/login/mfa                   second-leg login completion (public)
//	GET  /v1/me/mfa                            enrollment status (session)
//	POST /v1/me/mfa/totp/enroll                start TOTP enrollment (session)
//	POST /v1/me/mfa/totp/verify                verify TOTP and complete enrollment (session)
//	POST /v1/me/mfa/disable                    turn MFA off — REQUIRES current password (session)
//	POST /v1/me/mfa/recovery-codes/regenerate  rotate recovery codes — REQUIRES current password (session)
package auth

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/pquerna/otp/totp"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// mfaIssuer is the label that appears in the user's authenticator app.
// Hardcoded for now; if Concord ever ships white-labeled SaaS the issuer
// will need to come from per-tenant config.
const mfaIssuer = "Concord"

// recoveryCodeCount is the number of one-time codes we hand out at
// enrollment / regeneration. Ten is the industry norm.
const recoveryCodeCount = 10

// recoveryCodeBytes is the random byte length per code, base32-encoded,
// dashed in the middle for readability. 5 bytes → 8 base32 chars (40 bits).
const recoveryCodeBytes = 5

// GetMFAStatus returns the user's MFA enrollment state plus the number of
// unused recovery codes. Powers the dashboard "MFA: on/off" indicator.
func (h *Handlers) GetMFAStatus(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())
	enrolled, err := h.store.IsUserMFAEnrolled(r.Context(), u.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	remaining := 0
	if enrolled {
		remaining, err = h.store.CountUnusedRecoveryCodes(r.Context(), u.ID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"enrolled":                  enrolled,
		"recovery_codes_remaining": remaining,
	})
}

// EnrollTOTP starts the TOTP enrollment flow: generates a fresh secret,
// stores it as pending (enrolled_at IS NULL), and returns the
// provisioning URI so the UI can render a QR code. The next call is
// VerifyTOTP with a code from the user's authenticator app.
func (h *Handlers) EnrollTOTP(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      mfaIssuer,
		AccountName: u.Email,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, "failed to generate TOTP secret: "+err.Error())
		return
	}

	if err := h.store.BeginUserTOTPEnrollment(r.Context(), u.ID, key.Secret()); err != nil {
		if errors.Is(err, store.ErrMFAAlreadyEnrolled) {
			httpx.Error(w, http.StatusConflict,
				"MFA is already enrolled — call /v1/me/mfa/disable first if you want to re-enroll")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &u.ID,
		Action:      "auth.mfa.enroll_start",
		TargetType:  "user",
		TargetID:    &u.ID,
	})

	httpx.JSON(w, http.StatusOK, map[string]any{
		"secret":            key.Secret(),
		"provisioning_uri": key.URL(),
		"issuer":           mfaIssuer,
		"account_name":     u.Email,
		"note":             "Scan the QR built from `provisioning_uri`, then POST a 6-digit code to /v1/me/mfa/totp/verify.",
	})
}

// VerifyTOTP completes enrollment by validating the first code typed from
// the user's authenticator app. On success: marks the secret enrolled,
// generates a fresh batch of recovery codes (returned ONCE in the
// response), audits the event.
func (h *Handlers) VerifyTOTP(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())

	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.Code = strings.TrimSpace(body.Code)
	if body.Code == "" {
		httpx.Error(w, http.StatusBadRequest, "`code` is required")
		return
	}

	t, err := h.store.GetUserTOTP(r.Context(), u.ID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusBadRequest, "no pending enrollment — call /v1/me/mfa/totp/enroll first")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if t.EnrolledAt != nil {
		httpx.Error(w, http.StatusConflict, "MFA is already enrolled")
		return
	}

	if !totp.Validate(body.Code, t.Secret) {
		h.audit(r, store.RecordAuditParams{
			ActorKind:   store.AuditActorUser,
			ActorUserID: &u.ID,
			Action:      "auth.mfa.enroll_failure",
			TargetType:  "user",
			TargetID:    &u.ID,
		})
		httpx.Error(w, http.StatusUnauthorized, "code did not validate — try again with the next 30-second window")
		return
	}

	if err := h.store.MarkUserTOTPEnrolled(r.Context(), u.ID); err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	plaintexts, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.store.ReplaceRecoveryCodes(r.Context(), u.ID, plaintexts); err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &u.ID,
		Action:      "auth.mfa.enroll_complete",
		TargetType:  "user",
		TargetID:    &u.ID,
	})

	httpx.JSON(w, http.StatusOK, map[string]any{
		"enrolled":       true,
		"recovery_codes": plaintexts,
		"note":           "Save the recovery codes NOW — they are shown only once. Each is single-use.",
	})
}

// DisableMFA wipes the user's TOTP secret and every recovery code. Gated on
// a fresh password check so a stolen session can't disable the second
// factor on its own.
func (h *Handlers) DisableMFA(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "`password` is required")
		return
	}
	if _, err := h.store.VerifyUserPassword(r.Context(), u.Email, body.Password); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusUnauthorized, "password did not match")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := h.store.DisableUserMFA(r.Context(), u.ID); err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &u.ID,
		Action:      "auth.mfa.disable",
		TargetType:  "user",
		TargetID:    &u.ID,
	})
	w.WriteHeader(http.StatusNoContent)
}

// RegenerateRecoveryCodes wipes existing codes and mints a fresh batch.
// Gated on the user's current password (same reasoning as DisableMFA).
func (h *Handlers) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u, _ := authctx.SessionUserFrom(r.Context())
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "`password` is required")
		return
	}
	if _, err := h.store.VerifyUserPassword(r.Context(), u.Email, body.Password); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusUnauthorized, "password did not match")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	enrolled, err := h.store.IsUserMFAEnrolled(r.Context(), u.ID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !enrolled {
		httpx.Error(w, http.StatusBadRequest, "MFA is not enrolled")
		return
	}

	plaintexts, err := generateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.store.ReplaceRecoveryCodes(r.Context(), u.ID, plaintexts); err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &u.ID,
		Action:      "auth.mfa.recovery_regenerate",
		TargetType:  "user",
		TargetID:    &u.ID,
	})
	httpx.JSON(w, http.StatusOK, map[string]any{
		"recovery_codes": plaintexts,
		"note":           "Old codes are gone. Save these — they will not be shown again.",
	})
}

// LoginMFA is the second leg of the login flow. It consumes the challenge
// token returned by /v1/auth/login and validates either a TOTP code or a
// one-time recovery code. On success it mints a normal session, the same
// shape /v1/auth/login returns when MFA is not enrolled.
func (h *Handlers) LoginMFA(w http.ResponseWriter, r *http.Request) {
	if !allow(w, h.limits.MFASubmitIP, httpx.ClientIP(r)) {
		return
	}
	var body struct {
		MFAToken     string `json:"mfa_token"`
		Code         string `json:"code,omitempty"`
		RecoveryCode string `json:"recovery_code,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	body.MFAToken = strings.TrimSpace(body.MFAToken)
	body.Code = strings.TrimSpace(body.Code)
	body.RecoveryCode = strings.TrimSpace(body.RecoveryCode)
	if body.MFAToken == "" {
		httpx.Error(w, http.StatusBadRequest, "`mfa_token` is required")
		return
	}
	if body.Code == "" && body.RecoveryCode == "" {
		httpx.Error(w, http.StatusBadRequest, "either `code` or `recovery_code` is required")
		return
	}

	userID, err := h.store.ConsumeMFAChallenge(r.Context(), body.MFAToken)
	switch {
	case errors.Is(err, store.ErrNotFound):
		httpx.Error(w, http.StatusUnauthorized, "invalid or already-used MFA token")
		return
	case errors.Is(err, store.ErrMFAChallengeExpired):
		httpx.Error(w, http.StatusGone, "MFA token expired — start the login flow again")
		return
	case err != nil:
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	usedRecovery := false
	if body.Code != "" {
		t, err := h.store.GetUserTOTP(r.Context(), userID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !totp.Validate(body.Code, t.Secret) {
			h.audit(r, store.RecordAuditParams{
				ActorKind:   store.AuditActorUser,
				ActorUserID: &userID,
				Action:      "auth.mfa.failure",
				TargetType:  "user",
				TargetID:    &userID,
				Details:     map[string]any{"factor": "totp"},
			})
			httpx.Error(w, http.StatusUnauthorized, "code did not validate")
			return
		}
		h.store.MarkUserTOTPUsed(r.Context(), userID)
	} else {
		ok, err := h.store.ConsumeRecoveryCode(r.Context(), userID, body.RecoveryCode)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !ok {
			h.audit(r, store.RecordAuditParams{
				ActorKind:   store.AuditActorUser,
				ActorUserID: &userID,
				Action:      "auth.mfa.failure",
				TargetType:  "user",
				TargetID:    &userID,
				Details:     map[string]any{"factor": "recovery_code"},
			})
			httpx.Error(w, http.StatusUnauthorized, "recovery code did not match")
			return
		}
		usedRecovery = true
	}

	user, err := h.store.GetUserByID(r.Context(), userID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	sess, plain, err := h.store.CreateSession(r.Context(), userID, h.sessionTTL,
		httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	action := "auth.mfa.success"
	if usedRecovery {
		action = "auth.mfa.recovery_used"
	}
	h.audit(r, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &userID,
		Action:      action,
		TargetType:  "session",
		TargetID:    &sess.ID,
	})

	httpx.JSON(w, http.StatusCreated, map[string]any{
		"session_id":         sess.ID,
		"token":              plain,
		"expires_at":         sess.ExpiresAt,
		"user":               user,
		"used_recovery_code": usedRecovery,
	})
}

// generateRecoveryCodes returns `n` user-readable codes (`XXXX-XXXX`) drawn
// from crypto/rand. Codes are returned in plaintext for one-time display
// at enrollment / regeneration; the DB only ever stores their argon2id
// hashes (see store.ReplaceRecoveryCodes).
func generateRecoveryCodes(n int) ([]string, error) {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, recoveryCodeBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generating recovery code: %w", err)
		}
		s := strings.ToLower(strings.TrimRight(
			base32.StdEncoding.EncodeToString(buf), "="))
		// 5 bytes → 8 chars; split into a 4-4 group separated by a dash so
		// users typing them off paper can pace themselves.
		if len(s) >= 8 {
			s = s[:4] + "-" + s[4:8]
		}
		out = append(out, s)
	}
	return out, nil
}
