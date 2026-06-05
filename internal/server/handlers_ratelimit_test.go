package server_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/public"
	"github.com/concord-dev/concord/internal/server/limiter"
)

func tightAuthLimits(burst int) auth.Limits {
	cfg := limiter.Config{Rate: limiter.Every(time.Minute), Burst: burst}
	return auth.Limits{
		LoginIP:     limiter.NewMemoryBucket(cfg),
		LoginEmail:  limiter.NewMemoryBucket(cfg),
		PWResetIP:   limiter.NewMemoryBucket(cfg),
		PWConfirmIP: limiter.NewMemoryBucket(cfg),
	}
}

func tightPublicLimits(burst int) public.Limits {
	cfg := limiter.Config{Rate: limiter.Every(time.Minute), Burst: burst}
	return public.Limits{InviteAcceptIP: limiter.NewMemoryBucket(cfg)}
}

func TestLogin_ReturnsTooManyRequestsAfterBurstExceeded(t *testing.T) {
	h := newHarness(t)
	h.c.SetLimitsForTest(tightAuthLimits(2), tightPublicLimits(100))
	h.rebuildServer(t)

	body := fmt.Sprintf(`{"email":%q,"password":"wrong"}`, h.user.Email)
	resp, _ := h.do(t, "POST", "/v1/auth/login", body, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "first attempt: wrong password → 401")
	resp, _ = h.do(t, "POST", "/v1/auth/login", body, "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "second attempt within burst → still 401")
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"third attempt past burst must be rate-limited")
	assert.JSONEq(t, `{"error":"rate limit exceeded; retry shortly"}`, string(raw))

	ra, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	require.NoError(t, err, "Retry-After must be an integer second count")
	assert.GreaterOrEqual(t, ra, 1, "Retry-After must be at least 1s")
}

func TestPasswordReset_ReturnsTooManyRequestsAfterBurstExceeded(t *testing.T) {
	h := newHarness(t)
	h.c.SetLimitsForTest(tightAuthLimits(1), tightPublicLimits(100))
	h.rebuildServer(t)

	body := fmt.Sprintf(`{"email":%q}`, h.user.Email)
	resp, _ := h.do(t, "POST", "/v1/auth/password-reset", body, "")
	assert.Equal(t, http.StatusOK, resp.StatusCode, "first request consumes the burst")
	resp, _ = h.do(t, "POST", "/v1/auth/password-reset", body, "")
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"second back-to-back request must be 429 — and not leak that the email existed")
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}

func TestInviteAccept_ReturnsTooManyRequestsAfterBurstExceeded(t *testing.T) {
	h := newHarness(t)
	h.c.SetLimitsForTest(tightAuthLimits(100), tightPublicLimits(2))
	h.rebuildServer(t)

	body := `{"token":"nope-this-doesnt-exist-as-a-real-invitation"}`
	for i := 0; i < 2; i++ {
		resp, _ := h.do(t, "POST", "/v1/invitations/accept", body, "")
		assert.NotEqual(t, http.StatusTooManyRequests, resp.StatusCode,
			"requests within the burst must not be rate-limited")
	}
	resp, _ := h.do(t, "POST", "/v1/invitations/accept", body, "")
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode,
		"burst+1 invite-accept guess must be 429")
}

func TestLogin_RateLimitDoesNotApplyToValidSuccess(t *testing.T) {
	h := newHarness(t)
	h.c.SetLimitsForTest(tightAuthLimits(5), tightPublicLimits(100))
	h.rebuildServer(t)

	body := fmt.Sprintf(`{"email":%q,"password":%q}`, h.user.Email, h.password)
	resp, raw := h.do(t, "POST", "/v1/auth/login", body, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))

	var got struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.NotEmpty(t, got.Token, "successful login must mint a session token")
}
