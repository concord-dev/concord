package server_test

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/notify/mail"
)

type captureMailer struct {
	mu   sync.Mutex
	sent []mail.Message
}

func (c *captureMailer) Send(_ context.Context, m mail.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, m)
	return nil
}
func (c *captureMailer) waitFor(t *testing.T, n int) []mail.Message {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		got := append([]mail.Message(nil), c.sent...)
		c.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("captureMailer: expected %d message(s), still have %d after 2s", n, len(c.sent))
	return nil
}

func TestPasswordReset_DeliversEmailWithConfirmURL(t *testing.T) {
	h := newHarness(t)
	cm := &captureMailer{}
	h.c.SetMailerForTest(cm)
	h.rebuildServer(t)

	body := fmt.Sprintf(`{"email":%q}`, h.user.Email)
	resp, _ := h.do(t, "POST", "/v1/auth/password-reset", body, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	got := cm.waitFor(t, 1)[0]
	assert.Equal(t, h.user.Email, got.To,
		"reset email must address the user whose account is being reset")
	assert.Contains(t, got.Subject, "Reset your Concord password")
	assert.Contains(t, got.Body, "/v1/auth/password-reset/confirm?token=",
		"body must contain the single-use confirm URL — that's the whole point of the email")
	assert.Contains(t, got.Body, "expires shortly",
		"body must remind the user the link is single-use + time-limited")
}

func TestPasswordReset_UnknownEmailDoesNotSendMail(t *testing.T) {
	h := newHarness(t)
	cm := &captureMailer{}
	h.c.SetMailerForTest(cm)
	h.rebuildServer(t)

	resp, _ := h.do(t, "POST", "/v1/auth/password-reset",
		`{"email":"nobody-here@example.com"}`, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	time.Sleep(150 * time.Millisecond)
	cm.mu.Lock()
	defer cm.mu.Unlock()
	assert.Empty(t, cm.sent,
		"a password-reset request for an unknown email must NOT trigger an outbound email")
}

func TestInvitation_CreateDeliversEmailWithAcceptURL(t *testing.T) {
	h := newHarness(t)
	cm := &captureMailer{}
	h.c.SetMailerForTest(cm)
	h.rebuildServer(t)

	sessionToken := h.login(t)
	inviteeEmail := "new-teammate-" + h.org.Slug + "@example.com"
	body := fmt.Sprintf(`{"email":%q,"role":"member"}`, inviteeEmail)
	resp, raw := h.do(t, "POST",
		"/v1/orgs/"+h.org.Slug+"/invitations", body, sessionToken)
	require.Equalf(t, http.StatusCreated, resp.StatusCode, "create: %s", raw)

	got := cm.waitFor(t, 1)[0]
	assert.Equal(t, inviteeEmail, got.To,
		"invitation email must address the invitee, NOT the inviting admin")
	assert.Contains(t, got.Subject, h.org.Name,
		"subject should reference the org name so the invitee knows which workspace this is for")
	assert.Contains(t, got.Body, "/v1/invitations/accept?token=concord_inv_",
		"body must carry the accept URL with its token — that's how the invitee gets in")
	assert.Contains(t, got.Body, "member",
		"role should appear in the body so the invitee sees what access they're being granted")
}
