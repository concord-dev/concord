package logx_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/logx"
)

func newCapturingLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	json := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(logx.NewRedactingHandler(json, nil)), buf
}

func decodeLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	require.NotZero(t, buf.Len(), "expected a log line; got none")
	var m map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &m))
	return m
}

func TestRedacting_TopLevelSensitiveKeysAreReplaced(t *testing.T) {
	log, buf := newCapturingLogger(t)
	log.Info("login",
		slog.String("email", "alice@example.com"),
		slog.String("password", "hunter2"),
		slog.String("session_token", "concord_sess_abc"),
		slog.String("api_key", "sk_live_xyz"),
		slog.String("authorization", "Bearer concord_abc"),
	)

	m := decodeLine(t, buf)
	assert.Equal(t, "alice@example.com", m["email"], "email is non-sensitive by default — should pass through")
	for _, k := range []string{"password", "session_token", "api_key", "authorization"} {
		assert.Equal(t, "***REDACTED***", m[k], "%q must be redacted", k)
	}
}

func TestRedacting_SubstringMatchCatchesPrefixedKeys(t *testing.T) {
	log, buf := newCapturingLogger(t)
	log.Info("event",
		slog.String("user_password", "hunter2"),
		slog.String("oauth_token", "ya29.abc"),
		slog.String("not_secret_name", "fine"), // contains "secret" → REDACTED
	)
	m := decodeLine(t, buf)
	assert.Equal(t, "***REDACTED***", m["user_password"])
	assert.Equal(t, "***REDACTED***", m["oauth_token"])
	assert.Equal(t, "***REDACTED***", m["not_secret_name"],
		"substring match is deliberate — false-positives are better than missed secrets")
}

func TestRedacting_GroupAttrsAreRecursed(t *testing.T) {
	log, buf := newCapturingLogger(t)
	log.Info("nested",
		slog.Group("auth",
			slog.String("token", "concord_abc"),
			slog.String("scheme", "Bearer"),
		),
	)
	m := decodeLine(t, buf)
	auth, ok := m["auth"].(map[string]any)
	require.True(t, ok, "auth must be a group object")
	assert.Equal(t, "***REDACTED***", auth["token"])
	assert.Equal(t, "Bearer", auth["scheme"], "non-sensitive sibling must survive")
}

func TestRedacting_WithAttrsAlsoRedacts(t *testing.T) {
	// A logger pre-bound via .With("token", ...) must still go
	// through the redactor — without this guarantee, middleware that
	// attaches request-scoped attrs would leak tokens.
	log, buf := newCapturingLogger(t)
	log.With(slog.String("token", "concord_pre_bound")).Info("downstream",
		slog.String("user", "alice"))
	m := decodeLine(t, buf)
	assert.Equal(t, "***REDACTED***", m["token"])
	assert.Equal(t, "alice", m["user"])
}

func TestRedacting_CaseInsensitiveMatch(t *testing.T) {
	log, buf := newCapturingLogger(t)
	log.Info("hdr",
		slog.String("Authorization", "Bearer x"),
		slog.String("X-Concord-Signature", "sha256=..."),
	)
	m := decodeLine(t, buf)
	assert.Equal(t, "***REDACTED***", m["Authorization"])
	assert.Equal(t, "***REDACTED***", m["X-Concord-Signature"])
}

func TestRedacting_ExtraKeysAppendToDefault(t *testing.T) {
	buf := &bytes.Buffer{}
	json := slog.NewJSONHandler(buf, nil)
	log := slog.New(logx.NewRedactingHandler(json, []string{"ssn"}))

	log.Info("evt",
		slog.String("ssn", "111-22-3333"),
		slog.String("password", "hunter2"),
	)
	m := decodeLine(t, buf)
	assert.Equal(t, "***REDACTED***", m["ssn"])
	assert.Equal(t, "***REDACTED***", m["password"])
}

func TestRedacting_EnabledDelegatesToInner(t *testing.T) {
	// At LevelWarn the inner JSON handler shouldn't emit a Debug
	// line, and the wrapper must not change that.
	buf := &bytes.Buffer{}
	json := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	log := slog.New(logx.NewRedactingHandler(json, nil))
	log.Debug("noise", slog.String("password", "hunter2"))
	assert.Zero(t, buf.Len(), "Debug below threshold must not emit")

	log.Warn("loud", slog.String("password", "hunter2"))
	assert.NotZero(t, buf.Len(), "Warn above threshold must emit (redacted)")
	m := decodeLine(t, buf)
	assert.Equal(t, "***REDACTED***", m["password"])
}

func TestRedacting_MessageIsNeverInspected(t *testing.T) {
	// Documented non-feature: the message text is NOT scanned. This
	// test pins that contract so a future "helpful" change doesn't
	// quietly start redacting log messages.
	log, buf := newCapturingLogger(t)
	log.Info("attempted login with token=concord_abc")
	out := buf.String()
	assert.Contains(t, out, "attempted login with token=concord_abc",
		"message text passes through verbatim — callers must not put secrets there")
}

// TestRedacting_HandlerContractCompliance is the slogtest-style smoke:
// a redacted attr must still produce a parsable JSON record with the
// expected envelope (time, level, msg). We assert structural shape
// rather than diff against slog's text output because slog's record
// ordering isn't guaranteed.
func TestRedacting_HandlerContractCompliance(t *testing.T) {
	log, buf := newCapturingLogger(t)
	log.LogAttrs(context.Background(), slog.LevelInfo, "checked",
		slog.String("password", "hunter2"),
		slog.Int("count", 3),
	)
	m := decodeLine(t, buf)
	assert.NotEmpty(t, m["time"])
	assert.Equal(t, "INFO", m["level"])
	assert.Equal(t, "checked", m["msg"])
	assert.Equal(t, "***REDACTED***", m["password"])
	assert.EqualValues(t, 3, m["count"])
	out := buf.String()
	assert.NotContains(t, out, "hunter2",
		"raw secret value must not appear anywhere in the line")
	assert.True(t, strings.HasSuffix(strings.TrimSpace(out), "}"),
		"JSON line must end with a closing brace")
}
