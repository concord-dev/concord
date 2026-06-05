package logx

import (
	"context"
	"log/slog"
	"strings"
)

// redactValue replaces a redacted attr's value. Kept as a constant so
// log-search queries can pivot on it (`level=info redacted:true` etc.).
const redactValue = "***REDACTED***"

// defaultSensitiveKeys is the curated set of attribute names whose
// values must never appear in logs. Matched case-insensitively, and
// substring — `req_password` redacts the same way `password` does.
//
// Keep this list small and obvious. The redactor is a last line of
// defence; the right answer is for handlers not to slog these values
// in the first place. Adding noisy entries (e.g. "id") would make the
// log surface unreadable.
var defaultSensitiveKeys = []string{
	"password",
	"secret",
	"token",
	"authorization",
	"api_key",
	"apikey",
	"private_key",
	"client_secret",
	"otp",
	"totp",
	"recovery_code",
	"session_token",
	"refresh_token",
	"x-concord-signature",
}

// RedactingHandler wraps any slog.Handler and replaces values for
// sensitive attribute names with a redacted marker before passing them
// to the inner handler. The Init wiring installs this in front of the
// JSON/text handler so EVERY slog.Default() call goes through the
// filter — no caller-side discipline required.
//
// The redactor is best-effort and intentionally simple:
//   - Substring match on lower-cased attribute name.
//   - Top-level + nested slog.Group descent (so {auth: {token: "..."}}
//     gets caught).
//   - Replaces the entire value with a fixed marker, no length-hint
//     leak ("***REDACTED***" regardless of original length).
//
// What it does NOT do:
//   - Pattern-match values (no "looks like a JWT" detector). Pattern
//     matching is error-prone and creates false-positives that hide
//     legitimate data; we'd rather be loud about the curated key list
//     and let the security review catch new ones.
//   - Redact the message text. Handlers should never put a secret in
//     the message — it's harder to filter and the slog API
//     deliberately separates structured attrs from the message.
type RedactingHandler struct {
	inner slog.Handler
	keys  []string // pre-lowercased
}

// NewRedactingHandler wraps inner. extra adds project-specific
// attribute names beyond the default list (case-insensitive,
// substring match). Pass nil for the default-only configuration.
func NewRedactingHandler(inner slog.Handler, extra []string) *RedactingHandler {
	all := make([]string, 0, len(defaultSensitiveKeys)+len(extra))
	for _, k := range defaultSensitiveKeys {
		all = append(all, strings.ToLower(k))
	}
	for _, k := range extra {
		all = append(all, strings.ToLower(strings.TrimSpace(k)))
	}
	return &RedactingHandler{inner: inner, keys: all}
}

// Enabled delegates — the wrapping is zero-cost for filtered-out levels.
func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle rewrites the record's attributes in place (well — into a new
// record; slog.Record is value-typed but the attr-collection helper
// is allocation-free for the common no-redact case).
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

// WithAttrs propagates pre-bound attrs through the same redactor so a
// logger built via .With("token", ...) still gets filtered. Without
// this, the wrapper would only catch attrs added at slog.Info time.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = h.redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redacted), keys: h.keys}
}

// WithGroup wraps the inner handler's group result so subsequent
// .With / Handle calls retain the redacting behaviour.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name), keys: h.keys}
}

// redactAttr returns the attr with its value replaced when the key is
// sensitive. Recurses into slog.Group so nested structures are
// covered. Values are replaced with a constant string — losing the
// original type is the safe trade (an int "password=123" gets logged
// as "***REDACTED***" string).
func (h *RedactingHandler) redactAttr(a slog.Attr) slog.Attr {
	if h.isSensitive(a.Key) {
		return slog.String(a.Key, redactValue)
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		redacted := make([]any, 0, len(group)*2)
		for _, g := range group {
			gg := h.redactAttr(g)
			redacted = append(redacted, gg)
		}
		return slog.Group(a.Key, redacted...)
	}
	return a
}

func (h *RedactingHandler) isSensitive(key string) bool {
	lk := strings.ToLower(key)
	for _, k := range h.keys {
		if strings.Contains(lk, k) {
			return true
		}
	}
	return false
}
