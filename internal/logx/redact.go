package logx

import (
	"context"
	"log/slog"
	"strings"
)

const redactValue = "***REDACTED***"

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

type RedactingHandler struct {
	inner slog.Handler
	keys  []string // pre-lowercased
}

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

func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, out)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = h.redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redacted), keys: h.keys}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name), keys: h.keys}
}

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
