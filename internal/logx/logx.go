// Package logx is the server's structured logging facade. It wraps the
// stdlib slog and adds per-request context plumbing (request_id) so handlers
// can emit correlated logs without passing a logger around.
//
// Use Init at process start to install the configured logger as slog's default;
// after that any package can call slog.Info / slog.Error directly. Handlers
// should prefer FromContext(r.Context()) so emitted records inherit the
// request_id attribute attached by the request-id middleware.
package logx

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type ctxKey int

const ctxKeyRequestID ctxKey = iota

// Init constructs and installs a *slog.Logger as the process default.
// `format` is "json" (default) or "text"; `level` is parsed as a slog level
// name (debug|info|warn|error) and falls back to info when unset/invalid.
func Init(format, level string) *slog.Logger {
	lv := parseLevel(level)
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "text") {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	// Wrap the format handler in the PII redactor so EVERY slog call
	// in the process — including third-party libraries — has sensitive
	// attribute values stripped before they hit stderr.
	h = NewRedactingHandler(h, nil)
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}

// NewForTest returns a JSON logger writing to w. It does NOT touch the process
// default — tests can capture output without disturbing concurrent callers.
func NewForTest(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// WithRequestID attaches an inbound/generated request ID to ctx so downstream
// handlers and FromContext can surface it in their log lines.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// RequestID returns the request ID stored in ctx, or "" if none is present.
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(ctxKeyRequestID).(string)
	return s
}

// FromContext returns slog's default logger pre-bound with the ctx request_id
// when one is present, so handler-side log records correlate with the inflight
// HTTP request without callers having to remember to add the attr.
func FromContext(ctx context.Context) *slog.Logger {
	if id := RequestID(ctx); id != "" {
		return slog.Default().With("request_id", id)
	}
	return slog.Default()
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
