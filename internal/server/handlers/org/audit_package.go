package org

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/concord-dev/concord/internal/auditpackage"
	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// ExportAuditPackage serves GET /v1/orgs/{slug}/audit-package. Gated by
// audit:read (same as the audit-event endpoint) so the auditor-flag user
// can pull a bundle on every tenant in scope. Query params:
//
//	since   RFC3339 — lower bound for audit + drift event extracts
//	until   RFC3339 — upper bound (exclusive)
//	max_runs / max_audit_events / max_drift_events — caps; defaults are
//	         100 / 5000 / 5000 set inside auditpackage.Build
//
// Streams the ZIP directly to the response — no temp file, no buffer.
// On error AFTER headers are flushed the response is truncated; the
// client's zip reader will fail integrity checks rather than receive a
// silently-incomplete bundle.
func (h *Handlers) ExportAuditPackage(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	q := r.URL.Query()

	opts := auditpackage.Options{}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "`since` must be RFC3339")
			return
		}
		opts.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "`until` must be RFC3339")
			return
		}
		opts.Until = t
	}
	for _, pair := range []struct {
		key string
		set func(int)
	}{
		{"max_runs", func(n int) { opts.MaxRuns = n }},
		{"max_audit_events", func(n int) { opts.MaxAuditEvents = n }},
		{"max_drift_events", func(n int) { opts.MaxDriftEvents = n }},
	} {
		v := q.Get(pair.key)
		if v == "" {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpx.Error(w, http.StatusBadRequest, "`"+pair.key+"` must be a positive integer")
			return
		}
		pair.set(n)
	}

	// Attribution string for metadata.json. Sessions surface the user
	// email via the principal context (set by RequireSession); API
	// tokens record the token id. Either is enough for an external
	// auditor reviewing the bundle to know who pulled it.
	requestedBy := principalLabel(r)
	opts.RequestedBy = requestedBy

	// Set headers BEFORE any zip write — once auditpackage.Build starts
	// streaming, the response has flushed and we can't change them.
	filename := fmt.Sprintf("audit-package-%s-%s.zip",
		p.Org.Slug, time.Now().UTC().Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	meta, err := auditpackage.Build(r.Context(), h.store, p.Org.ID, opts, w)
	if err != nil {
		// Headers are already flushed; we can't switch to JSON 500. The
		// client will see a truncated zip and the operator gets the slog
		// from the package itself. Audit the failed attempt for visibility.
		h.audit(r, store.RecordAuditParams{
			Action:     "audit_package.export.failure",
			TargetType: "organization",
			TargetID:   &p.Org.ID,
			Details:    map[string]any{"err": err.Error()},
		})
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "audit_package.export",
		TargetType: "organization",
		TargetID:   &p.Org.ID,
		Details: map[string]any{
			"counts":         meta.Counts,
			"window_since":   meta.WindowSince,
			"window_until":   meta.WindowUntil,
			"format_version": meta.Version,
		},
	})
}

// principalLabel returns a short string identifying the caller for the
// metadata.json "requested_by" field. We prefer a human-friendly value
// when available so auditors reading the bundle see "alice@acme.test"
// not a UUID; falls back to the token id otherwise.
func principalLabel(r *http.Request) string {
	if u, ok := authctx.SessionUserFrom(r.Context()); ok && u.Email != "" {
		return u.Email
	}
	if p, ok := authctx.PrincipalFrom(r.Context()); ok && p.TokenID != nil {
		return "api_token:" + p.TokenID.String()
	}
	return ""
}
