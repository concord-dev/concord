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

	requestedBy := principalLabel(r)
	opts.RequestedBy = requestedBy

	filename := fmt.Sprintf("audit-package-%s-%s.zip",
		p.Org.Slug, time.Now().UTC().Format("20060102T150405Z"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	meta, err := auditpackage.Build(r.Context(), h.store, p.Org.ID, opts, w)
	if err != nil {
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

func principalLabel(r *http.Request) string {
	if u, ok := authctx.SessionUserFrom(r.Context()); ok && u.Email != "" {
		return u.Email
	}
	if p, ok := authctx.PrincipalFrom(r.Context()); ok && p.TokenID != nil {
		return "api_token:" + p.TokenID.String()
	}
	return ""
}
