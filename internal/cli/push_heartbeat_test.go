package cli

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestPushEvidenceHeartbeats_PostsOnePerSource(t *testing.T) {
	var mu sync.Mutex
	type hb struct {
		Source      string    `json:"source"`
		StartedAt   time.Time `json:"started_at"`
		SucceededAt time.Time `json:"succeeded_at"`
	}
	var got []hb
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b hb
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &b)
		mu.Lock()
		got = append(got, b)
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	opts := pushOpts{serverURL: srv.URL, orgSlug: "acme", projectSlug: "default", token: "concord_x"}
	started := time.Now().UTC().Add(-time.Minute)
	completed := time.Now().UTC()
	pushEvidenceHeartbeats(context.Background(), opts, []string{"github", "okta"}, started, completed)

	if len(got) != 2 {
		t.Fatalf("want 2 heartbeats, got %d", len(got))
	}
	for _, p := range paths {
		if p != "/v1/orgs/acme/projects/default/evidence-collections" {
			t.Fatalf("path = %q", p)
		}
	}
	sources := map[string]bool{got[0].Source: true, got[1].Source: true}
	if !sources["github"] || !sources["okta"] {
		t.Fatalf("sources = %v", sources)
	}
	if got[0].StartedAt.IsZero() || got[0].SucceededAt.IsZero() {
		t.Fatalf("timestamps not set: %+v", got[0])
	}
}

func TestPushEvidenceHeartbeats_NoSourcesNoRequests(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	opts := pushOpts{serverURL: srv.URL, orgSlug: "acme", projectSlug: "default", token: "concord_x"}
	pushEvidenceHeartbeats(context.Background(), opts, nil, time.Now(), time.Now())
	if calls != 0 {
		t.Fatalf("expected no requests for empty sources, got %d", calls)
	}
}
