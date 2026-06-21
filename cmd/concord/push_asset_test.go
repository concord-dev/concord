package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

func TestPushAssets_PostsBatch(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var gotBody struct {
		Assets []apiv1.ObservedAsset `json:"assets"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotCT = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"created":2,"updated":0,"unchanged":0}`))
	}))
	defer srv.Close()

	opts := pushOpts{serverURL: srv.URL, orgSlug: "acme", projectSlug: "default", token: "concord_x"}
	assets := []apiv1.ObservedAsset{
		{Source: "aws", ExternalID: "arn:aws:s3:::b1", Type: "cloud_resource", Name: "b1"},
		{Source: "aws", ExternalID: "arn:aws:s3:::b2", Type: "cloud_resource", Name: "b2"},
	}
	if err := pushAssets(context.Background(), opts, assets); err != nil {
		t.Fatalf("pushAssets: %v", err)
	}
	if gotPath != "/v1/orgs/acme/assets/ingest" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer concord_x" {
		t.Fatalf("auth = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Fatalf("content-type = %q", gotCT)
	}
	if len(gotBody.Assets) != 2 || gotBody.Assets[0].ExternalID != "arn:aws:s3:::b1" {
		t.Fatalf("posted assets wrong: %+v", gotBody.Assets)
	}
}

func TestPushAssets_ChunksLargeBatch(t *testing.T) {
	var requests, totalAssets int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var b struct {
			Assets []apiv1.ObservedAsset `json:"assets"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &b)
		if len(b.Assets) > maxAssetsPerRequest {
			t.Errorf("chunk of %d exceeds cap %d", len(b.Assets), maxAssetsPerRequest)
		}
		totalAssets += len(b.Assets)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"created":0,"updated":0,"unchanged":0}`))
	}))
	defer srv.Close()

	assets := make([]apiv1.ObservedAsset, maxAssetsPerRequest+1)
	for i := range assets {
		assets[i] = apiv1.ObservedAsset{Source: "aws", ExternalID: fmt.Sprintf("arn:%d", i), Type: "cloud_resource", Name: "b"}
	}
	opts := pushOpts{serverURL: srv.URL, orgSlug: "acme", projectSlug: "default", token: "concord_x"}
	if err := pushAssets(context.Background(), opts, assets); err != nil {
		t.Fatalf("pushAssets: %v", err)
	}
	if requests != 2 {
		t.Fatalf("want 2 chunked requests for %d assets, got %d", len(assets), requests)
	}
	if totalAssets != len(assets) {
		t.Fatalf("want all %d assets delivered, got %d", len(assets), totalAssets)
	}
}

func TestPushAssets_SurfacesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid input"}`))
	}))
	defer srv.Close()

	opts := pushOpts{serverURL: srv.URL, orgSlug: "acme", projectSlug: "default", token: "concord_x"}
	err := pushAssets(context.Background(), opts,
		[]apiv1.ObservedAsset{{Source: "aws", ExternalID: "arn:1", Type: "bogus", Name: "n"}})
	if err == nil {
		t.Fatal("expected an error when the server returns 400")
	}
}
