package plugins

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/concord-dev/concord-plugin-sdk/proto/concord/plugin/v1"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type fakeCollectorClient struct {
	resp *pluginv1.CollectResponse
}

func (fakeCollectorClient) Capabilities(context.Context, *pluginv1.CapabilitiesRequest, ...grpc.CallOption) (*pluginv1.CapabilitiesResponse, error) {
	return &pluginv1.CapabilitiesResponse{}, nil
}
func (fakeCollectorClient) Probe(context.Context, *pluginv1.ProbeRequest, ...grpc.CallOption) (*pluginv1.ProbeResponse, error) {
	return &pluginv1.ProbeResponse{}, nil
}
func (f fakeCollectorClient) Collect(context.Context, *pluginv1.CollectRequest, ...grpc.CallOption) (*pluginv1.CollectResponse, error) {
	return f.resp, nil
}

func TestPluginCollector_HarvestsAndDedupsAssets(t *testing.T) {
	meta, _ := structpb.NewStruct(map[string]any{"region": "us-east-1"})
	client := fakeCollectorClient{resp: &pluginv1.CollectResponse{
		Result: &pluginv1.CollectResponse_ValueJson{ValueJson: []byte(`{"ok":true}`)},
		ObservedAssets: []*pluginv1.ObservedAsset{
			// A spoofed source must be overwritten with the trusted registered name.
			{Source: "spoofed", ExternalId: "arn:1", Type: "cloud_resource", Name: "b1", Metadata: meta},
			{Source: "aws", ExternalId: "arn:1", Type: "cloud_resource", Name: "b1"}, // dup within one response
			{Source: "aws", ExternalId: "arn:2", Type: "cloud_resource", Name: "b2"},
			{Source: "aws", ExternalId: "", Type: "cloud_resource", Name: "bad"}, // empty key, dropped
		},
	}}
	sink := newAssetSink()
	pc := NewPluginCollector("aws", client, time.Second, sink)

	if _, err := pc.Collect(evidence.Context{}, apiv1.EvidenceRef{Type: "s3_bucket_encryption"}); err != nil {
		t.Fatalf("collect: %v", err)
	}
	// A second ref re-observes arn:1 and arn:2 — the sink must still dedupe.
	if _, err := pc.Collect(evidence.Context{}, apiv1.EvidenceRef{Type: "s3_public_access_block"}); err != nil {
		t.Fatalf("collect: %v", err)
	}

	got := sink.drain()
	if len(got) != 2 {
		t.Fatalf("want 2 deduped assets, got %d: %+v", len(got), got)
	}
	if got[0].Source != "aws" {
		t.Fatalf("source must be stamped with the trusted name, got %q", got[0].Source)
	}
	if got[0].ExternalID != "arn:1" || got[0].Metadata["region"] != "us-east-1" {
		t.Fatalf("first asset wrong (metadata not carried?): %+v", got[0])
	}
	if l := len(sink.drain()); l != 0 {
		t.Fatalf("drain must reset the sink, got %d", l)
	}
}

func TestPluginCollector_NilSinkIsSafe(t *testing.T) {
	client := fakeCollectorClient{resp: &pluginv1.CollectResponse{
		Result:         &pluginv1.CollectResponse_ValueJson{ValueJson: []byte(`{}`)},
		ObservedAssets: []*pluginv1.ObservedAsset{{Source: "aws", ExternalId: "arn:1", Type: "cloud_resource", Name: "b1"}},
	}}
	pc := NewPluginCollector("aws", client, time.Second, nil)
	if _, err := pc.Collect(evidence.Context{}, apiv1.EvidenceRef{Type: "s3"}); err != nil {
		t.Fatalf("collect with nil sink must not panic: %v", err)
	}
}
