// Package plugins is the host-side machinery that spawns Concord plugin
// binaries and exposes them as evidence.Collector implementations.
package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	pluginv1 "github.com/concord-dev/concord/proto/concord/plugin/v1"
)

// PluginCollector implements evidence.Collector by forwarding Collect calls to a running plugin process.
type PluginCollector struct {
	source  string
	client  pluginv1.CollectorClient
	timeout time.Duration
}

// Capabilities is the host-side projection of a plugin's CapabilitiesResponse.
type Capabilities struct {
	Source          string
	Version         string
	ProtocolVersion string
	SDKVersion      string
	SupportedTypes  []string
	RequiredEnv     []string
	OptionalEnv     []string
	Permissions     Permissions
	DocsURL         string
}

// Permissions advertises a plugin's runtime needs.
type Permissions struct {
	Network    []string
	Filesystem string
	Subprocess bool
}

// NewPluginCollector wraps a connected gRPC client.
func NewPluginCollector(source string, client pluginv1.CollectorClient, timeout time.Duration) *PluginCollector {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &PluginCollector{source: source, client: client, timeout: timeout}
}

// Source returns the source name this collector handles.
func (p *PluginCollector) Source() string { return p.source }

// Capabilities returns the plugin's self-declared capabilities.
func (p *PluginCollector) Capabilities(ctx context.Context) (Capabilities, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := p.client.Capabilities(ctx, &pluginv1.CapabilitiesRequest{})
	if err != nil {
		return Capabilities{}, mapGRPCError(err)
	}
	out := Capabilities{
		Source:          resp.Source,
		Version:         resp.Version,
		ProtocolVersion: resp.ConcordProtocolVersion,
		SDKVersion:      resp.SdkVersion,
		SupportedTypes:  resp.SupportedTypes,
		RequiredEnv:     resp.RequiredEnv,
		OptionalEnv:     resp.OptionalEnv,
		DocsURL:         resp.DocsUrl,
	}
	if resp.Permissions != nil {
		out.Permissions.Network = resp.Permissions.Network
		out.Permissions.Filesystem = resp.Permissions.Filesystem
		out.Permissions.Subprocess = resp.Permissions.Subprocess
	}
	return out, nil
}

// Probe runs the plugin's health-check RPC.
func (p *PluginCollector) Probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	resp, err := p.client.Probe(ctx, &pluginv1.ProbeRequest{TimeoutMs: 15000})
	if err != nil {
		return "", mapGRPCError(err)
	}
	return resp.Info, nil
}

// Collect satisfies evidence.Collector.
func (p *PluginCollector) Collect(cctx evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	params, err := paramsToStruct(ref.Params)
	if err != nil {
		return nil, fmt.Errorf("marshalling plugin %s params: %w", p.source, err)
	}

	resp, err := p.client.Collect(ctx, &pluginv1.CollectRequest{
		Ref: &pluginv1.EvidenceRef{
			Id:       ref.ID,
			Source:   ref.Source,
			Type:     ref.Type,
			Optional: ref.Optional,
			Params:   params,
			Fixture:  ref.Fixture,
		},
		ControlDir: cctx.ControlDir,
		TimeoutMs:  p.timeout.Milliseconds(),
	})
	if err != nil {
		return nil, mapGRPCError(err)
	}
	return decodeEvidence(resp)
}

func paramsToStruct(params map[string]any) (*structpb.Struct, error) {
	if len(params) == 0 {
		return nil, nil
	}
	return structpb.NewStruct(params)
}

func decodeEvidence(resp *pluginv1.CollectResponse) (any, error) {
	if resp == nil {
		return nil, nil
	}
	if raw := resp.GetValueJson(); len(raw) > 0 {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("decoding plugin response: %w", err)
		}
		return v, nil
	}
	if v := resp.GetValue(); v != nil {
		return v.AsMap(), nil
	}
	return nil, nil
}

// mapGRPCError translates a gRPC status into the evidence error vocabulary,
// preserving ErrUnsupportedType so the registry's fixture-fallback survives.
func mapGRPCError(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.InvalidArgument:
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok && info.Reason == "concord.evidence.unsupported_type" {
				return fmt.Errorf("%w: %s", evidence.ErrUnsupportedType, st.Message())
			}
		}
	case codes.DeadlineExceeded:
		return fmt.Errorf("plugin deadline exceeded: %s", st.Message())
	case codes.Unavailable:
		return fmt.Errorf("plugin unavailable: %s", st.Message())
	}
	return errors.New(st.Message())
}
