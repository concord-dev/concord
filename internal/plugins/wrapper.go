// Package plugins is the host-side machinery that spawns Concord
// plugin binaries and exposes them as evidence.Collector implementations.
// The wire protocol lives in proto/concord/plugin/v1; the SDK plugin
// authors import lives at pkg/plugin.
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

// PluginCollector implements evidence.Collector by forwarding Collect
// calls to a running plugin process over gRPC. Constructed by the
// Manager; not instantiated directly.
type PluginCollector struct {
	source  string
	client  pluginv1.CollectorClient
	timeout time.Duration
}

// NewPluginCollector wraps a connected gRPC client. The Manager owns
// the underlying client lifecycle; the wrapper just translates calls.
func NewPluginCollector(source string, client pluginv1.CollectorClient, timeout time.Duration) *PluginCollector {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &PluginCollector{source: source, client: client, timeout: timeout}
}

// Source returns the source name this collector handles.
func (p *PluginCollector) Source() string { return p.source }

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

// Collect satisfies evidence.Collector. The control-dir from the
// Concord-side evidence.Context becomes part of the gRPC request so
// the plugin can resolve relative fixture paths if it ever needs to.
func (p *PluginCollector) Collect(cctx evidence.Context, ref apiv1.EvidenceRef) (any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	params, perr := paramsToStruct(ref.Params)
	if perr != nil {
		return nil, fmt.Errorf("plugin %s: marshal params: %w", p.source, perr)
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
			return nil, fmt.Errorf("plugin: decode value_json: %w", err)
		}
		return v, nil
	}
	if v := resp.GetValue(); v != nil {
		return v.AsMap(), nil
	}
	return nil, nil
}

// mapGRPCError translates a gRPC status into the error vocabulary
// the existing evidence.Registry expects. Critically, it preserves
// ErrUnsupportedType so the registry's fixture-fallback still kicks in.
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
		return fmt.Errorf("plugin: deadline exceeded: %s", st.Message())
	case codes.Unavailable:
		return fmt.Errorf("plugin: unavailable: %s", st.Message())
	}
	return errors.New(st.Message())
}
