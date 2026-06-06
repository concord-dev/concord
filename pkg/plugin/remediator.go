package plugin

import (
	"context"

	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	pluginv1 "github.com/concord-dev/concord/proto/concord/plugin/v1"
)

// RemediatorPluginName is the key under go-plugin's plugin map for the
// remediator kind. A binary that serves both Collector and Remediator
// registers under both names.
const RemediatorPluginName = "remediator"

// Remediator is the interface a remediator plugin implements. The host
// invokes DryRun first; the operator confirms; then Execute runs against
// the target API.
type Remediator interface {
	Capabilities() RemediatorCapabilities
	DryRun(ctx context.Context, req RemediateRequest) (RemediateResponse, error)
	Execute(ctx context.Context, req RemediateRequest) (RemediateResponse, error)
}

// RemediatorCapabilities declares what actions a remediator implements
// and what credentials the host must supply.
type RemediatorCapabilities struct {
	Source      string
	Version     string
	Actions     []string
	RequiredEnv []string
	Permissions Permissions
}

// RemediateRequest is the action invocation payload.
type RemediateRequest struct {
	FindingID     string
	Action        string
	Params        map[string]any
	ApprovalToken string
}

// RemediateResponse carries the steps the plugin performed (or would
// perform) plus a terminal outcome.
type RemediateResponse struct {
	Outcome      string          // "executed" | "would_execute" | "failed"
	Steps        []RemediateStep
	ErrorMessage string
}

// RemediateStep is one resource-level operation. Mirrors the proto.
type RemediateStep struct {
	Resource  string
	Operation string
	Before    map[string]any
	After     map[string]any
}

// ServeRemediator runs a remediator plugin's main loop.
func ServeRemediator(impl Remediator) {
	if impl == nil {
		panic("plugin.ServeRemediator: nil Remediator")
	}
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			RemediatorPluginName: &RemediatorPlugin{Impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

// RemediatorPlugin is the go-plugin Plugin implementation shared by host
// and plugin sides for the Remediator service.
type RemediatorPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Remediator
}

func (p *RemediatorPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterRemediatorServer(s, &remediatorGRPCServer{impl: p.Impl})
	return nil
}

func (p *RemediatorPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pluginv1.NewRemediatorClient(c), nil
}

type remediatorGRPCServer struct {
	pluginv1.UnimplementedRemediatorServer
	impl Remediator
}

func (s *remediatorGRPCServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.RemediatorCapabilitiesResponse, error) {
	c := s.impl.Capabilities()
	return &pluginv1.RemediatorCapabilitiesResponse{
		ConcordProtocolVersion: ProtocolVersion,
		Source:                 c.Source,
		Version:                c.Version,
		Actions:                c.Actions,
		RequiredEnv:            c.RequiredEnv,
		Permissions: &pluginv1.Permissions{
			Network:    c.Permissions.Network,
			Filesystem: c.Permissions.Filesystem,
			Subprocess: c.Permissions.Subprocess,
		},
	}, nil
}

func (s *remediatorGRPCServer) DryRun(ctx context.Context, req *pluginv1.RemediateRequest) (resp *pluginv1.RemediateResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "plugin panic: %v", r)
		}
	}()
	out, err := s.impl.DryRun(ctx, remediateRequestFromProto(req))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return remediateResponseToProto(out)
}

func (s *remediatorGRPCServer) Execute(ctx context.Context, req *pluginv1.RemediateRequest) (resp *pluginv1.RemediateResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "plugin panic: %v", r)
		}
	}()
	out, err := s.impl.Execute(ctx, remediateRequestFromProto(req))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return remediateResponseToProto(out)
}

func remediateRequestFromProto(r *pluginv1.RemediateRequest) RemediateRequest {
	if r == nil {
		return RemediateRequest{}
	}
	out := RemediateRequest{
		FindingID:     r.FindingId,
		Action:        r.Action,
		ApprovalToken: r.ApprovalToken,
	}
	if r.Params != nil {
		out.Params = r.Params.AsMap()
	}
	return out
}

func remediateResponseToProto(out RemediateResponse) (*pluginv1.RemediateResponse, error) {
	steps := make([]*pluginv1.RemediateStep, 0, len(out.Steps))
	for _, s := range out.Steps {
		before, err := structpb.NewStruct(s.Before)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "step before-state: %v", err)
		}
		after, err := structpb.NewStruct(s.After)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "step after-state: %v", err)
		}
		steps = append(steps, &pluginv1.RemediateStep{
			Resource:  s.Resource,
			Operation: s.Operation,
			Before:    before,
			After:     after,
		})
	}
	return &pluginv1.RemediateResponse{
		Outcome:      out.Outcome,
		Steps:        steps,
		ErrorMessage: out.ErrorMessage,
	}, nil
}
