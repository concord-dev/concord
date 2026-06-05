package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pluginv1 "github.com/concord-dev/concord/proto/concord/plugin/v1"
)

type grpcServer struct {
	pluginv1.UnimplementedCollectorServer
	impl Collector
}

func (s *grpcServer) Capabilities(_ context.Context, _ *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	c := s.impl.Capabilities()
	return &pluginv1.CapabilitiesResponse{
		ConcordProtocolVersion: ProtocolVersion,
		Source:                 c.Source,
		Version:                c.Version,
		SdkVersion:             SDKVersion,
		SupportedTypes:         c.SupportedTypes,
		RequiredEnv:            c.RequiredEnv,
		OptionalEnv:            c.OptionalEnv,
		Permissions: &pluginv1.Permissions{
			Network:    c.Permissions.Network,
			Filesystem: c.Permissions.Filesystem,
			Subprocess: c.Permissions.Subprocess,
		},
		DocsUrl: c.DocsURL,
	}, nil
}

func (s *grpcServer) Probe(ctx context.Context, req *pluginv1.ProbeRequest) (*pluginv1.ProbeResponse, error) {
	if req.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
		defer cancel()
	}
	info, err := s.impl.Probe(ctx)
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	return &pluginv1.ProbeResponse{Info: info}, nil
}

func (s *grpcServer) Collect(ctx context.Context, req *pluginv1.CollectRequest) (resp *pluginv1.CollectResponse, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "plugin panic: %v", r)
		}
	}()

	if req.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	out, err := s.impl.Collect(ctx, refFromProto(req.Ref))
	if err != nil {
		if errors.Is(err, ErrUnsupportedType) {
			return nil, unsupportedTypeStatus(err).Err()
		}
		return nil, status.Error(codes.Internal, err.Error())
	}

	raw, jerr := json.Marshal(out)
	if jerr != nil {
		return nil, status.Errorf(codes.Internal, "marshalling evidence: %v", jerr)
	}
	return &pluginv1.CollectResponse{
		Result: &pluginv1.CollectResponse_ValueJson{ValueJson: raw},
	}, nil
}

func unsupportedTypeStatus(err error) *status.Status {
	st := status.New(codes.InvalidArgument, err.Error())
	withDetails, derr := st.WithDetails(&errdetails.ErrorInfo{Reason: "concord.evidence.unsupported_type"})
	if derr != nil {
		return st
	}
	return withDetails
}

func refFromProto(r *pluginv1.EvidenceRef) EvidenceRef {
	if r == nil {
		return EvidenceRef{}
	}
	out := EvidenceRef{
		ID:       r.Id,
		Source:   r.Source,
		Type:     r.Type,
		Optional: r.Optional,
		Fixture:  r.Fixture,
	}
	if r.Params != nil {
		out.Params = r.Params.AsMap()
	}
	return out
}

// CollectorPlugin is the go-plugin Plugin implementation shared by host and plugin.
type CollectorPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Collector
}

// GRPCServer registers the gRPC service on the plugin side.
func (p *CollectorPlugin) GRPCServer(_ *goplugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterCollectorServer(s, &grpcServer{impl: p.Impl})
	return nil
}

// GRPCClient returns the gRPC client wrapper on the host side.
func (p *CollectorPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pluginv1.NewCollectorClient(c), nil
}
