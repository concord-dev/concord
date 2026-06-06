package plugins

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"google.golang.org/protobuf/types/known/structpb"

	sdkplugin "github.com/concord-dev/concord/pkg/plugin"
	pluginv1 "github.com/concord-dev/concord/proto/concord/plugin/v1"
)

// RemediatorEntry describes a discovered remediator plugin binary on disk.
type RemediatorEntry struct {
	Source     string
	Version    string
	Path       string
	AllowedEnv []string
}

// PluginRemediator is the host-side wrapper around a spawned remediator
// plugin. Constructed by NewPluginRemediator; close by calling Close.
type PluginRemediator struct {
	gpc     *goplugin.Client
	client  pluginv1.RemediatorClient
	source  string
	version string
	timeout time.Duration
}

// SpawnRemediator launches the binary at e.Path and connects to its
// Remediator service.
func SpawnRemediator(e RemediatorEntry, timeout time.Duration) (*PluginRemediator, error) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	cmd := exec.Command(e.Path)
	cmd.Env = scopedEnv(e.AllowedEnv)
	gpc := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: sdkplugin.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			sdkplugin.RemediatorPluginName: &sdkplugin.RemediatorPlugin{},
		},
		Cmd:              cmd,
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Managed:          true,
		Logger:           hclog.NewNullLogger(),
	})
	conn, err := gpc.Client()
	if err != nil {
		gpc.Kill()
		return nil, fmt.Errorf("connecting to remediator plugin %s: %w", e.Source, err)
	}
	raw, err := conn.Dispense(sdkplugin.RemediatorPluginName)
	if err != nil {
		gpc.Kill()
		return nil, fmt.Errorf("dispensing remediator plugin %s: %w", e.Source, err)
	}
	stub, ok := raw.(pluginv1.RemediatorClient)
	if !ok {
		gpc.Kill()
		return nil, fmt.Errorf("remediator plugin %s: client is %T, want RemediatorClient", e.Source, raw)
	}
	return &PluginRemediator{
		gpc:     gpc,
		client:  stub,
		source:  e.Source,
		version: e.Version,
		timeout: timeout,
	}, nil
}

// Source returns the discovered plugin source name.
func (p *PluginRemediator) Source() string { return p.source }

// Version returns the discovered plugin version directory name.
func (p *PluginRemediator) Version() string { return p.version }

// Close terminates the plugin process.
func (p *PluginRemediator) Close() { p.gpc.Kill() }

// Capabilities returns the remediator's advertised action list.
func (p *PluginRemediator) Capabilities(ctx context.Context) (sdkplugin.RemediatorCapabilities, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	resp, err := p.client.Capabilities(ctx, &pluginv1.CapabilitiesRequest{})
	if err != nil {
		return sdkplugin.RemediatorCapabilities{}, err
	}
	return sdkplugin.RemediatorCapabilities{
		Source:      resp.Source,
		Version:     resp.Version,
		Actions:     resp.Actions,
		RequiredEnv: resp.RequiredEnv,
	}, nil
}

// DryRun asks the plugin what it would do without changing state.
func (p *PluginRemediator) DryRun(ctx context.Context, req sdkplugin.RemediateRequest) (sdkplugin.RemediateResponse, error) {
	return p.invoke(ctx, req, false)
}

// Execute runs the action against the target API.
func (p *PluginRemediator) Execute(ctx context.Context, req sdkplugin.RemediateRequest) (sdkplugin.RemediateResponse, error) {
	if req.ApprovalToken == "" {
		return sdkplugin.RemediateResponse{}, errors.New("execute requires an approval token")
	}
	return p.invoke(ctx, req, true)
}

func (p *PluginRemediator) invoke(ctx context.Context, req sdkplugin.RemediateRequest, exec bool) (sdkplugin.RemediateResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	params, err := structpb.NewStruct(req.Params)
	if err != nil {
		return sdkplugin.RemediateResponse{}, fmt.Errorf("encoding params: %w", err)
	}
	pbReq := &pluginv1.RemediateRequest{
		FindingId:     req.FindingID,
		Action:        req.Action,
		Params:        params,
		ApprovalToken: req.ApprovalToken,
	}
	var resp *pluginv1.RemediateResponse
	if exec {
		resp, err = p.client.Execute(ctx, pbReq)
	} else {
		resp, err = p.client.DryRun(ctx, pbReq)
	}
	if err != nil {
		return sdkplugin.RemediateResponse{}, err
	}
	out := sdkplugin.RemediateResponse{
		Outcome:      resp.Outcome,
		ErrorMessage: resp.ErrorMessage,
	}
	for _, s := range resp.Steps {
		step := sdkplugin.RemediateStep{
			Resource:  s.Resource,
			Operation: s.Operation,
		}
		if s.Before != nil {
			step.Before = s.Before.AsMap()
		}
		if s.After != nil {
			step.After = s.After.AsMap()
		}
		out.Steps = append(out.Steps, step)
	}
	return out, nil
}
