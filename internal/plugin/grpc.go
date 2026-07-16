package plugin

import (
	"context"

	pluginv1 "forgejo/linus/gophermailforge/proto/gophermailforge/plugin/v1"
	"google.golang.org/grpc"
)

type ControlServer struct {
	pluginv1.UnimplementedPluginControlServer
	Registry Registry
	Name     string
}

func RegisterControlServer(s grpc.ServiceRegistrar, srv ControlServer) {
	pluginv1.RegisterPluginControlServer(s, srv)
}

type ControlClient = pluginv1.PluginControlClient

func NewControlClient(cc grpc.ClientConnInterface) ControlClient {
	return pluginv1.NewPluginControlClient(cc)
}

func (s ControlServer) Health(ctx context.Context, in *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	resp, err := s.Registry.Health(ctx, s.Name, Request{CorrelationID: in.GetCorrelationId()})
	if err != nil {
		return nil, err
	}
	return &pluginv1.HealthResponse{Healthy: resp.Healthy, Message: resp.Message}, nil
}
func (s ControlServer) Version(ctx context.Context, in *pluginv1.VersionRequest) (*pluginv1.VersionResponse, error) {
	resp, err := s.Registry.Version(ctx, s.Name, Request{CorrelationID: in.GetCorrelationId()})
	if err != nil {
		return nil, err
	}
	return &pluginv1.VersionResponse{Name: resp.Name, Version: resp.Version}, nil
}
func (s ControlServer) Capabilities(ctx context.Context, in *pluginv1.CapabilitiesRequest) (*pluginv1.CapabilitiesResponse, error) {
	resp, err := s.Registry.Capabilities(ctx, s.Name, Request{CorrelationID: in.GetCorrelationId()})
	if err != nil {
		return nil, err
	}
	return &pluginv1.CapabilitiesResponse{Capabilities: resp.Capabilities}, nil
}
