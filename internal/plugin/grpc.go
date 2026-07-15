package plugin

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
)

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)   { return json.Marshal(v) }
func (jsonCodec) Unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
func (jsonCodec) Name() string                    { return "json" }

func init() { encoding.RegisterCodec(jsonCodec{}) }

type ControlServiceServer interface{ isControlServiceServer() }

type ControlServer struct {
	Registry Registry
	Name     string
}

func (ControlServer) isControlServiceServer() {}

func RegisterControlServer(s grpc.ServiceRegistrar, srv ControlServer) {
	s.RegisterService(&controlServiceDesc, srv)
}

type ControlClient struct{ cc grpc.ClientConnInterface }

func NewControlClient(cc grpc.ClientConnInterface) ControlClient { return ControlClient{cc: cc} }
func (c ControlClient) Health(ctx context.Context, in Request, opts ...grpc.CallOption) (HealthResponse, error) {
	var out HealthResponse
	err := c.cc.Invoke(ctx, "/gophermailforge.plugin.v1.PluginControl/Health", in, &out, append(opts, grpc.ForceCodec(jsonCodec{}))...)
	return out, err
}
func (c ControlClient) Version(ctx context.Context, in Request, opts ...grpc.CallOption) (VersionResponse, error) {
	var out VersionResponse
	err := c.cc.Invoke(ctx, "/gophermailforge.plugin.v1.PluginControl/Version", in, &out, append(opts, grpc.ForceCodec(jsonCodec{}))...)
	return out, err
}
func (c ControlClient) Capabilities(ctx context.Context, in Request, opts ...grpc.CallOption) (CapabilitiesResponse, error) {
	var out CapabilitiesResponse
	err := c.cc.Invoke(ctx, "/gophermailforge.plugin.v1.PluginControl/Capabilities", in, &out, append(opts, grpc.ForceCodec(jsonCodec{}))...)
	return out, err
}

var controlServiceDesc = grpc.ServiceDesc{ServiceName: "gophermailforge.plugin.v1.PluginControl", HandlerType: (*ControlServiceServer)(nil), Methods: []grpc.MethodDesc{{MethodName: "Health", Handler: healthHandler}, {MethodName: "Version", Handler: versionHandler}, {MethodName: "Capabilities", Handler: capabilitiesHandler}}, Streams: []grpc.StreamDesc{}}

func healthHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var in Request
	if err := dec(&in); err != nil {
		return nil, err
	}
	cs := srv.(ControlServer)
	h := func(ctx context.Context, req any) (any, error) {
		return cs.Registry.Health(ctx, cs.Name, req.(Request))
	}
	if interceptor == nil {
		return h(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/gophermailforge.plugin.v1.PluginControl/Health"}, h)
}
func versionHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var in Request
	if err := dec(&in); err != nil {
		return nil, err
	}
	cs := srv.(ControlServer)
	h := func(ctx context.Context, req any) (any, error) {
		return cs.Registry.Version(ctx, cs.Name, req.(Request))
	}
	if interceptor == nil {
		return h(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/gophermailforge.plugin.v1.PluginControl/Version"}, h)
}
func capabilitiesHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	var in Request
	if err := dec(&in); err != nil {
		return nil, err
	}
	cs := srv.(ControlServer)
	h := func(ctx context.Context, req any) (any, error) {
		return cs.Registry.Capabilities(ctx, cs.Name, req.(Request))
	}
	if interceptor == nil {
		return h(ctx, in)
	}
	return interceptor(ctx, in, &grpc.UnaryServerInfo{Server: srv, FullMethod: "/gophermailforge.plugin.v1.PluginControl/Capabilities"}, h)
}
