package plugin

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCControlAuthenticatedAndUnauthenticated(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(grpc.ForceServerCodec(jsonCodec{}))
	RegisterControlServer(srv, ControlServer{Name: "stub", Registry: reg()})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	ctx := context.Background()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure(), grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := NewControlClient(conn)
	if _, err := client.Health(ctx, Request{CorrelationID: "c"}); err == nil || !strings.Contains(err.Error(), "UNAUTHENTICATED") {
		t.Fatalf("expected unauthenticated grpc error, got %v", err)
	}
	resp, err := client.Health(ctx, Request{CorrelationID: "c", ServiceToken: "tok", Deadline: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Healthy {
		t.Fatalf("unhealthy response: %#v", resp)
	}
}
