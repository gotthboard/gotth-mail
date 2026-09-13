package plugin

import (
	"context"
	"net"
	"testing"
	"time"

	pluginv1 "forgejo/gotthboard/gotth-mail/proto/gotth/mail/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCControlUsesProtoMetadataDeadlineAndStatusCodes(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterControlServer(srv, ControlServer{Name: "stub", Registry: reg()})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := NewControlClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, "c"))
	if _, err := client.Health(ctx, &pluginv1.HealthRequest{CorrelationId: "c"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated grpc status, got %v", err)
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	ctx2 = metadata.NewOutgoingContext(ctx2, metadata.Pairs(MetadataCorrelationID, "c", MetadataServiceToken, "tok"))
	resp, err := client.Health(ctx2, &pluginv1.HealthRequest{CorrelationId: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.GetHealthy() {
		t.Fatalf("unhealthy response: %#v", resp)
	}

	ctx3 := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(MetadataCorrelationID, "c", MetadataServiceToken, "tok"))
	if _, err := client.Health(ctx3, &pluginv1.HealthRequest{CorrelationId: "c"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected missing deadline status, got %v", err)
	}
}
