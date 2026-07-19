package plugin

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	pluginv1 "forgejo/linus/gophermailforge/proto/gophermailforge/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestNotificationBackendGRPCSendsAlertAndPromptWithServiceIdentity(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	registry := reg()
	RegisterNotificationServer(srv, NotificationServer{Name: "stub", Registry: registry})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := pluginv1.NewNotificationBackendClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, "corr-1", MetadataServiceToken, "tok"))
	alert, err := client.SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-1", Class: "doctor.failure", Severity: "critical", Title: "Doctor failed", Summary: "database failed", CorrelationId: "corr-1", Resource: &pluginv1.AlertResource{Type: "doctor", Id: "system"}}})
	if err != nil {
		t.Fatal(err)
	}
	if alert.GetStatus() != "delivered" || !strings.Contains(alert.GetReason(), "accepted") {
		t.Fatalf("bad alert response: %#v", alert)
	}
	prompt, err := client.SendPrompt(ctx, &pluginv1.SendPromptRequest{Id: "prompt-1", CorrelationId: "corr-1", Transport: "telegram", ExternalActorId: "chat:42:user:99", ActorType: "api_token", ActorId: "ops", Action: "queue:flush", ResourceType: "queue", ResourceId: "default", RequestHash: "sha256:abc", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Title: "Approve queue flush", Summary: "Flush deferred queue"})
	if err != nil {
		t.Fatal(err)
	}
	if !prompt.GetAccepted() || prompt.GetMessage() == "" {
		t.Fatalf("bad prompt response: %#v", prompt)
	}
}

func TestNotificationBackendRejectsWrongTokenAndUnsafePayloads(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterNotificationServer(srv, NotificationServer{Name: "stub", Registry: reg()})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := pluginv1.NewNotificationBackendClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	badToken := metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, "corr-1", MetadataServiceToken, "wrong"))
	if _, err := client.SendAlert(badToken, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-1", Class: "doctor.failure", Title: "x", Summary: "y", CorrelationId: "corr-1"}}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong token accepted: %v", err)
	}
	goodCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, "corr-1", MetadataServiceToken, "tok"))
	if _, err := client.SendAlert(goodCtx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-1", Class: "doctor.failure", Severity: "nonsense", Title: "x", Summary: "y", CorrelationId: "corr-1"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad alert accepted: %v", err)
	}
	if _, err := client.SendPrompt(goodCtx, &pluginv1.SendPromptRequest{Id: "prompt-1", CorrelationId: "corr-1", Transport: "telegram", ExternalActorId: "chat:42:user:99", ActorType: "api_token", ActorId: "ops", Action: "queue:flush", ResourceType: "queue", ResourceId: "default", RequestHash: "sha256:abc", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Title: "Approve", Summary: "token=secret"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unsafe prompt accepted: %v", err)
	}
}
