package plugin

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	pluginv1 "forgejo/gotthboard/gotth-mail/proto/gotth/mail/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestLivePluginControlOverGRPC(t *testing.T) {
	endpoint := os.Getenv("GOTTH_MAIL_LIVE_PLUGIN_ENDPOINT")
	if endpoint == "" {
		t.Skip("GOTTH_MAIL_LIVE_PLUGIN_ENDPOINT not set")
	}
	name := os.Getenv("GOTTH_MAIL_LIVE_PLUGIN_NAME")
	if name == "" {
		name = FirstNotifyName
	}
	token := os.Getenv("GOTTH_MAIL_LIVE_PLUGIN_TOKEN")
	if token == "" {
		t.Fatal("GOTTH_MAIL_LIVE_PLUGIN_TOKEN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(endpoint, grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := NewControlClient(conn)
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, "live-plugin-smoke", MetadataServiceToken, token))
	health, err := client.Health(ctx, &pluginv1.HealthRequest{CorrelationId: "live-plugin-smoke"})
	if err != nil {
		t.Fatal(err)
	}
	if !health.GetHealthy() {
		t.Fatalf("unhealthy plugin response: %#v", health)
	}
	version, err := client.Version(ctx, &pluginv1.VersionRequest{CorrelationId: "live-plugin-smoke"})
	if err != nil {
		t.Fatal(err)
	}
	if version.GetName() != name {
		t.Fatalf("version name=%q want %q", version.GetName(), name)
	}
	caps, err := client.Capabilities(ctx, &pluginv1.CapabilitiesRequest{CorrelationId: "live-plugin-smoke"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(caps.GetCapabilities(), ",")
	if !strings.Contains(joined, "notification.alert.sink") || !strings.Contains(joined, "notification.delivery.status") {
		t.Fatalf("missing notification capabilities: %#v", caps.GetCapabilities())
	}

	badCtx, badCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer badCancel()
	badCtx = metadata.NewOutgoingContext(badCtx, metadata.Pairs(MetadataCorrelationID, "live-plugin-smoke", MetadataServiceToken, "wrong"))
	if _, err := client.Health(badCtx, &pluginv1.HealthRequest{CorrelationId: "live-plugin-smoke"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated for wrong token, got %v", err)
	}
}

func TestLiveNotificationBackendOverGRPC(t *testing.T) {
	endpoint := os.Getenv("GOTTH_MAIL_LIVE_PLUGIN_ENDPOINT")
	if endpoint == "" {
		t.Skip("GOTTH_MAIL_LIVE_PLUGIN_ENDPOINT not set")
	}
	token := os.Getenv("GOTTH_MAIL_LIVE_PLUGIN_TOKEN")
	if token == "" {
		t.Fatal("GOTTH_MAIL_LIVE_PLUGIN_TOKEN required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(endpoint, grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := pluginv1.NewNotificationBackendClient(conn)
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, "live-notify-smoke", MetadataServiceToken, token))
	alert, err := client.SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-live-1", Class: "doctor.failure", Severity: "critical", Title: "Doctor failed", Summary: "config check failed", CorrelationId: "live-notify-smoke", Resource: &pluginv1.AlertResource{Type: "doctor", Id: "system"}}})
	if err != nil {
		t.Fatal(err)
	}
	if alert.GetStatus() != "delivered" {
		t.Fatalf("bad live alert response: %#v", alert)
	}
	prompt, err := client.SendPrompt(ctx, &pluginv1.SendPromptRequest{Id: "prompt-live-1", CorrelationId: "live-notify-smoke", Transport: "telegram", ExternalActorId: "chat:42:user:99", ActorType: "api_token", ActorId: "ops", Action: "queue:flush", ResourceType: "queue", ResourceId: "default", RequestHash: "sha256:abc", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Title: "Approve queue flush", Summary: "Flush deferred queue"})
	if err != nil {
		t.Fatal(err)
	}
	if !prompt.GetAccepted() {
		t.Fatalf("bad live prompt response: %#v", prompt)
	}
}

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
