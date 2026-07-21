package plugin

import (
	"context"
	"net"
	"testing"
	"time"

	pluginv1 "forgejo/linus/gophermailforge/proto/gophermailforge/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestFirstMechanismPluginsExposeAuthenticatedCapabilities(t *testing.T) {
	reg := FirstMechanismPlugins("tok")
	want := map[string]Seam{FirstWebmailName: Webmail, FirstDNSName: DNS, FirstCertName: ACME, FirstBackupName: Backup, FirstNotifyName: Notification}
	for name, seam := range want {
		p, ok := reg.Plugins[name]
		if !ok {
			t.Fatalf("missing plugin %s", name)
		}
		if p.Seam != seam || !p.Enabled || p.ServiceToken == "" || len(p.Capabilities) == 0 {
			t.Fatalf("bad plugin %s: %#v", name, p)
		}
		resp, err := reg.Capabilities(context.Background(), name, Request{CorrelationID: "c", ServiceToken: "tok", Deadline: time.Now().Add(time.Second)})
		if err != nil {
			t.Fatalf("capabilities %s: %v", name, err)
		}
		if len(resp.Capabilities) == 0 {
			t.Fatalf("empty caps for %s", name)
		}
	}
	if _, ok := reg.Plugins[FirstEmailName]; ok {
		t.Fatal("explicit signed email sink leaked into default first-mechanism registry")
	}
	email, err := FirstMechanismPlugin(FirstEmailName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if email.Endpoint != "signed-email-notification-plugin:9443" || email.Seam != Notification || !email.Enabled || email.ServiceToken != "tok" {
		t.Fatalf("bad explicit signed email registration: %#v", email)
	}
	for _, capability := range email.Capabilities {
		if capability == "notification.prompt.send" {
			t.Fatalf("signed email sink advertises unsupported prompt capability: %#v", email.Capabilities)
		}
	}
	if _, err := FirstMechanismPlugin("not-a-plugin", "tok"); err == nil {
		t.Fatal("unknown first mechanism plugin accepted")
	}
}

func TestFirstMechanismPluginGRPCAuth(t *testing.T) {
	p, err := FirstMechanismPlugin(FirstDNSName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterControlServer(srv, ControlServer{Name: p.Name, Registry: Registry{Plugins: map[string]Registration{p.Name: p}}})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := NewControlClient(conn)
	bad := contextWithDeadlineAndMetadata(t, "wrong")
	if _, err := client.Health(bad, &pluginv1.HealthRequest{CorrelationId: "c"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
	good := contextWithDeadlineAndMetadata(t, "tok")
	caps, err := client.Capabilities(good, &pluginv1.CapabilitiesRequest{CorrelationId: "c"})
	if err != nil {
		t.Fatal(err)
	}
	if len(caps.GetCapabilities()) == 0 {
		t.Fatal("empty capabilities")
	}
}

func contextWithDeadlineAndMetadata(t *testing.T, token string) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, "c", MetadataServiceToken, token))
}
