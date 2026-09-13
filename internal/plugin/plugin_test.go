package plugin

import (
	"context"
	"testing"
	"time"

	buildversion "forgejo/gotthboard/gotth-mail/internal/version"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func reg() Registry {
	return Registry{Plugins: map[string]Registration{"stub": {Name: "stub", Seam: DNS, Endpoint: "stub:9443", Enabled: true, ServiceToken: "tok", Capabilities: []string{"dns.lookup"}}, "disabled": {Name: "disabled", Enabled: false, ServiceToken: "tok", Capabilities: []string{"x"}}, "badcaps": {Name: "badcaps", Enabled: true, ServiceToken: "tok"}}}
}
func req() Request {
	return Request{CorrelationID: "c", ServiceToken: "tok", Deadline: time.Now().Add(time.Second)}
}
func TestAuthenticatedPluginControl(t *testing.T) {
	r := reg()
	if h, err := r.Health(context.Background(), "stub", req()); err != nil || !h.Healthy {
		t.Fatalf("health %v %v", h, err)
	}
	if v, err := r.Version(context.Background(), "stub", req()); err != nil || v.Version != buildversion.Version {
		t.Fatalf("version %v %v", v, err)
	}
	if c, err := r.Capabilities(context.Background(), "stub", req()); err != nil || len(c.Capabilities) != 1 {
		t.Fatalf("caps %v %v", c, err)
	}
}
func TestPluginAuthMetadataContract(t *testing.T) {
	_, err := reg().Health(context.Background(), "stub", Request{CorrelationID: "c", Deadline: time.Now().Add(time.Second)})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
	_, err = reg().Health(context.Background(), "stub", Request{ServiceToken: "tok", Deadline: time.Now().Add(time.Second)})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected missing correlation rejection, got %v", err)
	}
	_, err = reg().Health(context.Background(), "stub", Request{CorrelationID: "c", ServiceToken: "tok"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected missing deadline rejection, got %v", err)
	}
}
func TestPluginFailureIsolation(t *testing.T) {
	r := reg()
	_, err := r.Capabilities(context.Background(), "badcaps", req())
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected malformed capability failure, got %v", err)
	}
	if len(r.Plugins) != 3 {
		t.Fatal("registry corrupted")
	}
	_, err = reg().Health(context.Background(), "disabled", req())
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected disabled rejection, got %v", err)
	}
}
