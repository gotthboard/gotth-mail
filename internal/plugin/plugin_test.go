package plugin

import (
	"context"
	"strings"
	"testing"
	"time"
)

func reg() Registry {
	return Registry{Plugins: map[string]Registration{"stub": {Name: "stub", Seam: DNS, Endpoint: "stub:9443", Enabled: true, ServiceToken: "tok", Capabilities: []string{"dns.lookup"}}, "disabled": {Name: "disabled", Enabled: false, ServiceToken: "tok", Capabilities: []string{"x"}}, "badcaps": {Name: "badcaps", Enabled: true, ServiceToken: "tok"}}}
}
func TestAuthenticatedPluginControl(t *testing.T) {
	r := reg()
	req := Request{CorrelationID: "c", ServiceToken: "tok", Deadline: time.Now().Add(time.Second)}
	if h, err := r.Health(context.Background(), "stub", req); err != nil || !h.Healthy {
		t.Fatalf("health %v %v", h, err)
	}
	if v, err := r.Version(context.Background(), "stub", req); err != nil || v.Version == "" {
		t.Fatalf("version %v %v", v, err)
	}
	if c, err := r.Capabilities(context.Background(), "stub", req); err != nil || len(c.Capabilities) != 1 {
		t.Fatalf("caps %v %v", c, err)
	}
}
func TestUnauthenticatedRejected(t *testing.T) {
	_, err := reg().Health(context.Background(), "stub", Request{})
	if err == nil || !strings.Contains(err.Error(), "UNAUTHENTICATED") {
		t.Fatalf("expected unauthenticated, got %v", err)
	}
}
func TestPluginFailureIsolation(t *testing.T) {
	r := reg()
	_, err := r.Capabilities(context.Background(), "badcaps", Request{ServiceToken: "tok", Deadline: time.Now().Add(time.Second)})
	if err == nil {
		t.Fatal("expected malformed capability failure")
	}
	if len(r.Plugins) != 3 {
		t.Fatal("registry corrupted")
	}
	_, err = reg().Health(context.Background(), "disabled", Request{ServiceToken: "tok", Deadline: time.Now().Add(time.Second)})
	if err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("expected disabled rejection, got %v", err)
	}
}
