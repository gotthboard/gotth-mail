package extensionsruntime

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	extensionsv1 "forgejo/gotthboard/gotth-mail/proto/gotth/extensions/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type interleavedControl struct {
	extensionsv1.UnimplementedExtensionControlServer
	calls   atomic.Int32
	fail    atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (c *interleavedControl) Handshake(ctx context.Context, r *extensionsv1.HandshakeRequest) (*extensionsv1.HandshakeResponse, error) {
	if c.calls.Add(1) == 3 {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.fail.Load() {
		return nil, errors.New("fixture rejected handshake")
	}
	return &extensionsv1.HandshakeResponse{Challenge: r.Challenge, ExtensionId: r.ExpectedExtensionId, ExtensionVersion: "1.0.0", ManifestSha256: r.ExpectedManifestSha256, GrantSha256: r.ExpectedGrantSha256, SessionSha256: r.ExpectedSessionSha256, Control: &extensionsv1.ProtocolVersion{Name: "gotth.extensions.control", Major: 1}, Interfaces: []*extensionsv1.InterfaceVersion{{Name: Interface, Major: 1}}, Capabilities: capabilities}, nil
}
func (c *interleavedControl) Health(context.Context, *extensionsv1.HealthRequest) (*extensionsv1.HealthResponse, error) {
	return &extensionsv1.HealthResponse{State: extensionsv1.HealthState_HEALTH_STATE_READY, Code: "extension.ready"}, nil
}

func TestHealthObservationDoesNotChangeAdmission(t *testing.T) {
	listener := bufconn.Listen(65536)
	control := &interleavedControl{entered: make(chan struct{}), release: make(chan struct{})}
	server := grpc.NewServer()
	extensionsv1.RegisterExtensionControlServer(server, control)
	served := make(chan struct{})
	go func() { defer close(served); _ = server.Serve(listener) }()
	defer func() { server.Stop(); listener.Close(); <-served }()
	conn, err := grpc.NewClient("passthrough:///control", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	instance := extensionsadmin.Instance{InstanceID: "fixture", ExtensionID: ExtensionID}
	p := &process{instance: instance, conn: conn, runDir: filepath.Join(root, "owned"), done: make(chan struct{})}
	s := &Supervisor{runtimeRoot: root, rand: rand.Reader, processes: map[string]*process{instance.InstanceID: p}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.Probe(ctx, instance); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitRouting(ctx, instance); err != nil {
		t.Fatal(err)
	}
	// Explicit repeated Enable's probe has succeeded. Pause a concurrent GET
	// inside its authenticated RPC before repeating admission; no scheduler luck.
	if _, err := s.Probe(ctx, instance); err != nil {
		t.Fatal(err)
	}
	observed := make(chan error, 1)
	go func() { _, err := s.Health(ctx, ExtensionID); observed <- err }()
	select {
	case <-control.entered:
	case <-ctx.Done():
		t.Fatal("observation never entered RPC")
	}
	admissionErr := s.AdmitRouting(ctx, instance)
	close(control.release)
	if err := <-observed; err != nil {
		t.Fatal(err)
	}
	if admissionErr != nil {
		t.Errorf("read-only Health invalidated successful explicit Probe: %v", admissionErr)
	}
	// Observational failure cannot revoke the attestation either.
	control.fail.Store(true)
	if _, err := s.Health(ctx, ExtensionID); err == nil {
		t.Fatal("fixture failure hidden")
	}
	if err := s.AdmitRouting(ctx, instance); err != nil {
		t.Errorf("failed observation changed admission: %v", err)
	}
	// Explicit failed revalidation must clear prior attestation; subsequent
	// successful observation must not mint replacement lifecycle authority.
	if _, err := s.Probe(ctx, instance); err == nil {
		t.Fatal("explicit failure hidden")
	}
	if err := s.AdmitRouting(ctx, instance); err == nil {
		t.Error("failed explicit Probe retained readiness")
	}
	control.fail.Store(false)
	if _, err := s.Health(ctx, ExtensionID); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitRouting(ctx, instance); err == nil {
		t.Error("observation granted admission without explicit Probe")
	}
	if _, err := s.Probe(ctx, instance); err != nil {
		t.Fatal(err)
	}
	if err := s.AdmitRouting(ctx, instance); err != nil {
		t.Fatal(err)
	}
}
