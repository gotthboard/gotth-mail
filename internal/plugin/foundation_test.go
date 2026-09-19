package plugin

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	extensionsv1 "forgejo/gotthboard/gotth-mail/proto/gotth/extensions/v1"
	extensioncore "github.com/gotthboard/gotth-extensions/pkg/extensions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const foundationTestCorrelationID = "00000000-0000-4000-8000-000000000123"

func TestFirstMechanismsNegotiateExactFoundationBindings(t *testing.T) {
	registry := FirstMechanismPlugins("tok")
	seenInstances := map[string]bool{}
	for name, registration := range registry.Plugins {
		binding, err := validatedFoundation(registration)
		if err != nil {
			t.Fatalf("%s foundation: %v", name, err)
		}
		if binding.Lifecycle != extensioncore.StateReady || binding.Session.ExtensionID != binding.Manifest.ID || binding.Session.ManifestDigest != binding.Grant.ManifestDigest || binding.Session.Fingerprint == "" {
			t.Fatalf("%s incomplete foundation binding: %#v", name, binding)
		}
		if seenInstances[binding.Session.InstanceID] {
			t.Fatalf("duplicate instance id %q", binding.Session.InstanceID)
		}
		seenInstances[binding.Session.InstanceID] = true
		if got, want := strings.Join(binding.Session.Capabilities, ","), sortedJoin(registration.Capabilities); got != want {
			t.Fatalf("%s capabilities=%q want=%q", name, got, want)
		}
		if got, want := strings.Join(binding.Session.Secrets, ","), sortedJoin(registration.SecretSlots); got != want {
			t.Fatalf("%s secret slots=%q want=%q", name, got, want)
		}
	}
	email, err := FirstMechanismPlugin(FirstEmailName, "tok")
	if err != nil || email.Foundation == nil {
		t.Fatalf("signed-email foundation=%#v err=%v", email.Foundation, err)
	}
}

func TestFoundationLifecycleUsesAdmittedTransitions(t *testing.T) {
	registration, err := FirstMechanismPlugin(FirstNotifyName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TransitionFoundation(registration.Foundation, extensioncore.StateStopped); err == nil {
		t.Fatal("ready-to-stopped transition accepted")
	}
	current := registration.Foundation
	for _, next := range []extensioncore.State{extensioncore.StateStopping, extensioncore.StateStopped, extensioncore.StateStarting, extensioncore.StateReady, extensioncore.StateDegraded, extensioncore.StateFailed} {
		current, err = TransitionFoundation(current, next)
		if err != nil {
			t.Fatalf("transition to %s: %v", next, err)
		}
	}
}

func TestFoundationRejectsInvalidConstructionAndRegistrationDrift(t *testing.T) {
	for _, registration := range []Registration{
		{},
		{Name: "x", Seam: Seam("unknown"), Capabilities: []string{"test.read"}},
		{Name: "x", Seam: Import},
		{Name: "x", Seam: Import, Capabilities: []string{"Invalid"}},
	} {
		if _, err := NewFoundationBinding(registration); err == nil {
			t.Fatalf("invalid registration accepted: %#v", registration)
		}
	}
	if _, err := validatedFoundation(Registration{}); err == nil {
		t.Fatal("missing foundation accepted")
	}

	registration, err := FirstMechanismPlugin(FirstNotifyName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	invalid := registration
	invalid.Capabilities = []string{"Invalid"}
	if _, err := validatedFoundation(invalid); err == nil {
		t.Fatal("invalid registration accepted with an old binding")
	}
	stopped := *registration.Foundation
	stopped.Lifecycle = extensioncore.StateStopped
	invalid = registration
	invalid.Foundation = &stopped
	if _, err := validatedFoundation(invalid); err == nil {
		t.Fatal("stopped registration exposed as available")
	}
}

func TestFoundationHealthStateCodePairs(t *testing.T) {
	for _, test := range []struct {
		lifecycle extensioncore.State
		state     extensionsv1.HealthState
		code      string
	}{
		{extensioncore.StateStarting, extensionsv1.HealthState_HEALTH_STATE_STARTING, "extension.starting"},
		{extensioncore.StateReady, extensionsv1.HealthState_HEALTH_STATE_READY, "extension.ready"},
		{extensioncore.StateDegraded, extensionsv1.HealthState_HEALTH_STATE_DEGRADED, "extension.degraded"},
		{extensioncore.StateStopping, extensionsv1.HealthState_HEALTH_STATE_STOPPING, "extension.stopping"},
		{extensioncore.StateFailed, extensionsv1.HealthState_HEALTH_STATE_FAILED, "extension.failed"},
	} {
		state, code := foundationHealth(test.lifecycle)
		if state != test.state || code != test.code || !validFoundationHealth(state, code) {
			t.Fatalf("health(%q)=(%v,%q)", test.lifecycle, state, code)
		}
	}
	if state, code := foundationHealth(extensioncore.StateStopped); state != extensionsv1.HealthState_HEALTH_STATE_FAILED || code != "extension.failed" {
		t.Fatalf("stopped health=(%v,%q)", state, code)
	}
	if validFoundationHealth(extensionsv1.HealthState_HEALTH_STATE_UNSPECIFIED, "extension.failed") {
		t.Fatal("unspecified health state accepted")
	}
}

func TestFoundationHandshakeHealthAuthenticationAndFailureIsolation(t *testing.T) {
	good, err := FirstMechanismPlugin(FirstNotifyName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	bad := good
	bad.Name = "bad"
	registry := Registry{Plugins: map[string]Registration{good.Name: good, bad.Name: bad}}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterFoundationServer(server, FoundationServer{Name: good.Name, Registry: registry})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	connection, err := grpc.NewClient("passthrough:///foundation", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client, err := NewFoundationClient(connection, good, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFoundationClient(connection, bad, "tok"); err == nil {
		t.Fatal("cross-bound client registration accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	health, err := client.Health(ctx)
	if err != nil || !health.Healthy || health.Message != "extension.ready" {
		t.Fatalf("health=%#v err=%v", health, err)
	}
	wrongToken, err := NewFoundationClient(connection, good, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongToken.Health(ctx); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong token error=%v", err)
	}
	if _, err := client.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("missing deadline error=%v", err)
	}
	badServer := FoundationServer{Name: bad.Name, Registry: registry}
	badCtx := metadata.NewIncomingContext(ctx, metadata.Pairs(MetadataCorrelationID, foundationTestCorrelationID, MetadataServiceToken, "tok"))
	if _, err := badServer.Handshake(badCtx, &extensionsv1.HandshakeRequest{
		CorrelationId: foundationTestCorrelationID, Challenge: make([]byte, 32),
		ExpectedExtensionId: good.Foundation.Session.ExtensionID, ExpectedManifestSha256: good.Foundation.Session.ManifestDigest,
		ExpectedGrantSha256: good.Foundation.Session.GrantDigest, ExpectedSessionSha256: good.Foundation.Session.Fingerprint,
	}); status.Code(err) != codes.Unavailable {
		t.Fatalf("cross-bound registration handshake error=%v", err)
	}
	if _, err := badServer.Health(badCtx, &extensionsv1.HealthRequest{CorrelationId: foundationTestCorrelationID, SessionSha256: good.Foundation.Session.Fingerprint}); status.Code(err) != codes.Unavailable {
		t.Fatalf("cross-bound registration health error=%v", err)
	}
	if _, err := client.Health(ctx); err != nil {
		t.Fatalf("bad registration contaminated good registration: %v", err)
	}
}

func TestFoundationRejectsMalformedAndStaleWireBindings(t *testing.T) {
	registration, err := FirstMechanismPlugin(FirstDNSName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	server := FoundationServer{Name: registration.Name, Registry: Registry{Plugins: map[string]Registration{registration.Name: registration}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(MetadataCorrelationID, foundationTestCorrelationID, MetadataServiceToken, "tok"))
	challenge := make([]byte, 32)
	request := &extensionsv1.HandshakeRequest{
		CorrelationId: foundationTestCorrelationID, Challenge: challenge,
		ExpectedExtensionId:    registration.Foundation.Session.ExtensionID,
		ExpectedManifestSha256: registration.Foundation.Session.ManifestDigest,
		ExpectedGrantSha256:    registration.Foundation.Session.GrantDigest,
		ExpectedSessionSha256:  registration.Foundation.Session.Fingerprint,
	}
	response, err := server.Handshake(ctx, request)
	if err != nil || !validHandshakeResponse(response, challenge, registration.Foundation.Session) {
		t.Fatalf("handshake=%#v err=%v", response, err)
	}
	request.ExpectedSessionSha256 = strings.Repeat("0", 64)
	if _, err := server.Handshake(ctx, request); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale session error=%v", err)
	}
	request.ExpectedSessionSha256 = registration.Foundation.Session.Fingerprint
	request.Challenge = challenge[:31]
	if _, err := server.Handshake(ctx, request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("short challenge error=%v", err)
	}
	request.Challenge = challenge
	request.CorrelationId = "not-a-uuid"
	if _, err := server.Handshake(ctx, request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad correlation error=%v", err)
	}
	request.CorrelationId = foundationTestCorrelationID
	if _, err := server.Health(ctx, &extensionsv1.HealthRequest{CorrelationId: "not-a-uuid", SessionSha256: registration.Foundation.Session.Fingerprint}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad health correlation error=%v", err)
	}
	if _, err := server.Health(ctx, &extensionsv1.HealthRequest{CorrelationId: foundationTestCorrelationID, SessionSha256: strings.Repeat("0", 64)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stale health session error=%v", err)
	}
	wrongToken := metadata.NewIncomingContext(ctx, metadata.Pairs(MetadataCorrelationID, foundationTestCorrelationID, MetadataServiceToken, "wrong"))
	if _, err := server.Health(wrongToken, &extensionsv1.HealthRequest{CorrelationId: foundationTestCorrelationID, SessionSha256: registration.Foundation.Session.Fingerprint}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("health authentication error=%v", err)
	}
}

func TestFoundationClientRejectsEntropyAndHostileHealthFields(t *testing.T) {
	registration, err := FirstMechanismPlugin(FirstNotifyName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	client := &FoundationClient{client: &hostileFoundationClient{}, registration: registration, token: "tok", rand: errorReader{}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Health(ctx); err == nil || !strings.Contains(err.Error(), "entropy") {
		t.Fatalf("entropy failure=%v", err)
	}
	client.rand = strings.NewReader(strings.Repeat("x", 48))
	if _, err := client.Health(ctx); err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("hostile handshake failure=%v", err)
	}
	client.client = &hostileFoundationClient{
		session: registration.Foundation.Session,
		health:  &extensionsv1.HealthResponse{State: extensionsv1.HealthState_HEALTH_STATE_READY, Code: "extension.failed"},
	}
	client.rand = strings.NewReader(strings.Repeat("y", 48))
	if _, err := client.Health(ctx); err == nil || !strings.Contains(err.Error(), "health response") {
		t.Fatalf("contradictory health failure=%v", err)
	}
	for _, code := range []string{"", "ok", "extension.", ".ready", "Extension.ready", strings.Repeat("a", 65)} {
		if validFoundationCode(code) {
			t.Fatalf("invalid health code accepted: %q", code)
		}
	}
	if !validFoundationCode("extension.ready") {
		t.Fatal("valid health code rejected")
	}
}

func TestFoundationClientConfigurationAndFailurePaths(t *testing.T) {
	registration, err := FirstMechanismPlugin(FirstNotifyName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFoundationClient(nil, registration, "tok"); err == nil {
		t.Fatal("nil connection accepted")
	}
	if _, err := NewFoundationClient(nil, registration, ""); err == nil {
		t.Fatal("empty client configuration accepted")
	}
	if _, err := (&FoundationClient{}).Health(deadlineContext(t)); err == nil {
		t.Fatal("unconfigured client health accepted")
	}

	client := &FoundationClient{client: &hostileFoundationClient{handshakeErr: errors.New("handshake failed")}, registration: registration, token: "tok", rand: strings.NewReader(strings.Repeat("z", 48))}
	if _, err := client.Health(deadlineContext(t)); err == nil || !strings.Contains(err.Error(), "handshake failed") {
		t.Fatalf("handshake transport failure=%v", err)
	}
	client.client = &hostileFoundationClient{session: registration.Foundation.Session, healthErr: errors.New("health failed")}
	client.rand = strings.NewReader(strings.Repeat("q", 48))
	if _, err := client.Health(deadlineContext(t)); err == nil || !strings.Contains(err.Error(), "health failed") {
		t.Fatalf("health transport failure=%v", err)
	}
	client.client = &hostileFoundationClient{session: registration.Foundation.Session, health: &extensionsv1.HealthResponse{State: extensionsv1.HealthState_HEALTH_STATE_DEGRADED, Code: "extension.degraded"}}
	client.rand = strings.NewReader(strings.Repeat("r", 48))
	health, err := client.Health(deadlineContext(t))
	if err != nil || health.Healthy || health.Message != "extension.degraded" {
		t.Fatalf("degraded health=%#v err=%v", health, err)
	}
	client.registration.Name = "cross-bound"
	client.rand = strings.NewReader(strings.Repeat("s", 48))
	if _, err := client.Health(deadlineContext(t)); err == nil {
		t.Fatal("drifted client registration accepted")
	}
}

func TestFoundationWireValidatorsRejectExactMalformedFields(t *testing.T) {
	registration, err := FirstMechanismPlugin(FirstNotifyName, "tok")
	if err != nil {
		t.Fatal(err)
	}
	session := registration.Foundation.Session
	challenge := []byte(strings.Repeat("c", 32))
	base := hostileFoundationClient{session: session}
	response, err := base.Handshake(context.Background(), &extensionsv1.HandshakeRequest{Challenge: challenge})
	if err != nil || !validHandshakeResponse(response, challenge, session) {
		t.Fatalf("valid response rejected: %v", err)
	}
	mutations := []func(*extensionsv1.HandshakeResponse){
		func(r *extensionsv1.HandshakeResponse) { r.Control = nil },
		func(r *extensionsv1.HandshakeResponse) { r.Interfaces[0].Minor++ },
		func(r *extensionsv1.HandshakeResponse) { r.Capabilities[0] = "unexpected.capability" },
	}
	for _, mutate := range mutations {
		candidate, err := base.Handshake(context.Background(), &extensionsv1.HandshakeRequest{Challenge: challenge})
		if err != nil {
			t.Fatal(err)
		}
		mutate(candidate)
		if validHandshakeResponse(candidate, challenge, session) {
			t.Fatal("malformed handshake response accepted")
		}
	}
	for _, value := range []string{
		"0000000-0000-4000-8000-000000000123",
		"00000000_0000-4000-8000-000000000123",
		"g0000000-0000-4000-8000-000000000123",
	} {
		if validFoundationUUID(value) {
			t.Fatalf("invalid UUID accepted: %q", value)
		}
	}
	if validFoundationCode("extension.re@dy") {
		t.Fatal("invalid health-code character accepted")
	}
}

func deadlineContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	return ctx
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy failed") }

type hostileFoundationClient struct {
	extensionsv1.ExtensionControlClient
	session      extensioncore.Session
	health       *extensionsv1.HealthResponse
	handshakeErr error
	healthErr    error
}

func (c hostileFoundationClient) Handshake(_ context.Context, request *extensionsv1.HandshakeRequest, _ ...grpc.CallOption) (*extensionsv1.HandshakeResponse, error) {
	if c.handshakeErr != nil {
		return nil, c.handshakeErr
	}
	if c.session.Fingerprint == "" {
		return &extensionsv1.HandshakeResponse{Challenge: make([]byte, 32)}, nil
	}
	interfaces := make([]*extensionsv1.InterfaceVersion, len(c.session.Interfaces))
	for i, item := range c.session.Interfaces {
		interfaces[i] = &extensionsv1.InterfaceVersion{Name: item.Name, Major: item.Major, Minor: item.Minor}
	}
	return &extensionsv1.HandshakeResponse{
		Challenge: request.GetChallenge(), ExtensionId: c.session.ExtensionID, ExtensionVersion: c.session.ExtensionVersion,
		ManifestSha256: c.session.ManifestDigest, GrantSha256: c.session.GrantDigest, SessionSha256: c.session.Fingerprint,
		Control:    &extensionsv1.ProtocolVersion{Name: c.session.Control.Name, Major: c.session.Control.Major, Minor: c.session.Control.Minor},
		Interfaces: interfaces, Capabilities: append([]string(nil), c.session.Capabilities...),
	}, nil
}

func (c hostileFoundationClient) Health(context.Context, *extensionsv1.HealthRequest, ...grpc.CallOption) (*extensionsv1.HealthResponse, error) {
	return c.health, c.healthErr
}

func sortedJoin(values []string) string {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	return strings.Join(copyValues, ",")
}
