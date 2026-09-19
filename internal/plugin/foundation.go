package plugin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	extensionsv1 "forgejo/gotthboard/gotth-mail/proto/gotth/extensions/v1"
	extensioncore "github.com/gotthboard/gotth-extensions/pkg/extensions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const extensionDevelopmentVersion = "0.0.0-dev"

var foundationControlRange = extensioncore.VersionRange{
	Name: extensioncore.ControlName, Major: 1, MinMinor: 0, MaxMinor: 0,
}

// FoundationBinding is the immutable manifest/grant/session identity admitted
// for one Mail-owned extension instance. It contains no credential or secret
// value; service authentication remains a separate transport concern.
type FoundationBinding struct {
	Manifest  extensioncore.Manifest
	Grant     extensioncore.Grant
	Profile   extensioncore.HostProfile
	Session   extensioncore.Session
	Lifecycle extensioncore.State
}

// NewFoundationBinding projects an existing seam registration into the exact
// gotth-extensions compatibility contract without changing the seam protocol.
func NewFoundationBinding(reg Registration) (*FoundationBinding, error) {
	if strings.TrimSpace(reg.Name) == "" || !validSeam(reg.Seam) || len(reg.Capabilities) == 0 {
		return nil, errors.New("complete extension registration required")
	}
	interfaceName := "gotth.mail.interface." + string(reg.Seam)
	manifest := extensioncore.Manifest{
		Schema: extensioncore.ManifestSchema,
		ID:     "gotth.mail." + strings.ReplaceAll(reg.Name, "-", "."),
		Name:   reg.Name, Version: extensionDevelopmentVersion,
		Protocols:    []extensioncore.VersionRange{foundationControlRange},
		Interfaces:   []extensioncore.VersionRange{{Name: interfaceName, Major: 1, MinMinor: 0, MaxMinor: 0}},
		Capabilities: append([]string(nil), reg.Capabilities...),
	}
	manifest.Secrets = make([]extensioncore.SecretRequirement, len(reg.SecretSlots))
	for i, slot := range reg.SecretSlots {
		manifest.Secrets[i] = extensioncore.SecretRequirement{ID: slot, Required: true}
	}
	digest, err := extensioncore.ManifestDigest(manifest)
	if err != nil {
		return nil, errors.New("extension manifest rejected")
	}
	grant := extensioncore.Grant{
		Schema: extensioncore.GrantSchema, InstanceID: deterministicInstanceID(reg.Name),
		ExtensionID: manifest.ID, ManifestDigest: digest,
		Capabilities: append([]string(nil), reg.Capabilities...),
		Interfaces:   []extensioncore.InterfaceGrant{{Name: interfaceName, Major: 1, Minor: 0}},
		Secrets:      append([]string(nil), reg.SecretSlots...),
	}
	profile := extensioncore.HostProfile{
		Protocols:  []extensioncore.VersionRange{foundationControlRange},
		Interfaces: []extensioncore.VersionRange{{Name: interfaceName, Major: 1, MinMinor: 0, MaxMinor: 0}},
	}
	session, err := extensioncore.Negotiate(manifest, grant, profile)
	if err != nil {
		return nil, errors.New("extension negotiation rejected")
	}
	binding := &FoundationBinding{Manifest: manifest, Grant: grant, Profile: profile, Session: session, Lifecycle: extensioncore.StateDiscovered}
	binding, err = TransitionFoundation(binding, extensioncore.StateStarting)
	if err == nil {
		binding, err = TransitionFoundation(binding, extensioncore.StateReady)
	}
	if err != nil {
		return nil, errors.New("extension lifecycle rejected")
	}
	return binding, nil
}

// TransitionFoundation returns a new binding after validating the lifecycle
// edge. Callers replace registrations atomically; bindings are never mutated
// in place behind an active route.
func TransitionFoundation(binding *FoundationBinding, to extensioncore.State) (*FoundationBinding, error) {
	if binding == nil || extensioncore.ValidateTransition(binding.Lifecycle, to) != nil {
		return nil, errors.New("extension lifecycle transition rejected")
	}
	next := *binding
	next.Lifecycle = to
	return &next, nil
}

func validSeam(seam Seam) bool {
	switch seam {
	case Webmail, DNS, ACME, Backup, Notification, Import:
		return true
	default:
		return false
	}
}

func deterministicInstanceID(name string) string {
	digest := sha256.Sum256([]byte("gotth-mail-extension-instance\x00" + name))
	digest[6] = digest[6]&0x0f | 0x40
	digest[8] = digest[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		digest[0:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}

func validatedFoundation(reg Registration) (*FoundationBinding, error) {
	if reg.Foundation == nil {
		return nil, errors.New("extension foundation binding required")
	}
	expected, err := NewFoundationBinding(Registration{
		Name: reg.Name, Seam: reg.Seam,
		Capabilities: append([]string(nil), reg.Capabilities...),
		SecretSlots:  append([]string(nil), reg.SecretSlots...),
	})
	if err != nil {
		return nil, errors.New("extension registration invalid")
	}
	binding := reg.Foundation
	session, err := extensioncore.Negotiate(binding.Manifest, binding.Grant, binding.Profile)
	if err != nil || session.Fingerprint != binding.Session.Fingerprint || session.Fingerprint != expected.Session.Fingerprint {
		return nil, errors.New("extension foundation binding invalid")
	}
	if binding.Lifecycle != extensioncore.StateStarting && binding.Lifecycle != extensioncore.StateReady && binding.Lifecycle != extensioncore.StateDegraded && binding.Lifecycle != extensioncore.StateStopping && binding.Lifecycle != extensioncore.StateFailed {
		return nil, errors.New("extension lifecycle state unavailable")
	}
	normalized := *binding
	normalized.Session = session
	return &normalized, nil
}

type FoundationServer struct {
	extensionsv1.UnimplementedExtensionControlServer
	Registry Registry
	Name     string
}

func RegisterFoundationServer(server grpc.ServiceRegistrar, service FoundationServer) {
	extensionsv1.RegisterExtensionControlServer(server, service)
}

func (s FoundationServer) Handshake(ctx context.Context, in *extensionsv1.HandshakeRequest) (*extensionsv1.HandshakeResponse, error) {
	reg, err := s.Registry.auth(ctx, s.Name, Request{CorrelationID: in.GetCorrelationId()})
	if err != nil {
		return nil, err
	}
	if !validFoundationUUID(in.GetCorrelationId()) || len(in.GetChallenge()) != 32 {
		return nil, status.Error(codes.InvalidArgument, "valid extension handshake required")
	}
	binding, err := validatedFoundation(reg)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "extension binding unavailable")
	}
	if in.GetExpectedExtensionId() != binding.Session.ExtensionID ||
		subtle.ConstantTimeCompare([]byte(in.GetExpectedManifestSha256()), []byte(binding.Session.ManifestDigest)) != 1 ||
		subtle.ConstantTimeCompare([]byte(in.GetExpectedGrantSha256()), []byte(binding.Session.GrantDigest)) != 1 ||
		subtle.ConstantTimeCompare([]byte(in.GetExpectedSessionSha256()), []byte(binding.Session.Fingerprint)) != 1 {
		return nil, status.Error(codes.FailedPrecondition, "extension binding mismatch")
	}
	interfaces := make([]*extensionsv1.InterfaceVersion, len(binding.Session.Interfaces))
	for i, item := range binding.Session.Interfaces {
		interfaces[i] = &extensionsv1.InterfaceVersion{Name: item.Name, Major: item.Major, Minor: item.Minor}
	}
	return &extensionsv1.HandshakeResponse{
		Challenge: append([]byte(nil), in.GetChallenge()...), ExtensionId: binding.Session.ExtensionID,
		ExtensionVersion: binding.Session.ExtensionVersion, ManifestSha256: binding.Session.ManifestDigest,
		GrantSha256: binding.Session.GrantDigest, SessionSha256: binding.Session.Fingerprint,
		Control:    &extensionsv1.ProtocolVersion{Name: binding.Session.Control.Name, Major: binding.Session.Control.Major, Minor: binding.Session.Control.Minor},
		Interfaces: interfaces, Capabilities: append([]string(nil), binding.Session.Capabilities...),
	}, nil
}

func (s FoundationServer) Health(ctx context.Context, in *extensionsv1.HealthRequest) (*extensionsv1.HealthResponse, error) {
	reg, err := s.Registry.auth(ctx, s.Name, Request{CorrelationID: in.GetCorrelationId()})
	if err != nil {
		return nil, err
	}
	if !validFoundationUUID(in.GetCorrelationId()) {
		return nil, status.Error(codes.InvalidArgument, "valid extension health request required")
	}
	binding, err := validatedFoundation(reg)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "extension binding unavailable")
	}
	if subtle.ConstantTimeCompare([]byte(in.GetSessionSha256()), []byte(binding.Session.Fingerprint)) != 1 {
		return nil, status.Error(codes.FailedPrecondition, "extension session mismatch")
	}
	state, code := foundationHealth(binding.Lifecycle)
	return &extensionsv1.HealthResponse{State: state, Code: code}, nil
}

func foundationHealth(state extensioncore.State) (extensionsv1.HealthState, string) {
	switch state {
	case extensioncore.StateStarting:
		return extensionsv1.HealthState_HEALTH_STATE_STARTING, "extension.starting"
	case extensioncore.StateReady:
		return extensionsv1.HealthState_HEALTH_STATE_READY, "extension.ready"
	case extensioncore.StateDegraded:
		return extensionsv1.HealthState_HEALTH_STATE_DEGRADED, "extension.degraded"
	case extensioncore.StateStopping:
		return extensionsv1.HealthState_HEALTH_STATE_STOPPING, "extension.stopping"
	default:
		return extensionsv1.HealthState_HEALTH_STATE_FAILED, "extension.failed"
	}
}

type FoundationClient struct {
	client       extensionsv1.ExtensionControlClient
	registration Registration
	token        string
	rand         io.Reader
}

func NewFoundationClient(connection grpc.ClientConnInterface, registration Registration, token string) (*FoundationClient, error) {
	if connection == nil || strings.TrimSpace(token) == "" {
		return nil, errors.New("extension foundation client configuration required")
	}
	if _, err := validatedFoundation(registration); err != nil {
		return nil, err
	}
	return &FoundationClient{client: extensionsv1.NewExtensionControlClient(connection), registration: registration, token: token, rand: rand.Reader}, nil
}

func (c *FoundationClient) Health(ctx context.Context) (HealthResponse, error) {
	if c == nil || c.client == nil {
		return HealthResponse{}, errors.New("extension foundation client unavailable")
	}
	if _, ok := ctx.Deadline(); !ok {
		return HealthResponse{}, errors.New("extension foundation deadline required")
	}
	binding, err := validatedFoundation(c.registration)
	if err != nil {
		return HealthResponse{}, err
	}
	material := make([]byte, 48)
	if _, err := io.ReadFull(c.rand, material); err != nil {
		return HealthResponse{}, errors.New("extension foundation entropy unavailable")
	}
	correlationID := foundationUUID(material[:16])
	challenge := material[16:]
	rpcCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs(MetadataCorrelationID, correlationID, MetadataServiceToken, c.token))
	response, err := c.client.Handshake(rpcCtx, &extensionsv1.HandshakeRequest{
		CorrelationId: correlationID, Challenge: challenge, ExpectedExtensionId: binding.Session.ExtensionID,
		ExpectedManifestSha256: binding.Session.ManifestDigest, ExpectedGrantSha256: binding.Session.GrantDigest,
		ExpectedSessionSha256: binding.Session.Fingerprint,
	})
	if err != nil {
		return HealthResponse{}, err
	}
	if !validHandshakeResponse(response, challenge, binding.Session) {
		return HealthResponse{}, errors.New("extension handshake response rejected")
	}
	health, err := c.client.Health(rpcCtx, &extensionsv1.HealthRequest{CorrelationId: correlationID, SessionSha256: binding.Session.Fingerprint})
	if err != nil {
		return HealthResponse{}, err
	}
	if !validFoundationCode(health.GetCode()) || !validFoundationHealth(health.GetState(), health.GetCode()) {
		return HealthResponse{}, errors.New("extension health response rejected")
	}
	if health.GetState() == extensionsv1.HealthState_HEALTH_STATE_READY {
		return HealthResponse{Healthy: true, Message: health.GetCode()}, nil
	}
	return HealthResponse{Healthy: false, Message: health.GetCode()}, nil
}

func validHandshakeResponse(response *extensionsv1.HandshakeResponse, challenge []byte, session extensioncore.Session) bool {
	if response == nil || subtle.ConstantTimeCompare(response.GetChallenge(), challenge) != 1 || response.GetExtensionId() != session.ExtensionID || response.GetExtensionVersion() != session.ExtensionVersion || subtle.ConstantTimeCompare([]byte(response.GetManifestSha256()), []byte(session.ManifestDigest)) != 1 || subtle.ConstantTimeCompare([]byte(response.GetGrantSha256()), []byte(session.GrantDigest)) != 1 || subtle.ConstantTimeCompare([]byte(response.GetSessionSha256()), []byte(session.Fingerprint)) != 1 {
		return false
	}
	control := response.GetControl()
	if control == nil || control.GetName() != session.Control.Name || control.GetMajor() != session.Control.Major || control.GetMinor() != session.Control.Minor || len(response.GetInterfaces()) != len(session.Interfaces) || len(response.GetCapabilities()) != len(session.Capabilities) {
		return false
	}
	for i, item := range session.Interfaces {
		got := response.GetInterfaces()[i]
		if got.GetName() != item.Name || got.GetMajor() != item.Major || got.GetMinor() != item.Minor {
			return false
		}
	}
	capabilities := append([]string(nil), response.GetCapabilities()...)
	sort.Strings(capabilities)
	for i := range session.Capabilities {
		if capabilities[i] != session.Capabilities[i] {
			return false
		}
	}
	return true
}

func foundationUUID(seed []byte) string {
	var value [16]byte
	copy(value[:], seed)
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

func validFoundationUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := range len(value) {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if value[i] != '-' {
				return false
			}
			continue
		}
		if !(value[i] >= '0' && value[i] <= '9' || value[i] >= 'a' && value[i] <= 'f') {
			return false
		}
	}
	return true
}

func validFoundationCode(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part[0] < 'a' || part[0] > 'z' || part[len(part)-1] == '-' {
			return false
		}
		for _, char := range part {
			if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validFoundationHealth(state extensionsv1.HealthState, code string) bool {
	switch state {
	case extensionsv1.HealthState_HEALTH_STATE_STARTING:
		return code == "extension.starting"
	case extensionsv1.HealthState_HEALTH_STATE_READY:
		return code == "extension.ready"
	case extensionsv1.HealthState_HEALTH_STATE_DEGRADED:
		return code == "extension.degraded"
	case extensionsv1.HealthState_HEALTH_STATE_STOPPING:
		return code == "extension.stopping"
	case extensionsv1.HealthState_HEALTH_STATE_FAILED:
		return code == "extension.failed"
	default:
		return false
	}
}
