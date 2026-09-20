package extensionsruntime

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	extensionsv1 "forgejo/gotthboard/gotth-mail/proto/gotth/extensions/v1"
	pluginv1 "forgejo/gotthboard/gotth-mail/proto/gotth/mail/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	ExtensionID = "gotth.mail.notification.webhook"
	Repository  = "https://github.com/gotthboard/gotth-extension-webhook"
	Interface   = "gotth.mail.interface.notification"
	SecretSlot  = "webhook.hmac-key"

	executableName = "gotth-extension-webhook"
	startupTimeout = 5 * time.Second
	requestTimeout = 5 * time.Second
)

var capabilities = []string{
	"notification.alert.send",
	"notification.alert.sink",
	"notification.delivery.status",
}

type Supervisor struct {
	artifactRoot string
	runtimeRoot  string
	rand         io.Reader

	mu        sync.RWMutex
	processes map[string]*process
	active    string
}

type process struct {
	instance extensionsadmin.Instance
	command  *exec.Cmd
	conn     *grpc.ClientConn
	token    string
	socket   string
	runDir   string
	done     chan struct{}
}

func New(artifactRoot, runtimeRoot string) (*Supervisor, error) {
	artifactRoot = filepath.Clean(strings.TrimSpace(artifactRoot))
	runtimeRoot = filepath.Clean(strings.TrimSpace(runtimeRoot))
	if !filepath.IsAbs(artifactRoot) || !filepath.IsAbs(runtimeRoot) || artifactRoot == runtimeRoot {
		return nil, errors.New("distinct absolute extension roots required")
	}
	if err := validateDirectory(artifactRoot, false); err != nil {
		return nil, fmt.Errorf("artifact root: %w", err)
	}
	if err := validateDirectory(runtimeRoot, true); err != nil {
		return nil, fmt.Errorf("runtime root: %w", err)
	}
	return &Supervisor{artifactRoot: artifactRoot, runtimeRoot: runtimeRoot, rand: rand.Reader, processes: map[string]*process{}}, nil
}

func validateDirectory(path string, private bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("regular directory required")
	}
	if private && info.Mode().Perm()&0o077 != 0 || !private && info.Mode().Perm()&0o022 != 0 {
		return errors.New("unsafe directory permissions")
	}
	return nil
}

func (s *Supervisor) Start(ctx context.Context, instance extensionsadmin.Instance, secrets map[string][]byte) error {
	if err := validateInstance(instance, secrets); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	existing := s.processes[instance.InstanceID]
	s.mu.RUnlock()
	if existing != nil {
		if existing.instance.ArtifactPin == instance.ArtifactPin && existing.instance.ConfigurationRev == instance.ConfigurationRev && !processExited(existing) {
			return nil
		}
		return extensionsadmin.ErrConflict
	}
	artifactDir := filepath.Join(s.artifactRoot, strings.TrimPrefix(instance.ArtifactPin, "sha256:"))
	if err := validateArtifact(artifactDir, instance.ArtifactPin); err != nil {
		return err
	}
	runDir, err := os.MkdirTemp(s.runtimeRoot, "x-")
	if err != nil {
		return err
	}
	if err := os.Chmod(runDir, 0o700); err != nil {
		_ = os.RemoveAll(runDir)
		return err
	}
	fail := func(err error) error {
		_ = os.RemoveAll(runDir)
		return err
	}
	secretDir := filepath.Join(runDir, "secrets")
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		return fail(err)
	}
	config, err := runtimeConfiguration(instance.Configuration)
	if err != nil {
		return fail(err)
	}
	binding, err := json.Marshal(map[string]string{
		"schema": "gotth.extension.runtime-binding.v1", "instance_id": instance.InstanceID,
		"manifest_sha256": instance.ManifestDigest, "grant_sha256": instance.GrantDigest, "session_sha256": instance.SessionDigest,
	})
	if err != nil {
		return fail(err)
	}
	token := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, token); err != nil {
		return fail(err)
	}
	tokenText := fmt.Sprintf("%x", token)
	clear(token)
	files := map[string][]byte{
		filepath.Join(runDir, "config.json"):   config,
		filepath.Join(runDir, "binding.json"):  binding,
		filepath.Join(runDir, "service.token"): []byte(tokenText),
		filepath.Join(secretDir, SecretSlot):   secrets[SecretSlot],
	}
	for path, data := range files {
		if err := writePrivate(path, data); err != nil {
			return fail(err)
		}
	}
	socket := filepath.Join(runDir, "extension.sock")
	command := exec.Command(filepath.Join(artifactDir, executableName))
	command.Env = []string{
		"GOTTH_EXTENSION_CONFIG_FILE=" + filepath.Join(runDir, "config.json"),
		"GOTTH_EXTENSION_BINDING_FILE=" + filepath.Join(runDir, "binding.json"),
		"GOTTH_EXTENSION_SECRET_DIR=" + secretDir,
		"GOTTH_EXTENSION_SERVICE_TOKEN_FILE=" + filepath.Join(runDir, "service.token"),
		"GOTTH_EXTENSION_SOCKET=" + socket,
	}
	command.Dir = runDir
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true}
	if err := command.Start(); err != nil {
		return fail(err)
	}
	p := &process{instance: instance, command: command, token: tokenText, socket: socket, runDir: runDir, done: make(chan struct{})}
	go func() {
		_ = command.Wait()
		close(p.done)
	}()
	if err := waitForSocket(ctx, p); err != nil {
		if stopErr := terminate(p); stopErr != nil {
			return stopErr
		}
		return fail(err)
	}
	conn, err := grpc.NewClient("unix://"+socket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		if stopErr := terminate(p); stopErr != nil {
			return stopErr
		}
		return fail(errors.New("open extension transport"))
	}
	p.conn = conn
	s.mu.Lock()
	if current := s.processes[instance.InstanceID]; current != nil {
		s.mu.Unlock()
		_ = conn.Close()
		if stopErr := terminate(p); stopErr != nil {
			return stopErr
		}
		return fail(extensionsadmin.ErrConflict)
	}
	s.processes[instance.InstanceID] = p
	s.mu.Unlock()
	return nil
}

func validateInstance(instance extensionsadmin.Instance, secrets map[string][]byte) error {
	if instance.ExtensionID != ExtensionID || instance.Repository != Repository || len(instance.Interfaces) != 1 || instance.Interfaces[0] != Interface || !equalStrings(instance.Capabilities, capabilities) || len(instance.SecretSlots) != 1 || instance.SecretSlots[0] != SecretSlot || len(secrets) != 1 || len(secrets[SecretSlot]) < 32 || !validMetadata(instance.Metadata) {
		return errors.New("unsupported extension runtime contract")
	}
	return nil
}

func validMetadata(metadata extensionsadmin.Metadata) bool {
	if metadata.Schema != extensionsadmin.MetadataSchema || len(metadata.Fields) != 3 {
		return false
	}
	endpoint, timeout, secret := metadata.Fields[0], metadata.Fields[1], metadata.Fields[2]
	return endpoint.Name == "webhook.endpoint" && endpoint.Label == "HTTPS webhook endpoint" && endpoint.Kind == extensionsadmin.FieldString && endpoint.Required && endpoint.Min != nil && *endpoint.Min == 1 && endpoint.Max != nil && *endpoint.Max == 2048 &&
		timeout.Name == "webhook.timeout-seconds" && timeout.Label == "Request timeout in seconds" && timeout.Kind == extensionsadmin.FieldInteger && timeout.Required && timeout.Min != nil && *timeout.Min == 1 && timeout.Max != nil && *timeout.Max == 30 && integerDefault(timeout.Default, 10) &&
		secret.Name == SecretSlot && secret.Label == "Webhook HMAC key" && secret.Kind == extensionsadmin.FieldSecret && secret.Required
}

func integerDefault(value any, expected int64) bool {
	actual, ok := integer(value)
	return ok && actual == expected
}

func validateArtifact(dir, pin string) error {
	if !validPin(pin) {
		return errors.New("valid immutable artifact pin required")
	}
	if err := validateDirectory(dir, false); err != nil {
		return errors.New("installed immutable artifact required")
	}
	pinPath := filepath.Join(dir, "artifact-pin")
	pinInfo, err := os.Lstat(pinPath)
	if err != nil || pinInfo.Mode()&os.ModeSymlink != 0 || !pinInfo.Mode().IsRegular() || pinInfo.Mode().Perm()&0o022 != 0 || pinInfo.Size() > 128 {
		return errors.New("installed artifact pin mismatch")
	}
	pinData, err := os.ReadFile(pinPath)
	if err != nil || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(pinData))), []byte(pin)) != 1 {
		return errors.New("installed artifact pin mismatch")
	}
	executable := filepath.Join(dir, executableName)
	info, err := os.Lstat(executable)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("immutable extension executable required")
	}
	return nil
}

func validPin(pin string) bool {
	if !strings.HasPrefix(pin, "sha256:") || len(pin) != len("sha256:")+64 {
		return false
	}
	for _, value := range pin[len("sha256:"):] {
		if !(value >= '0' && value <= '9' || value >= 'a' && value <= 'f') {
			return false
		}
	}
	return true
}

func runtimeConfiguration(values map[string]any) ([]byte, error) {
	endpoint, ok := values["webhook.endpoint"].(string)
	if !ok || endpoint == "" {
		return nil, errors.New("webhook endpoint required")
	}
	timeout, ok := integer(values["webhook.timeout-seconds"])
	if !ok || timeout < 1 || timeout > 30 || len(values) != 2 {
		return nil, errors.New("bounded webhook timeout required")
	}
	return json.Marshal(map[string]any{"schema": "gotth.extension.webhook.config.v1", "endpoint": endpoint, "timeout_seconds": timeout})
}

func integer(value any) (int64, bool) {
	switch n := value.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), n == float64(int64(n))
	case json.Number:
		value, err := strconv.ParseInt(string(n), 10, 64)
		return value, err == nil
	default:
		return 0, false
	}
}

func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func waitForSocket(ctx context.Context, p *process) error {
	deadline := time.NewTimer(startupTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return errors.New("extension process exited before readiness")
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("extension socket startup timed out")
		case <-ticker.C:
			info, err := os.Lstat(p.socket)
			if err == nil && info.Mode()&os.ModeSocket != 0 {
				return nil
			}
		}
	}
}

func processExited(p *process) bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (s *Supervisor) Probe(ctx context.Context, instance extensionsadmin.Instance) (extensionsadmin.Health, error) {
	s.mu.RLock()
	p := s.processes[instance.InstanceID]
	s.mu.RUnlock()
	if p == nil || p.conn == nil || p.instance.ArtifactPin != instance.ArtifactPin || p.instance.ConfigurationRev != instance.ConfigurationRev || processExited(p) {
		return extensionsadmin.Health{}, errors.New("extension process unavailable")
	}
	probeCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	probeCtx = metadata.NewOutgoingContext(probeCtx, metadata.Pairs(plugin.MetadataServiceToken, p.token, plugin.MetadataCorrelationID, "extension-probe"))
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, challenge); err != nil {
		return extensionsadmin.Health{}, err
	}
	control := extensionsv1.NewExtensionControlClient(p.conn)
	handshake, err := control.Handshake(probeCtx, &extensionsv1.HandshakeRequest{CorrelationId: "extension-probe", Challenge: challenge, ExpectedExtensionId: instance.ExtensionID, ExpectedManifestSha256: instance.ManifestDigest, ExpectedGrantSha256: instance.GrantDigest, ExpectedSessionSha256: instance.SessionDigest})
	controlVersion := handshake.GetControl()
	if err != nil || subtle.ConstantTimeCompare(handshake.GetChallenge(), challenge) != 1 || handshake.GetExtensionId() != instance.ExtensionID || !validVersion(handshake.GetExtensionVersion()) || handshake.GetManifestSha256() != instance.ManifestDigest || handshake.GetGrantSha256() != instance.GrantDigest || handshake.GetSessionSha256() != instance.SessionDigest || controlVersion.GetName() != "gotth.extensions.control" || controlVersion.GetMajor() != 1 || controlVersion.GetMinor() != 0 || len(handshake.GetInterfaces()) != 1 || handshake.GetInterfaces()[0].GetName() != Interface || handshake.GetInterfaces()[0].GetMajor() != 1 || handshake.GetInterfaces()[0].GetMinor() != 0 || !equalStrings(handshake.GetCapabilities(), capabilities) {
		return extensionsadmin.Health{}, extensionsadmin.ErrUnauthenticated
	}
	health, err := control.Health(probeCtx, &extensionsv1.HealthRequest{CorrelationId: "extension-probe", SessionSha256: instance.SessionDigest})
	if err != nil || health.GetState() != extensionsv1.HealthState_HEALTH_STATE_READY || health.GetCode() != "extension.ready" {
		return extensionsadmin.Health{}, extensionsadmin.ErrUnhealthy
	}
	return extensionsadmin.Health{Healthy: true, Code: health.GetCode()}, nil
}

func validVersion(value string) bool {
	if value == "1.0.0" {
		return true
	}
	for _, prefix := range []string{"1.0.0-alpha.", "1.0.0-beta."} {
		if strings.HasPrefix(value, prefix) {
			number := value[len(prefix):]
			return number != "" && number[0] != '0' && strings.Trim(number, "0123456789") == ""
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (s *Supervisor) AdmitRouting(_ context.Context, instance extensionsadmin.Instance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p := s.processes[instance.InstanceID]; p == nil || processExited(p) {
		return errors.New("extension process unavailable")
	}
	if s.active != "" && s.active != instance.InstanceID {
		return extensionsadmin.ErrConflict
	}
	s.active = instance.InstanceID
	return nil
}

func (s *Supervisor) RevokeRouting(_ context.Context, instance extensionsadmin.Instance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == "" {
		return nil
	}
	if s.active != instance.InstanceID {
		return extensionsadmin.ErrConflict
	}
	s.active = ""
	return nil
}

func (s *Supervisor) Stop(_ context.Context, instance extensionsadmin.Instance) error {
	s.mu.Lock()
	if s.active == instance.InstanceID {
		s.mu.Unlock()
		return extensionsadmin.ErrConflict
	}
	p := s.processes[instance.InstanceID]
	s.mu.Unlock()
	if p == nil {
		return nil
	}
	if p.conn != nil {
		_ = p.conn.Close()
	}
	if err := terminate(p); err != nil {
		return err
	}
	s.mu.Lock()
	if s.processes[instance.InstanceID] == p {
		delete(s.processes, instance.InstanceID)
	}
	s.mu.Unlock()
	return os.RemoveAll(p.runDir)
}

func terminate(p *process) error {
	if p == nil || p.command == nil || p.command.Process == nil || processExited(p) {
		return nil
	}
	_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
		select {
		case <-p.done:
		case <-time.After(time.Second):
			return errors.New("extension process did not terminate")
		}
	}
	return nil
}

func (s *Supervisor) SendAlert(ctx context.Context, alert notification.Alert) (notification.DeliveryResult, error) {
	s.mu.RLock()
	p := s.processes[s.active]
	s.mu.RUnlock()
	if p == nil || p.conn == nil || processExited(p) {
		return notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "notification_plugin_unavailable"}, errors.New("notification extension unavailable")
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	requestCtx = metadata.NewOutgoingContext(requestCtx, metadata.Pairs(plugin.MetadataServiceToken, p.token, plugin.MetadataCorrelationID, alert.CorrelationID))
	details := make(map[string]string, len(alert.Details))
	for key, value := range alert.Details {
		details[key] = value
	}
	response, err := pluginv1.NewNotificationBackendClient(p.conn).SendAlert(requestCtx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: alert.ID, Class: alert.Class, Severity: string(alert.Severity), Title: alert.Title, Summary: alert.Summary, CorrelationId: alert.CorrelationID, Resource: &pluginv1.AlertResource{Type: alert.Resource.Type, Id: alert.Resource.ID}, Details: details}})
	if err != nil {
		if status.Code(err) == codes.InvalidArgument || status.Code(err) == codes.PermissionDenied || status.Code(err) == codes.Unimplemented {
			return notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "notification_plugin_rejected"}, errors.New("notification extension rejected delivery")
		}
		return notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "notification_plugin_unavailable"}, errors.New("notification extension unavailable")
	}
	result := notification.DeliveryResult{Status: notification.DeliveryStatus(response.GetStatus()), Reason: notification.SanitizeDeliveryReason(response.GetReason())}
	if evidence := response.GetEvidence(); evidence != nil {
		result.Evidence = notification.SanitizeDeliveryEvidence(notification.DeliveryEvidence{Transport: evidence.GetTransport(), MessageID: evidence.GetMessageId(), VerificationResult: evidence.GetVerificationResult(), Workflow: evidence.GetWorkflow()})
		if generated, err := time.Parse(time.RFC3339Nano, evidence.GetGeneratedAt()); err == nil {
			result.Evidence.GeneratedAt = generated
		}
	}
	return result, nil
}

func (s *Supervisor) Health(ctx context.Context, requested string) (plugin.HealthResponse, error) {
	s.mu.RLock()
	p := s.processes[s.active]
	s.mu.RUnlock()
	if p == nil || requested != ExtensionID {
		return plugin.HealthResponse{}, errors.New("configured extension not found")
	}
	health, err := s.Probe(ctx, p.instance)
	return plugin.HealthResponse{Healthy: err == nil && health.Healthy, Message: health.Code}, err
}
