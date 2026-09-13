package plugin

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	pluginv1 "forgejo/gotthboard/gotth-mail/proto/gotth/mail/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type failingNotificationSink struct{}

func (failingNotificationSink) SendAlert(context.Context, notification.Alert) (notification.DeliveryResult, error) {
	return notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "openpgp_verification_failed"}, errors.New("private signer detail")
}

type leakingNotificationSink struct{}

func (leakingNotificationSink) SendAlert(context.Context, notification.Alert) (notification.DeliveryResult, error) {
	return notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "smtp password=supersecret"}, errors.New("private transport detail")
}

func (leakingNotificationSink) SendPrompt(context.Context, NotificationPrompt) (PromptResult, error) {
	return PromptResult{}, errors.New("unsupported")
}

func (failingNotificationSink) SendPrompt(context.Context, NotificationPrompt) (PromptResult, error) {
	return PromptResult{}, errors.New("unsupported")
}

type statusErrorNotificationSink struct {
	code codes.Code
}

func (s statusErrorNotificationSink) SendAlert(context.Context, notification.Alert) (notification.DeliveryResult, error) {
	return notification.DeliveryResult{}, leakingSinkStatus(s.code)
}

func (s statusErrorNotificationSink) SendPrompt(context.Context, NotificationPrompt) (PromptResult, error) {
	return PromptResult{}, leakingSinkStatus(s.code)
}

type leakingEvidenceNotificationSink struct{}

func (leakingEvidenceNotificationSink) SendAlert(context.Context, notification.Alert) (notification.DeliveryResult, error) {
	secret := "password=supersecret"
	return notification.DeliveryResult{Status: notification.StatusDelivered, Evidence: notification.DeliveryEvidence{
		Transport: "email", MessageID: secret, From: "alerts@example.test", Sender: secret,
		SigningFingerprint: secret, SenderIdentityID: secret, SenderIdentityClass: secret,
		PolicyVersion: secret, IdentityStateRef: secret, VerificationResult: secret, Workflow: secret,
	}}, nil
}

func (leakingEvidenceNotificationSink) SendPrompt(context.Context, NotificationPrompt) (PromptResult, error) {
	return PromptResult{}, errors.New("unsupported")
}

func leakingSinkStatus(code codes.Code) error {
	leaking, err := status.New(code, "smtp password=supersecret token=bearer-secret").WithDetails(&pluginv1.PromptResponse{Message: "private key: secret detail"})
	if err != nil {
		return status.Error(code, "smtp password=supersecret token=bearer-secret")
	}
	return leaking.Err()
}

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

func TestNotificationBackendReturnsSanitizedDeliveryFailureAsDomainResult(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterNotificationServer(srv, NotificationServer{Name: "stub", Registry: reg(), Sink: failingNotificationSink{}})
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
	result, err := client.SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-1", Class: "doctor.failure", Severity: "critical", Title: "Doctor failed", Summary: "failed", CorrelationId: "corr-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.GetStatus() != string(notification.StatusFailedPermanent) || result.GetReason() != "openpgp_verification_failed" || strings.Contains(result.GetReason(), "private") {
		t.Fatalf("bad failure response: %#v", result)
	}
}

func TestNotificationBackendBoundsAndRedactsUntrustedSinkReason(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterNotificationServer(srv, NotificationServer{Name: "stub", Registry: reg(), Sink: leakingNotificationSink{}})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	baseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := metadata.NewOutgoingContext(baseCtx, metadata.Pairs(MetadataCorrelationID, "corr-1", MetadataServiceToken, "tok"))
	result, err := pluginv1.NewNotificationBackendClient(conn).SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-1", Class: "doctor.failure", Severity: "critical", Title: "failed", Summary: "failed", CorrelationId: "corr-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.GetReason() != "delivery_reason_redacted" || strings.Contains(result.GetReason(), "secret") {
		t.Fatalf("unsafe sink reason crossed gRPC boundary: %#v", result)
	}
}

func TestNotificationBackendDoesNotExposeSinkGRPCStatusDescriptions(t *testing.T) {
	tests := []struct {
		name        string
		sinkCode    codes.Code
		wantCode    codes.Code
		wantMessage string
	}{
		{name: "canceled", sinkCode: codes.Canceled, wantCode: codes.Canceled, wantMessage: "notification delivery canceled"},
		{name: "invalid argument", sinkCode: codes.InvalidArgument, wantCode: codes.InvalidArgument, wantMessage: "invalid notification alert"},
		{name: "deadline exceeded", sinkCode: codes.DeadlineExceeded, wantCode: codes.DeadlineExceeded, wantMessage: "notification delivery deadline exceeded"},
		{name: "resource exhausted", sinkCode: codes.ResourceExhausted, wantCode: codes.ResourceExhausted, wantMessage: "notification delivery resource exhausted"},
		{name: "unavailable", sinkCode: codes.Unavailable, wantCode: codes.Unavailable, wantMessage: "notification delivery unavailable"},
		{name: "unimplemented", sinkCode: codes.Unimplemented, wantCode: codes.Unimplemented, wantMessage: "notification prompts are not supported"},
		{name: "disallowed credential status", sinkCode: codes.Unauthenticated, wantCode: codes.Unavailable, wantMessage: "notification delivery failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lis := bufconn.Listen(1024 * 1024)
			srv := grpc.NewServer()
			RegisterNotificationServer(srv, NotificationServer{Name: "stub", Registry: reg(), Sink: statusErrorNotificationSink{code: tt.sinkCode}})
			go func() { _ = srv.Serve(lis) }()
			defer srv.Stop()
			conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			baseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctx := metadata.NewOutgoingContext(baseCtx, metadata.Pairs(MetadataCorrelationID, "corr-1", MetadataServiceToken, "tok"))
			_, err = pluginv1.NewNotificationBackendClient(conn).SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-1", Class: "doctor.failure", Severity: "critical", Title: "failed", Summary: "failed", CorrelationId: "corr-1"}})
			if status.Code(err) != tt.wantCode {
				t.Fatalf("status code=%v want %v: %v", status.Code(err), tt.wantCode, err)
			}
			message := status.Convert(err).Message()
			if message != tt.wantMessage {
				t.Fatalf("status message=%q want %q", message, tt.wantMessage)
			}
			if strings.Contains(strings.ToLower(message), "password") || strings.Contains(strings.ToLower(message), "secret") || strings.Contains(strings.ToLower(message), "token") {
				t.Fatalf("sink status description crossed gRPC boundary: %q", message)
			}
			if details := status.Convert(err).Details(); len(details) != 0 {
				t.Fatalf("sink status details crossed gRPC boundary: %#v", details)
			}
		})
	}
}

func TestNotificationBackendDoesNotExposePromptSinkGRPCStatusDescriptionsOrDetails(t *testing.T) {
	tests := []struct {
		name        string
		sinkCode    codes.Code
		wantCode    codes.Code
		wantMessage string
	}{
		{name: "canceled", sinkCode: codes.Canceled, wantCode: codes.Canceled, wantMessage: "notification delivery canceled"},
		{name: "invalid argument", sinkCode: codes.InvalidArgument, wantCode: codes.InvalidArgument, wantMessage: "invalid notification alert"},
		{name: "deadline exceeded", sinkCode: codes.DeadlineExceeded, wantCode: codes.DeadlineExceeded, wantMessage: "notification delivery deadline exceeded"},
		{name: "resource exhausted", sinkCode: codes.ResourceExhausted, wantCode: codes.ResourceExhausted, wantMessage: "notification delivery resource exhausted"},
		{name: "unavailable", sinkCode: codes.Unavailable, wantCode: codes.Unavailable, wantMessage: "notification delivery unavailable"},
		{name: "disallowed credential status", sinkCode: codes.Unauthenticated, wantCode: codes.Unavailable, wantMessage: "notification delivery failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lis := bufconn.Listen(1024 * 1024)
			srv := grpc.NewServer()
			RegisterNotificationServer(srv, NotificationServer{Name: "stub", Registry: reg(), Sink: statusErrorNotificationSink{code: tt.sinkCode}})
			go func() { _ = srv.Serve(lis) }()
			defer srv.Stop()
			conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			baseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			ctx := metadata.NewOutgoingContext(baseCtx, metadata.Pairs(MetadataCorrelationID, "corr-1", MetadataServiceToken, "tok"))
			_, err = pluginv1.NewNotificationBackendClient(conn).SendPrompt(ctx, validPromptRequest())
			converted := status.Convert(err)
			if converted.Code() != tt.wantCode {
				t.Fatalf("status code=%v want %v: %v", converted.Code(), tt.wantCode, err)
			}
			if message := converted.Message(); message != tt.wantMessage {
				t.Fatalf("status message=%q want %q", message, tt.wantMessage)
			}
			if details := converted.Details(); len(details) != 0 {
				t.Fatalf("sink prompt status details crossed gRPC boundary: %#v", details)
			}
		})
	}
}

func TestNotificationBackendRemovesSecretMarkedEvidenceAtGRPCBoundary(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	RegisterNotificationServer(srv, NotificationServer{Name: "stub", Registry: reg(), Sink: leakingEvidenceNotificationSink{}})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	baseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx := metadata.NewOutgoingContext(baseCtx, metadata.Pairs(MetadataCorrelationID, "corr-1", MetadataServiceToken, "tok"))
	result, err := pluginv1.NewNotificationBackendClient(conn).SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: "alert-1", Class: "doctor.failure", Severity: "critical", Title: "failed", Summary: "failed", CorrelationId: "corr-1"}})
	if err != nil {
		t.Fatal(err)
	}
	evidence := result.GetEvidence()
	if evidence == nil || evidence.GetTransport() != "email" || evidence.GetFrom() != "alerts@example.test" {
		t.Fatalf("safe evidence fields were lost: %#v", evidence)
	}
	if evidence.GetMessageId() != "" || evidence.GetSender() != "" || evidence.GetSigningFingerprint() != "" || evidence.GetSenderIdentityId() != "" || evidence.GetSenderIdentityClass() != "" || evidence.GetPolicyVersion() != "" || evidence.GetIdentityStateRef() != "" || evidence.GetVerificationResult() != "" || evidence.GetWorkflow() != "" {
		t.Fatalf("secret-marked evidence crossed gRPC boundary: %#v", evidence)
	}
	if text := strings.ToLower(evidence.String()); strings.Contains(text, "password") || strings.Contains(text, "supersecret") {
		t.Fatalf("secret text crossed gRPC boundary: %q", text)
	}
}

func validPromptRequest() *pluginv1.SendPromptRequest {
	return &pluginv1.SendPromptRequest{Id: "prompt-1", CorrelationId: "corr-1", Transport: "telegram", ExternalActorId: "chat:42:user:99", ActorType: "api_token", ActorId: "ops", Action: "queue:flush", ResourceType: "queue", ResourceId: "default", RequestHash: "sha256:abc", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Title: "Approve queue flush", Summary: "Flush deferred queue"}
}
