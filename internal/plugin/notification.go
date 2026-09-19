package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	pluginv1 "forgejo/gotthboard/gotth-mail/proto/gotth/mail/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type NotificationSink interface {
	SendAlert(context.Context, notification.Alert) (notification.DeliveryResult, error)
	SendPrompt(context.Context, NotificationPrompt) (PromptResult, error)
}

type NotificationPrompt struct {
	ID, CorrelationID, Transport, ExternalActorID string
	ActorType, ActorID                            string
	Action, ResourceType, ResourceID              string
	RequestHash, ExpiresAt, ConfirmationToken     string
	Title, Summary                                string
}

type PromptResult struct {
	Accepted bool
	Message  string
}

type NotificationServer struct {
	pluginv1.UnimplementedNotificationBackendServer
	Registry Registry
	Name     string
	Sink     NotificationSink
}

func RegisterNotificationServer(s grpc.ServiceRegistrar, srv NotificationServer) {
	pluginv1.RegisterNotificationBackendServer(s, srv)
}

func (s NotificationServer) SendAlert(ctx context.Context, in *pluginv1.SendAlertRequest) (*pluginv1.DeliveryResponse, error) {
	if in.GetAlert() == nil {
		return nil, status.Error(codes.InvalidArgument, "alert required")
	}
	if _, err := s.Registry.auth(ctx, s.Name, Request{CorrelationID: in.GetAlert().GetCorrelationId()}); err != nil {
		return nil, err
	}
	sink := s.Sink
	if sink == nil {
		return nil, status.Error(codes.Unavailable, "notification delivery unavailable")
	}
	result, err := sink.SendAlert(ctx, protoAlert(in.GetAlert()))
	reason := notification.SanitizeDeliveryReason(result.Reason)
	evidence := protoDeliveryEvidence(result.Evidence)
	if err != nil {
		if (result.Status == notification.StatusFailedPermanent || result.Status == notification.StatusFailedRetryable) && reason != "" {
			return &pluginv1.DeliveryResponse{Status: string(result.Status), Reason: reason, Evidence: evidence}, nil
		}
		return nil, notificationSinkError(err)
	}
	return &pluginv1.DeliveryResponse{Status: string(result.Status), Reason: reason, Evidence: evidence}, nil
}

func notificationSinkError(err error) error {
	switch status.Code(err) {
	case codes.Canceled:
		return status.Error(codes.Canceled, "notification delivery canceled")
	case codes.InvalidArgument:
		return status.Error(codes.InvalidArgument, "invalid notification alert")
	case codes.DeadlineExceeded:
		return status.Error(codes.DeadlineExceeded, "notification delivery deadline exceeded")
	case codes.ResourceExhausted:
		return status.Error(codes.ResourceExhausted, "notification delivery resource exhausted")
	case codes.Unavailable:
		return status.Error(codes.Unavailable, "notification delivery unavailable")
	case codes.Unimplemented:
		return status.Error(codes.Unimplemented, "notification prompts are not supported")
	default:
		return status.Error(codes.Unavailable, "notification delivery failed")
	}
}

func protoDeliveryEvidence(in notification.DeliveryEvidence) *pluginv1.DeliveryEvidence {
	e := notification.SanitizeDeliveryEvidence(in)
	if e == (notification.DeliveryEvidence{}) {
		return nil
	}
	generatedAt := ""
	if !e.GeneratedAt.IsZero() {
		generatedAt = e.GeneratedAt.UTC().Format(time.RFC3339Nano)
	}
	return &pluginv1.DeliveryEvidence{
		Transport:           e.Transport,
		MessageId:           e.MessageID,
		GeneratedAt:         generatedAt,
		From:                e.From,
		Sender:              e.Sender,
		SigningFingerprint:  e.SigningFingerprint,
		SenderIdentityId:    e.SenderIdentityID,
		SenderIdentityClass: e.SenderIdentityClass,
		PolicyVersion:       e.PolicyVersion,
		IdentityStateRef:    e.IdentityStateRef,
		VerificationResult:  e.VerificationResult,
		Workflow:            e.Workflow,
	}
}

func (s NotificationServer) SendPrompt(ctx context.Context, in *pluginv1.SendPromptRequest) (*pluginv1.PromptResponse, error) {
	if _, err := s.Registry.auth(ctx, s.Name, Request{CorrelationID: in.GetCorrelationId()}); err != nil {
		return nil, err
	}
	sink := s.Sink
	if sink == nil {
		return nil, status.Error(codes.Unavailable, "notification delivery unavailable")
	}
	result, err := sink.SendPrompt(ctx, NotificationPrompt{ID: in.GetId(), CorrelationID: in.GetCorrelationId(), Transport: in.GetTransport(), ExternalActorID: in.GetExternalActorId(), ActorType: in.GetActorType(), ActorID: in.GetActorId(), Action: in.GetAction(), ResourceType: in.GetResourceType(), ResourceID: in.GetResourceId(), RequestHash: in.GetRequestHash(), ExpiresAt: in.GetExpiresAt(), Title: in.GetTitle(), Summary: in.GetSummary(), ConfirmationToken: in.GetConfirmationToken()})
	if err != nil {
		return nil, notificationSinkError(err)
	}
	return &pluginv1.PromptResponse{Accepted: result.Accepted, Message: result.Message}, nil
}

type LocalNotificationSink struct{}

type FixtureNotificationSink struct {
	Path string
	mu   sync.Mutex
}

func (s *FixtureNotificationSink) SendAlert(ctx context.Context, alert notification.Alert) (notification.DeliveryResult, error) {
	return (LocalNotificationSink{}).SendAlert(ctx, alert)
}

func (s *FixtureNotificationSink) SendPrompt(ctx context.Context, prompt NotificationPrompt) (PromptResult, error) {
	result, err := (LocalNotificationSink{}).SendPrompt(ctx, prompt)
	if err != nil {
		return result, err
	}
	path := filepath.Clean(strings.TrimSpace(s.Path))
	if !strings.HasPrefix(path, "/run/gotth-mail-plugins/") || filepath.Dir(path) != "/run/gotth-mail-plugins" {
		return PromptResult{}, errors.New("invalid fixture notification capture path")
	}
	encoded, err := json.Marshal(prompt)
	if err != nil {
		return PromptResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return PromptResult{}, err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return PromptResult{}, err
	}
	return result, file.Sync()
}

func (LocalNotificationSink) SendAlert(ctx context.Context, a notification.Alert) (notification.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return notification.DeliveryResult{}, status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	if _, err := notification.SanitizeAlert(a); err != nil {
		return notification.DeliveryResult{}, status.Error(codes.InvalidArgument, err.Error())
	}
	return notification.DeliveryResult{Status: notification.StatusDelivered, Reason: "accepted_by_notification_sink"}, nil
}

func (LocalNotificationSink) SendPrompt(ctx context.Context, p NotificationPrompt) (PromptResult, error) {
	if err := ctx.Err(); err != nil {
		return PromptResult{}, status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	binding, bindingErr := base64.RawURLEncoding.DecodeString(p.ConfirmationToken)
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.CorrelationID) == "" || strings.TrimSpace(p.Transport) == "" || strings.TrimSpace(p.ExternalActorID) == "" || strings.TrimSpace(p.ActorType) == "" || strings.TrimSpace(p.ActorID) == "" || strings.TrimSpace(p.Action) == "" || strings.TrimSpace(p.ResourceType) == "" || strings.TrimSpace(p.ResourceID) == "" || strings.TrimSpace(p.RequestHash) == "" || strings.TrimSpace(p.ExpiresAt) == "" || len(p.ConfirmationToken) != 22 || bindingErr != nil || len(binding) != 16 {
		return PromptResult{}, status.Error(codes.InvalidArgument, "complete prompt binding required")
	}
	if strings.Contains(strings.ToLower(p.Summary+p.Title), "password=") || strings.Contains(strings.ToLower(p.Summary+p.Title), "token=") || strings.Contains(strings.ToLower(p.Summary+p.Title), "secret=") {
		return PromptResult{}, status.Error(codes.InvalidArgument, "prompt contains secret-looking value")
	}
	return PromptResult{Accepted: true, Message: "prompt_accepted_for_delivery"}, nil
}

func protoAlert(a *pluginv1.AlertMessage) notification.Alert {
	out := notification.Alert{ID: a.GetId(), Class: a.GetClass(), Severity: notification.Severity(a.GetSeverity()), Title: a.GetTitle(), Summary: a.GetSummary(), CorrelationID: a.GetCorrelationId(), Details: map[string]string{}}
	if a.GetResource() != nil {
		out.Resource = notification.ResourceRef{Type: a.GetResource().GetType(), ID: a.GetResource().GetId()}
	}
	for k, v := range a.GetDetails() {
		out.Details[k] = v
	}
	return out
}
