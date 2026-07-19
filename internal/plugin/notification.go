package plugin

import (
	"context"
	"strings"

	"forgejo/linus/gophermailforge/internal/notification"
	pluginv1 "forgejo/linus/gophermailforge/proto/gophermailforge/plugin/v1"
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
	RequestHash, ExpiresAt                        string
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
		sink = LocalNotificationSink{}
	}
	result, err := sink.SendAlert(ctx, protoAlert(in.GetAlert()))
	if err != nil {
		return nil, err
	}
	return &pluginv1.DeliveryResponse{Status: string(result.Status), Reason: result.Reason}, nil
}

func (s NotificationServer) SendPrompt(ctx context.Context, in *pluginv1.SendPromptRequest) (*pluginv1.PromptResponse, error) {
	if _, err := s.Registry.auth(ctx, s.Name, Request{CorrelationID: in.GetCorrelationId()}); err != nil {
		return nil, err
	}
	sink := s.Sink
	if sink == nil {
		sink = LocalNotificationSink{}
	}
	result, err := sink.SendPrompt(ctx, NotificationPrompt{ID: in.GetId(), CorrelationID: in.GetCorrelationId(), Transport: in.GetTransport(), ExternalActorID: in.GetExternalActorId(), ActorType: in.GetActorType(), ActorID: in.GetActorId(), Action: in.GetAction(), ResourceType: in.GetResourceType(), ResourceID: in.GetResourceId(), RequestHash: in.GetRequestHash(), ExpiresAt: in.GetExpiresAt(), Title: in.GetTitle(), Summary: in.GetSummary()})
	if err != nil {
		return nil, err
	}
	return &pluginv1.PromptResponse{Accepted: result.Accepted, Message: result.Message}, nil
}

type LocalNotificationSink struct{}

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
	if strings.TrimSpace(p.ID) == "" || strings.TrimSpace(p.CorrelationID) == "" || strings.TrimSpace(p.Transport) == "" || strings.TrimSpace(p.ExternalActorID) == "" || strings.TrimSpace(p.ActorType) == "" || strings.TrimSpace(p.ActorID) == "" || strings.TrimSpace(p.Action) == "" || strings.TrimSpace(p.ResourceType) == "" || strings.TrimSpace(p.ResourceID) == "" || strings.TrimSpace(p.RequestHash) == "" || strings.TrimSpace(p.ExpiresAt) == "" {
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
