package notifyruntime

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	pluginv1 "forgejo/gotthboard/gotth-mail/proto/gotth/mail/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type GRPCNotificationBackend struct {
	conn    *grpc.ClientConn
	client  pluginv1.NotificationBackendClient
	token   string
	timeout time.Duration
}

func NewGRPCNotificationBackend(endpoint, token string) (*GRPCNotificationBackend, error) {
	endpoint = strings.TrimSpace(endpoint)
	token = strings.TrimSpace(token)
	if !localGRPCEndpoint(endpoint) {
		return nil, errors.New("notification plugin endpoint must be a local service host:port")
	}
	if len(token) < 16 || len(token) > 4096 || strings.ContainsAny(token, "\r\n") {
		return nil, errors.New("valid notification plugin service token required")
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, errors.New("open notification plugin connection")
	}
	return &GRPCNotificationBackend{conn: conn, client: pluginv1.NewNotificationBackendClient(conn), token: token, timeout: 5 * time.Second}, nil
}

func localGRPCEndpoint(endpoint string) bool {
	if strings.HasPrefix(endpoint, "unix://") {
		path := strings.TrimPrefix(endpoint, "unix://")
		return strings.HasPrefix(path, "/run/gotth-mail-plugins/") && !strings.Contains(path, "..") && len(path) <= 200
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" {
		return false
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

func validServiceName(host string) bool {
	if len(host) > 63 {
		return false
	}
	for i, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9' && i > 0) || (r == '-' && i > 0 && i < len(host)-1) {
			continue
		}
		return false
	}
	return true
}

func (b *GRPCNotificationBackend) Close() error {
	if b == nil || b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *GRPCNotificationBackend) SendAlert(ctx context.Context, alert notification.Alert) (notification.DeliveryResult, error) {
	if b == nil || b.client == nil {
		return notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "notification_backend_unconfigured"}, errors.New("notification backend unconfigured")
	}
	ctx, cancel := b.outgoingContext(ctx, alert.CorrelationID)
	defer cancel()
	details := make(map[string]string, len(alert.Details))
	for key, value := range alert.Details {
		details[key] = value
	}
	response, err := b.client.SendAlert(ctx, &pluginv1.SendAlertRequest{Alert: &pluginv1.AlertMessage{Id: alert.ID, Class: alert.Class, Severity: string(alert.Severity), Title: alert.Title, Summary: alert.Summary, CorrelationId: alert.CorrelationID, Resource: &pluginv1.AlertResource{Type: alert.Resource.Type, Id: alert.Resource.ID}, Details: details}})
	if err != nil {
		return grpcDeliveryFailure(err)
	}
	result := notification.DeliveryResult{Status: notification.DeliveryStatus(response.GetStatus()), Reason: notification.SanitizeDeliveryReason(response.GetReason())}
	if evidence := response.GetEvidence(); evidence != nil {
		result.Evidence = notification.DeliveryEvidence{Transport: evidence.GetTransport(), MessageID: evidence.GetMessageId(), From: evidence.GetFrom(), Sender: evidence.GetSender(), SigningFingerprint: evidence.GetSigningFingerprint(), SenderIdentityID: evidence.GetSenderIdentityId(), SenderIdentityClass: evidence.GetSenderIdentityClass(), PolicyVersion: evidence.GetPolicyVersion(), IdentityStateRef: evidence.GetIdentityStateRef(), VerificationResult: evidence.GetVerificationResult(), Workflow: evidence.GetWorkflow()}
		if generatedAt, err := time.Parse(time.RFC3339Nano, evidence.GetGeneratedAt()); err == nil {
			result.Evidence.GeneratedAt = generatedAt
		}
		result.Evidence = notification.SanitizeDeliveryEvidence(result.Evidence)
	}
	return result, nil
}

func (b *GRPCNotificationBackend) SendPrompt(ctx context.Context, prompt plugin.NotificationPrompt) (plugin.PromptResult, error) {
	if b == nil || b.client == nil {
		return plugin.PromptResult{}, errors.New("notification backend unconfigured")
	}
	ctx, cancel := b.outgoingContext(ctx, prompt.CorrelationID)
	defer cancel()
	response, err := b.client.SendPrompt(ctx, &pluginv1.SendPromptRequest{Id: prompt.ID, CorrelationId: prompt.CorrelationID, Transport: prompt.Transport, ExternalActorId: prompt.ExternalActorID, ActorType: prompt.ActorType, ActorId: prompt.ActorID, Action: prompt.Action, ResourceType: prompt.ResourceType, ResourceId: prompt.ResourceID, RequestHash: prompt.RequestHash, ExpiresAt: prompt.ExpiresAt, Title: prompt.Title, Summary: prompt.Summary, ConfirmationToken: prompt.ConfirmationToken})
	if err != nil {
		return plugin.PromptResult{}, err
	}
	message := notification.SanitizeDeliveryReason(response.GetMessage())
	return plugin.PromptResult{Accepted: response.GetAccepted(), Message: message}, nil
}

func (b *GRPCNotificationBackend) outgoingContext(ctx context.Context, correlationID string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	return metadata.NewOutgoingContext(ctx, metadata.Pairs(plugin.MetadataCorrelationID, correlationID, plugin.MetadataServiceToken, b.token)), cancel
}

func grpcDeliveryFailure(err error) (notification.DeliveryResult, error) {
	code := status.Code(err)
	if code == codes.InvalidArgument || code == codes.PermissionDenied || code == codes.Unimplemented {
		return notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "notification_plugin_rejected"}, errors.New("notification plugin rejected delivery")
	}
	return notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "notification_plugin_unavailable"}, errors.New("notification plugin unavailable")
}
