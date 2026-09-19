package notifyruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
)

type ApprovalCreator interface {
	Create(context.Context, notification.ApprovalRequest, time.Time) (notification.ApprovalRequest, error)
	Activate(context.Context, string, time.Time) error
	Invalidate(context.Context, string, time.Time, string) error
}

type PromptSender interface {
	SendPrompt(context.Context, plugin.NotificationPrompt) (plugin.PromptResult, error)
}

type TelegramApprovalRequest struct {
	TransportActor notification.TransportActor
	Action         authz.Action
	Resource       authz.Resource
	CorrelationID  string
	ExpiresAt      time.Time
	Title          string
	Summary        string
}

type ApprovalService struct {
	Mapper     notification.ActorMapper
	Authorizer authz.Authorizer
	Store      ApprovalCreator
	Prompter   PromptSender
	Queue      QueueController
	Now        func() time.Time
}

func (s ApprovalService) RequestTelegramApproval(ctx context.Context, input TelegramApprovalRequest) (notification.ApprovalRequest, error) {
	if s.Mapper == nil || s.Authorizer == nil || s.Store == nil || s.Prompter == nil || s.Queue == nil {
		return notification.ApprovalRequest{}, errors.New("approval request dependencies required")
	}
	if input.Action != "queue:flush" && input.Action != "queue:retry" {
		return notification.ApprovalRequest{}, errors.New("unsupported approval action")
	}
	if input.Resource.Type != "queue" && input.Resource.Type != "postfix_queue" {
		return notification.ApprovalRequest{}, errors.New("queue approval resource required")
	}
	actor, mapped, err := s.Mapper.Map(ctx, input.TransportActor)
	if err != nil {
		return notification.ApprovalRequest{}, err
	}
	if !mapped {
		return notification.ApprovalRequest{}, errors.New("notification actor mapping required")
	}
	decision, err := s.Authorizer.Decide(ctx, actor, input.Action, input.Resource)
	if err != nil {
		return notification.ApprovalRequest{}, err
	}
	if !decision.Allow {
		return notification.ApprovalRequest{}, errors.New("approval action unauthorized")
	}
	now := s.now()
	requestHash, err := queueApprovalRequestHash(ctx, input.Action, input.Resource, s.Queue)
	if err != nil {
		return notification.ApprovalRequest{}, err
	}
	created, err := s.Store.Create(ctx, notification.ApprovalRequest{TransportActor: input.TransportActor, Actor: actor, Action: input.Action, Resource: input.Resource, RequestHash: requestHash, CorrelationID: input.CorrelationID, ExpiresAt: input.ExpiresAt}, now)
	if err != nil {
		return notification.ApprovalRequest{}, err
	}
	result, err := s.Prompter.SendPrompt(ctx, plugin.NotificationPrompt{ID: created.ID, CorrelationID: created.CorrelationID, Transport: created.TransportActor.Transport, ExternalActorID: created.TransportActor.ExternalID, ActorType: created.Actor.Type, ActorID: created.Actor.ID, Action: string(created.Action), ResourceType: created.Resource.Type, ResourceID: created.Resource.ID, RequestHash: created.RequestHash, ExpiresAt: created.ExpiresAt.UTC().Format(time.RFC3339), Title: input.Title, Summary: input.Summary, ConfirmationToken: created.BindingToken})
	if err != nil || !result.Accepted {
		if invalidateErr := s.Store.Invalidate(ctx, created.ID, s.now(), "prompt_delivery_failed"); invalidateErr != nil {
			return notification.ApprovalRequest{}, errors.New("notification prompt invalidation failed")
		}
		if err != nil {
			return notification.ApprovalRequest{}, err
		}
		return notification.ApprovalRequest{}, errors.New("notification prompt rejected")
	}
	if err := s.Store.Activate(ctx, created.ID, s.now()); err != nil {
		return notification.ApprovalRequest{}, errors.New("notification approval activation failed")
	}
	created.Result = "pending"
	created.BindingToken = ""
	return created, nil
}

type QueueController interface {
	Snapshot(context.Context, string) (outboundpolicy.QueueSnapshot, error)
	Flush(context.Context) error
	Retry(context.Context, string) error
}

func queueApprovalRequestHash(ctx context.Context, action authz.Action, resource authz.Resource, queue QueueController) (string, error) {
	if queue == nil {
		return "", errors.New("queue runtime required")
	}
	selector := ""
	if action == "queue:retry" {
		selector = resource.ID
	}
	snapshot, err := queue.Snapshot(ctx, selector)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(struct {
		Action   authz.Action                 `json:"action"`
		Resource authz.Resource               `json:"resource"`
		Snapshot outboundpolicy.QueueSnapshot `json:"snapshot"`
	}{Action: action, Resource: resource, Snapshot: snapshot})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (s ApprovalService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
