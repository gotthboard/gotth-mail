package notifyruntime

import (
	"context"
	"errors"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/notification"
)

type ApprovalStore interface {
	Get(context.Context, string) (notification.ApprovalRequest, bool, error)
	Claim(context.Context, notification.ApprovalConfirmation, time.Duration) (notification.ApprovalRequest, error)
	Complete(context.Context, string, time.Time) error
	Retry(context.Context, string, time.Time, string) error
}

type ApprovalExecutor struct {
	Mapper     notification.ActorMapper
	Approvals  ApprovalStore
	Authorizer authz.Authorizer
	Queue      QueueController
	Audit      audit.Writer
	Now        func() time.Time
}

type ExecutionResult struct {
	ApprovalID string `json:"approval_id"`
	Action     string `json:"action"`
	Resource   string `json:"resource"`
	Executed   bool   `json:"executed"`
}

func (e ApprovalExecutor) ExecuteTelegramApproval(ctx context.Context, approvalID, bindingToken string, actor notification.TransportActor) (ExecutionResult, error) {
	if e.Mapper == nil || e.Approvals == nil || e.Authorizer == nil {
		return ExecutionResult{}, errors.New("approval execution dependencies required")
	}
	mapped, ok, err := e.Mapper.Map(ctx, actor)
	if err != nil {
		return ExecutionResult{}, err
	}
	if !ok {
		return ExecutionResult{}, errors.New("notification actor mapping required")
	}
	req, found, err := e.Approvals.Get(ctx, approvalID)
	if err != nil {
		return ExecutionResult{}, err
	}
	if !found {
		return ExecutionResult{}, errors.New("approval request not found")
	}
	if req.UsedAt != nil || (req.Result != "pending" && req.Result != "executing") {
		return ExecutionResult{}, errors.New("approval replay rejected")
	}
	decision, err := e.Authorizer.Decide(ctx, mapped, req.Action, req.Resource)
	if err != nil {
		_ = e.writeAudit(ctx, req, "failure", "authorization_failed")
		return ExecutionResult{}, err
	}
	if !decision.Allow {
		_ = e.writeAudit(ctx, req, "denied", "authorization_denied")
		return ExecutionResult{}, errors.New("approval action unauthorized")
	}
	if err := e.preflight(ctx, req); err != nil {
		_ = e.writeAudit(ctx, req, "denied", err.Error())
		return ExecutionResult{}, err
	}
	confirmed, err := e.Approvals.Claim(ctx, notification.ApprovalConfirmation{ID: approvalID, TransportActor: actor, Actor: mapped, Action: req.Action, Resource: req.Resource, RequestHash: req.RequestHash, BindingToken: bindingToken, Now: e.now()}, 2*time.Minute)
	if err != nil {
		return ExecutionResult{}, err
	}
	result := ExecutionResult{ApprovalID: confirmed.ID, Action: string(confirmed.Action), Resource: confirmed.Resource.Type + ":" + confirmed.Resource.ID}
	if err := e.execute(ctx, confirmed); err != nil {
		_ = e.Approvals.Retry(ctx, confirmed.ID, e.now(), "queue_mutation_failed")
		_ = e.writeAudit(ctx, confirmed, "failure", err.Error())
		return result, err
	}
	result.Executed = true
	if err := e.Approvals.Complete(ctx, confirmed.ID, e.now()); err != nil {
		return result, err
	}
	_ = e.writeAudit(ctx, confirmed, "success", "")
	return result, nil
}

func (e ApprovalExecutor) preflight(ctx context.Context, r notification.ApprovalRequest) error {
	if r.Action != "queue:flush" && r.Action != "queue:retry" {
		return errors.New("unsupported approved mutation")
	}
	if r.Resource.Type != "queue" && r.Resource.Type != "postfix_queue" {
		return errors.New("queue approval resource required")
	}
	if e.Queue == nil {
		return errors.New("queue runtime required")
	}
	requestHash, err := queueApprovalRequestHash(ctx, r.Action, r.Resource, e.Queue)
	if err != nil {
		return err
	}
	if requestHash != r.RequestHash {
		return errors.New("approval request changed")
	}
	return nil
}

func (e ApprovalExecutor) execute(ctx context.Context, r notification.ApprovalRequest) error {
	if err := e.preflight(ctx, r); err != nil {
		return err
	}
	switch r.Action {
	case "queue:flush":
		return e.Queue.Flush(ctx)
	case "queue:retry":
		return e.Queue.Retry(ctx, r.Resource.ID)
	default:
		return errors.New("unsupported approved mutation")
	}
}

func (e ApprovalExecutor) writeAudit(ctx context.Context, r notification.ApprovalRequest, result, code string) error {
	if e.Audit == nil {
		return nil
	}
	return e.Audit.Write(ctx, audit.Event{Actor: audit.ActorRef{Type: r.Actor.Type, ID: r.Actor.ID}, Action: "notification.approval.execute", Resource: audit.ResourceRef{Type: r.Resource.Type, ID: r.Resource.ID}, CorrelationID: r.CorrelationID, Result: result, ErrorCode: code, AfterRedacted: map[string]any{"approval_id": r.ID, "approved_action": string(r.Action)}})
}

func (e ApprovalExecutor) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}
