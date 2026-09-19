package notifyruntime

import (
	"context"
	"errors"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/ops"
)

type ApprovalStore interface {
	Get(context.Context, string) (notification.ApprovalRequest, bool, error)
	Confirm(context.Context, notification.ApprovalConfirmation) (notification.ApprovalRequest, error)
}

type ApprovalExecutor struct {
	Mapper     notification.ActorMapper
	Approvals  ApprovalStore
	Authorizer authz.Authorizer
	Queue      *ops.Queue
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
	if req.UsedAt != nil || req.Result != "pending" {
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
	if err := e.preflight(req); err != nil {
		_ = e.writeAudit(ctx, req, "denied", err.Error())
		return ExecutionResult{}, err
	}
	confirmed, err := e.Approvals.Confirm(ctx, notification.ApprovalConfirmation{ID: approvalID, TransportActor: actor, Actor: mapped, Action: req.Action, Resource: req.Resource, RequestHash: req.RequestHash, BindingToken: bindingToken, Now: e.now()})
	if err != nil {
		return ExecutionResult{}, err
	}
	result := ExecutionResult{ApprovalID: confirmed.ID, Action: string(confirmed.Action), Resource: confirmed.Resource.Type + ":" + confirmed.Resource.ID}
	if err := e.execute(ctx, confirmed); err != nil {
		_ = e.writeAudit(ctx, confirmed, "failure", err.Error())
		return result, err
	}
	result.Executed = true
	return result, e.writeAudit(ctx, confirmed, "success", "")
}

func (e ApprovalExecutor) preflight(r notification.ApprovalRequest) error {
	if r.Action != "queue:flush" && r.Action != "queue:retry" {
		return errors.New("unsupported approved mutation")
	}
	if r.Resource.Type != "queue" && r.Resource.Type != "postfix_queue" {
		return errors.New("queue approval resource required")
	}
	if e.Queue == nil {
		return errors.New("queue runtime required")
	}
	requestHash, err := queueApprovalRequestHash(r.Action, r.Resource, e.Queue)
	if err != nil {
		return err
	}
	if requestHash != r.RequestHash {
		return errors.New("approval request changed")
	}
	return nil
}

func (e ApprovalExecutor) execute(ctx context.Context, r notification.ApprovalRequest) error {
	if err := e.preflight(r); err != nil {
		return err
	}
	switch r.Action {
	case "queue:flush":
		if e.Queue == nil {
			return errors.New("queue runtime required")
		}
		if r.Resource.Type != "queue" && r.Resource.Type != "postfix_queue" {
			return errors.New("queue approval resource required")
		}
		return e.Queue.Flush(ctx, e.Audit, audit.ActorRef{Type: r.Actor.Type, ID: r.Actor.ID}, "flush")
	case "queue:retry":
		if e.Queue == nil {
			return errors.New("queue runtime required")
		}
		if r.Resource.Type != "queue" && r.Resource.Type != "postfix_queue" {
			return errors.New("queue approval resource required")
		}
		return e.Queue.Retry(ctx, e.Audit, audit.ActorRef{Type: r.Actor.Type, ID: r.Actor.ID}, "retry")
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
