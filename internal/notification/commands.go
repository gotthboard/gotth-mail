package notification

import (
	"context"
	"errors"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
)

type ReadOnlyCommand string

const (
	CommandDoctorSummary    ReadOnlyCommand = "doctor_summary"
	CommandQueueSummary     ReadOnlyCommand = "queue_summary"
	CommandDomainHealth     ReadOnlyCommand = "domain_health"
	CommandBackupStatus     ReadOnlyCommand = "backup_status"
	CommandDeploymentStatus ReadOnlyCommand = "deployment_status"
	CommandPluginHealth     ReadOnlyCommand = "plugin_health"
	maxCommandSummaryBytes                  = 1024
)

type ActorMapper interface {
	Map(context.Context, TransportActor) (authz.Actor, bool, error)
}

type CommandProvider interface {
	Summary(context.Context, ReadOnlyCommand) (string, error)
}

type CommandService struct {
	Mapper     ActorMapper
	Authorizer authz.Authorizer
	Provider   CommandProvider
	Audit      audit.Writer
	Now        func() time.Time
}

type CommandRequest struct {
	TransportActor TransportActor
	Command        ReadOnlyCommand
	CorrelationID  string
}

type CommandResponse struct {
	Actor         authz.Actor     `json:"actor"`
	Command       ReadOnlyCommand `json:"command"`
	Summary       string          `json:"summary"`
	CorrelationID string          `json:"correlation_id,omitempty"`
}

func (s CommandService) Run(ctx context.Context, req CommandRequest) (CommandResponse, error) {
	if s.Mapper == nil {
		return CommandResponse{}, errors.New("notification actor mapper required")
	}
	if s.Authorizer == nil {
		return CommandResponse{}, errors.New("notification command authorizer required")
	}
	if s.Provider == nil {
		return CommandResponse{}, errors.New("notification command provider required")
	}
	cmd, err := commandSpec(req.Command)
	if err != nil {
		return CommandResponse{}, err
	}
	actor, ok, err := s.Mapper.Map(ctx, req.TransportActor)
	if err != nil {
		return CommandResponse{}, err
	}
	if !ok {
		err := errors.New("notification actor mapping required")
		if auditErr := s.audit(ctx, authz.Actor{Type: "unmapped", ID: req.TransportActor.Transport}, req, cmd, "denied", err); auditErr != nil {
			return CommandResponse{}, errors.New("notification command audit unavailable")
		}
		return CommandResponse{}, err
	}
	decision, err := s.Authorizer.Decide(ctx, actor, cmd.Action, cmd.Resource)
	if err != nil || !decision.Allow {
		if err == nil {
			err = errors.New(decision.Reason)
		}
		if auditErr := s.audit(ctx, actor, req, cmd, "denied", err); auditErr != nil {
			return CommandResponse{}, errors.New("notification command audit unavailable")
		}
		return CommandResponse{}, err
	}
	summary, err := s.Provider.Summary(ctx, req.Command)
	if err != nil {
		if auditErr := s.audit(ctx, actor, req, cmd, "failure", err); auditErr != nil {
			return CommandResponse{}, errors.New("notification command audit unavailable")
		}
		return CommandResponse{}, err
	}
	resp := CommandResponse{Actor: actor, Command: req.Command, Summary: boundCommandSummary(summary), CorrelationID: cleanToken(req.CorrelationID, 128)}
	return resp, s.audit(ctx, actor, req, cmd, "success", nil)
}

type readCommandSpec struct {
	Action   authz.Action
	Resource authz.Resource
}

func commandSpec(c ReadOnlyCommand) (readCommandSpec, error) {
	switch c {
	case CommandDoctorSummary:
		return readCommandSpec{Action: "doctor:read", Resource: authz.Resource{Type: "system", ID: "doctor"}}, nil
	case CommandQueueSummary:
		return readCommandSpec{Action: "queue:read", Resource: authz.Resource{Type: "postfix_queue", ID: "default"}}, nil
	case CommandDomainHealth:
		return readCommandSpec{Action: "domain:read", Resource: authz.Resource{Type: "domain", ID: "*"}}, nil
	case CommandBackupStatus:
		return readCommandSpec{Action: "backup:read", Resource: authz.Resource{Type: "backup", ID: "status"}}, nil
	case CommandDeploymentStatus:
		return readCommandSpec{Action: "deployment:read", Resource: authz.Resource{Type: "deployment", ID: "current"}}, nil
	case CommandPluginHealth:
		return readCommandSpec{Action: "plugin:read", Resource: authz.Resource{Type: "plugin", ID: "health"}}, nil
	default:
		return readCommandSpec{}, errors.New("unsupported notification command")
	}
}

func (s CommandService) audit(ctx context.Context, actor authz.Actor, req CommandRequest, cmd readCommandSpec, result string, err error) error {
	if s.Audit == nil {
		return nil
	}
	e := audit.Event{Time: s.now(), Actor: audit.ActorRef{Type: actor.Type, ID: actor.ID}, Action: "notification.command." + string(req.Command), Resource: audit.ResourceRef{Type: cmd.Resource.Type, ID: cmd.Resource.ID}, CorrelationID: cleanToken(req.CorrelationID, 128), Result: result, AfterRedacted: map[string]any{"transport": req.TransportActor.Transport, "external_actor_id": req.TransportActor.ExternalID, "authorized_action": string(cmd.Action)}}
	if err != nil {
		e.ErrorCode = boundLine(err.Error(), 80)
	}
	return s.Audit.Write(ctx, e)
}

func (s CommandService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func boundCommandSummary(v string) string {
	v = redact(v)
	v = strings.Join(strings.Fields(v), " ")
	return bound(v, maxCommandSummaryBytes)
}
