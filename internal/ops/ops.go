package ops

import (
	"context"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
)

type Status string

const (
	OK      Status = "ok"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Unknown Status = "unknown"
)

type Check struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   Status `json:"status"`
	Reason   string `json:"reason"`
}

type DoctorReport struct {
	Status Status  `json:"status"`
	Checks []Check `json:"checks"`
}

type DoctorInput struct {
	ConfigOK       bool
	DatabaseOK     bool
	AuthentikOK    bool
	WebmailOK      bool
	Daemon         daemon.Service
	DNSChecks      []diag.DNSRecordCheck
	CertCheck      diag.CertCheck
	PluginRegistry plugin.Registry
	PluginToken    string
	CorrelationID  string
}

func Doctor(ctx context.Context, in DoctorInput) DoctorReport {
	checks := []Check{}
	checks = append(checks, boolCheck("config", "typed-config", in.ConfigOK))
	checks = append(checks, boolCheck("database", "postgres", in.DatabaseOK))
	checks = append(checks, boolCheck("identity", "authentik", in.AuthentikOK))
	checks = append(checks, boolCheck("webmail", "provider", in.WebmailOK))
	for _, d := range in.DNSChecks {
		checks = append(checks, Check{Category: "DNS", Name: d.Family + " " + d.Name, Status: dnsStatus(d.Status), Reason: d.Remediation})
	}
	checks = append(checks, Check{Category: "TLS", Name: "certificate", Status: certStatus(in.CertCheck.Status), Reason: in.CertCheck.Reason})
	if got := in.Daemon.PostfixRecipient(in.CorrelationID, "postmaster@example.test"); got.Decision == daemon.Defer || got.Decision == daemon.Error {
		checks = append(checks, Check{Category: "daemon", Name: "postfix-recipient", Status: Fail, Reason: got.Reason})
	} else {
		checks = append(checks, Check{Category: "daemon", Name: "postfix-recipient", Status: OK, Reason: "lookup_path_responded"})
	}
	for name := range in.PluginRegistry.Plugins {
		_, err := in.PluginRegistry.Health(ctx, name, plugin.Request{CorrelationID: in.CorrelationID, ServiceToken: in.PluginToken, Deadline: time.Now().Add(time.Second)})
		if err != nil {
			checks = append(checks, Check{Category: "plugin", Name: name, Status: Fail, Reason: err.Error()})
		} else {
			checks = append(checks, Check{Category: "plugin", Name: name, Status: OK, Reason: "health_ok"})
		}
	}
	return DoctorReport{Status: worst(checks), Checks: checks}
}

func boolCheck(cat, name string, ok bool) Check {
	if ok {
		return Check{Category: cat, Name: name, Status: OK, Reason: "ok"}
	}
	return Check{Category: cat, Name: name, Status: Fail, Reason: "failed"}
}
func dnsStatus(s diag.RecordStatus) Status {
	switch s {
	case diag.Present:
		return OK
	case diag.Unsupported, diag.NotChecked:
		return Warn
	default:
		return Fail
	}
}
func certStatus(s diag.CertStatus) Status {
	switch s {
	case diag.CertOK:
		return OK
	case diag.CertWarn, diag.CertUnknown:
		return Warn
	default:
		return Fail
	}
}
func worst(checks []Check) Status {
	out := OK
	for _, c := range checks {
		if c.Status == Fail {
			return Fail
		}
		if c.Status == Warn {
			out = Warn
		}
	}
	return out
}

type LookupStep struct {
	Source   string          `json:"source"`
	Decision daemon.Decision `json:"decision"`
	Reason   string          `json:"reason"`
}

type LookupResult struct {
	Kind  string       `json:"kind"`
	Value string       `json:"value"`
	Steps []LookupStep `json:"steps"`
}

func DebugLookup(s daemon.Service, kind, value, correlationID string) LookupResult {
	out := LookupResult{Kind: kind, Value: value}
	add := func(source string, r daemon.Response) {
		out.Steps = append(out.Steps, LookupStep{Source: source, Decision: r.Decision, Reason: r.Reason})
	}
	switch kind {
	case "recipient":
		add("postfix.recipient", s.PostfixRecipient(correlationID, value))
	case "sender":
		add("postfix.sender_policy", s.PostfixSenderPolicy(correlationID, daemon.SenderLoginRequest{MailFrom: value}))
	case "dovecot":
		add("dovecot.userdb", s.DovecotUserdb(correlationID, value))
	case "rspamd-domain":
		add("rspamd.dkim", s.RspamdDKIM(correlationID, value))
	default:
		add("debug", daemon.Response{Decision: daemon.Error, Reason: "unsupported_lookup_kind"})
	}
	return out
}

type TracePhase struct {
	Name     string          `json:"name"`
	Decision daemon.Decision `json:"decision"`
	Reason   string          `json:"reason"`
}

type MailTrace struct {
	Recipient string       `json:"recipient"`
	Phases    []TracePhase `json:"phases"`
}

func TraceMailFlow(s daemon.Service, recipient, correlationID string) MailTrace {
	mk := func(name string, r daemon.Response) TracePhase {
		return TracePhase{Name: name, Decision: r.Decision, Reason: r.Reason}
	}
	return MailTrace{Recipient: recipient, Phases: []TracePhase{
		mk("recipient lookup", s.PostfixRecipient(correlationID, recipient)),
		mk("alias expansion", s.PostfixAlias(correlationID, recipient)),
		mk("transport decision", s.PostfixTransport(correlationID, domainOf(recipient))),
		mk("spam/DKIM path", s.RspamdSigningDecision(correlationID, domainOf(recipient))),
		mk("delivery mailbox", s.DovecotUserdb(correlationID, recipient)),
	}}
}

func domainOf(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == '@' {
			return addr[i+1:]
		}
	}
	return addr
}

type QueueSummary struct {
	Active   int      `json:"active"`
	Deferred []string `json:"deferred"`
}

type Queue struct{ Summary QueueSummary }

func (q *Queue) Flush(ctx context.Context, w audit.Writer, actor audit.ActorRef, confirm string) error {
	if confirm != "flush" {
		return ErrConfirmationRequired
	}
	q.Summary.Active = 0
	if w != nil {
		return w.Write(ctx, audit.Event{Actor: actor, Action: "queue.flush", Resource: audit.ResourceRef{Type: "postfix_queue", ID: "default"}, Result: "success"})
	}
	return nil
}

func (q *Queue) Retry(ctx context.Context, w audit.Writer, actor audit.ActorRef, confirm string) error {
	if confirm != "retry" {
		return ErrConfirmationRequired
	}
	q.Summary.Deferred = nil
	if w != nil {
		return w.Write(ctx, audit.Event{Actor: actor, Action: "queue.retry", Resource: audit.ResourceRef{Type: "postfix_queue", ID: "default"}, Result: "success"})
	}
	return nil
}

var ErrConfirmationRequired = errString("explicit queue confirmation required")

type errString string

func (e errString) Error() string { return string(e) }

type SmokeResult struct {
	OK                 bool     `json:"ok"`
	Phases             []string `json:"phases"`
	WebmailVisible     bool     `json:"webmail_visible"`
	CreatedArtifacts   []string `json:"created_artifacts,omitempty"`
	CleanupPerformed   bool     `json:"cleanup_performed"`
	FailureExplanation string   `json:"failure_explanation,omitempty"`
}

type Snapshot struct {
	GeneratedConfigSetID string    `json:"generated_config_set_id"`
	ImageVersions        []string  `json:"image_versions"`
	MigrationVersion     string    `json:"migration_version"`
	PluginVersions       []string  `json:"plugin_versions"`
	DeploymentPolicyHash string    `json:"deployment_policy_hash"`
	Timestamp            time.Time `json:"timestamp"`
	IsRollback           bool      `json:"is_rollback"`
}

func CaptureSnapshot(configSetID, migration, policyHash string, images, plugins []string, now time.Time) Snapshot {
	return Snapshot{GeneratedConfigSetID: configSetID, ImageVersions: append([]string(nil), images...), MigrationVersion: migration, PluginVersions: append([]string(nil), plugins...), DeploymentPolicyHash: policyHash, Timestamp: now, IsRollback: false}
}
