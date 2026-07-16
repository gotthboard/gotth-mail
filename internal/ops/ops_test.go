package ops

import (
	"context"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/diag"
	"forgejo/linus/gophermailforge/internal/plugin"
)

func daemonFixture() daemon.Service {
	verifier := daemon.MakeDjangoPBKDF2SHA256("secret", "salt", 1200)
	return daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true, DKIMSelector: "mail", DKIMPrivateKeyPath: "/run/dkim/example.test.key"}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true, Home: "/mail/example.test/postmaster", UID: 5000, GID: 5000, QuotaBytes: 1024, Verifier: verifier}}, Aliases: map[string]daemon.Alias{"alias@example.test": {Address: "alias@example.test", Enabled: true, Targets: []string{"postmaster@example.test"}}}}
}

func TestDoctorAggregatesFailuresAndWarnings(t *testing.T) {
	report := Doctor(context.Background(), DoctorInput{ConfigOK: true, DatabaseOK: true, AuthentikOK: true, WebmailOK: true, Daemon: daemonFixture(), DNSChecks: []diag.DNSRecordCheck{{Family: "SPF", Name: "example.test", Status: diag.Mismatch, Remediation: "fix SPF"}}, CertCheck: diag.CertCheck{Status: diag.CertWarn, Reason: "certificate_expiring_soon"}, PluginRegistry: plugin.FirstMechanismPlugins("tok"), PluginToken: "tok", CorrelationID: "c"})
	if report.Status != Fail {
		t.Fatalf("doctor status=%s checks=%#v", report.Status, report.Checks)
	}
	if len(report.Checks) == 0 {
		t.Fatal("no checks")
	}
}

func TestDebugLookupAndTraceAreMachineReadable(t *testing.T) {
	s := daemonFixture()
	lookup := DebugLookup(s, "recipient", "postmaster@example.test", "c")
	if len(lookup.Steps) != 1 || lookup.Steps[0].Decision != daemon.OK {
		t.Fatalf("lookup=%#v", lookup)
	}
	trace := TraceMailFlow(s, "postmaster@example.test", "c")
	if len(trace.Phases) != 5 {
		t.Fatalf("trace=%#v", trace)
	}
	if trace.Phases[0].Decision != daemon.OK {
		t.Fatalf("recipient phase=%#v", trace.Phases[0])
	}
}

func TestQueueMutationsRequireConfirmationAndAudit(t *testing.T) {
	q := &Queue{Summary: QueueSummary{Active: 2, Deferred: []string{"a", "b"}}}
	w := &audit.MemoryWriter{}
	if err := q.Flush(context.Background(), w, audit.ActorRef{Type: "local_admin", ID: "test"}, "wrong"); err == nil {
		t.Fatal("flush accepted wrong confirmation")
	}
	if err := q.Flush(context.Background(), w, audit.ActorRef{Type: "local_admin", ID: "test"}, "flush"); err != nil {
		t.Fatal(err)
	}
	if q.Summary.Active != 0 || len(w.Events) != 1 || w.Events[0].Action != "queue.flush" {
		t.Fatalf("flush q=%#v events=%#v", q, w.Events)
	}
	if err := q.Retry(context.Background(), w, audit.ActorRef{Type: "local_admin", ID: "test"}, "retry"); err != nil {
		t.Fatal(err)
	}
	if len(q.Summary.Deferred) != 0 || len(w.Events) != 2 || w.Events[1].Action != "queue.retry" {
		t.Fatalf("retry q=%#v events=%#v", q, w.Events)
	}
}

func TestSnapshotIsNotRollback(t *testing.T) {
	now := time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	s := CaptureSnapshot("set1", "schema_migrations", "policy", []string{"gophermailforge:v1"}, []string{"external-webmail:v0"}, now)
	if s.IsRollback || s.Timestamp != now || s.GeneratedConfigSetID != "set1" {
		t.Fatalf("snapshot=%#v", s)
	}
}
