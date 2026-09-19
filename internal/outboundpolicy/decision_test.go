package outboundpolicy

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestEnforcementServiceResolvesSubmissionAuthority(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	insertDecisionFixtures(t, db)
	service := EnforcementService{DB: db}
	base := EnforcementRequest{Stage: StageSubmission, AuthenticatedMailbox: "user@example.test", EnvelopeSender: "user@example.test"}

	allowed := base
	allowed.Recipient = "local@example.test"
	decision, err := service.Decide(context.Background(), "corr-allowed", allowed)
	if err != nil || decision.Action != ActionOK || decision.Reason != ReasonSameDomain {
		t.Fatalf("allowed decision=%+v err=%v", decision, err)
	}
	for _, recipient := range []string{"outside@example.net", "user@other.test", "user@sub.example.test"} {
		request := base
		request.Recipient = recipient
		decision, err := service.Decide(context.Background(), "corr-reject", request)
		if err != nil || decision.Action != ActionReject || decision.Reason != ReasonRecipientForbidden {
			t.Fatalf("recipient=%q decision=%+v err=%v", recipient, decision, err)
		}
	}

	conflict := base
	conflict.Recipient = "local@example.test"
	conflict.ExpansionSources = []QueueSource{{Kind: SourceAlias, ObjectID: "00000000-0000-4000-8000-000000000924"}}
	decision, err = service.Decide(context.Background(), "corr-conflict", conflict)
	if err != nil || decision.Action != ActionReject || decision.Reason != ReasonCrossDomainConflict {
		t.Fatalf("conflict decision=%+v err=%v", decision, err)
	}
}

func TestEnforcementServiceTransportRechecksCurrentPolicyAndRequiresHold(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	insertDecisionFixtures(t, db)
	if _, err := db.Exec(`UPDATE domains SET outbound_scope='unrestricted',outbound_policy_revision=1 WHERE name='example.test'`); err != nil {
		t.Fatal(err)
	}
	queue := QueueStore{DB: db}
	registration := QueueRegistration{
		QueueID:            "3Pt2mN2VXxznjll",
		ArrivalFingerprint: strings.Repeat("a", 64),
		EnvelopeSender:     "user@example.test",
		Recipients:         []string{"outside@example.net"},
		Sources: []QueueSource{
			{Kind: SourceAuthenticatedMailbox, ObjectID: "00000000-0000-4000-8000-000000000922"},
			{Kind: SourceEnvelopeSender, ObjectID: "00000000-0000-4000-8000-000000000922"},
		},
	}
	if _, _, err := queue.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE domains SET outbound_scope='same_domain_only',outbound_policy_revision=2 WHERE name='example.test'`); err != nil {
		t.Fatal(err)
	}
	service := EnforcementService{DB: db, Queue: queue, HoldActor: audit.ActorRef{Type: "service", ID: "outbound-policy"}}
	decision, err := service.Decide(context.Background(), "corr-transport", EnforcementRequest{Stage: StageTransport, QueueID: registration.QueueID, Recipient: "outside@example.net"})
	if err != nil || decision.Action != ActionDefer || decision.Reason != ReasonPolicyHold || decision.Revisions["example.test"] != 2 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	record, err := queue.Load(context.Background(), registration.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if record.HoldState != HoldRequired || record.PolicyRevisions["example.test"] != 2 {
		t.Fatalf("record=%+v", record)
	}
}

func TestEnforcementServiceSystemSenderBindingIsAuthoritative(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	insertDecisionFixtures(t, db)
	binder := SystemSenderStore{DB: db}
	actor := audit.ActorRef{Type: "local_admin", ID: "operator"}
	if _, err := binder.Bind(context.Background(), actor, "corr-bind", "system:alerts@example.test", "alerts@example.test"); err != nil {
		t.Fatal(err)
	}
	service := EnforcementService{DB: db}
	decision, err := service.Decide(context.Background(), "corr-system", EnforcementRequest{
		Stage: StageSubmission, SystemSenderID: "system:alerts@example.test", EnvelopeSender: "alerts@example.test", Recipient: "outside@example.net",
	})
	if err != nil || decision.Action != ActionReject || decision.Reason != ReasonRecipientForbidden {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if _, err := binder.Bind(context.Background(), actor, "corr-rebind", "system:alerts@example.test", "different@example.test"); err == nil {
		t.Fatal("stable system sender ID rebound")
	}
}

func TestEnforcementServiceFailsClosedOnMissingAuthority(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	insertDecisionFixtures(t, db)
	service := EnforcementService{DB: db}
	decision, err := service.Decide(context.Background(), "corr-missing", EnforcementRequest{Stage: StageSubmission, AuthenticatedMailbox: "missing@example.test", EnvelopeSender: "missing@example.test", Recipient: "outside@example.net"})
	if err == nil || decision.Action != ActionDefer || decision.Reason != ReasonUnavailable {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestEnforcementServiceAuditsRejectionWithoutFullAddress(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	insertDecisionFixtures(t, db)
	decision, err := (EnforcementService{DB: db}).Decide(context.Background(), "corr-audit-reject", EnforcementRequest{
		Stage: StageSubmission, AuthenticatedMailbox: "user@example.test", EnvelopeSender: "user@example.test", Recipient: "private-recipient@outside.example",
	})
	if err != nil || decision.Action != ActionReject {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	var action, after string
	if err := db.QueryRow(`SELECT action,after_redacted_json FROM audit_events WHERE correlation_id='corr-audit-reject'`).Scan(&action, &after); err != nil {
		t.Fatal(err)
	}
	if action != "outbound.policy.reject" || strings.Contains(after, "private-recipient") || !strings.Contains(after, "outside.example") {
		t.Fatalf("action=%q after=%s", action, after)
	}
}

func TestEnforcementServiceTreatsAliasForwardListAndCatchAllAsGoverningSources(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	insertDecisionFixtures(t, db)
	service := EnforcementService{DB: db}
	for _, kind := range []SourceKind{SourceAlias, SourceForward, SourceList, SourceCatchAll} {
		decision, err := service.Decide(context.Background(), "corr-source-"+string(kind), EnforcementRequest{
			Stage: StageSubmission, AuthenticatedMailbox: "user@example.test", EnvelopeSender: "user@example.test", Recipient: "local@example.test",
			ExpansionSources: []QueueSource{{Kind: kind, ObjectID: "00000000-0000-4000-8000-000000000924"}},
		})
		if err != nil || decision.Action != ActionReject || decision.Reason != ReasonCrossDomainConflict {
			t.Fatalf("kind=%s decision=%#v err=%v", kind, decision, err)
		}
	}
}

func insertDecisionFixtures(t *testing.T, db interface {
	Exec(string, ...any) (sql.Result, error)
}) {
	t.Helper()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000921','example.test',true,'same_domain_only',2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, nil},
		{`INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000922','00000000-0000-4000-8000-000000000921','user',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, nil},
		{`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000923','other.test',true,'same_domain_only',4,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, nil},
		{`INSERT INTO aliases(id,domain_id,local_part,targets_json,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000924','00000000-0000-4000-8000-000000000923','list','["local@example.test"]',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, nil},
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
