package outboundpolicy

import (
	"context"
	"errors"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestAutomaticMailKindsBlockWithoutBounceAndRetryUncertainty(t *testing.T) {
	for _, kind := range []AutomaticKind{AutomaticNotification, AutomaticAutoresponder, AutomaticDSN, AutomaticBounce} {
		blocked, err := ClassifyAutomaticDecision(kind, Decision{Action: ActionReject, Reason: ReasonRecipientForbidden}, nil)
		if err != nil || blocked.Disposition != AutomaticPolicyBlocked || blocked.GenerateBounce {
			t.Fatalf("kind=%s blocked=%#v err=%v", kind, blocked, err)
		}
		retry, err := ClassifyAutomaticDecision(kind, Decision{Action: ActionDefer, Reason: ReasonUnavailable}, errors.New("policy unavailable"))
		if err != nil || retry.Disposition != AutomaticRetry || retry.GenerateBounce {
			t.Fatalf("kind=%s retry=%#v err=%v", kind, retry, err)
		}
	}
}

func TestAutomaticMailKindIsClosed(t *testing.T) {
	if _, err := ClassifyAutomaticDecision("vacation-ish", Decision{Action: ActionOK}, nil); err == nil {
		t.Fatal("accepted unknown automatic mail kind")
	}
}

func TestAutomaticMailKindsUseDurableSystemSenderAuthority(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000a11','example.test',true,'same_domain_only',2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	binder := SystemSenderStore{DB: db}
	actor := audit.ActorRef{Type: "service", ID: "automatic-test"}
	for i, kind := range []AutomaticKind{AutomaticNotification, AutomaticAutoresponder, AutomaticDSN, AutomaticBounce} {
		address := string(kind) + "@example.test"
		id := "system:" + address
		if _, err := binder.Bind(context.Background(), actor, "bind-automatic-"+string(rune('0'+i)), id, address); err != nil {
			t.Fatal(err)
		}
		decision, decisionErr := (EnforcementService{DB: db}).Decide(context.Background(), "automatic-"+string(kind), EnforcementRequest{
			Stage: StageSubmission, SystemSenderID: id, EnvelopeSender: address, Recipient: "outside@example.net",
		})
		outcome, err := ClassifyAutomaticDecision(kind, decision, decisionErr)
		if err != nil || outcome.Disposition != AutomaticPolicyBlocked || outcome.GenerateBounce {
			t.Fatalf("kind=%s decision=%#v outcome=%#v decisionErr=%v err=%v", kind, decision, outcome, decisionErr, err)
		}
	}
}
