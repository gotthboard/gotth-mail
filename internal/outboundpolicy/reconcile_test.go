package outboundpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type fakeQueueBoundary struct {
	metadata QueueMetadata
	holds    int
	holdErr  error
}

func (f *fakeQueueBoundary) Inspect(context.Context, string) (QueueMetadata, error) {
	return f.metadata, nil
}

func (f *fakeQueueBoundary) Hold(context.Context, string) error {
	f.holds++
	if f.holdErr != nil {
		return f.holdErr
	}
	f.metadata.Held = true
	return nil
}

func TestQueueHoldReconciliationIsVerifiedAuditedAndIdempotent(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	queue := QueueStore{DB: db}
	registration := testQueueRegistration()
	if _, _, err := queue.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "service", ID: "outbound-policy"}
	decision := Decision{Action: ActionDefer, Reason: ReasonPolicyHold, Revisions: map[string]uint64{"example.test": 2}}
	if err := queue.RequireHold(context.Background(), actor, "corr-hold", registration.QueueID, decision); err != nil {
		t.Fatal(err)
	}
	boundary := &fakeQueueBoundary{metadata: queueMetadata(registration)}
	reconciler := QueueReconciler{Store: queue, Inspector: boundary, Holder: boundary}
	result, err := reconciler.Reconcile(context.Background(), actor, "corr-reconcile", registration.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Record.HoldState != HoldApplied || result.Record.ReconciliationAttempts != 1 || result.Record.PolicyRevisions["example.test"] != 2 || boundary.holds != 1 {
		t.Fatalf("result=%+v holds=%d", result, boundary.holds)
	}
	result, err = reconciler.Reconcile(context.Background(), actor, "corr-repeat", registration.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed || boundary.holds != 1 {
		t.Fatalf("repeat result=%+v holds=%d", result, boundary.holds)
	}
	var audits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action LIKE 'queue.policy_hold.%'`, registration.QueueID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 3 {
		t.Fatalf("audit count=%d, want require/start/applied", audits)
	}
}

func TestQueueHoldReconciliationFailsClosedOnMetadataMismatch(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	queue := QueueStore{DB: db}
	registration := testQueueRegistration()
	if _, _, err := queue.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "service", ID: "outbound-policy"}
	decision := Decision{Action: ActionDefer, Reason: ReasonPolicyHold, Revisions: map[string]uint64{"example.test": 2}}
	if err := queue.RequireHold(context.Background(), actor, "corr-hold", registration.QueueID, decision); err != nil {
		t.Fatal(err)
	}
	metadata := queueMetadata(registration)
	metadata.ArrivalFingerprint = strings.Repeat("f", 64)
	boundary := &fakeQueueBoundary{metadata: metadata}
	_, err := (QueueReconciler{Store: queue, Inspector: boundary, Holder: boundary}).Reconcile(context.Background(), actor, "corr-reconcile", registration.QueueID)
	if err == nil {
		t.Fatal("mismatched queue metadata accepted")
	}
	record, loadErr := queue.Load(context.Background(), registration.QueueID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if record.HoldState != HoldReconciliationError || record.LastErrorCode != "queue_metadata_mismatch" || boundary.holds != 0 {
		t.Fatalf("record=%+v holds=%d", record, boundary.holds)
	}
}

func TestQueueHoldDoesNotRunHelperWhenStartAuditFails(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	queue := QueueStore{DB: db}
	registration := testQueueRegistration()
	if _, _, err := queue.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "service", ID: "outbound-policy"}
	decision := Decision{Action: ActionDefer, Reason: ReasonPolicyHold, Revisions: map[string]uint64{"example.test": 2}}
	if err := queue.RequireHold(context.Background(), actor, "corr-hold", registration.QueueID, decision); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE FUNCTION reject_queue_hold_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='queue.policy_hold.reconcile_start' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_queue_hold_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_queue_hold_audit()`); err != nil {
		t.Fatal(err)
	}
	boundary := &fakeQueueBoundary{metadata: queueMetadata(registration)}
	_, err := (QueueReconciler{Store: queue, Inspector: boundary, Holder: boundary}).Reconcile(context.Background(), actor, "corr-reconcile", registration.QueueID)
	if err == nil {
		t.Fatal("audit failure accepted")
	}
	record, loadErr := queue.Load(context.Background(), registration.QueueID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if record.HoldState != HoldRequired || record.ReconciliationAttempts != 0 || boundary.holds != 0 {
		t.Fatalf("record=%+v holds=%d", record, boundary.holds)
	}
}

func TestQueueHoldRecordsHelperFailureForRetry(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	queue := QueueStore{DB: db}
	registration := testQueueRegistration()
	if _, _, err := queue.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "service", ID: "outbound-policy"}
	decision := Decision{Action: ActionDefer, Reason: ReasonPolicyHold, Revisions: map[string]uint64{"example.test": 2}}
	if err := queue.RequireHold(context.Background(), actor, "corr-hold", registration.QueueID, decision); err != nil {
		t.Fatal(err)
	}
	boundary := &fakeQueueBoundary{metadata: queueMetadata(registration), holdErr: errors.New("postsuper failed")}
	_, err := (QueueReconciler{Store: queue, Inspector: boundary, Holder: boundary}).Reconcile(context.Background(), actor, "corr-reconcile", registration.QueueID)
	if err == nil {
		t.Fatal("helper failure accepted")
	}
	record, loadErr := queue.Load(context.Background(), registration.QueueID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if record.HoldState != HoldReconciliationError || record.LastErrorCode != "queue_hold_failed" || record.ReconciliationAttempts != 1 {
		t.Fatalf("record=%+v", record)
	}
}

func testQueueRegistration() QueueRegistration {
	return QueueRegistration{
		QueueID:            "3Pt2mN2VXxznjll",
		ArrivalFingerprint: strings.Repeat("e", 64),
		EnvelopeSender:     "sender@example.test",
		Recipients:         []string{"recipient@outside.test", "local@example.test"},
		Sources:            []QueueSource{{Kind: SourceAuthenticatedMailbox, ObjectID: "mailbox-1"}},
	}
}

func queueMetadata(in QueueRegistration) QueueMetadata {
	return QueueMetadata{
		QueueID:            in.QueueID,
		ArrivalFingerprint: in.ArrivalFingerprint,
		EnvelopeSender:     in.EnvelopeSender,
		Recipients:         append([]string(nil), in.Recipients...),
	}
}
