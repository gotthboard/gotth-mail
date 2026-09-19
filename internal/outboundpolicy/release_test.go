package outboundpolicy

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type fakeReleaseBoundary struct {
	metadata     QueueMetadata
	holdCalls    int
	releaseCalls int
	releaseErr   error
}

func (f *fakeReleaseBoundary) Inspect(context.Context, string) (QueueMetadata, error) {
	return f.metadata, nil
}

func (f *fakeReleaseBoundary) Hold(context.Context, string) error {
	f.holdCalls++
	f.metadata.Held = true
	return nil
}

func (f *fakeReleaseBoundary) Release(context.Context, string) error {
	f.releaseCalls++
	if f.releaseErr != nil {
		return f.releaseErr
	}
	f.metadata.Held = false
	return nil
}

func TestQueueReleaseRequiresCurrentPolicyPreviewAndIsIdempotent(t *testing.T) {
	db, queue, boundary, actor := heldReleaseFixture(t)
	if _, err := (QueueReleaseService{Store: queue, Boundary: boundary}).Preview(context.Background(), releaseQueueID); err == nil {
		t.Fatal("preview allowed a queue that remains forbidden")
	}
	if _, err := db.Exec(`UPDATE domains SET outbound_scope='unrestricted',outbound_policy_revision=outbound_policy_revision+1,updated_at=CURRENT_TIMESTAMP WHERE name='example.test'`); err != nil {
		t.Fatal(err)
	}
	service := QueueReleaseService{Store: queue, Boundary: boundary}
	plan, err := service.Preview(context.Background(), releaseQueueID)
	if err != nil || plan.HoldState != HoldApplied || !validLowerHexDigest(plan.ConfirmationHash) || plan.PolicyRevisions["example.test"] != 3 {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}
	result, err := service.Release(context.Background(), actor, "release-apply", releaseQueueID, plan.ConfirmationHash)
	if err != nil || !result.Changed || result.Record.HoldState != HoldReleased || boundary.releaseCalls != 1 {
		t.Fatalf("result=%#v calls=%d err=%v", result, boundary.releaseCalls, err)
	}
	result, err = service.Release(context.Background(), actor, "release-repeat", releaseQueueID, plan.ConfirmationHash)
	if err != nil || result.Changed || boundary.releaseCalls != 1 {
		t.Fatalf("repeat=%#v calls=%d err=%v", result, boundary.releaseCalls, err)
	}
	var releasedAudits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='queue.policy_hold.released'`, releaseQueueID).Scan(&releasedAudits); err != nil || releasedAudits != 1 {
		t.Fatalf("released audits=%d err=%v", releasedAudits, err)
	}
}

func TestQueueReleaseRejectsStaleConfirmationAndRecordsHelperFailure(t *testing.T) {
	db, queue, boundary, actor := heldReleaseFixture(t)
	if _, err := db.Exec(`UPDATE domains SET outbound_scope='unrestricted',outbound_policy_revision=3,updated_at=CURRENT_TIMESTAMP WHERE name='example.test'`); err != nil {
		t.Fatal(err)
	}
	service := QueueReleaseService{Store: queue, Boundary: boundary}
	plan, err := service.Preview(context.Background(), releaseQueueID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE domains SET outbound_policy_revision=4,updated_at=CURRENT_TIMESTAMP WHERE name='example.test'`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Release(context.Background(), actor, "release-stale", releaseQueueID, plan.ConfirmationHash); err == nil || boundary.releaseCalls != 0 {
		t.Fatalf("stale release err=%v calls=%d", err, boundary.releaseCalls)
	}
	plan, err = service.Preview(context.Background(), releaseQueueID)
	if err != nil {
		t.Fatal(err)
	}
	boundary.releaseErr = errors.New("postsuper failed")
	result, err := service.Release(context.Background(), actor, "release-failure", releaseQueueID, plan.ConfirmationHash)
	if err == nil || result.Record.HoldState != HoldReleaseError || boundary.metadata.Held != true {
		t.Fatalf("result=%#v held=%v err=%v", result, boundary.metadata.Held, err)
	}
}

type blockingReleaseBoundary struct {
	metadata QueueMetadata
	entered  chan struct{}
	proceed  chan struct{}
}

func (b *blockingReleaseBoundary) Inspect(context.Context, string) (QueueMetadata, error) {
	return b.metadata, nil
}

func (b *blockingReleaseBoundary) Release(ctx context.Context, _ string) error {
	close(b.entered)
	select {
	case <-b.proceed:
		b.metadata.Held = false
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestQueueReleaseSerializesPolicyAuthorityMutationAcrossPostfixRelease(t *testing.T) {
	db, queue, held, actor := heldReleaseFixture(t)
	if _, err := db.Exec(`UPDATE domains SET outbound_scope='unrestricted',outbound_policy_revision=3,updated_at=CURRENT_TIMESTAMP WHERE name='example.test'`); err != nil {
		t.Fatal(err)
	}
	boundary := &blockingReleaseBoundary{metadata: held.metadata, entered: make(chan struct{}), proceed: make(chan struct{})}
	service := QueueReleaseService{Store: queue, Boundary: boundary}
	plan, err := service.Preview(context.Background(), releaseQueueID)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, releaseErr := service.Release(context.Background(), actor, "release-policy-lock", releaseQueueID, plan.ConfirmationHash)
		done <- releaseErr
	}()
	select {
	case <-boundary.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("release helper was not reached")
	}
	updateCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_, updateErr := db.ExecContext(updateCtx, `UPDATE domains SET outbound_policy_revision=4,updated_at=CURRENT_TIMESTAMP WHERE name='example.test'`)
	cancel()
	if updateErr == nil {
		close(boundary.proceed)
		t.Fatal("policy mutation crossed an in-flight Postfix release")
	}
	close(boundary.proceed)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("release did not complete after policy mutation was canceled")
	}
}

const releaseQueueID = "GHJKLMNPQRSTz2345"

func heldReleaseFixture(t *testing.T) (*sql.DB, QueueStore, *fakeReleaseBoundary, audit.ActorRef) {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000c01','example.test',true,'same_domain_only',2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000c02','00000000-0000-4000-8000-000000000c01','user',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	registration := QueueRegistration{
		QueueID:            releaseQueueID,
		ArrivalFingerprint: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		EnvelopeSender:     "user@example.test",
		Recipients:         []string{"outside@example.net"},
		Sources:            []QueueSource{{Kind: SourceAuthenticatedMailbox, ObjectID: "00000000-0000-4000-8000-000000000c02"}},
	}
	queue := QueueStore{DB: db}
	if _, _, err := queue.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "local_admin", ID: "operator"}
	if err := queue.RequireHold(context.Background(), actor, "hold-required", releaseQueueID, Decision{Action: ActionDefer, Reason: ReasonPolicyHold, Revisions: map[string]uint64{"example.test": 2}}); err != nil {
		t.Fatal(err)
	}
	boundary := &fakeReleaseBoundary{metadata: queueMetadata(registration)}
	result, err := (QueueReconciler{Store: queue, Inspector: boundary, Holder: boundary}).Reconcile(context.Background(), actor, "hold-apply", releaseQueueID)
	if err != nil || result.Record.HoldState != HoldApplied || !boundary.metadata.Held {
		t.Fatalf("hold result=%#v err=%v", result, err)
	}
	return db, queue, boundary, actor
}
