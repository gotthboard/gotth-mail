package outboundpolicy

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

const (
	finalQueueDomainID   = "00000000-0000-4000-8000-000000020101"
	finalQueueMailboxID  = "00000000-0000-4000-8000-000000020102"
	finalQueueInstanceID = "postfix-alpha-1"
)

func finalQueuePolicyDB(t *testing.T) *sql.DB {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'example.test',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, finalQueueDomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id,domain_id,local_part,display_name,enabled,created_at,updated_at) VALUES ($1,$2,'forwarder','Forwarder',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, finalQueueMailboxID, finalQueueDomainID); err != nil {
		t.Fatal(err)
	}
	return db
}

func finalQueueFixture() FinalQueueArtifact {
	return FinalQueueArtifact{
		ArtifactID:         "artifact-20261007-0001",
		SignedMessageID:    "<new-forward@example.test>",
		SignedDate:         time.Date(2026, 10, 7, 13, 0, 0, 0, time.UTC),
		ContentSHA256:      strings.Repeat("a", 64),
		ContentBytes:       maxSignedArtifactBytes,
		LocalIdentityID:    "identity:forwarder@example.test",
		LocalMailboxID:     finalQueueMailboxID,
		EnvelopeSender:     "Forwarder@Example.Test",
		NullEnvelopeSender: false,
		SignerIdentityID:   "signer:forwarder@example.test",
		SignerFingerprint:  strings.Repeat("b", 64),
		PreparedAt:         time.Date(2026, 10, 7, 13, 1, 0, 0, time.UTC),
		ExpiresAt:          time.Date(2026, 10, 8, 13, 1, 0, 0, time.UTC),
		Recipients:         []string{"outside@Example.NET.", "audit@example.org"},
		Sources: []FinalQueueSource{
			{QueueSource: QueueSource{Kind: SourceForward, ObjectID: "forward:primary"}, Revision: 12},
			{QueueSource: QueueSource{Kind: SourceAuthenticatedMailbox, ObjectID: finalQueueMailboxID}, Revision: 7},
		},
	}
}

func registerFixtureQueue(t *testing.T, db *sql.DB, artifact FinalQueueArtifact, queueID, fingerprint string) QueueRecord {
	t.Helper()
	sources := make([]QueueSource, len(artifact.Sources))
	for i, source := range artifact.Sources {
		sources[i] = source.QueueSource
	}
	record, _, err := (QueueStore{DB: db}).Register(context.Background(), QueueRegistration{QueueID: queueID, ArrivalFingerprint: fingerprint, EnvelopeSender: artifact.EnvelopeSender, Recipients: artifact.Recipients, Sources: sources})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestFinalQueuePrepareExactOrderIdempotentMismatchAndUniqueMessageID(t *testing.T) {
	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	artifact := finalQueueFixture()
	got, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != FinalQueueStatePrepared || got.EnvelopeSender != "Forwarder@example.test" || got.recipientSetDigest == "" || got.sourceSetDigest == "" || got.provenanceDigest == "" {
		t.Fatalf("prepared=%#v", got)
	}
	if got.Recipients[0] != "audit@example.org" || got.Recipients[1] != "outside@example.net" || got.Sources[0].Kind != SourceAuthenticatedMailbox || got.Sources[1].Kind != SourceForward {
		t.Fatalf("not canonical: recipients=%#v sources=%#v", got.Recipients, got.Sources)
	}
	reordered := artifact
	reordered.Recipients = []string{"audit@example.org", "outside@example.net"}
	reordered.Sources = []FinalQueueSource{artifact.Sources[1], artifact.Sources[0]}
	again, err := fq.PrepareFinalQueueArtifact(context.Background(), reordered)
	if err != nil {
		t.Fatalf("order-idempotent prepare failed: %v", err)
	}
	if again.provenanceDigest != got.provenanceDigest || again.recipientSetDigest != got.recipientSetDigest || again.sourceSetDigest != got.sourceSetDigest {
		t.Fatalf("idempotent digests drifted: %#v %#v", got, again)
	}
	changed := artifact
	changed.ContentSHA256 = strings.Repeat("c", 64)
	if _, err := fq.PrepareFinalQueueArtifact(context.Background(), changed); err == nil {
		t.Fatal("mismatched artifact id prepare accepted")
	}
	second := artifact
	second.ArtifactID = "artifact-20261007-0002"
	if _, err := fq.PrepareFinalQueueArtifact(context.Background(), second); err == nil {
		t.Fatal("duplicate signed message id accepted")
	}
}

func TestFinalQueuePrepareReturnsPersistedTruthForOmittedTimeBoundaries(t *testing.T) {
	db := finalQueuePolicyDB(t)
	firstNow := time.Date(2026, 10, 7, 13, 1, 0, 1_499, time.UTC)
	currentNow := firstNow
	calls := 0
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID, Now: func() time.Time {
		calls++
		return currentNow
	}}
	artifact := finalQueueFixture()
	artifact.ArtifactID = "artifact-omitted-time-boundaries"
	artifact.SignedMessageID = "<omitted-time-boundaries@example.test>"
	artifact.PreparedAt = time.Time{}
	artifact.UpdatedAt = time.Time{}
	artifact.ExpiresAt = firstNow.Add(24 * time.Hour)
	created, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	wantPrepared := canonicalPostgresTime(firstNow)
	for _, retryNow := range []time.Time{artifact.SignedDate.Add(-time.Second), created.ExpiresAt, created.ExpiresAt.Add(time.Second)} {
		currentNow = retryNow
		replayed, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
		if err != nil {
			t.Fatalf("replay at retry now %s failed: %v", retryNow.Format(time.RFC3339Nano), err)
		}
		if replayed.State != FinalQueueStatePrepared || !replayed.PreparedAt.Equal(wantPrepared) || !replayed.UpdatedAt.Equal(created.UpdatedAt) || !replayed.ExpiresAt.Equal(created.ExpiresAt) {
			t.Fatalf("prepare replay did not return persisted truth at retry now %s: created=%#v replayed=%#v", retryNow.Format(time.RFC3339Nano), created, replayed)
		}
	}
	if calls != 1 {
		t.Fatalf("prepare replay consulted retry-local Now calls=%d", calls)
	}
}

func TestFinalQueueConcurrentPrepareOmittedTimesReturnsOnePersistedTruth(t *testing.T) {
	db := finalQueuePolicyDB(t)
	baseNow := time.Date(2026, 10, 7, 13, 1, 0, 1_499, time.UTC)
	var mu sync.Mutex
	calls := 0
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID, Now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			return baseNow
		}
		return baseNow.Add(48 * time.Hour)
	}}
	artifact := finalQueueFixture()
	artifact.ArtifactID = "artifact-concurrent-omitted-times"
	artifact.SignedMessageID = "<concurrent-omitted-times@example.test>"
	artifact.PreparedAt = time.Time{}
	artifact.UpdatedAt = time.Time{}
	artifact.ExpiresAt = baseNow.Add(24 * time.Hour)
	type prepareResult struct {
		got FinalQueueArtifact
		err error
	}
	results := make(chan prepareResult, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
			results <- prepareResult{got: got, err: err}
		}()
	}
	wg.Wait()
	close(results)
	var got []FinalQueueArtifact
	for result := range results {
		if result.err != nil {
			t.Fatalf("exact concurrent prepare with omitted times failed: %v", result.err)
		}
		got = append(got, result.got)
	}
	if len(got) != 2 {
		t.Fatalf("prepare results=%d", len(got))
	}
	if got[0].State != FinalQueueStatePrepared || got[1].State != FinalQueueStatePrepared || !got[0].PreparedAt.Equal(got[1].PreparedAt) || !got[0].UpdatedAt.Equal(got[1].UpdatedAt) || !got[0].PreparedAt.Equal(got[0].UpdatedAt) {
		t.Fatalf("concurrent prepare did not return one persisted truth: %#v %#v", got[0], got[1])
	}
	stored, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.PreparedAt.Equal(got[0].PreparedAt) || !stored.UpdatedAt.Equal(got[0].UpdatedAt) || stored.State != got[0].State {
		t.Fatalf("stored prepare truth differs: stored=%#v first=%#v", stored, got[0])
	}
	if calls != 1 {
		t.Fatalf("same-artifact prepare replay consulted Now calls=%d", calls)
	}
}

func TestFinalQueuePrepareReplayAfterBindReturnsBoundPersistedTruthAtRetryBoundaries(t *testing.T) {
	db := finalQueuePolicyDB(t)
	firstNow := time.Date(2026, 10, 7, 13, 1, 0, 1_499, time.UTC)
	currentNow := firstNow
	calls := 0
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID, Now: func() time.Time {
		calls++
		return currentNow
	}}
	artifact := finalQueueFixture()
	artifact.ArtifactID = "artifact-replay-after-bind"
	artifact.SignedMessageID = "<replay-after-bind@example.test>"
	artifact.PreparedAt = time.Time{}
	artifact.UpdatedAt = time.Time{}
	artifact.ExpiresAt = firstNow.Add(24 * time.Hour)
	prepared, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	binding := FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "BBBBBB0006zb", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(time.Minute + 501*time.Nanosecond)}
	registerFixtureQueue(t, db, prepared, binding.QueueID, binding.ArrivalFingerprint)
	bound, err := fq.BindFinalQueueArtifact(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, retryNow := range []time.Time{artifact.SignedDate.Add(-time.Second), prepared.ExpiresAt, prepared.ExpiresAt.Add(time.Second)} {
		currentNow = retryNow
		replayed, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
		if err != nil {
			t.Fatalf("bound replay at retry now %s failed: %v", retryNow.Format(time.RFC3339Nano), err)
		}
		if replayed.State != FinalQueueStateBound || !replayed.PreparedAt.Equal(prepared.PreparedAt) || !replayed.ExpiresAt.Equal(prepared.ExpiresAt) || !replayed.UpdatedAt.Equal(bound.BoundAt) {
			t.Fatalf("prepare replay after bind did not return bound persisted truth at retry now %s: prepared=%#v bound=%#v replayed=%#v", retryNow.Format(time.RFC3339Nano), prepared, bound, replayed)
		}
	}
	if calls != 1 {
		t.Fatalf("bound prepare replay consulted retry-local Now calls=%d", calls)
	}
}

func TestFinalQueuePrepareAdvisoryLockContextCancelLeavesNoRows(t *testing.T) {
	db := finalQueuePolicyDB(t)
	artifact := finalQueueFixture()
	artifact.ArtifactID = "artifact-advisory-cancel"
	artifact.SignedMessageID = "<advisory-cancel@example.test>"
	artifact.PreparedAt = time.Time{}
	artifact.UpdatedAt = time.Time{}
	artifact.ExpiresAt = time.Date(2026, 10, 8, 13, 1, 0, 0, time.UTC)
	hold, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	if err := lockFinalQueueArtifactPrepareTx(context.Background(), hold, artifact.ArtifactID); err != nil {
		hold.Rollback()
		t.Fatal(err)
	}
	calls := 0
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID, Now: func() time.Time {
		calls++
		return time.Date(2026, 10, 7, 13, 1, 0, 0, time.UTC)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, err = fq.PrepareFinalQueueArtifact(ctx, artifact)
	cancel()
	if err == nil {
		hold.Rollback()
		t.Fatal("prepare waiting on advisory lock did not observe context cancellation")
	}
	if calls != 0 {
		hold.Rollback()
		t.Fatalf("prepare read Now before same-artifact advisory lock calls=%d", calls)
	}
	if err := hold.Rollback(); err != nil {
		t.Fatal(err)
	}
	var parents, recipients, sources int
	if err := db.QueryRow("SELECT (SELECT count(*) FROM final_queue_artifacts WHERE artifact_id=$1), (SELECT count(*) FROM final_queue_recipients WHERE artifact_id=$1), (SELECT count(*) FROM final_queue_sources WHERE artifact_id=$1)", artifact.ArtifactID).Scan(&parents, &recipients, &sources); err != nil {
		t.Fatal(err)
	}
	if parents != 0 || recipients != 0 || sources != 0 {
		t.Fatalf("canceled prepare leaked rows parent=%d recipients=%d sources=%d", parents, recipients, sources)
	}
}

func TestFinalQueueNullAndNonNullSenderMapping(t *testing.T) {
	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	nonNull := finalQueueFixture()
	if got, err := fq.PrepareFinalQueueArtifact(context.Background(), nonNull); err != nil || got.NullEnvelopeSender || got.EnvelopeSender == "<>" {
		t.Fatalf("non-null sender got=%#v err=%v", got, err)
	}
	nullSender := finalQueueFixture()
	nullSender.ArtifactID = "artifact-null-sender"
	nullSender.SignedMessageID = "<null-forward@example.test>"
	nullSender.EnvelopeSender = "<>"
	nullSender.NullEnvelopeSender = true
	if got, err := fq.PrepareFinalQueueArtifact(context.Background(), nullSender); err != nil || !got.NullEnvelopeSender || got.EnvelopeSender != "<>" {
		t.Fatalf("null sender got=%#v err=%v", got, err)
	}
}

func TestFinalQueueBindRequiresRegisteredExactQueueAndLookupFullSet(t *testing.T) {
	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	artifact := finalQueueFixture()
	prepared, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	binding := FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "BCDFGHJKLMNPz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(time.Minute)}
	if _, err := fq.BindFinalQueueArtifact(context.Background(), binding); err == nil {
		t.Fatal("unregistered queue bound")
	}
	queue := registerFixtureQueue(t, db, prepared, binding.QueueID, binding.ArrivalFingerprint)
	bound, err := fq.BindFinalQueueArtifact(context.Background(), binding)
	if err != nil {
		t.Fatalf("bind failed: %v", err)
	}
	if bound.State != FinalQueueStateBound || bound.QueueID != binding.QueueID || bound.Queue.ArrivalFingerprint != queue.ArrivalFingerprint || len(bound.Recipients) != 2 || len(bound.Sources) != 2 {
		t.Fatalf("bound=%#v", bound)
	}
	if _, err := fq.BindFinalQueueArtifact(context.Background(), binding); err != nil {
		t.Fatalf("exact bind replay failed: %v", err)
	}
	lookup, err := fq.LookupFinalQueueBinding(context.Background(), binding.InstanceID, binding.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if lookup.provenanceDigest != prepared.provenanceDigest || lookup.Queue.RecipientSetDigest != prepared.recipientSetDigest || lookup.Queue.SourceSetDigest != prepared.sourceSetDigest {
		t.Fatalf("lookup=%#v prepared=%#v", lookup, prepared)
	}
}

func TestFinalQueuePrepareBindLookupSingleConnectionAndMicrosecondTimes(t *testing.T) {
	db := finalQueuePolicyDB(t)
	db.SetMaxOpenConns(1)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	artifact := finalQueueFixture()
	artifact.SignedDate = time.Date(2026, 10, 7, 13, 0, 0, 999_999_500, time.FixedZone("offset", -5*3600))
	artifact.PreparedAt = time.Date(2026, 10, 7, 13, 1, 0, 1_499, time.FixedZone("offset", -5*3600))
	artifact.ExpiresAt = artifact.PreparedAt.Add(24*time.Hour + 999*time.Nanosecond)
	prepared, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	again, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatalf("microsecond replay failed: %v", err)
	}
	if !again.SignedDate.Equal(prepared.SignedDate) || prepared.SignedDate.Nanosecond()%1000 != 0 || prepared.PreparedAt.Nanosecond()%1000 != 0 || prepared.ExpiresAt.Nanosecond()%1000 != 0 {
		t.Fatalf("noncanonical times prepared=%s/%s/%s again=%s", prepared.SignedDate.Format(time.RFC3339Nano), prepared.PreparedAt.Format(time.RFC3339Nano), prepared.ExpiresAt.Format(time.RFC3339Nano), again.SignedDate.Format(time.RFC3339Nano))
	}
	binding := FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "LMNPQRSTVWXZz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(time.Minute + 501*time.Nanosecond)}
	registerFixtureQueue(t, db, prepared, binding.QueueID, binding.ArrivalFingerprint)
	bound, err := fq.BindFinalQueueArtifact(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	lookup, err := fq.LookupFinalQueueBinding(context.Background(), binding.InstanceID, binding.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if !bound.BoundAt.Equal(lookup.BoundAt) || lookup.BoundAt.Nanosecond()%1000 != 0 || !lookup.UpdatedAt.Equal(lookup.BoundAt) {
		t.Fatalf("bound/lookup time mismatch bound=%s lookup=%s updated=%s", bound.BoundAt.Format(time.RFC3339Nano), lookup.BoundAt.Format(time.RFC3339Nano), lookup.UpdatedAt.Format(time.RFC3339Nano))
	}
}

func TestFinalQueueConcurrentPrepareAndBind(t *testing.T) {
	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	artifact := finalQueueFixture()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("exact concurrent prepare leaked error: %v", err)
		}
	}
	mismatch := artifact
	mismatch.ContentSHA256 = strings.Repeat("c", 64)
	errs = make(chan error, 2)
	for _, candidate := range []FinalQueueArtifact{artifact, mismatch} {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fq.PrepareFinalQueueArtifact(context.Background(), candidate)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	var rejected bool
	for err := range errs {
		if err != nil {
			rejected = true
			if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "could not serialize") {
				t.Fatalf("leaked storage/concurrency error: %v", err)
			}
		}
	}
	if !rejected {
		t.Fatal("mismatched concurrent prepare was not rejected")
	}
	prepared, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	binding := FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "MNPQRSTVWXZbz234", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(time.Minute)}
	registerFixtureQueue(t, db, prepared, binding.QueueID, binding.ArrivalFingerprint)
	type bindResult struct {
		got FinalQueueBoundArtifact
		err error
	}
	bindResults := make(chan bindResult, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := fq.BindFinalQueueArtifact(context.Background(), binding)
			bindResults <- bindResult{got: got, err: err}
		}()
	}
	wg.Wait()
	close(bindResults)
	boundResults := make([]FinalQueueBoundArtifact, 0, 2)
	for result := range bindResults {
		if result.err != nil {
			t.Fatalf("exact concurrent bind returned error: %v", result.err)
		}
		boundResults = append(boundResults, result.got)
	}
	if len(boundResults) != 2 {
		t.Fatalf("bind results=%d", len(boundResults))
	}
	if boundResults[0].ArtifactID != boundResults[1].ArtifactID || boundResults[0].InstanceID != boundResults[1].InstanceID || boundResults[0].QueueID != boundResults[1].QueueID || boundResults[0].ArrivalFingerprint != boundResults[1].ArrivalFingerprint || !boundResults[0].BoundAt.Equal(boundResults[1].BoundAt) || boundResults[0].Queue.QueueID != boundResults[1].Queue.QueueID || boundResults[0].Queue.ArrivalFingerprint != boundResults[1].Queue.ArrivalFingerprint {
		t.Fatalf("exact concurrent bind returned divergent bindings: %#v %#v", boundResults[0], boundResults[1])
	}
	if _, err := fq.LookupFinalQueueBinding(context.Background(), finalQueueInstanceID, binding.QueueID); err != nil {
		t.Fatal(err)
	}
	mismatchBindArtifact := finalQueueFixture()
	mismatchBindArtifact.ArtifactID = "artifact-concurrent-bind-mismatch"
	mismatchBindArtifact.SignedMessageID = "<concurrent-bind-mismatch@example.test>"
	preparedMismatchBind, err := fq.PrepareFinalQueueArtifact(context.Background(), mismatchBindArtifact)
	if err != nil {
		t.Fatal(err)
	}
	mismatchQueueBinding := FinalQueueBinding{ArtifactID: preparedMismatchBind.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "BBBBBB0003zb", ArrivalFingerprint: strings.Repeat("3", 64), BoundAt: preparedMismatchBind.PreparedAt.Add(time.Minute)}
	registerFixtureQueue(t, db, preparedMismatchBind, mismatchQueueBinding.QueueID, mismatchQueueBinding.ArrivalFingerprint)
	mismatchedBinding := mismatchQueueBinding
	mismatchedBinding.ArrivalFingerprint = strings.Repeat("4", 64)
	bindResults = make(chan bindResult, 2)
	for _, candidate := range []FinalQueueBinding{mismatchQueueBinding, mismatchedBinding} {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := fq.BindFinalQueueArtifact(context.Background(), candidate)
			bindResults <- bindResult{got: got, err: err}
		}()
	}
	wg.Wait()
	close(bindResults)
	var successes, failures int
	for result := range bindResults {
		if result.err != nil {
			failures++
			if strings.Contains(result.err.Error(), "duplicate key") || strings.Contains(result.err.Error(), "could not serialize") {
				t.Fatalf("mismatched concurrent bind leaked storage/concurrency error: %v", result.err)
			}
			continue
		}
		successes++
		if result.got.ArtifactID != mismatchQueueBinding.ArtifactID || result.got.QueueID != mismatchQueueBinding.QueueID || result.got.ArrivalFingerprint != mismatchQueueBinding.ArrivalFingerprint {
			t.Fatalf("wrong concurrent bind succeeded: %#v", result.got)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("mismatched concurrent bind successes=%d failures=%d", successes, failures)
	}
}

func TestFinalQueueBindRejectsObservedQueueMismatchesAndReuse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*QueueRegistration)
	}{
		{"arrival", func(q *QueueRegistration) { q.ArrivalFingerprint = strings.Repeat("2", 64) }},
		{"sender", func(q *QueueRegistration) { q.EnvelopeSender = "other@example.test" }},
		{"recipient", func(q *QueueRegistration) { q.Recipients = []string{"other@example.net"} }},
		{"source", func(q *QueueRegistration) { q.Sources = []QueueSource{{Kind: SourceAlias, ObjectID: "alias:other"}} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := finalQueuePolicyDB(t)
			fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
			artifact, err := fq.PrepareFinalQueueArtifact(context.Background(), finalQueueFixture())
			if err != nil {
				t.Fatal(err)
			}
			sources := make([]QueueSource, len(artifact.Sources))
			for i, source := range artifact.Sources {
				sources[i] = source.QueueSource
			}
			registration := QueueRegistration{QueueID: "CDFGHJKLMNPQz2345", ArrivalFingerprint: strings.Repeat("1", 64), EnvelopeSender: artifact.EnvelopeSender, Recipients: artifact.Recipients, Sources: sources}
			tc.mutate(&registration)
			if _, _, err := (QueueStore{DB: db}).Register(context.Background(), registration); err != nil {
				t.Fatal(err)
			}
			if _, err := fq.BindFinalQueueArtifact(context.Background(), FinalQueueBinding{ArtifactID: artifact.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: registration.QueueID, ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: artifact.PreparedAt.Add(time.Minute)}); err == nil {
				t.Fatal("mismatched observed queue bound")
			}
		})
	}

	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	first, err := fq.PrepareFinalQueueArtifact(context.Background(), finalQueueFixture())
	if err != nil {
		t.Fatal(err)
	}
	binding := FinalQueueBinding{ArtifactID: first.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "DFGHJKLMNPQRz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: first.PreparedAt.Add(time.Minute)}
	registerFixtureQueue(t, db, first, binding.QueueID, binding.ArrivalFingerprint)
	if _, err := fq.BindFinalQueueArtifact(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	second := finalQueueFixture()
	second.ArtifactID = "artifact-20261007-0002"
	second.SignedMessageID = "<other-forward@example.test>"
	preparedSecond, err := fq.PrepareFinalQueueArtifact(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	binding.ArtifactID = preparedSecond.ArtifactID
	if _, err := fq.BindFinalQueueArtifact(context.Background(), binding); err == nil {
		t.Fatal("queue reuse accepted")
	}
	binding.ArtifactID = first.ArtifactID
	binding.QueueID = "FGHJKLMNPQRTz2345"
	registerFixtureQueue(t, db, first, binding.QueueID, binding.ArrivalFingerprint)
	if _, err := fq.BindFinalQueueArtifact(context.Background(), binding); err == nil {
		t.Fatal("artifact rebind accepted")
	}
}

func TestFinalQueueBindLocksObservedQueueParent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		queue  string
		mutate func(*testing.T, *sql.Tx, string)
	}{
		{
			name:  "update",
			queue: "BBBBBB0004zb",
			mutate: func(t *testing.T, tx *sql.Tx, queueID string) {
				t.Helper()
				if _, err := tx.Exec("UPDATE outbound_queue_messages SET updated_at=updated_at + interval '1 second' WHERE queue_id=$1", queueID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:  "delete",
			queue: "BBBBBB0005zb",
			mutate: func(t *testing.T, tx *sql.Tx, queueID string) {
				t.Helper()
				if _, err := tx.Exec("DELETE FROM outbound_queue_messages WHERE queue_id=$1", queueID); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := finalQueuePolicyDB(t)
			fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
			artifact := finalQueueFixture()
			artifact.ArtifactID = "artifact-lock-" + tc.name
			artifact.SignedMessageID = "<lock-" + tc.name + "@example.test>"
			prepared, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
			if err != nil {
				t.Fatal(err)
			}
			binding := FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: tc.queue, ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(time.Minute)}
			queueBefore := registerFixtureQueue(t, db, prepared, binding.QueueID, binding.ArrivalFingerprint)
			tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, tx, binding.QueueID)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err = fq.BindFinalQueueArtifact(ctx, binding)
			cancel()
			if err == nil {
				t.Fatal("bind did not wait on observed queue parent lock")
			}
			if rbErr := tx.Rollback(); rbErr != nil {
				t.Fatal(rbErr)
			}
			bound, err := fq.BindFinalQueueArtifact(context.Background(), binding)
			if err != nil {
				t.Fatalf("bind after lock rollback failed: %v", err)
			}
			if bound.Queue.QueueID != queueBefore.QueueID || bound.Queue.ArrivalFingerprint != queueBefore.ArrivalFingerprint || bound.Queue.EnvelopeSender != queueBefore.EnvelopeSender || bound.Queue.RecipientSetDigest != queueBefore.RecipientSetDigest || bound.Queue.SourceSetDigest != queueBefore.SourceSetDigest {
				t.Fatalf("queue changed across rolled-back lock: before=%#v after=%#v", queueBefore, bound.Queue)
			}
		})
	}
}

func TestFinalQueueLookupRejectsTamperAndDeletedChildRows(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *sql.DB, FinalQueueBinding)
	}{
		{"recipient delete", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			_, err := db.Exec("DELETE FROM final_queue_recipients WHERE artifact_id=$1", b.ArtifactID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"recipient ordinal gap", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			if _, err := db.Exec("UPDATE final_queue_recipients SET ordinal=10 WHERE artifact_id=$1 AND recipient='audit@example.org'", b.ArtifactID); err != nil {
				t.Fatal(err)
			}
		}},
		{"recipient ordinal swap", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, query := range []string{
				"UPDATE final_queue_recipients SET ordinal=99 WHERE artifact_id=$1 AND recipient='audit@example.org'",
				"UPDATE final_queue_recipients SET ordinal=0 WHERE artifact_id=$1 AND recipient='outside@example.net'",
				"UPDATE final_queue_recipients SET ordinal=1 WHERE artifact_id=$1 AND recipient='audit@example.org'",
			} {
				if _, err := tx.Exec(query, b.ArtifactID); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}},
		{"source ordinal gap", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			if _, err := db.Exec("UPDATE final_queue_sources SET ordinal=10 WHERE artifact_id=$1 AND source_kind='authenticated_mailbox'", b.ArtifactID); err != nil {
				t.Fatal(err)
			}
		}},
		{"source ordinal swap", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, query := range []string{
				"UPDATE final_queue_sources SET ordinal=99 WHERE artifact_id=$1 AND source_kind='authenticated_mailbox'",
				"UPDATE final_queue_sources SET ordinal=0 WHERE artifact_id=$1 AND source_kind='forward'",
				"UPDATE final_queue_sources SET ordinal=1 WHERE artifact_id=$1 AND source_kind='authenticated_mailbox'",
			} {
				if _, err := tx.Exec(query, b.ArtifactID); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}},
		{"source ordinal shift", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			tx, err := db.BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, query := range []string{
				"UPDATE final_queue_sources SET ordinal=99 WHERE artifact_id=$1 AND source_kind='authenticated_mailbox'",
				"UPDATE final_queue_sources SET ordinal=2 WHERE artifact_id=$1 AND source_kind='forward'",
				"UPDATE final_queue_sources SET ordinal=1 WHERE artifact_id=$1 AND source_kind='authenticated_mailbox'",
			} {
				if _, err := tx.Exec(query, b.ArtifactID); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}},
		{"recipient tamper", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			_, err := db.Exec("UPDATE final_queue_recipients SET recipient='evil@example.net', recipient_domain='example.net' WHERE artifact_id=$1 AND recipient='audit@example.org'", b.ArtifactID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"source delete", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			_, err := db.Exec("DELETE FROM final_queue_sources WHERE artifact_id=$1", b.ArtifactID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"digest tamper", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			_, err := db.Exec("UPDATE final_queue_artifacts SET recipient_set_digest=$2 WHERE artifact_id=$1", b.ArtifactID, strings.Repeat("f", 64))
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"prepared updated tamper", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			if _, err := db.Exec("UPDATE final_queue_artifacts SET state='prepared', updated_at=updated_at + interval '1 second' WHERE artifact_id=$1", b.ArtifactID); err != nil {
				t.Fatal(err)
			}
		}},
		{"bound updated tamper", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			if _, err := db.Exec("UPDATE final_queue_artifacts SET updated_at=updated_at + interval '1 second' WHERE artifact_id=$1", b.ArtifactID); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing binding", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			if _, err := db.Exec("DELETE FROM final_queue_bindings WHERE artifact_id=$1", b.ArtifactID); err != nil {
				t.Fatal(err)
			}
		}},
		{"state tamper", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			_, err := db.Exec("UPDATE final_queue_artifacts SET state='prepared' WHERE artifact_id=$1", b.ArtifactID)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"observed queue tamper", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			_, err := db.Exec("UPDATE outbound_queue_messages SET recipient_set_digest=$2 WHERE queue_id=$1", b.QueueID, strings.Repeat("8", 64))
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"binding arrival tamper", func(t *testing.T, db *sql.DB, b FinalQueueBinding) {
			_, err := db.Exec("UPDATE final_queue_bindings SET arrival_fingerprint=$2 WHERE artifact_id=$1", b.ArtifactID, strings.Repeat("9", 64))
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := finalQueuePolicyDB(t)
			fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
			artifact, err := fq.PrepareFinalQueueArtifact(context.Background(), finalQueueFixture())
			if err != nil {
				t.Fatal(err)
			}
			binding := FinalQueueBinding{ArtifactID: artifact.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "GHJKLMNPQRSTz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: artifact.PreparedAt.Add(time.Minute)}
			registerFixtureQueue(t, db, artifact, binding.QueueID, binding.ArrivalFingerprint)
			if _, err := fq.BindFinalQueueArtifact(context.Background(), binding); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, db, binding)
			if _, err := fq.LookupFinalQueueBinding(context.Background(), binding.InstanceID, binding.QueueID); err == nil {
				t.Fatal("tampered final queue artifact lookup accepted")
			}
		})
	}
}

func TestFinalQueueRejectsForeignEmptyAndWrongInstance(t *testing.T) {
	localDB := finalQueuePolicyDB(t)
	foreignDB := finalQueuePolicyDB(t)
	artifact, err := (FinalQueueStore{DB: localDB, InstanceID: finalQueueInstanceID}).PrepareFinalQueueArtifact(context.Background(), finalQueueFixture())
	if err != nil {
		t.Fatal(err)
	}
	binding := FinalQueueBinding{ArtifactID: artifact.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "JKLMNPQRSTVWz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: artifact.PreparedAt.Add(time.Minute)}
	registerFixtureQueue(t, foreignDB, artifact, binding.QueueID, binding.ArrivalFingerprint)
	if _, err := (FinalQueueStore{DB: localDB, InstanceID: finalQueueInstanceID}).BindFinalQueueArtifact(context.Background(), binding); err == nil {
		t.Fatal("foreign database queue authority accepted")
	}
	registerFixtureQueue(t, localDB, artifact, binding.QueueID, binding.ArrivalFingerprint)
	if _, err := (FinalQueueStore{DB: localDB}).BindFinalQueueArtifact(context.Background(), binding); err == nil {
		t.Fatal("empty configured instance accepted")
	}
	if _, err := (FinalQueueStore{DB: localDB, InstanceID: "postfix-beta-1"}).BindFinalQueueArtifact(context.Background(), binding); err == nil {
		t.Fatal("wrong configured instance accepted")
	}
	if _, err := (FinalQueueStore{DB: localDB, InstanceID: finalQueueInstanceID}).LookupFinalQueueBinding(context.Background(), "postfix-beta-1", binding.QueueID); err == nil {
		t.Fatal("wrong lookup instance accepted")
	}
}

func TestFinalQueueMessageIDParityAndDuplicateSourceRevisions(t *testing.T) {
	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	for _, id := range []string{"<new-forward@example.test>", "<A.!#$%&'*+-/=?^_`{|}~@example.test>", "<x@y>"} {
		candidate := finalQueueFixture()
		candidate.ArtifactID = "artifact-" + strings.ReplaceAll(strings.Trim(id, "<>"), "@", "-")
		candidate.SignedMessageID = id
		if _, err := fq.PrepareFinalQueueArtifact(context.Background(), candidate); err != nil {
			t.Fatalf("valid Message-ID %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"new-forward@example.test", "<new-forward..bad@example.test>", "<new forward@example.test>", "<@example.test>", "<local@>"} {
		candidate := finalQueueFixture()
		candidate.ArtifactID = "bad-msgid-" + strings.Repeat("x", 8)
		candidate.SignedMessageID = id
		if _, err := fq.PrepareFinalQueueArtifact(context.Background(), candidate); err == nil {
			t.Fatalf("invalid Message-ID %q accepted", id)
		}
	}
	exactDup := finalQueueFixture()
	exactDup.ArtifactID = "artifact-exact-source-dup"
	exactDup.SignedMessageID = "<exact-source-dup@example.test>"
	exactDup.Sources = append(exactDup.Sources, exactDup.Sources[0])
	if _, err := fq.PrepareFinalQueueArtifact(context.Background(), exactDup); err != nil {
		t.Fatalf("exact duplicate source rejected: %v", err)
	}
	conflict := finalQueueFixture()
	conflict.ArtifactID = "artifact-source-conflict"
	conflict.SignedMessageID = "<source-conflict@example.test>"
	conflicting := conflict.Sources[0]
	conflicting.Revision++
	conflict.Sources = append(conflict.Sources, conflicting)
	if _, err := fq.PrepareFinalQueueArtifact(context.Background(), conflict); err == nil {
		t.Fatal("conflicting duplicate source revision accepted")
	}
}

func TestFinalQueueHighCardinalityCopyPath(t *testing.T) {
	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	artifact := finalQueueFixture()
	artifact.ArtifactID = "artifact-high-cardinality"
	artifact.SignedMessageID = "<high-cardinality@example.test>"
	artifact.Recipients = make([]string, maxQueueRecipients)
	for i := range artifact.Recipients {
		artifact.Recipients[i] = fmt.Sprintf("user%05d@example.net", i)
	}
	start := time.Now()
	prepared, err := fq.PrepareFinalQueueArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("prepared %d recipients through COPY in %s", len(prepared.Recipients), time.Since(start))
	if len(prepared.Recipients) != maxQueueRecipients {
		t.Fatalf("recipient count=%d", len(prepared.Recipients))
	}
	binding := FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "KLMNPQRSTVWXz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(time.Minute)}
	registerFixtureQueue(t, db, prepared, binding.QueueID, binding.ArrivalFingerprint)
	if _, err := fq.BindFinalQueueArtifact(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
}

func TestFinalQueueCopyFailureRollsBackParentAndChildren(t *testing.T) {
	db := finalQueuePolicyDB(t)
	artifact, err := canonicalFinalQueueArtifact(finalQueueFixture())
	if err != nil {
		t.Fatal(err)
	}
	artifact.Recipients = append(artifact.Recipients, "bad-recipient")
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatal(err)
	}
	created, err := insertFinalQueueArtifactParentTx(context.Background(), tx, artifact)
	if err != nil || !created {
		t.Fatalf("parent insert created=%v err=%v", created, err)
	}
	if err := copyFinalQueueRecipients(context.Background(), tx, artifact); err == nil {
		t.Fatal("invalid COPY row unexpectedly succeeded")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM final_queue_artifacts WHERE artifact_id=$1", artifact.ArtifactID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("parent leaked after COPY rollback: %d", count)
	}
	if err := db.QueryRow("SELECT count(*) FROM final_queue_recipients WHERE artifact_id=$1", artifact.ArtifactID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("children leaked after COPY rollback: %d", count)
	}
}

func TestFinalQueueCopyCancellationRollsBackParentAndChildren(t *testing.T) {
	db := finalQueuePolicyDB(t)
	artifact, err := canonicalFinalQueueArtifact(finalQueueFixture())
	if err != nil {
		t.Fatal(err)
	}
	artifact.ArtifactID = "artifact-copy-canceled"
	artifact.SignedMessageID = "<copy-canceled@example.test>"
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	created, err := insertFinalQueueArtifactParentTx(context.Background(), tx, artifact)
	if err != nil || !created {
		t.Fatalf("parent insert created=%v err=%v", created, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := copyFinalQueueRecipients(canceled, tx, artifact); err == nil {
		t.Fatal("canceled COPY unexpectedly succeeded")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM final_queue_artifacts WHERE artifact_id=$1", artifact.ArtifactID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("parent leaked after canceled COPY rollback: %d", count)
	}
	if err := db.QueryRow("SELECT count(*) FROM final_queue_recipients WHERE artifact_id=$1", artifact.ArtifactID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("children leaked after canceled COPY rollback: %d", count)
	}
}

func TestFinalQueueRejectsBoundarySizesInvalidIDsAndTimes(t *testing.T) {
	db := finalQueuePolicyDB(t)
	fq := FinalQueueStore{DB: db, InstanceID: finalQueueInstanceID}
	valid := finalQueueFixture()
	for _, tc := range []struct {
		name   string
		mutate func(*FinalQueueArtifact)
	}{
		{"artifact id", func(a *FinalQueueArtifact) { a.ArtifactID = " bad " }},
		{"message id", func(a *FinalQueueArtifact) { a.SignedMessageID = "bad message" }},
		{"content size", func(a *FinalQueueArtifact) { a.ContentBytes = maxSignedArtifactBytes + 1 }},
		{"signed after prepared", func(a *FinalQueueArtifact) { a.SignedDate = a.PreparedAt.Add(time.Second) }},
		{"expiry", func(a *FinalQueueArtifact) { a.ExpiresAt = a.PreparedAt }},
		{"source revision", func(a *FinalQueueArtifact) { a.Sources[0].Revision = 0 }},
		{"null mapping", func(a *FinalQueueArtifact) { a.EnvelopeSender = "<>"; a.NullEnvelopeSender = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := valid
			candidate.Sources = append([]FinalQueueSource(nil), valid.Sources...)
			candidate.Recipients = append([]string(nil), valid.Recipients...)
			tc.mutate(&candidate)
			if _, err := fq.PrepareFinalQueueArtifact(context.Background(), candidate); err == nil {
				t.Fatal("invalid artifact accepted")
			}
		})
	}
	prepared, err := fq.PrepareFinalQueueArtifact(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	registerFixtureQueue(t, db, prepared, "HJKLMNPQRSTVz2345", strings.Repeat("1", 64))
	if _, err := fq.BindFinalQueueArtifact(context.Background(), FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "bad", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(time.Minute)}); err == nil {
		t.Fatal("invalid queue id accepted")
	}
	if _, err := fq.BindFinalQueueArtifact(context.Background(), FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "HJKLMNPQRSTVz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.PreparedAt.Add(-time.Second)}); err == nil {
		t.Fatal("bound time before prepared accepted")
	}
	if _, err := fq.BindFinalQueueArtifact(context.Background(), FinalQueueBinding{ArtifactID: prepared.ArtifactID, InstanceID: finalQueueInstanceID, QueueID: "HJKLMNPQRSTVz2345", ArrivalFingerprint: strings.Repeat("1", 64), BoundAt: prepared.ExpiresAt}); err == nil {
		t.Fatal("bound time at expiry accepted")
	}
}
