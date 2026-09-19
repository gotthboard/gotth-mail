package notification

import (
	"context"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestSQLActorMapperRequiresExplicitMapping(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	ctx := context.Background()
	if _, ok, err := mapper.Map(ctx, TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}); err != nil || ok {
		t.Fatalf("unexpected unmapped result ok=%v err=%v", ok, err)
	}
	if err := mapper.Put(ctx, ActorMapping{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Actor: authz.Actor{Type: "api_token", ID: "ops-reader", Scopes: []string{"status:read", "notification:read"}}}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := mapper.Map(ctx, TransportActor{Transport: "TELEGRAM", ExternalID: "chat:42:user:99"})
	if err != nil || !ok {
		t.Fatalf("mapped ok=%v err=%v", ok, err)
	}
	if got.Type != "api_token" || got.ID != "ops-reader" || strings.Join(got.Scopes, ",") != "status:read,notification:read" {
		t.Fatalf("bad actor: %#v", got)
	}
}

func approvalFixture(now time.Time) ApprovalRequest {
	return ApprovalRequest{ID: "approval-1", TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Initiator: authz.Actor{Type: "api_token", ID: "approval-admin"}, Actor: authz.Actor{Type: "api_token", ID: "ops-admin"}, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "mail.example.test"}, RequestHash: "sha256:abcdef", CorrelationID: "corr-1", ExpiresAt: now.Add(5 * time.Minute)}
}

func confirmationFixture(now time.Time) ApprovalConfirmation {
	return ApprovalConfirmation{ID: "approval-1", TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Actor: authz.Actor{Type: "api_token", ID: "ops-admin"}, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "mail.example.test"}, RequestHash: "sha256:abcdef", Now: now.Add(time.Minute)}
}

func TestSQLApprovalStoreAcceptsExactBindingOnce(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	store := SQLApprovalStore{DB: db}
	now := time.Unix(10, 0).UTC()
	created, err := store.Create(context.Background(), approvalFixture(now), now)
	if err != nil {
		t.Fatal(err)
	}
	if created.Result != "creating" || created.ID != "approval-1" {
		t.Fatalf("bad created approval: %#v", created)
	}
	if err := store.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	confirmation := confirmationFixture(now)
	confirmation.BindingToken = created.BindingToken
	approved, err := store.Claim(context.Background(), confirmation, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(context.Background(), approved.ID, confirmation.Now); err != nil {
		t.Fatal(err)
	}
	approved, _, _ = store.Get(context.Background(), approved.ID)
	if approved.Result != "approved" || approved.UsedAt == nil {
		t.Fatalf("not marked approved: %#v", approved)
	}
	if _, err := store.Claim(context.Background(), confirmation, 2*time.Minute); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay accepted: %v", err)
	}
	var auditCount int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE correlation_id='corr-1' AND action IN ('notification.approval.create','notification.approval.confirm','notification.approval.execute')`).Scan(&auditCount); err != nil || auditCount != 4 {
		t.Fatalf("durable audit count=%d err=%v", auditCount, err)
	}
	var creator string
	if err := db.QueryRow(`SELECT actor_id FROM audit_events WHERE correlation_id='corr-1' AND action='notification.approval.create'`).Scan(&creator); err != nil || creator != "approval-admin" {
		t.Fatalf("approval creator audit actor=%q err=%v", creator, err)
	}
}

func TestSQLApprovalStoreRejectsMismatchAndExpiry(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	store := SQLApprovalStore{DB: db}
	now := time.Unix(20, 0).UTC()
	created, err := store.Create(context.Background(), approvalFixture(now), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	mismatch := confirmationFixture(now)
	mismatch.BindingToken = created.BindingToken
	mismatch.RequestHash = "sha256:changed"
	if _, err := store.Claim(context.Background(), mismatch, 2*time.Minute); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("mismatch accepted: %v", err)
	}
	got, ok, err := store.Get(context.Background(), "approval-1")
	if err != nil || !ok || got.Result != "pending" || got.UsedAt != nil {
		t.Fatalf("mismatch consumed legitimate approval: got=%#v ok=%v err=%v", got, ok, err)
	}
	legitimate := confirmationFixture(now)
	legitimate.BindingToken = created.BindingToken
	if _, err := store.Claim(context.Background(), legitimate, 2*time.Minute); err != nil {
		t.Fatalf("legitimate confirmation failed after mismatch: %v", err)
	}

	expired := approvalFixture(now)
	expired.ID = "approval-2"
	expiredCreated, err := store.Create(context.Background(), expired, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(context.Background(), expiredCreated.ID, now); err != nil {
		t.Fatal(err)
	}
	c := confirmationFixture(now)
	c.ID = "approval-2"
	c.BindingToken = expiredCreated.BindingToken
	c.Now = expired.ExpiresAt
	if _, err := store.Claim(context.Background(), c, 2*time.Minute); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired approval accepted: %v", err)
	}
	got, ok, err = store.Get(context.Background(), "approval-2")
	if err != nil || !ok || got.Result != "expired" {
		t.Fatalf("expired approval state=%#v ok=%v err=%v", got, ok, err)
	}
}

func TestSQLApprovalCreateRejectsIncompleteOrExpiredRequests(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	store := SQLApprovalStore{DB: db}
	now := time.Unix(30, 0).UTC()
	bad := approvalFixture(now)
	bad.Actor.ID = ""
	if _, err := store.Create(context.Background(), bad, now); err == nil {
		t.Fatal("incomplete approval accepted")
	}
	bad = approvalFixture(now)
	bad.ID = "approval-expired"
	bad.ExpiresAt = now
	if _, err := store.Create(context.Background(), bad, now); err == nil {
		t.Fatal("expired approval accepted")
	}
	bad = approvalFixture(now)
	bad.ID = "approval-caller-token"
	bad.BindingToken = "abcdefghijklmnopqrstuv"
	if _, err := store.Create(context.Background(), bad, now); err == nil || !strings.Contains(err.Error(), "generated by the store") {
		t.Fatalf("caller-controlled binding token accepted: %v", err)
	}
}

func TestSQLApprovalStoreExpiresStaleExecutingClaim(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	approvalStore := SQLApprovalStore{DB: db}
	now := time.Unix(35, 0).UTC()
	created, err := approvalStore.Create(context.Background(), approvalFixture(now), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvalStore.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	confirmation := confirmationFixture(now)
	confirmation.BindingToken = created.BindingToken
	confirmation.Now = now.Add(time.Second)
	if _, err := approvalStore.Claim(context.Background(), confirmation, time.Second); err != nil {
		t.Fatal(err)
	}
	confirmation.Now = created.ExpiresAt
	if _, err := approvalStore.Claim(context.Background(), confirmation, time.Second); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired executing approval accepted: %v", err)
	}
	got, ok, err := approvalStore.Get(context.Background(), created.ID)
	if err != nil || !ok || got.Result != "expired" {
		t.Fatalf("expired executing state=%#v ok=%v err=%v", got, ok, err)
	}
}

func TestSQLApprovalStateChangesRollbackWhenAuditIsUnavailable(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	store := SQLApprovalStore{DB: db}
	now := time.Unix(40, 0).UTC()
	created, err := store.Create(context.Background(), approvalFixture(now), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`ALTER TABLE audit_events RENAME TO audit_events_unavailable`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`ALTER TABLE audit_events_unavailable RENAME TO audit_events`)
	confirmation := confirmationFixture(now)
	confirmation.BindingToken = created.BindingToken
	if _, err := store.Claim(context.Background(), confirmation, 2*time.Minute); err == nil {
		t.Fatal("claim committed without durable audit")
	}
	got, ok, err := store.Get(context.Background(), created.ID)
	if err != nil || !ok || got.Result != "pending" || got.ExecutionAttempts != 0 {
		t.Fatalf("claim did not roll back got=%#v ok=%v err=%v", got, ok, err)
	}
	second := approvalFixture(now)
	second.ID = "approval-audit-failure"
	if _, err := store.Create(context.Background(), second, now); err == nil {
		t.Fatal("create committed without durable audit")
	}
	if _, ok, err := store.Get(context.Background(), second.ID); err != nil || ok {
		t.Fatalf("unaudited approval persisted ok=%v err=%v", ok, err)
	}
}
