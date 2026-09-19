package notifyruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestApprovalExecutorConfirmsAndExecutesQueueFlushOnce(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := notification.SQLActorMapper{DB: db}
	now := time.Unix(1, 0).UTC()
	transportActor := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:flush"}}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	approvals := notification.SQLApprovalStore{DB: db}
	queue := &fakeQueueController{snapshot: outboundpolicy.QueueSnapshot{Active: 3, Deferred: 1, Total: 4, Digest: strings.Repeat("a", 64)}}
	requestHash, err := queueApprovalRequestHash(context.Background(), "queue:flush", authz.Resource{Type: "queue", ID: "default"}, queue)
	if err != nil {
		t.Fatal(err)
	}
	created, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Initiator: actor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: requestHash, CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvals.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	exec := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Authorizer: authz.StaticAuthorizer{}, Queue: queue, Audit: audit.SQLWriter{DB: db}, Now: func() time.Time { return now.Add(10 * time.Second) }}
	result, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", created.BindingToken, transportActor)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Executed || result.Action != "queue:flush" || queue.flushes != 1 {
		t.Fatalf("not executed result=%#v flushes=%d", result, queue.flushes)
	}
	var successAudits int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='notification.approval.execute' AND result='success' AND resource_id='default'`).Scan(&successAudits); err != nil || successAudits != 1 {
		t.Fatalf("success audits=%d err=%v", successAudits, err)
	}
	if _, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", created.BindingToken, transportActor); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestApprovalExecutorRecoversMutationFailureAndExpiredClaim(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := notification.SQLActorMapper{DB: db}
	now := time.Unix(20, 0).UTC()
	ta := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:flush"}}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: ta, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	queue := &fakeQueueController{snapshot: outboundpolicy.QueueSnapshot{Total: 1, Active: 1, Digest: strings.Repeat("c", 64)}, flushErr: errors.New("postfix unavailable")}
	hash, err := queueApprovalRequestHash(context.Background(), "queue:flush", authz.Resource{Type: "queue", ID: "default"}, queue)
	if err != nil {
		t.Fatal(err)
	}
	approvalStore := notification.SQLApprovalStore{DB: db}
	created, err := approvalStore.Create(context.Background(), notification.ApprovalRequest{ID: "approval-recover", TransportActor: ta, Initiator: actor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: hash, CorrelationID: "corr-recover", ExpiresAt: now.Add(10 * time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvalStore.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	executor := ApprovalExecutor{Mapper: mapper, Approvals: approvalStore, Authorizer: authz.StaticAuthorizer{}, Queue: queue, Audit: audit.SQLWriter{DB: db}, Now: func() time.Time { return now.Add(time.Minute) }}
	if _, err := executor.ExecuteTelegramApproval(context.Background(), created.ID, created.BindingToken, ta); err == nil {
		t.Fatal("mutation failure accepted")
	}
	pending, _, err := approvalStore.Get(context.Background(), created.ID)
	if err != nil || pending.Result != "pending" || pending.ExecutionAttempts != 1 {
		t.Fatalf("pending=%#v err=%v", pending, err)
	}
	claimed, err := approvalStore.Claim(context.Background(), notification.ApprovalConfirmation{ID: created.ID, TransportActor: ta, Actor: actor, Action: created.Action, Resource: created.Resource, RequestHash: created.RequestHash, BindingToken: created.BindingToken, Now: now.Add(2 * time.Minute)}, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Result != "executing" {
		t.Fatalf("claimed=%#v", claimed)
	}
	executor.Now = func() time.Time { return now.Add(5 * time.Minute) }
	result, err := executor.ExecuteTelegramApproval(context.Background(), created.ID, created.BindingToken, ta)
	if err != nil || !result.Executed || queue.flushes != 1 {
		t.Fatalf("result=%#v flushes=%d err=%v", result, queue.flushes, err)
	}
}

func TestApprovalExecutorRecoversAmbiguousPostMutationCrashAfterQueueChanges(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := notification.SQLActorMapper{DB: db}
	now := time.Unix(25, 0).UTC()
	ta := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:flush"}}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: ta, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	queue := &fakeQueueController{snapshot: outboundpolicy.QueueSnapshot{Deferred: 1, Total: 1, Digest: strings.Repeat("d", 64)}}
	hash, err := queueApprovalRequestHash(context.Background(), "queue:flush", authz.Resource{Type: "postfix_queue", ID: "default"}, queue)
	if err != nil {
		t.Fatal(err)
	}
	approvals := notification.SQLApprovalStore{DB: db}
	created, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-ambiguous", TransportActor: ta, Initiator: actor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "postfix_queue", ID: "default"}, RequestHash: hash, CorrelationID: "corr-ambiguous", ExpiresAt: now.Add(10 * time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvals.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	executor := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Authorizer: authz.StaticAuthorizer{}, Queue: queue, Audit: audit.SQLWriter{DB: db}, Lease: time.Second, Now: func() time.Time { return now.Add(time.Second) }, AfterMutation: func(notification.ApprovalRequest) error {
		queue.snapshot = outboundpolicy.QueueSnapshot{Digest: strings.Repeat("e", 64)}
		return errors.New("injected crash after queue mutation")
	}}
	if _, err := executor.ExecuteTelegramApproval(context.Background(), created.ID, created.BindingToken, ta); err == nil {
		t.Fatal("injected ambiguous failure was hidden")
	}
	executing, _, err := approvals.Get(context.Background(), created.ID)
	if err != nil || executing.Result != "executing" || executing.ExecutionAttempts != 1 {
		t.Fatalf("executing=%#v err=%v", executing, err)
	}
	executor.AfterMutation = nil
	executor.Now = func() time.Time { return now.Add(3 * time.Second) }
	result, err := executor.ExecuteTelegramApproval(context.Background(), created.ID, created.BindingToken, ta)
	if err != nil || !result.Executed || queue.flushes != 2 {
		t.Fatalf("recovery result=%#v flushes=%d err=%v", result, queue.flushes, err)
	}
	approved, _, err := approvals.Get(context.Background(), created.ID)
	if err != nil || approved.Result != "approved" || approved.ExecutionAttempts != 2 {
		t.Fatalf("approved=%#v err=%v", approved, err)
	}
}

func TestApprovalExecutorRejectsUnsupportedMutationBeforeConfirmation(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := notification.SQLActorMapper{DB: db}
	now := time.Unix(2, 0).UTC()
	transportActor := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"domain:delete"}}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	approvals := notification.SQLApprovalStore{DB: db}
	created, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Initiator: actor, Actor: actor, Action: "domain:delete", Resource: authz.Resource{Type: "domain", ID: "example.test"}, RequestHash: "sha256:abc", CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvals.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	aud := &audit.MemoryWriter{}
	exec := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Authorizer: authz.StaticAuthorizer{}, Queue: &fakeQueueController{}, Audit: aud, Now: func() time.Time { return now.Add(10 * time.Second) }}
	result, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", created.BindingToken, transportActor)
	if err == nil || !strings.Contains(err.Error(), "unsupported") || result.Executed {
		t.Fatalf("unsupported mutation executed result=%#v err=%v", result, err)
	}
	if len(aud.Events) == 0 || aud.Events[len(aud.Events)-1].Result != "denied" {
		t.Fatalf("missing failure audit: %#v", aud.Events)
	}
	pending, ok, err := approvals.Get(context.Background(), created.ID)
	if err != nil || !ok || pending.Result != "pending" || pending.UsedAt != nil {
		t.Fatalf("unsupported mutation consumed approval: approval=%#v ok=%v err=%v", pending, ok, err)
	}
}

func TestApprovalExecutorRejectsUnmappedActorBeforeConfirmation(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	exec := ApprovalExecutor{Mapper: notification.SQLActorMapper{DB: db}, Approvals: notification.SQLApprovalStore{DB: db}, Authorizer: authz.StaticAuthorizer{}, Queue: &fakeQueueController{}, Audit: audit.SQLWriter{DB: db}, Now: func() time.Time { return time.Unix(3, 0) }}
	if _, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", "abcdefghijklmnopqrstuv", notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}); err == nil || !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("unmapped actor accepted: %v", err)
	}
}

func TestApprovalExecutorRequiresAuditWriter(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	exec := ApprovalExecutor{
		Mapper:     notification.SQLActorMapper{DB: db},
		Approvals:  notification.SQLApprovalStore{DB: db},
		Authorizer: authz.StaticAuthorizer{},
		Queue:      &fakeQueueController{},
	}
	_, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", "abcdefghijklmnopqrstuv", notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"})
	if err == nil || !strings.Contains(err.Error(), "dependencies") {
		t.Fatalf("missing audit writer accepted: %v", err)
	}
}

func TestApprovalExecutorRejectsChangedQueueStateWithoutConsumingPrompt(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	now := time.Unix(4, 0).UTC()
	transportActor := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:flush"}}
	mapper := notification.SQLActorMapper{DB: db}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	queue := &fakeQueueController{snapshot: outboundpolicy.QueueSnapshot{Active: 1, Total: 1, Digest: strings.Repeat("a", 64)}}
	requestHash, err := queueApprovalRequestHash(context.Background(), "queue:flush", authz.Resource{Type: "queue", ID: "default"}, queue)
	if err != nil {
		t.Fatal(err)
	}
	approvals := notification.SQLApprovalStore{DB: db}
	created, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-change", TransportActor: transportActor, Initiator: actor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: requestHash, CorrelationID: "corr-change", ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := approvals.Activate(context.Background(), created.ID, now); err != nil {
		t.Fatal(err)
	}
	queue.snapshot.Active = 2
	queue.snapshot.Total = 2
	executor := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Authorizer: authz.StaticAuthorizer{}, Queue: queue, Audit: audit.SQLWriter{DB: db}, Now: func() time.Time { return now.Add(10 * time.Second) }}
	if _, err := executor.ExecuteTelegramApproval(context.Background(), created.ID, created.BindingToken, transportActor); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed queue state accepted: %v", err)
	}
	pending, ok, err := approvals.Get(context.Background(), created.ID)
	if err != nil || !ok || pending.Result != "pending" || pending.UsedAt != nil {
		t.Fatalf("changed request consumed prompt: %#v ok=%v err=%v", pending, ok, err)
	}
}
