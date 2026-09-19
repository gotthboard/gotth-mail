package notifyruntime

import (
	"context"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/ops"
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
	queue := &ops.Queue{Summary: ops.QueueSummary{Active: 3, Deferred: []string{"a"}}}
	requestHash, err := queueApprovalRequestHash("queue:flush", authz.Resource{Type: "queue", ID: "default"}, queue)
	if err != nil {
		t.Fatal(err)
	}
	created, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: requestHash, CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	aud := &audit.MemoryWriter{}
	exec := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Authorizer: authz.StaticAuthorizer{}, Queue: queue, Audit: aud, Now: func() time.Time { return now.Add(10 * time.Second) }}
	result, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", created.BindingToken, transportActor)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Executed || result.Action != "queue:flush" || queue.Summary.Active != 0 {
		t.Fatalf("not executed result=%#v queue=%#v", result, queue.Summary)
	}
	if len(aud.Events) < 2 || aud.Events[len(aud.Events)-1].Action != "notification.approval.execute" || aud.Events[len(aud.Events)-1].Result != "success" {
		t.Fatalf("missing execution audit: %#v", aud.Events)
	}
	if _, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", created.BindingToken, transportActor); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay accepted: %v", err)
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
	created, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Actor: actor, Action: "domain:delete", Resource: authz.Resource{Type: "domain", ID: "example.test"}, RequestHash: "sha256:abc", CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	aud := &audit.MemoryWriter{}
	exec := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Authorizer: authz.StaticAuthorizer{}, Queue: &ops.Queue{}, Audit: aud, Now: func() time.Time { return now.Add(10 * time.Second) }}
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
	exec := ApprovalExecutor{Mapper: notification.SQLActorMapper{DB: db}, Approvals: notification.SQLApprovalStore{DB: db}, Authorizer: authz.StaticAuthorizer{}, Queue: &ops.Queue{}, Now: func() time.Time { return time.Unix(3, 0) }}
	if _, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", "abcdefghijklmnopqrstuv", notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}); err == nil || !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("unmapped actor accepted: %v", err)
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
	queue := &ops.Queue{Summary: ops.QueueSummary{Active: 1, Deferred: []string{"a"}}}
	requestHash, err := queueApprovalRequestHash("queue:flush", authz.Resource{Type: "queue", ID: "default"}, queue)
	if err != nil {
		t.Fatal(err)
	}
	approvals := notification.SQLApprovalStore{DB: db}
	created, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-change", TransportActor: transportActor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: requestHash, CorrelationID: "corr-change", ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	queue.Summary.Active = 2
	executor := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Authorizer: authz.StaticAuthorizer{}, Queue: queue, Now: func() time.Time { return now.Add(10 * time.Second) }}
	if _, err := executor.ExecuteTelegramApproval(context.Background(), created.ID, created.BindingToken, transportActor); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed queue state accepted: %v", err)
	}
	pending, ok, err := approvals.Get(context.Background(), created.ID)
	if err != nil || !ok || pending.Result != "pending" || pending.UsedAt != nil {
		t.Fatalf("changed request consumed prompt: %#v ok=%v err=%v", pending, ok, err)
	}
}
