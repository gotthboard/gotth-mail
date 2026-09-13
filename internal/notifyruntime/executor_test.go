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
	actor := authz.Actor{Type: "api_token", ID: "ops"}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	approvals := notification.SQLApprovalStore{DB: db}
	if _, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: "sha256:abc", CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	aud := &audit.MemoryWriter{}
	queue := &ops.Queue{Summary: ops.QueueSummary{Active: 3, Deferred: []string{"a"}}}
	exec := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Queue: queue, Audit: aud, Now: func() time.Time { return now.Add(10 * time.Second) }}
	result, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", transportActor)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Executed || result.Action != "queue:flush" || queue.Summary.Active != 0 {
		t.Fatalf("not executed result=%#v queue=%#v", result, queue.Summary)
	}
	if len(aud.Events) < 2 || aud.Events[len(aud.Events)-1].Action != "notification.approval.execute" || aud.Events[len(aud.Events)-1].Result != "success" {
		t.Fatalf("missing execution audit: %#v", aud.Events)
	}
	if _, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", transportActor); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replay accepted: %v", err)
	}
}

func TestApprovalExecutorRejectsUnsupportedMutationAfterConfirmation(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := notification.SQLActorMapper{DB: db}
	now := time.Unix(2, 0).UTC()
	transportActor := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops"}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	approvals := notification.SQLApprovalStore{DB: db}
	if _, err := approvals.Create(context.Background(), notification.ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Actor: actor, Action: "domain:delete", Resource: authz.Resource{Type: "domain", ID: "example.test"}, RequestHash: "sha256:abc", CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	aud := &audit.MemoryWriter{}
	exec := ApprovalExecutor{Mapper: mapper, Approvals: approvals, Queue: &ops.Queue{}, Audit: aud, Now: func() time.Time { return now.Add(10 * time.Second) }}
	result, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", transportActor)
	if err == nil || !strings.Contains(err.Error(), "unsupported") || result.Executed {
		t.Fatalf("unsupported mutation executed result=%#v err=%v", result, err)
	}
	if len(aud.Events) == 0 || aud.Events[len(aud.Events)-1].Result != "failure" {
		t.Fatalf("missing failure audit: %#v", aud.Events)
	}
}

func TestApprovalExecutorRejectsUnmappedActorBeforeConfirmation(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	exec := ApprovalExecutor{Mapper: notification.SQLActorMapper{DB: db}, Approvals: notification.SQLApprovalStore{DB: db}, Queue: &ops.Queue{}, Now: func() time.Time { return time.Unix(3, 0) }}
	if _, err := exec.ExecuteTelegramApproval(context.Background(), "approval-1", notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}); err == nil || !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("unmapped actor accepted: %v", err)
	}
}
