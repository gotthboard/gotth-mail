package notifyruntime

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type capturePrompter struct {
	prompt plugin.NotificationPrompt
	err    error
}

func (p *capturePrompter) SendPrompt(_ context.Context, prompt plugin.NotificationPrompt) (plugin.PromptResult, error) {
	p.prompt = prompt
	return plugin.PromptResult{Accepted: p.err == nil}, p.err
}

func TestApprovalServiceCreatesAndDeliversBoundPromptWithoutReturningSecret(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	now := time.Unix(100, 0).UTC()
	transportActor := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:flush"}}
	mapper := notification.SQLActorMapper{DB: db}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	prompter := &capturePrompter{}
	service := ApprovalService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Store: notification.SQLApprovalStore{DB: db}, Prompter: prompter, Queue: &fakeQueueController{snapshot: outboundpolicy.QueueSnapshot{Active: 2, Total: 2, Digest: strings.Repeat("a", 64)}}, Now: func() time.Time { return now }}
	created, err := service.RequestTelegramApproval(context.Background(), TelegramApprovalRequest{TransportActor: transportActor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute), Title: "Approve flush", Summary: "Flush deferred mail"})
	if err != nil {
		t.Fatal(err)
	}
	if created.BindingToken != "" || created.BindingHash == "" || prompter.prompt.ConfirmationToken == "" || prompter.prompt.ID != created.ID {
		t.Fatalf("created=%#v prompt=%#v", created, prompter.prompt)
	}
}

func TestApprovalServiceInvalidatesPromptWhenDeliveryFails(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	now := time.Unix(200, 0).UTC()
	transportActor := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:retry"}}
	mapper := notification.SQLActorMapper{DB: db}
	if err := mapper.Put(context.Background(), notification.ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	approvalStore := notification.SQLApprovalStore{DB: db}
	prompter := &capturePrompter{err: errors.New("delivery unavailable")}
	service := ApprovalService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Store: approvalStore, Prompter: prompter, Queue: &fakeQueueController{snapshot: outboundpolicy.QueueSnapshot{Digest: strings.Repeat("b", 64)}}, Now: func() time.Time { return now }}
	if _, err := service.RequestTelegramApproval(context.Background(), TelegramApprovalRequest{TransportActor: transportActor, Action: "queue:retry", Resource: authz.Resource{Type: "queue", ID: "default"}, CorrelationID: "corr-2", ExpiresAt: now.Add(time.Minute), Title: "Approve retry", Summary: "Retry deferred mail"}); err == nil {
		t.Fatal("delivery failure accepted")
	}
	stored, ok, err := approvalStore.Get(context.Background(), prompter.prompt.ID)
	if err != nil || !ok || stored.Result != "rejected" {
		t.Fatalf("stored=%#v ok=%v err=%v", stored, ok, err)
	}
}
