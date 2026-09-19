package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/notifyruntime"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type approvalAPIPrompter struct{ prompt plugin.NotificationPrompt }

func (p *approvalAPIPrompter) SendPrompt(_ context.Context, prompt plugin.NotificationPrompt) (plugin.PromptResult, error) {
	p.prompt = prompt
	return plugin.PromptResult{Accepted: true}, nil
}

type approvalAPIQueue struct {
	retried string
	calls   int
}

func (q *approvalAPIQueue) Snapshot(_ context.Context, selector string) (outboundpolicy.QueueSnapshot, error) {
	return outboundpolicy.QueueSnapshot{Deferred: 1, Total: 1, Digest: strings.Repeat("a", 64)}, nil
}
func (q *approvalAPIQueue) Flush(context.Context) error { q.calls++; return nil }
func (q *approvalAPIQueue) Retry(_ context.Context, queueID string) error {
	q.calls++
	q.retried = queueID
	return nil
}

func TestQueueApprovalAPIToTelegramCallbackExecutesDurably(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("approval-initiator", "api_token", "approval-initiator-secret", "notification:approval.create"); err != nil {
		t.Fatal(err)
	}
	mapper := notification.SQLActorMapper{DB: db}
	transportActor := notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	if err := mapper.ReplaceTelegram(context.Background(), []notification.ActorMapping{{TransportActor: transportActor, Actor: authz.Actor{Type: "api_token", ID: "telegram-operator", Scopes: []string{"queue:retry"}}}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	queue := &approvalAPIQueue{}
	prompter := &approvalAPIPrompter{}
	approvalStore := notification.SQLApprovalStore{DB: db}
	service := &notifyruntime.ApprovalService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Store: approvalStore, Prompter: prompter, Queue: queue}
	server := Server{AuditDB: db, Identity: ids, Authz: authz.StaticAuthorizer{}, ApprovalService: service}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/queue/retry", bytes.NewBufferString(`{"external_actor_id":"chat:42:user:99","queue_id":"4hnGXw0JJWzhPMN"}`))
	request.Header.Set("Authorization", "Bearer approval-initiator-secret")
	request.Header.Set("X-Correlation-ID", "approval-api-test")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("initiation status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if prompter.prompt.ID == "" || prompter.prompt.ConfirmationToken == "" || prompter.prompt.ResourceID != "4hnGXw0JJWzhPMN" {
		t.Fatalf("incomplete prompt: %#v", prompter.prompt)
	}
	executor := notifyruntime.ApprovalExecutor{Mapper: mapper, Approvals: approvalStore, Authorizer: authz.StaticAuthorizer{}, Queue: queue, Audit: audit.SQLWriter{DB: db}}
	receiver := notification.TelegramReceiver{
		Updates: notification.SQLTelegramUpdateStore{DB: db},
		ExecuteApproval: func(ctx context.Context, id, token string, actor notification.TransportActor) error {
			_, err := executor.ExecuteTelegramApproval(ctx, id, token, actor)
			return err
		},
	}
	callback := map[string]any{"update_id": 1001, "callback_query": map[string]any{"id": "callback-1", "from": map[string]any{"id": 99}, "message": map[string]any{"message_id": 7, "from": map[string]any{"id": 99}, "chat": map[string]any{"id": 42}, "text": "approval"}, "data": "gm:a:" + prompter.prompt.ID + ":" + prompter.prompt.ConfirmationToken}}
	body, _ := json.Marshal(callback)
	callbackRequest := httptest.NewRequest(http.MethodPost, "/internal/v1/notifications/telegram", bytes.NewReader(body))
	callbackRequest.Header.Set("X-Telegram-Bot-Api-Secret-Token", "webhook-secret-123456")
	callbackRecorder := httptest.NewRecorder()
	receiver.HandlerWithSecret("webhook-secret-123456").ServeHTTP(callbackRecorder, callbackRequest)
	if callbackRecorder.Code != http.StatusOK || !strings.Contains(callbackRecorder.Body.String(), "approval accepted") {
		t.Fatalf("callback status=%d body=%s", callbackRecorder.Code, callbackRecorder.Body.String())
	}
	if queue.calls != 1 || queue.retried != "4hnGXw0JJWzhPMN" {
		t.Fatalf("queue mutation calls=%d retry=%q", queue.calls, queue.retried)
	}
	var result string
	if err := db.QueryRow(`SELECT result FROM notification_approvals WHERE id=$1`, prompter.prompt.ID).Scan(&result); err != nil || result != "approved" {
		t.Fatalf("approval result=%q err=%v", result, err)
	}
	var auditCount int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE action='notification.approval.execute' AND resource_id='4hnGXw0JJWzhPMN' AND result='success'`).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("success audit count=%d err=%v", auditCount, err)
	}
}
