package notification

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestTelegramReceiverRoutesReadOnlyCommandThroughCommandService(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	if err := mapper.Put(context.Background(), ActorMapping{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Actor: authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"doctor:read"}}}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	provider := &fakeSummaryProvider{out: "doctor ok password=hunter2"}
	recv := TelegramReceiver{Commands: CommandService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Provider: provider}}
	reply, err := recv.Process(context.Background(), telegramUpdate{Message: &telegramMessage{MessageID: 7, From: telegramUser{ID: 99}, Chat: telegramChat{ID: 42}, Text: "/doctor@GOTTH MailBot"}})
	if err != nil {
		t.Fatal(err)
	}
	if provider.got != CommandDoctorSummary || reply.ChatID != "42" || !strings.Contains(reply.Text, "[REDACTED]") || strings.Contains(reply.Text, "hunter2") {
		t.Fatalf("bad reply=%#v provider=%s", reply, provider.got)
	}
	rr := httptest.NewRecorder()
	recv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/telegram", strings.NewReader(`{"message":{"message_id":7,"from":{"id":99},"chat":{"id":42},"text":"/doctor"}}`)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"method":"sendMessage"`) {
		t.Fatalf("webhook reply status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestTelegramReceiverRejectsUnmappedCommandActor(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	recv := TelegramReceiver{Commands: CommandService{Mapper: SQLActorMapper{DB: db}, Authorizer: authz.StaticAuthorizer{}, Provider: &fakeSummaryProvider{out: "ok"}}}
	reply, err := recv.Process(context.Background(), telegramUpdate{Message: &telegramMessage{MessageID: 7, From: telegramUser{ID: 99}, Chat: telegramChat{ID: 42}, Text: "/doctor"}})
	if err == nil || !strings.Contains(err.Error(), "mapping") || !strings.Contains(reply.Text, "denied") {
		t.Fatalf("unmapped command accepted reply=%#v err=%v", reply, err)
	}
}

func TestTelegramReceiverConfirmsApprovalThroughSQLStoreOnce(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	now := time.Unix(10, 0).UTC()
	actor := authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:write"}}
	transportActor := TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	if err := mapper.Put(context.Background(), ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	approvals := SQLApprovalStore{DB: db}
	created, err := approvals.Create(context.Background(), ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: "sha256:abc", CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now)
	if err != nil || created.ID == "" {
		t.Fatalf("create=%#v err=%v", created, err)
	}
	recv := TelegramReceiver{ExecuteApproval: func(ctx context.Context, id, token string, transportActor TransportActor) error {
		mapped, ok, err := mapper.Map(ctx, transportActor)
		if err != nil || !ok {
			return errors.New("notification actor mapping required")
		}
		req, found, err := approvals.Get(ctx, id)
		if err != nil || !found {
			return errors.New("approval request not found")
		}
		claimed, err := approvals.Claim(ctx, ApprovalConfirmation{ID: id, TransportActor: transportActor, Actor: mapped, Action: req.Action, Resource: req.Resource, RequestHash: req.RequestHash, BindingToken: token, Now: now.Add(10 * time.Second)}, 2*time.Minute)
		if err != nil {
			return err
		}
		return approvals.Complete(ctx, claimed.ID, now.Add(10*time.Second))
	}}
	callback := "gm:a:approval-1:" + created.BindingToken
	reply, err := recv.Process(context.Background(), telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb-1", From: telegramUser{ID: 99}, Message: &telegramMessage{Chat: telegramChat{ID: 42}}, Data: callback}})
	if err != nil || reply.Text != "approval accepted" {
		t.Fatalf("approval rejected reply=%#v err=%v", reply, err)
	}
	if _, err := recv.Process(context.Background(), telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb-2", From: telegramUser{ID: 99}, Message: &telegramMessage{Chat: telegramChat{ID: 42}}, Data: callback}}); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("approval replay accepted: %v", err)
	}
}

func TestTelegramReceiverRejectsWrongCallbackActor(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	now := time.Unix(20, 0).UTC()
	actor := authz.Actor{Type: "api_token", ID: "ops"}
	transportActor := TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}
	if err := mapper.Put(context.Background(), ActorMapping{TransportActor: transportActor, Actor: actor}, now); err != nil {
		t.Fatal(err)
	}
	approvals := SQLApprovalStore{DB: db}
	if _, err := approvals.Create(context.Background(), ApprovalRequest{ID: "approval-1", TransportActor: transportActor, Actor: actor, Action: "queue:flush", Resource: authz.Resource{Type: "queue", ID: "default"}, RequestHash: "sha256:abc", CorrelationID: "corr-1", ExpiresAt: now.Add(time.Minute)}, now); err != nil {
		t.Fatal(err)
	}
	recv := TelegramReceiver{ExecuteApproval: func(ctx context.Context, id, token string, transportActor TransportActor) error {
		_, ok, err := mapper.Map(ctx, transportActor)
		if err != nil || !ok {
			return errors.New("notification actor mapping required")
		}
		return nil
	}}
	reply, err := recv.Process(context.Background(), telegramUpdate{CallbackQuery: &telegramCallbackQuery{ID: "cb-1", From: telegramUser{ID: 100}, Message: &telegramMessage{Chat: telegramChat{ID: 42}}, Data: "gm:a:approval-1:" + strings.Repeat("a", 22)}})
	if err == nil || !strings.Contains(err.Error(), "mapping") || !strings.Contains(reply.Text, "rejected") {
		t.Fatalf("wrong callback actor accepted reply=%#v err=%v", reply, err)
	}
}

func TestTelegramReceiverHTTPHandlerBoundsAndRejectsBadJSON(t *testing.T) {
	recv := TelegramReceiver{}
	rr := httptest.NewRecorder()
	recv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/telegram", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	recv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/telegram", bytes.NewBufferString("{")))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad json status=%d", rr.Code)
	}
	rr = httptest.NewRecorder()
	recv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/telegram", bytes.NewBufferString(`{} {}`)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("trailing json status=%d", rr.Code)
	}
}

func TestTelegramReceiverHTTPHandlerRequiresWebhookSecret(t *testing.T) {
	recv := TelegramReceiver{}
	handler := recv.HandlerWithSecret("webhook-secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/telegram", bytes.NewBufferString(`{}`)))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing secret status=%d", rr.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/telegram", bytes.NewBufferString(`{}`))
	req.Header.Set("X-Telegram-Bot-Api-Secret-Token", "webhook-secret")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || strings.Contains(strings.ToLower(rr.Body.String()), "unsupported") {
		t.Fatalf("authenticated error leaked detail status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestTelegramReceiverDeduplicatesAcceptedUpdate(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	calls := 0
	recv := TelegramReceiver{Updates: SQLTelegramUpdateStore{DB: db}, ExecuteApproval: func(context.Context, string, string, TransportActor) error { calls++; return nil }}
	handler := recv.HandlerWithSecret("webhook-secret")
	body := `{"update_id":123,"callback_query":{"id":"cb","from":{"id":99},"message":{"message_id":1,"from":{"id":99},"chat":{"id":42},"text":""},"data":"gm:a:approval-1:abcdefghijklmnopqrstuv"}}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/telegram", bytes.NewBufferString(body))
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", "webhook-secret")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "approval accepted") {
			t.Fatalf("attempt=%d status=%d body=%q", i, rr.Code, rr.Body.String())
		}
	}
	if calls != 1 {
		t.Fatalf("approval executed %d times", calls)
	}
}
