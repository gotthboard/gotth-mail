package notifyruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const testTelegramToken = "123456789:test-telegram-token"
const testBindingToken = "abcdefghijklmnopqrstuv"

func TestTelegramBackendDeliversSanitizedAlert(t *testing.T) {
	var got telegramSendMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/bot"+testTelegramToken+"/sendMessage" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":77}}`))
	}))
	defer server.Close()
	backend, err := NewTelegramBackend(TelegramConfig{BotToken: testTelegramToken, AlertChatID: "-10042", APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.SendAlert(context.Background(), notification.Alert{ID: "alert-1", Class: "doctor.failure", Severity: notification.SeverityCritical, Title: "Doctor failed", Summary: "password=hunter2", Details: map[string]string{"token": "secret", "node": "mail-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != notification.StatusDelivered || result.Evidence.MessageID != "telegram:-10042:77" || got.ChatID != "-10042" {
		t.Fatalf("result=%#v payload=%#v", result, got)
	}
	if strings.Contains(got.Text, "hunter2") || strings.Contains(got.Text, "secret") || !strings.Contains(got.Text, "[REDACTED]") {
		t.Fatalf("unsafe alert text: %q", got.Text)
	}
}

func TestTelegramBackendDeliversBoundApprovalPrompt(t *testing.T) {
	var got telegramSendMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":78}}`))
	}))
	defer server.Close()
	backend, err := NewTelegramBackend(TelegramConfig{BotToken: testTelegramToken, AlertChatID: "42", AllowedChatIDs: []string{"-10055"}, APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	prompt := plugin.NotificationPrompt{ID: "00000000-0000-4000-8000-000000000001", CorrelationID: "corr-1", Transport: "telegram", ExternalActorID: "chat:-10055:user:99", ActorType: "api_token", ActorID: "ops", Action: "queue:flush", ResourceType: "queue", ResourceID: "default", RequestHash: "sha256:abc", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Title: "Approve queue flush", Summary: "Flush deferred queue", ConfirmationToken: testBindingToken}
	result, err := backend.SendPrompt(context.Background(), prompt)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || got.ChatID != "-10055" || got.ReplyMarkup == nil {
		t.Fatalf("result=%#v payload=%#v", result, got)
	}
	callback := got.ReplyMarkup.InlineKeyboard[0][0].CallbackData
	if callback != "gm:a:"+prompt.ID+":"+testBindingToken || len(callback) > 64 {
		t.Fatalf("callback=%q", callback)
	}
}

func TestTelegramBackendRejectsUnsafeConfigurationAndPrompt(t *testing.T) {
	if _, err := NewTelegramBackend(TelegramConfig{BotToken: testTelegramToken, AlertChatID: "42", APIBaseURL: "https://example.com"}); err == nil {
		t.Fatal("arbitrary API host accepted")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("unexpected delivery") }))
	defer server.Close()
	backend, err := NewTelegramBackend(TelegramConfig{BotToken: testTelegramToken, AlertChatID: "42", APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = backend.SendPrompt(context.Background(), plugin.NotificationPrompt{ID: "prompt", CorrelationID: "corr", Transport: "telegram", ExternalActorID: "chat:99:user:1", ActorType: "api_token", ActorID: "ops", Action: "queue:flush", ResourceType: "queue", ResourceID: "default", RequestHash: "hash", ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Title: "Approve", Summary: "Do it", ConfirmationToken: testBindingToken})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("disallowed chat error=%v", err)
	}
}

func TestTelegramBackendClassifiesAPIOutageWithoutLeakingResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"ok":false,"description":"bot token=private"}`))
	}))
	defer server.Close()
	backend, err := NewTelegramBackend(TelegramConfig{BotToken: testTelegramToken, AlertChatID: "42", APIBaseURL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.SendAlert(context.Background(), notification.Alert{ID: "alert-1", Class: "doctor.failure", Title: "failed", Summary: "failed"})
	if status.Code(err) != codes.Unavailable || result.Status != notification.StatusFailedRetryable || strings.Contains(err.Error(), "private") {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}
