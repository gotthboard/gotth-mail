package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"google.golang.org/grpc"
)

type envTestQueue struct{}

func (envTestQueue) Snapshot(context.Context, string) (outboundpolicy.QueueSnapshot, error) {
	return outboundpolicy.QueueSnapshot{Digest: strings.Repeat("a", 64)}, nil
}
func (envTestQueue) Flush(context.Context) error         { return nil }
func (envTestQueue) Retry(context.Context, string) error { return nil }

func TestConfigureNotificationsWiresGRPCSQLAndAuthenticatedReceiver(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer()
	registration, err := plugin.FirstMechanismPlugin(plugin.FirstNotifyName, token)
	if err != nil {
		t.Fatal(err)
	}
	registry := plugin.Registry{Plugins: map[string]plugin.Registration{registration.Name: registration}}
	plugin.RegisterNotificationServer(grpcServer, plugin.NotificationServer{Name: registration.Name, Registry: registry, Sink: plugin.LocalNotificationSink{}})
	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	t.Setenv("GOTTH_MAIL_NOTIFICATION_PLUGIN_NAME", plugin.FirstNotifyName)
	t.Setenv("GOTTH_MAIL_NOTIFICATION_PLUGIN_ENDPOINT", listener.Addr().String())
	t.Setenv("GOTTH_MAIL_NOTIFICATION_PLUGIN_SERVICE_TOKEN", token)
	t.Setenv("GOTTH_MAIL_TELEGRAM_WEBHOOK_SECRET", "0123456789abcdef-webhook")
	mappingPath := filepath.Join(t.TempDir(), "telegram-actors.json")
	if err := os.WriteFile(mappingPath, []byte(`[{"external_id":"chat:42:user:99","actor_type":"api_token","actor_id":"ops","scopes":["queue:read"]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_TELEGRAM_ACTOR_MAPPINGS_FILE", mappingPath)
	db := testpg.DB(t, store.MigrateSQL)
	server := api.Server{AuditDB: db, Authz: authz.StaticAuthorizer{}, NotificationQueue: envTestQueue{}}
	backend, err := configureNotificationsFromEnv(&server)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if server.NotificationService == nil || server.NotificationPrompter == nil || server.NotificationReceiver == nil || server.NotificationRecorder == nil || server.ApprovalService == nil {
		t.Fatalf("incomplete notification wiring: %#v", server)
	}
	record, err := server.NotificationService.SendAlert(context.Background(), notification.Alert{ID: "runtime-alert-1", Class: "doctor.failure", Severity: notification.SeverityCritical, Title: "Doctor failed", Summary: "database failed", CorrelationID: "corr-1"})
	if err != nil || record.Status != notification.StatusDelivered {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	persisted, ok, err := server.NotificationRecorder.Get(context.Background(), "runtime-alert-1")
	if err != nil || !ok || persisted.Status != notification.StatusDelivered {
		t.Fatalf("persisted=%#v ok=%v err=%v", persisted, ok, err)
	}

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/notifications/telegram", strings.NewReader(`{}`))
	rr := httptest.NewRecorder()
	server.NotificationReceiver.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated webhook status=%d", rr.Code)
	}
}

func TestConfigureTelegramActorMappingsReplacesAndClearsAuthoritativeSet(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := notification.SQLActorMapper{DB: db}
	path := filepath.Join(t.TempDir(), "telegram-actors.json")
	if err := os.WriteFile(path, []byte(`[{"external_id":"chat:42:user:99","actor_type":"api_token","actor_id":"ops","scopes":["queue:retry"]}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOTTH_MAIL_TELEGRAM_ACTOR_MAPPINGS_FILE", path)
	if err := configureTelegramActorMappings(mapper, true); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := mapper.Map(context.Background(), notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}); err != nil || !ok {
		t.Fatalf("mapping absent ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(path, []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureTelegramActorMappings(mapper, true); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := mapper.Map(context.Background(), notification.TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}); err != nil || ok {
		t.Fatalf("stale mapping survived clear ok=%v err=%v", ok, err)
	}
	t.Setenv("GOTTH_MAIL_TELEGRAM_ACTOR_MAPPINGS_FILE", "")
	if err := configureTelegramActorMappings(mapper, true); err == nil {
		t.Fatal("required authoritative mapping source was omitted")
	}
}

func TestConfigureTelegramActorMappingsRejectsUnsafeFilesAndDuplicateActors(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := notification.SQLActorMapper{DB: db}
	path := filepath.Join(t.TempDir(), "telegram-actors.json")
	t.Setenv("GOTTH_MAIL_TELEGRAM_ACTOR_MAPPINGS_FILE", path)
	if err := os.WriteFile(path, []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := configureTelegramActorMappings(mapper, true); err == nil || !strings.Contains(err.Error(), "private regular") {
		t.Fatalf("unsafe permissions accepted: %v", err)
	}
	duplicate := `[{"external_id":"chat:42:user:99","actor_type":"api_token","actor_id":"a","scopes":["queue:read"]},{"external_id":"chat:42:user:99","actor_type":"api_token","actor_id":"b","scopes":["queue:read"]}]`
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureTelegramActorMappings(mapper, true); err == nil || !strings.Contains(err.Error(), "invalid Telegram actor mapping set") {
		t.Fatalf("duplicate actors accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"not":"an-array"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := configureTelegramActorMappings(mapper, true); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("malformed mapping accepted: %v", err)
	}
}

func TestConfigureNotificationsRejectsPartialOrRemotePlaintextConfig(t *testing.T) {
	t.Setenv("GOTTH_MAIL_NOTIFICATION_PLUGIN_NAME", plugin.FirstNotifyName)
	if backend, err := configureNotificationsFromEnv(&api.Server{}); err == nil || backend != nil {
		t.Fatalf("partial config accepted backend=%#v err=%v", backend, err)
	}
	t.Setenv("GOTTH_MAIL_NOTIFICATION_PLUGIN_ENDPOINT", "public.example:9443")
	t.Setenv("GOTTH_MAIL_NOTIFICATION_PLUGIN_SERVICE_TOKEN", "0123456789abcdef")
	server := api.Server{AuditDB: testpg.DB(t, store.MigrateSQL), Authz: authz.StaticAuthorizer{}}
	if backend, err := configureNotificationsFromEnv(&server); err == nil || backend != nil {
		t.Fatalf("remote plaintext endpoint accepted backend=%#v err=%v", backend, err)
	}
}

func TestNotificationDomainCountsReadCurrentSQLState(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-00000000e001','enabled.test',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),('00000000-0000-4000-8000-00000000e002','disabled.test',false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP); INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-00000000e003','00000000-0000-4000-8000-00000000e001','user',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP); INSERT INTO aliases(id,domain_id,local_part,targets_json,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-00000000e004','00000000-0000-4000-8000-00000000e001','alias','["user@enabled.test"]',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	counts, err := notificationDomainCounts(context.Background(), db)
	if err != nil || counts.EnabledDomains != 1 || counts.DisabledDomains != 1 || counts.EnabledMailboxes != 1 || counts.EnabledAliases != 1 {
		t.Fatalf("counts=%#v err=%v", counts, err)
	}
}
