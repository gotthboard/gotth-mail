package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
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
