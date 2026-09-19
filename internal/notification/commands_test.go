package notification

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type fakeSummaryProvider struct {
	got ReadOnlyCommand
	out string
	err error
}

type failingAuditWriter struct{}

func (failingAuditWriter) Write(context.Context, audit.Event) error {
	return errors.New("audit offline password=secret")
}

func (f *fakeSummaryProvider) Summary(ctx context.Context, c ReadOnlyCommand) (string, error) {
	f.got = c
	return f.out, f.err
}

func TestCommandServiceRequiresExplicitMappedAuthorizedActor(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	aud := &audit.MemoryWriter{}
	provider := &fakeSummaryProvider{out: "ok"}
	svc := CommandService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Provider: provider, Audit: aud, Now: func() time.Time { return time.Unix(1, 0) }}
	_, err := svc.Run(context.Background(), CommandRequest{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Command: CommandDoctorSummary, CorrelationID: "corr-1"})
	if err == nil || !strings.Contains(err.Error(), "mapping") {
		t.Fatalf("unmapped actor accepted: %v", err)
	}
	if len(aud.Events) != 1 || aud.Events[0].Result != "denied" || aud.Events[0].Action != "notification.command.doctor_summary" {
		t.Fatalf("missing denied audit: %#v", aud.Events)
	}
	if err := mapper.Put(context.Background(), ActorMapping{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Actor: authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"notification:read"}}}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Run(context.Background(), CommandRequest{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Command: CommandDoctorSummary})
	if err == nil || !strings.Contains(err.Error(), "scope") {
		t.Fatalf("unauthorized actor accepted: %v", err)
	}
}

func TestCommandServiceReturnsBoundedRedactedSummaryAndAudits(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	if err := mapper.Put(context.Background(), ActorMapping{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Actor: authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"doctor:read"}}}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	aud := &audit.MemoryWriter{}
	provider := &fakeSummaryProvider{out: "doctor ok\npassword=hunter2 " + strings.Repeat("x", 2000)}
	svc := CommandService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Provider: provider, Audit: aud, Now: func() time.Time { return time.Unix(2, 0) }}
	resp, err := svc.Run(context.Background(), CommandRequest{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Command: CommandDoctorSummary, CorrelationID: "corr-2"})
	if err != nil {
		t.Fatal(err)
	}
	if provider.got != CommandDoctorSummary || resp.Actor.ID != "ops" || resp.CorrelationID != "corr-2" {
		t.Fatalf("bad response: %#v provider=%s", resp, provider.got)
	}
	if len(resp.Summary) > maxCommandSummaryBytes || strings.Contains(resp.Summary, "hunter2") || strings.Contains(resp.Summary, "\n") || !strings.Contains(resp.Summary, "[REDACTED]") {
		t.Fatalf("summary not bounded/redacted: %q", resp.Summary)
	}
	if len(aud.Events) != 1 || aud.Events[0].Result != "success" || aud.Events[0].Actor.ID != "ops" || aud.Events[0].CorrelationID != "corr-2" {
		t.Fatalf("missing success audit: %#v", aud.Events)
	}
}

func TestCommandServiceAuditsProviderFailure(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	if err := mapper.Put(context.Background(), ActorMapping{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Actor: authz.Actor{Type: "api_token", ID: "ops", Scopes: []string{"queue:read"}}}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	aud := &audit.MemoryWriter{}
	svc := CommandService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Provider: &fakeSummaryProvider{err: errors.New("queue unavailable")}, Audit: aud}
	_, err := svc.Run(context.Background(), CommandRequest{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Command: CommandQueueSummary})
	if err == nil || !strings.Contains(err.Error(), "queue unavailable") {
		t.Fatalf("provider failure hidden: %v", err)
	}
	if len(aud.Events) != 1 || aud.Events[0].Result != "failure" || aud.Events[0].ErrorCode == "" {
		t.Fatalf("missing failure audit: %#v", aud.Events)
	}
}

func TestCommandServiceRejectsUnsupportedCommand(t *testing.T) {
	svc := CommandService{Mapper: SQLActorMapper{DB: testpg.DB(t, store.MigrateSQL)}, Authorizer: authz.StaticAuthorizer{}, Provider: &fakeSummaryProvider{}}
	if _, err := svc.Run(context.Background(), CommandRequest{Command: ReadOnlyCommand("shell")}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported command accepted: %v", err)
	}
}

func TestCommandServiceFailsClosedWhenDeniedAuditCannotPersist(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	mapper := SQLActorMapper{DB: db}
	svc := CommandService{Mapper: mapper, Authorizer: authz.StaticAuthorizer{}, Provider: &fakeSummaryProvider{}, Audit: failingAuditWriter{}}
	_, err := svc.Run(context.Background(), CommandRequest{TransportActor: TransportActor{Transport: "telegram", ExternalID: "chat:42:user:99"}, Command: CommandDoctorSummary})
	if err == nil || err.Error() != "notification command audit unavailable" {
		t.Fatalf("audit failure not closed safely: %v", err)
	}
}
