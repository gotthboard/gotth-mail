package ops

import (
	"context"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/store"
	"forgejo/linus/gophermailforge/internal/testpg"
)

func TestSQLAuditStoreQueryGetRedactsAndFilters(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	w := audit.SQLWriter{DB: db}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := w.Write(context.Background(), audit.Event{ID: "00000000-0000-4000-8000-000000000101", Time: old, Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "auth.failure", Resource: audit.ResourceRef{Type: "session", ID: "s"}, BeforeRedacted: map[string]any{"password": "secret"}, Result: "failure", ErrorCode: "bad_secret"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(context.Background(), audit.Event{ID: "00000000-0000-4000-8000-000000000102", Time: old.Add(time.Hour), Actor: audit.ActorRef{Type: "api", ID: "b"}, Action: "config.apply", Resource: audit.ResourceRef{Type: "generated_config_set", ID: "cfg"}, AfterRedacted: map[string]any{"token": "secret-token"}, Result: "success"}); err != nil {
		t.Fatal(err)
	}
	st := SQLAuditStore{DB: db}
	events, err := st.Query(context.Background(), AuditFilter{ActorType: "admin", Result: "failure"}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "00000000-0000-4000-8000-000000000101" || audit.ContainsSecretJSON(events[0].BeforeRedacted, "secret") {
		t.Fatalf("events=%#v", events)
	}
	got, ok, err := st.Get(context.Background(), "00000000-0000-4000-8000-000000000102")
	if err != nil || !ok {
		t.Fatalf("get ok=%v err=%v", ok, err)
	}
	if got.Action != "config.apply" || audit.ContainsSecretJSON(got.AfterRedacted, "secret-token") {
		t.Fatalf("got=%#v", got)
	}
}

func TestSQLAuditStoreRetentionDeletesOnlyExpiredWithAudit(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	w := audit.SQLWriter{DB: db}
	now := time.Date(2026, 7, 18, 0, 0, 0, 0, time.UTC)
	if err := w.Write(context.Background(), audit.Event{ID: "00000000-0000-4000-8000-000000000201", Time: now.AddDate(0, 0, -120), Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "old", Resource: audit.ResourceRef{Type: "r", ID: "old"}, Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Write(context.Background(), audit.Event{ID: "00000000-0000-4000-8000-000000000202", Time: now.AddDate(0, 0, -10), Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "new", Resource: audit.ResourceRef{Type: "r", ID: "new"}, Result: "success"}); err != nil {
		t.Fatal(err)
	}
	st := SQLAuditStore{DB: db}
	p, err := st.PreviewRetention(context.Background(), "older-than-90d", now)
	if err != nil {
		t.Fatal(err)
	}
	if p.DeleteCount != 1 {
		t.Fatalf("preview=%#v", p)
	}
	if err := st.ApplyRetention(context.Background(), audit.ActorRef{Type: "admin", ID: "a"}, p, "wrong", now); err == nil {
		t.Fatal("accepted wrong confirmation")
	}
	if err := st.ApplyRetention(context.Background(), audit.ActorRef{Type: "admin", ID: "a"}, p, p.ID, now); err != nil {
		t.Fatal(err)
	}
	events, err := st.Query(context.Background(), AuditFilter{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	seenOld, seenNew, seenRetention := false, false, false
	for _, e := range events {
		switch e.Action {
		case "old":
			seenOld = true
		case "new":
			seenNew = true
		case "audit.retention.apply":
			seenRetention = true
		}
	}
	if seenOld || !seenNew || !seenRetention {
		t.Fatalf("events=%#v", events)
	}
}

func TestSQLBackupVerificationStoreRecordsVerifiedBackup(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	storage := MemoryBackupStorage{Artifacts: map[string]BackupArtifact{"artifact": {SchemaVersion: "schema_migrations", ConfigSetID: "cfg", Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true}}, Aliases: map[string]daemon.Alias{}}}}
	st := SQLBackupVerificationStore{DB: db}
	b, err := st.VerifyAndRecord(context.Background(), storage, "artifact", "plugin-backup", "isolated-test", time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if b.Status != "verified" || b.SchemaVersion != "schema_migrations" || b.ConfigSetID != "cfg" {
		t.Fatalf("backup=%#v", b)
	}
	got, ok, err := st.Latest(context.Background(), "artifact")
	if err != nil || !ok {
		t.Fatalf("latest ok=%v err=%v", ok, err)
	}
	if got.Status != "verified" || got.ArtifactRef != "artifact" {
		t.Fatalf("latest=%#v", got)
	}
}
