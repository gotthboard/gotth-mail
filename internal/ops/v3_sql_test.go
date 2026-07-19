package ops

import (
	"context"
	"os"
	"strings"
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

func TestSQLIsolatedRestoreEngineVerifiesThroughRestoredDatabase(t *testing.T) {
	restoreDB := testpg.DB(t, nil)
	storage := MemoryBackupStorage{Artifacts: map[string]BackupArtifact{"artifact": {SchemaVersion: "schema_migrations", ConfigSetID: "cfg", Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true, QuotaBytes: 1024}}, Aliases: map[string]daemon.Alias{"alias@example.test": {Address: "alias@example.test", Enabled: true, Targets: []string{"user@example.test"}}}}}}
	b := VerifyBackupWithRestore(context.Background(), storage, "artifact", SQLIsolatedRestoreEngine{DB: restoreDB, Ref: "restore-db"})
	if b.Status != "verified" || b.IsolatedRestoreRef != "restore-db" || b.SchemaVersion != "schema_migrations" || b.ConfigSetID != "cfg" {
		t.Fatalf("backup=%#v", b)
	}
	var mailboxCount int
	if err := restoreDB.QueryRow(`SELECT count(*) FROM mailboxes`).Scan(&mailboxCount); err != nil {
		t.Fatal(err)
	}
	if mailboxCount != 1 {
		t.Fatalf("mailboxCount=%d", mailboxCount)
	}
}

func TestSQLIsolatedRestoreEngineRejectsNonEmptyRestoreDatabase(t *testing.T) {
	restoreDB := testpg.DB(t, store.MigrateSQL)
	storage := MemoryBackupStorage{Artifacts: map[string]BackupArtifact{"artifact": {SchemaVersion: "schema_migrations", ConfigSetID: "cfg", Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true}}}}}
	b := VerifyBackupWithRestore(context.Background(), storage, "artifact", SQLIsolatedRestoreEngine{DB: restoreDB, Ref: "dirty-db"})
	if b.Status != "failed" || b.FailureReport.Step != "isolated_restore" {
		t.Fatalf("backup=%#v", b)
	}
}

func TestSQLBackupVerificationStoreRecordsIsolatedRestoreRef(t *testing.T) {
	recordDB := testpg.DB(t, store.MigrateSQL)
	restoreDB := testpg.DB(t, nil)
	storage := MemoryBackupStorage{Artifacts: map[string]BackupArtifact{"artifact": {SchemaVersion: "schema_migrations", ConfigSetID: "cfg", Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true}}}}}
	st := SQLBackupVerificationStore{DB: recordDB}
	b, err := st.VerifyAndRecordWithRestore(context.Background(), storage, "artifact", "plugin-backup", "", SQLIsolatedRestoreEngine{DB: restoreDB, Ref: "sql-restore-db"}, time.Unix(10, 0))
	if err != nil {
		t.Fatal(err)
	}
	if b.Status != "verified" || b.IsolatedRestoreRef != "sql-restore-db" {
		t.Fatalf("backup=%#v", b)
	}
	got, ok, err := st.Latest(context.Background(), "artifact")
	if err != nil || !ok {
		t.Fatalf("latest ok=%v err=%v", ok, err)
	}
	if got.IsolatedRestoreRef != "sql-restore-db" {
		t.Fatalf("latest=%#v", got)
	}
}

func TestSQLBulkStoreMutatesCanonicalMailboxAndAliasState(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id, name, created_at, updated_at) VALUES ($1,$2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, "00000000-0000-4000-8000-000000000501", "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id, domain_id, local_part, enabled, created_at, updated_at) VALUES ($1,$2,$3,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, "00000000-0000-4000-8000-000000000502", "00000000-0000-4000-8000-000000000501", "user"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO aliases(id, domain_id, local_part, targets_json, enabled, created_at, updated_at) VALUES ($1,$2,$3,$4,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, "00000000-0000-4000-8000-000000000503", "00000000-0000-4000-8000-000000000501", "alias", `["user@example.test"]`); err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "admin", ID: "ops"}
	previews := NewBulkStore()
	p, err := previews.Preview("disable-users", []string{"user@example.test"}, actor, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	res, err := (SQLBulkStore{DB: db}).Apply(context.Background(), audit.SQLWriter{DB: db}, previews, actor, "disable-users", p.ID, p.ID, p.Hash, time.Unix(1, 0))
	if err != nil || len(res) != 1 || res[0].Status != "success" {
		t.Fatalf("res=%#v err=%v", res, err)
	}
	var enabled bool
	if err := db.QueryRow(`SELECT enabled FROM mailboxes WHERE id=$1`, "00000000-0000-4000-8000-000000000502").Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("mailbox remained enabled")
	}
	p, err = previews.Preview("delete-aliases", []string{"alias@example.test"}, actor, time.Unix(2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (SQLBulkStore{DB: db}).Apply(context.Background(), audit.SQLWriter{DB: db}, previews, actor, "delete-aliases", p.ID, p.ID, p.Hash, time.Unix(3, 0)); err != nil {
		t.Fatal(err)
	}
	var aliasCount int
	if err := db.QueryRow(`SELECT count(*) FROM aliases`).Scan(&aliasCount); err != nil {
		t.Fatal(err)
	}
	if aliasCount != 0 {
		t.Fatalf("aliasCount=%d", aliasCount)
	}
	events, err := (SQLAuditStore{DB: db}).Query(context.Background(), AuditFilter{Action: "bulk.disable-users"}, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestSQLImportStoreAppliesLiveMailuExportToCanonicalState(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	actor := audit.ActorRef{Type: "admin", ID: "ops"}
	source, err := os.ReadFile("../../test/fixtures/mailu/config-export-secrets.json")
	if err != nil {
		t.Fatal(err)
	}
	previews := NewImportStore()
	p := previews.Preview(string(source), actor, time.Unix(0, 0))
	if err := (SQLImportStore{DB: db}).Apply(context.Background(), audit.SQLWriter{DB: db}, previews, actor, p.ID, p.Hash, p.SourceFingerprint, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	var verifier string
	if err := db.QueryRow(`SELECT m.verifier FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE d.name='example.test' AND m.local_part='user'`).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(verifier, mailuBcryptSHA256Prefix+"$bcrypt-sha256$") {
		t.Fatalf("verifier=%q", verifier)
	}
	var targets string
	if err := db.QueryRow(`SELECT a.targets_json FROM aliases a JOIN domains d ON d.id=a.domain_id WHERE d.name='example.test' AND a.local_part='alias'`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(targets, "postmaster@example.test") || !strings.Contains(targets, "user@example.test") {
		t.Fatalf("targets=%s", targets)
	}
	svc, err := loadDaemonServiceFromSQL(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.PostfixRecipient("sql-import", "user@example.test"); got.Decision != daemon.OK {
		t.Fatalf("mailbox recipient not accepted: %#v", got)
	}
	events, err := (SQLAuditStore{DB: db}).Query(context.Background(), AuditFilter{Action: "import.mailu.apply"}, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestSQLSnapshotStorePersistsVerifiedBackupLinkage(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	storage := MemoryBackupStorage{Artifacts: map[string]BackupArtifact{"artifact": {SchemaVersion: "schema_migrations", ConfigSetID: "cfg", Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"user@example.test": {Address: "user@example.test", Enabled: true}}}}}
	backupStore := SQLBackupVerificationStore{DB: db}
	b, err := backupStore.VerifyAndRecord(context.Background(), storage, "artifact", "plugin-backup", "snapshot-restore", time.Unix(10, 0))
	if err != nil || b.Status != "verified" {
		t.Fatalf("backup=%#v err=%v", b, err)
	}
	latest, ok, err := backupStore.Latest(context.Background(), "artifact")
	if err != nil || !ok {
		t.Fatalf("latest ok=%v err=%v", ok, err)
	}
	snap, err := (SQLSnapshotStore{DB: db}).Capture(context.Background(), SnapshotView{ID: "00000000-0000-4000-8000-000000000301", MigrationVersion: "schema_migrations", DeploymentPolicyHash: "policy", LinkedBackupVerificationID: latest.ID, ImageVersions: []string{"gmf@sha256:1"}, PluginVersions: []string{"backup:v1"}}, time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	if snap.VerifiedRestoreStatus != "verified" || snap.LinkedBackupVerificationID != latest.ID {
		t.Fatalf("snapshot=%#v", snap)
	}
	list, err := (SQLSnapshotStore{DB: db}).List(context.Background())
	if err != nil || len(list) != 1 || list[0].VerifiedRestoreStatus != "verified" {
		t.Fatalf("list=%#v err=%v", list, err)
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
