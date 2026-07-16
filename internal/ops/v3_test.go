package ops

import (
	"context"
	"strings"
	"testing"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/daemon"
)

func TestAuditFilterExportRetentionPreserveRedaction(t *testing.T) {
	events := []audit.Event{{ID: "1", Actor: audit.ActorRef{Type: "admin", ID: "a"}, Action: "user.create", Resource: audit.ResourceRef{Type: "mailbox", ID: "u"}, Result: "success", BeforeRedacted: map[string]any{"password": "secret"}}, {ID: "2", Actor: audit.ActorRef{Type: "api", ID: "b"}, Action: "auth.failure", Result: "failure"}}
	got := FilterAudit(events, AuditFilter{ActorType: "admin", Action: "user.create"})
	if len(got) != 1 || got[0].ID != "1" {
		t.Fatalf("filter=%#v", got)
	}
	jsonl := ExportAuditJSONL(events)
	if strings.Contains(jsonl, "secret") || !strings.Contains(jsonl, "[REDACTED]") {
		t.Fatalf("jsonl redaction failed %s", jsonl)
	}
	csv := ExportAuditCSV(events)
	if !strings.Contains(csv, "actor_type") || strings.Contains(csv, "secret") {
		t.Fatalf("csv=%s", csv)
	}
	p, err := PreviewRetention(events, "older-than-90d", time.Now())
	if err != nil || p.ID == "" {
		t.Fatalf("preview %#v err %v", p, err)
	}
	w := &audit.MemoryWriter{}
	if err := ApplyRetention(context.Background(), w, audit.ActorRef{Type: "admin", ID: "a"}, p, "wrong"); err == nil {
		t.Fatal("accepted wrong retention confirmation")
	}
	if err := ApplyRetention(context.Background(), w, audit.ActorRef{Type: "admin", ID: "a"}, p, p.ID); err != nil {
		t.Fatal(err)
	}
	if len(w.Events) != 1 || w.Events[0].Action != "audit.retention.apply" {
		t.Fatalf("events=%#v", w.Events)
	}
}

func TestBackupSnapshotRollbackContracts(t *testing.T) {
	bad := VerifyBackup(context.Background(), Backup{ID: "b1"}, daemon.Service{})
	if bad.Status != "failed" || bad.FailureReport.RemediationHint == "" {
		t.Fatalf("bad=%#v", bad)
	}
	goodSvc := daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}
	good := VerifyBackup(context.Background(), Backup{ID: "b2", ArtifactRef: "artifact", SchemaVersion: "schema_migrations", ConfigSetID: "cfg"}, goodSvc)
	if good.Status != "verified" || good.VerifiedAt.IsZero() {
		t.Fatalf("good=%#v", good)
	}
	if !strings.Contains(RollbackGuidance(SnapshotView{VerifiedRestoreStatus: "failed"}), "blocked") {
		t.Fatal("rollback made fake safety promise")
	}
	if diff := SnapshotDiff(SnapshotView{GeneratedConfigSetID: "a"}, SnapshotView{GeneratedConfigSetID: "b"}); len(diff) != 1 || diff[0] != "generated_config_set" {
		t.Fatalf("diff=%#v", diff)
	}
}

func TestMailuImportRequiresPreviewBindingAndRejectsWeakening(t *testing.T) {
	actor := audit.ActorRef{Type: "admin", ID: "u"}
	p := PreviewMailuImport(`[{"Type":"domain","ID":"example.test"},{"Type":"token","ID":"bad","PlaintextSecret":true}]`, actor, time.Unix(0, 0))
	if p.Items[1].Status != "incompatible" {
		t.Fatalf("preview=%#v", p)
	}
	w := &audit.MemoryWriter{}
	if err := ApplyMailuImport(context.Background(), w, actor, p, p.Hash, p.SourceFingerprint, time.Unix(1, 0)); err == nil {
		t.Fatal("applied incompatible import")
	}
	p = PreviewMailuImport(`[{"Type":"domain","ID":"example.test"}]`, actor, time.Unix(0, 0))
	if err := ApplyMailuImport(context.Background(), w, audit.ActorRef{Type: "admin", ID: "other"}, p, p.Hash, p.SourceFingerprint, time.Unix(1, 0)); err == nil {
		t.Fatal("accepted actor mismatch")
	}
	st := NewImportStore()
	p = st.Preview(`[{"Type":"domain","ID":"example.test"}]`, actor, time.Unix(0, 0))
	verify := daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}
	if err := st.Apply(context.Background(), w, actor, p.ID, p.Hash, p.SourceFingerprint, time.Unix(1, 0), verify); err != nil {
		t.Fatal(err)
	}
	if len(w.Events) != 1 || w.Events[0].Action != "import.mailu.apply" {
		t.Fatalf("events=%#v", w.Events)
	}
}

func TestAbuseSummaryAndBulkPreviewApply(t *testing.T) {
	events := []audit.Event{{Action: "auth.failure"}, {Action: "sender.limit"}, {Action: "recipient.reject"}, {Action: "spam.decision"}, {Action: "outbound.suspicious"}}
	s := BuildAbuseSummary(events, QueueSummary{Deferred: []string{"q1", "q2"}})
	if s.AuthFailures != 1 || s.DeferredCorrelations != 2 {
		t.Fatalf("summary=%#v", s)
	}
	actor := audit.ActorRef{Type: "admin", ID: "u"}
	p := PreviewBulk("disable-users", []string{"a", "b"}, actor, time.Unix(0, 0))
	w := &audit.MemoryWriter{}
	if _, err := ApplyBulk(context.Background(), w, actor, p, "wrong", p.Hash, time.Unix(1, 0)); err == nil {
		t.Fatal("accepted wrong bulk confirmation")
	}
	res, err := ApplyBulk(context.Background(), w, actor, p, p.ID, p.Hash, time.Unix(1, 0))
	if err != nil || len(res) != 2 || len(w.Events) != 2 {
		t.Fatalf("res=%#v err=%v events=%#v", res, err, w.Events)
	}
}

func TestV3RejectsMalformedUnsupportedAndEmptyBackup(t *testing.T) {
	actor := audit.ActorRef{Type: "admin", ID: "u"}
	st := NewImportStore()
	p := st.Preview(`not-json`, actor, time.Unix(0, 0))
	if p.Items[0].Status != "failed_validation" {
		t.Fatalf("malformed preview=%#v", p)
	}
	p = st.Preview(`[{"Type":"unsupported","ID":"x"}]`, actor, time.Unix(0, 0))
	if p.Items[0].Status != "failed_validation" {
		t.Fatalf("unsupported preview=%#v", p)
	}
	b := VerifyBackupFromStorage(context.Background(), MemoryBackupStorage{Artifacts: map[string]BackupArtifact{"empty": {SchemaVersion: "schema", ConfigSetID: "cfg"}}}, "empty")
	if b.Status != "failed" || b.FailureReport.Step != "restored_state" {
		t.Fatalf("backup=%#v", b)
	}
}

func TestBulkApplyBindsOperationPath(t *testing.T) {
	actor := audit.ActorRef{Type: "admin", ID: "u"}
	st := NewBulkStore()
	p, err := st.Preview("disable-users", []string{"user@example.test"}, actor, time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(context.Background(), &audit.MemoryWriter{}, actor, "enable-users", p.ID, p.ID, p.Hash, time.Unix(1, 0)); err == nil {
		t.Fatal("accepted operation mismatch")
	}
}

func TestMailuImportVerifiesAdoptedCandidateState(t *testing.T) {
	actor := audit.ActorRef{Type: "admin", ID: "u"}
	st := NewImportStore()
	p := st.Preview(`[{"Type":"user","ID":"user@missing.test"}]`, actor, time.Unix(0, 0))
	base := daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}
	if err := st.Apply(context.Background(), &audit.MemoryWriter{}, actor, p.ID, p.Hash, p.SourceFingerprint, time.Unix(1, 0), base); err == nil {
		t.Fatal("accepted imported mailbox without adopted domain")
	}
	p = st.Preview(`[{"Type":"domain","ID":"example.test"},{"Type":"user","ID":"user@example.test"}]`, actor, time.Unix(2, 0))
	if err := st.Apply(context.Background(), &audit.MemoryWriter{}, actor, p.ID, p.Hash, p.SourceFingerprint, time.Unix(3, 0), daemon.Service{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Mailboxes["user@example.test"]; !ok {
		t.Fatal("imported mailbox was not adopted")
	}
}
