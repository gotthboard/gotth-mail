package outboundpolicy

import (
	"context"
	"testing"
	"time"
)

func TestVerifyBackupStateRejectsMailboxCredentialOrQuotaDrift(t *testing.T) {
	db := runtimeAuthorityDB(t, "fresh")
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000c01','example.test',true,'same_domain_only',3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP); INSERT INTO mailboxes(id,domain_id,local_part,enabled,verifier,quota_bytes,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000c02','00000000-0000-4000-8000-000000000c01','user',true,'verifier-hash',4096,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	state, err := CaptureBackupState(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBackupState(context.Background(), db, state); err != nil {
		t.Fatalf("unchanged state rejected: %v", err)
	}
	if _, err := db.Exec(`UPDATE mailboxes SET verifier='different-hash' WHERE id='00000000-0000-4000-8000-000000000c02'`); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBackupState(context.Background(), db, state); err == nil {
		t.Fatal("credential drift was reported as verified")
	}
	if _, err := db.Exec(`UPDATE mailboxes SET verifier='verifier-hash',quota_bytes=8192 WHERE id='00000000-0000-4000-8000-000000000c02'`); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBackupState(context.Background(), db, state); err == nil {
		t.Fatal("quota drift was reported as verified")
	}
}

func TestRestoreBackupStateRunsAsRuntimeAppAfterExactUpgradeBootstrap(t *testing.T) {
	db := runtimeAuthorityDB(t, "upgrade")
	state := BackupState{
		Domains:   []BackupDomain{{ID: "00000000-0000-4000-8000-000000000d01", Name: "example.test", Enabled: true, Scope: ScopeSameDomainOnly, Revision: 3}},
		Mailboxes: []BackupMailbox{{ID: "00000000-0000-4000-8000-000000000d02", DomainID: "00000000-0000-4000-8000-000000000d01", LocalPart: "user", Enabled: true, Verifier: "verifier-hash", QuotaBytes: 4096}},
		Aliases:   []BackupAlias{{ID: "00000000-0000-4000-8000-000000000d03", DomainID: "00000000-0000-4000-8000-000000000d01", LocalPart: "alias", Enabled: true, Targets: []string{"user@example.test"}}},
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := RestoreBackupState(context.Background(), tx, state, time.Unix(100, 0)); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBackupState(context.Background(), db, state); err != nil {
		t.Fatal(err)
	}
}
