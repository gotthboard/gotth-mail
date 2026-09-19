package outboundpolicy

import (
	"context"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestVerifyBackupStateRejectsMailboxCredentialOrQuotaDrift(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
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
