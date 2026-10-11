package store_test

import (
	"context"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"testing"
)

func TestValidateCurrentSQLReadOnlyAndMissing(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	ctx := context.Background()
	if e := store.ValidateCurrentSQL(ctx, nil); e == nil {
		t.Fatal("nil transaction")
	}
	for _, q := range []string{"", "ALTER TABLE schema_migrations RENAME TO recovery_ledger_missing", "DELETE FROM schema_migrations WHERE version='0020_final_queue_artifact_binding'", "UPDATE schema_migrations SET dirty=true WHERE version='0020_final_queue_artifact_binding'", "UPDATE schema_migrations SET checksum='bad' WHERE version='0020_final_queue_artifact_binding'", "INSERT INTO schema_migrations VALUES ('9999_unknown',now(),'bad',false)"} {
		tx, e := db.Begin()
		if e != nil {
			t.Fatal(e)
		}
		if q != "" {
			if _, e = tx.Exec(q); e != nil {
				t.Fatal(e)
			}
		}
		e = store.ValidateCurrentSQL(ctx, tx)
		if (q == "") != (e == nil) {
			t.Fatal("current validator", q, e)
		}
		tx.Rollback()
	}
}
