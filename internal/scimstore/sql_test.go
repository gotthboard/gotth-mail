package scimstore

import (
	"context"
	"database/sql"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
)

func TestSQLStorePassesGotthSCIMConformance(t *testing.T) {
	for _, lane := range []string{"fresh", "upgrade"} {
		t.Run(lane, func(t *testing.T) {
			db := testpg.RuntimeDB(t, lane, func(ctx context.Context, db *sql.DB) error {
				return store.MigrateSQLThrough(ctx, db, "0020_final_queue_artifact_binding")
			}, store.MigrateSQL, store.ValidateCurrentSQL)
			if err := gotthscim.CheckStore(context.Background(), func() gotthscim.Store {
				return &SQLStore{DB: db}
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
