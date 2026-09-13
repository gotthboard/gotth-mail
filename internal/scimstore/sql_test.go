package scimstore

import (
	"context"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
)

func TestSQLStorePassesGotthSCIMConformance(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if err := gotthscim.CheckStore(context.Background(), func() gotthscim.Store {
		return &SQLStore{DB: db}
	}); err != nil {
		t.Fatal(err)
	}
}
