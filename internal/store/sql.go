package store

import (
	"context"
	"database/sql"
)

func MigrateSQL(ctx context.Context, db *sql.DB) error {
	for _, stmt := range InitialSchema {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, m := range (&Runner{}).mustMigrations() {
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at, checksum, dirty) VALUES ($1, $2, $3, $4)`, m.Version, m.AppliedAt, m.Checksum, false); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) mustMigrations() []Migration {
	if len(r.Applied) == 0 {
		_ = r.MigrateEmpty()
	}
	return r.Applied
}
