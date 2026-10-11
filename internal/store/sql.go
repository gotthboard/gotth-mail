package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

func MigrateSQL(ctx context.Context, db *sql.DB) error {
	return migrateSQL(ctx, db, false, upgradeMigrations)
}

// MigrateSQLThrough runs the normal migration runner against the exact
// registered prefix ending at target. It intentionally supports only 0020,
// the fresh-install authority handoff boundary. Complexity: for U registered
// upgrades and delegated migration cost M, successful-path time O(U+M),
// Omega(U); auxiliary space O(U+A), Omega(U). No uniform tight bounds exist
// because migration SQL and runner/database memory are delegated.
func MigrateSQLThrough(ctx context.Context, db *sql.DB, target string) error {
	if target != finalQueueArtifactBindingMigrationVersion {
		return fmt.Errorf("unsupported migration target %q", target)
	}
	for index, migration := range upgradeMigrations {
		if migration.Version == target {
			return migrateSQL(ctx, db, false, upgradeMigrations[:index+1])
		}
	}
	return fmt.Errorf("migration target %q is not registered", target)
}

// MigrateEmptySQL initializes a database only when the target schema has no
// user relations. Isolated restore callers use this stricter boundary so an
// existing database cannot be mistaken for a disposable restore target.
func MigrateEmptySQL(ctx context.Context, db *sql.DB) error {
	return migrateSQL(ctx, db, true, upgradeMigrations)
}

// migrateSQL validates and applies the supplied ordered migration prefix in
// one transaction. Complexity: for U upgrades, L ledger rows, and delegated
// SQL cost Q, successful-path time O(U+L log L+Q), Omega(U+L);
// auxiliary space O(U+L+S), Omega(U+L). No uniform tight bounds exist because
// Q and S are delegated database/driver work and state.
func migrateSQL(ctx context.Context, db *sql.DB, requireEmpty bool, migrations []Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL search_path = public, pg_catalog`); err != nil {
		return err
	}
	var initialized bool
	if err := tx.QueryRowContext(ctx, `SELECT to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&initialized); err != nil {
		return err
	}
	if requireEmpty {
		var occupied bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public'
			  AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
		)`).Scan(&occupied); err != nil {
			return err
		}
		if occupied {
			return errors.New("database not empty")
		}
	}
	baseMigrations := (&Runner{}).mustMigrations()
	if !initialized {
		for _, stmt := range InitialSchema {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return err
			}
		}
		for _, m := range baseMigrations {
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at, checksum, dirty) VALUES ($1, $2, $3, $4)`, m.Version, m.AppliedAt, m.Checksum, false); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `LOCK TABLE schema_migrations IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return err
	}
	ledger, err := readMigrationLedger(ctx, tx)
	if err != nil {
		return err
	}
	if err := validateMigrationLedger(ledger, baseMigrations, migrations); err != nil {
		return err
	}
	for _, m := range migrations {
		if _, applied := ledger[m.Version]; applied {
			continue
		}
		if err := applyNewSQLMigration(ctx, tx, m); err != nil {
			return err
		}
		ledger[m.Version] = migrationLedgerRow{Checksum: m.Checksum}
	}
	return tx.Commit()
}

type migrationLedgerRow struct {
	Checksum string
	Dirty    bool
}

func readMigrationLedger(ctx context.Context, tx *sql.Tx) (map[string]migrationLedgerRow, error) {
	rows, err := tx.QueryContext(ctx, `SELECT version, checksum, dirty FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ledger := map[string]migrationLedgerRow{}
	for rows.Next() {
		var version string
		var row migrationLedgerRow
		if err := rows.Scan(&version, &row.Checksum, &row.Dirty); err != nil {
			return nil, err
		}
		ledger[version] = row
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ledger, nil
}

func validateMigrationLedger(ledger map[string]migrationLedgerRow, base, upgrades []Migration) error {
	known := make(map[string]Migration, len(base)+len(upgrades))
	for _, migration := range append(append([]Migration(nil), base...), upgrades...) {
		if _, exists := known[migration.Version]; exists {
			return fmt.Errorf("migration %s registered more than once", migration.Version)
		}
		known[migration.Version] = migration
	}
	versions := make([]string, 0, len(ledger))
	for version := range ledger {
		versions = append(versions, version)
	}
	sort.Strings(versions)
	for _, version := range versions {
		if _, ok := known[version]; !ok {
			return fmt.Errorf("unknown migration %s", version)
		}
	}
	for _, migration := range base {
		row, ok := ledger[migration.Version]
		if !ok {
			return fmt.Errorf("migration %s missing", migration.Version)
		}
		if err := validateMigrationLedgerRow(migration, row); err != nil {
			return err
		}
	}
	for _, migration := range upgrades {
		if row, ok := ledger[migration.Version]; ok {
			if err := validateMigrationLedgerRow(migration, row); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateMigrationLedgerRow(migration Migration, row migrationLedgerRow) error {
	if row.Dirty {
		return fmt.Errorf("migration %s is dirty", migration.Version)
	}
	if row.Checksum != migration.Checksum {
		return fmt.Errorf("migration %s checksum mismatch", migration.Version)
	}
	return nil
}

func applyNewSQLMigration(ctx context.Context, tx *sql.Tx, m Migration) error {
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at, checksum, dirty) VALUES ($1, $2, $3, false)`, m.Version, time.Now().UTC(), m.Checksum)
	return err
}

func (r *Runner) mustMigrations() []Migration {
	if len(r.Applied) == 0 {
		_ = r.MigrateEmpty()
	}
	return r.Applied
}

// ValidateCurrentSQL only reads the current ledger in the caller's transaction.
// Caller owns namespace/RLS policy, locks and rollback. Unlike MigrateSQL this
// requires every registered upgrade and never bootstraps or applies anything.
// Complexity: L ledger/registry bytes; time O(L log L+Q), Omega(L), auxiliary
// O(L+S), Omega(L); Q/S delegated SQL; no tight bound for delegated costs.
func ValidateCurrentSQL(ctx context.Context, tx *sql.Tx) error {
	if tx == nil {
		return errors.New("current schema transaction is required")
	}
	ledger, err := readMigrationLedger(ctx, tx)
	if err != nil {
		return err
	}
	base := (&Runner{}).mustMigrations()
	if err = validateMigrationLedger(ledger, base, upgradeMigrations); err != nil {
		return err
	}
	for _, m := range upgradeMigrations {
		if _, ok := ledger[m.Version]; !ok {
			return errors.New("current schema upgrade is missing")
		}
	}
	return nil
}
