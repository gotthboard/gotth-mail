package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestMigrateSQLUpgradesRealBaseLedgerAndPersistsEvidence(t *testing.T) {
	legacyAlert := notification.Alert{
		ID: "legacy-alert", Class: "backup.failure", Severity: notification.SeverityCritical,
		Title: "Legacy backup failed", Summary: "legacy failure",
	}
	legacyJSON, err := json.Marshal(legacyAlert)
	if err != nil {
		t.Fatal(err)
	}
	db := testpg.DB(t, func(ctx context.Context, db *sql.DB) error {
		if err := createBaseLedger(ctx, db); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO notification_deliveries(alert_id, alert_json, status, reason, created_at, updated_at) VALUES ($1,$2,'failed_retryable','legacy_failure',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, legacyAlert.ID, string(legacyJSON)); err != nil {
			return err
		}
		return store.MigrateSQL(ctx, db)
	})

	ctx := context.Background()
	if err := store.MigrateSQL(ctx, db); err != nil {
		t.Fatalf("idempotent migration rerun: %v", err)
	}
	assertEvidenceColumn(t, db, "text", "NO", "'{}'::text")
	assertProtectedOIDCAttemptColumns(t, db)
	var legacyEvidence string
	if err := db.QueryRowContext(ctx, `SELECT evidence_json FROM notification_deliveries WHERE alert_id=$1`, legacyAlert.ID).Scan(&legacyEvidence); err != nil {
		t.Fatal(err)
	}
	if legacyEvidence != "{}" {
		t.Fatalf("legacy row evidence=%q want empty object", legacyEvidence)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	alert := notification.Alert{
		ID: "migration-alert", Class: "backup.failure", Severity: notification.SeverityCritical,
		Title: "Backup failed", Summary: "backup failed", CorrelationID: "corr-1",
		Resource: notification.ResourceRef{Type: "backup", ID: "artifact-1"},
	}
	evidence := notification.DeliveryEvidence{
		Transport: "email", MessageID: "<migration-alert@example.test>", GeneratedAt: now,
		From: "alerts@example.test", SigningFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
		SenderIdentityID: "system:alerts@example.test", SenderIdentityClass: "system",
		PolicyVersion: "gotth-mail-exact-sender-v1", IdentityStateRef: "openpgp:0123456789ABCDEF0123456789ABCDEF01234567",
		VerificationResult: "valid_exact_sender", Workflow: "notification",
	}
	recorder := notification.SQLRecorder{DB: db}
	if err := recorder.RecordPending(ctx, alert, now); err != nil {
		t.Fatal(err)
	}
	if err := recorder.RecordFinal(ctx, alert.ID, notification.StatusDelivered, "signed_email_delivered", evidence, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := recorder.Get(ctx, alert.ID)
	if err != nil || !ok {
		t.Fatalf("reload ok=%v err=%v", ok, err)
	}
	if got.Status != notification.StatusDelivered || got.Reason != "signed_email_delivered" || got.Evidence != evidence {
		t.Fatalf("migrated recorder lost structured evidence: %#v", got)
	}
}

func TestOIDCProtectedAttemptsMigrationInvalidatesLegacyInflightState(t *testing.T) {
	db := testpg.DB(t, func(ctx context.Context, db *sql.DB) error {
		if err := createBaseLedger(ctx, db); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO oidc_login_states(state_id, nonce, browser_binding_hash, redirect_after_login, created_at, expires_at) VALUES ('legacy-state','legacy-nonce','legacy-browser','/',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + interval '10 minutes')`); err != nil {
			return err
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO sessions(id, identity_ref_id, csrf_secret_hash, auth_method, created_at, expires_at, last_seen_at) VALUES ('existing-session','issuer|subject','csrf','oidc',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP + interval '1 hour',CURRENT_TIMESTAMP)`); err != nil {
			return err
		}
		return store.MigrateSQL(ctx, db)
	})
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM oidc_login_states`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("legacy OIDC attempts survived protected-storage migration: %d", count)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sessions WHERE id='existing-session'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("protected-attempt migration removed existing sessions: %d", count)
	}
	assertProtectedOIDCAttemptColumns(t, db)
}

func TestSCIMResourcesMigrationCreatesOpaqueDurableStore(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	for _, relation := range []string{"scim_resources", "scim_index_contracts", "scim_resource_indexes", "scim_tombstones"} {
		var exists bool
		if err := db.QueryRow(`SELECT to_regclass('public.' || $1) IS NOT NULL`, relation).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("migration did not create %s", relation)
		}
	}
	var dataType, nullable string
	if err := db.QueryRow(`SELECT data_type, is_nullable FROM information_schema.columns WHERE table_schema='public' AND table_name='mailboxes' AND column_name='scim_resource_id'`).Scan(&dataType, &nullable); err != nil {
		t.Fatal(err)
	}
	if dataType != "text" || nullable != "YES" {
		t.Fatalf("mailboxes.scim_resource_id type=%s nullable=%s", dataType, nullable)
	}
}

func TestMigrateSQLRejectsInvalidBaseLedgerBeforeUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		mutate  string
		wantErr string
	}{
		{name: "dirty", mutate: `UPDATE schema_migrations SET dirty=true WHERE version='notification_deliveries'`, wantErr: "migration notification_deliveries is dirty"},
		{name: "checksum", mutate: `UPDATE schema_migrations SET checksum='wrong' WHERE version='notification_deliveries'`, wantErr: "migration notification_deliveries checksum mismatch"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := baseDB(t)
			if _, err := db.Exec(tc.mutate); err != nil {
				t.Fatal(err)
			}
			err := store.MigrateSQL(context.Background(), db)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want %q", err, tc.wantErr)
			}
			assertNoEvidenceMigrationRecord(t, db)
			assertEvidenceColumnAbsent(t, db)
		})
	}
}

func TestMigrateSQLRejectsUnknownAndMissingLedgerRowsBeforeUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		mutate  string
		wantErr string
	}{
		{
			name:    "unknown future migration",
			mutate:  `INSERT INTO schema_migrations(version, applied_at, checksum, dirty) VALUES ('9999_future', CURRENT_TIMESTAMP, 'future', false)`,
			wantErr: "unknown migration 9999_future",
		},
		{
			name:    "missing baseline migration",
			mutate:  `DELETE FROM schema_migrations WHERE version='notification_deliveries'`,
			wantErr: "migration notification_deliveries missing",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := baseDB(t)
			if _, err := db.Exec(tc.mutate); err != nil {
				t.Fatal(err)
			}
			err := store.MigrateSQL(context.Background(), db)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want %q", err, tc.wantErr)
			}
			assertNoEvidenceMigrationRecord(t, db)
			assertEvidenceColumnAbsent(t, db)
		})
	}
}

func TestMigrateSQLRejectsInvalidAppliedUpgradeLedger(t *testing.T) {
	tests := []struct {
		name    string
		mutate  string
		wantErr string
	}{
		{
			name:    "dirty",
			mutate:  `UPDATE schema_migrations SET dirty=true WHERE version='0002_notification_delivery_evidence'`,
			wantErr: "migration 0002_notification_delivery_evidence is dirty",
		},
		{
			name:    "checksum",
			mutate:  `UPDATE schema_migrations SET checksum='wrong' WHERE version='0002_notification_delivery_evidence'`,
			wantErr: "migration 0002_notification_delivery_evidence checksum mismatch",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := testpg.DB(t, store.MigrateSQL)
			if _, err := db.Exec(tc.mutate); err != nil {
				t.Fatal(err)
			}
			err := store.MigrateSQL(context.Background(), db)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v want %q", err, tc.wantErr)
			}
			assertEvidenceColumn(t, db, "text", "NO", "'{}'::text")
		})
	}
}

func TestMigrateSQLRejectsPreexistingWrongEvidenceColumnShape(t *testing.T) {
	db := baseDB(t)
	if _, err := db.Exec(`ALTER TABLE notification_deliveries ADD COLUMN evidence_json integer NOT NULL DEFAULT 0`); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateSQL(context.Background(), db); err == nil {
		t.Fatal("wrong preexisting evidence column accepted")
	}
	assertEvidenceColumn(t, db, "integer", "NO", "0")
	assertNoEvidenceMigrationRecord(t, db)
}

func TestFreshAndBaseUpgradeLedgerChecksumsMatch(t *testing.T) {
	fresh := testpg.DB(t, store.MigrateSQL)
	upgraded := testpg.DB(t, func(ctx context.Context, db *sql.DB) error {
		if err := createBaseLedger(ctx, db); err != nil {
			return err
		}
		return store.MigrateSQL(ctx, db)
	})
	freshLedger := ledgerChecksums(t, fresh)
	upgradedLedger := ledgerChecksums(t, upgraded)
	if !reflect.DeepEqual(freshLedger, upgradedLedger) {
		t.Fatalf("fresh/upgraded ledger mismatch\nfresh: %#v\nupgraded: %#v", freshLedger, upgradedLedger)
	}
}

func TestMigrateEmptySQLRejectsAnyExistingUserRelationWithoutDDL(t *testing.T) {
	db := testpg.DB(t, nil)
	if _, err := db.Exec(`CREATE TABLE sentinel (id integer primary key, value text NOT NULL); INSERT INTO sentinel(id, value) VALUES (1, 'untouched')`); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateEmptySQL(context.Background(), db); err == nil || err.Error() != "database not empty" {
		t.Fatalf("error=%v want database not empty", err)
	}
	var value string
	if err := db.QueryRow(`SELECT value FROM sentinel WHERE id=1`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "untouched" {
		t.Fatalf("sentinel changed: %q", value)
	}
	var ledger sql.NullString
	if err := db.QueryRow(`SELECT to_regclass('public.schema_migrations')::text`).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if ledger.Valid {
		t.Fatalf("migration DDL ran before empty check: %q", ledger.String)
	}
}

func TestMigrateEmptySQLPinsPublicTargetUnderHostileSearchPath(t *testing.T) {
	db := testpg.DB(t, nil)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`CREATE SCHEMA shadow; CREATE TABLE shadow.sentinel (id integer primary key, value text NOT NULL); INSERT INTO shadow.sentinel(id, value) VALUES (1, 'untouched'); SET search_path = shadow, public`); err != nil {
		t.Fatal(err)
	}
	if err := store.MigrateEmptySQL(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var publicLedger, shadowLedger sql.NullString
	if err := db.QueryRow(`SELECT to_regclass('public.schema_migrations')::text, to_regclass('shadow.schema_migrations')::text`).Scan(&publicLedger, &shadowLedger); err != nil {
		t.Fatal(err)
	}
	if !publicLedger.Valid || shadowLedger.Valid {
		t.Fatalf("migration escaped public target: public=%q shadow=%q", publicLedger.String, shadowLedger.String)
	}
	var value string
	if err := db.QueryRow(`SELECT value FROM shadow.sentinel WHERE id=1`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	if value != "untouched" {
		t.Fatalf("shadow sentinel changed: %q", value)
	}
	assertEvidenceColumn(t, db, "text", "NO", "'{}'::text")
}

func baseDB(t *testing.T) *sql.DB {
	t.Helper()
	return testpg.DB(t, createBaseLedger)
}

func createBaseLedger(ctx context.Context, db *sql.DB) error {
	var runner store.Runner
	if err := runner.MigrateEmpty(); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, migration := range runner.Applied {
		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			return err
		}
	}
	for _, migration := range runner.Applied {
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at, checksum, dirty) VALUES ($1,$2,$3,false)`, migration.Version, migration.AppliedAt, migration.Checksum); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func ledgerChecksums(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var version, checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			t.Fatal(err)
		}
		out[version] = checksum
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func assertEvidenceColumn(t *testing.T, db *sql.DB, dataType, nullable, defaultValue string) {
	t.Helper()
	var gotType, gotNullable string
	var columnDefault sql.NullString
	if err := db.QueryRow(`SELECT data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema='public' AND table_name='notification_deliveries' AND column_name='evidence_json'`).Scan(&gotType, &gotNullable, &columnDefault); err != nil {
		t.Fatal(err)
	}
	if gotType != dataType || gotNullable != nullable || !columnDefault.Valid || columnDefault.String != defaultValue {
		t.Fatalf("bad evidence column type=%q nullable=%q default=%q", gotType, gotNullable, columnDefault.String)
	}
}

func assertNoEvidenceMigrationRecord(t *testing.T, db *sql.DB) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version='0002_notification_delivery_evidence'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("failed migration was recorded: count=%d", count)
	}
}

func assertEvidenceColumnAbsent(t *testing.T, db *sql.DB) {
	t.Helper()
	var columnCount int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='notification_deliveries' AND column_name='evidence_json'`).Scan(&columnCount); err != nil {
		t.Fatal(err)
	}
	if columnCount != 0 {
		t.Fatalf("failed migration changed schema: evidence columns=%d", columnCount)
	}
}

func assertProtectedOIDCAttemptColumns(t *testing.T, db *sql.DB) {
	t.Helper()
	rows, err := db.Query(`SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema='public' AND table_name='oidc_login_states' ORDER BY ordinal_position`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var name, dataType, nullable string
		if err := rows.Scan(&name, &dataType, &nullable); err != nil {
			t.Fatal(err)
		}
		got[name] = dataType + ":" + nullable
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"state_hash": "bytea:NO", "nonce_ciphertext": "bytea:NO", "pkce_verifier_ciphertext": "bytea:NO",
		"context_ciphertext": "text:NO", "browser_binding_hash": "bytea:NO", "redirect_after_login": "text:NO",
		"created_at": "timestamp without time zone:NO", "expires_at": "timestamp without time zone:NO", "used_at": "timestamp without time zone:YES",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("OIDC attempt schema=%#v want=%#v", got, want)
	}
}
