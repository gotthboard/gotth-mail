package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

var d432e5bBaselineChecksums = map[string]string{
	"schema_migrations":           "413687179f8e273fb76c98d3e22798130dddd35e0856d6e6a0892824c5cab4e5",
	"domains":                     "240be515a722f64555a47a847073cc5b018990d507bf439a82cd604411257895",
	"mailboxes":                   "d4f2b3e862baec674d5e996102cbedc2361d6bee55675aa79819b46ce11085b9",
	"aliases":                     "3cc0c4263826f159c42c5e65c4bb2283d5a09ad344b42fadf8b18dea0cd09521",
	"relays":                      "54a2156cbc7265f9980af794ec35f91abb7bd12318ed9b665d010db27d917b7f",
	"tokens":                      "b3b36866d9fefde39b62902778b0d59ae39965ea870263e7f0a3f7c351f0a902",
	"oidc_login_states":           "a66c85bc9d82371c4fed89b5253f4f267b3492a68bf8e02754a529356cab762d",
	"sessions":                    "badbbe90775ecd01ff7ea681535acfab5fc5b5af2c343646a8509c48c4b3b8ff",
	"identity_refs":               "1c375ba15e044417abf37167c43f0e251440faff1710ae01b2d8eb42ed8d5783",
	"role_bindings":               "bfe321d34a28fb3ce4d92f56742226c2f3f2242a78ad75fcc8c89761d3cf9419",
	"audit_events":                "d82cfe3c025c66a2a55998b7fabbb951f781d2b73482d9998d291d0cead933a4",
	"generated_config_sets":       "0c5f4518b4d3a5f65d8014975471c309eb07bd3326dc8f190028358f6e1f0dd2",
	"backup_artifacts":            "9529cdc1a0e7ba853bd0bdf49bd8704f832b9829e4e31b661ccb787643904b46",
	"backup_verifications":        "c65a854038b9e0990f95469300b8bbf63d4d13993db8bbe57502af863d7d6550",
	"snapshots":                   "e8e9a93b84e219e27c457f69671bd1fd88fc1c8c8c6cd5dea156ab7ffcb2ef8b",
	"webmail_drafts":              "4272f75c54e2319e545f55c9ed248dbd300ad0ba512dfcaed426b4ac62461a7f",
	"notification_deliveries":     "271354b05f1a6f9ce50f51960e988353145e313a83249b855ed3268ae7551c15",
	"notification_actor_mappings": "4304c7e219445dcff670286c366dd90d8dce3910ebcc898acef10b3b2f1dcf0f",
	"notification_approvals":      "783aa96eee2814bfed9a008a73acd8d1165a4d071ff1c413b71ccd46bddcfd1f",
	"plugin_registrations":        "bbfe82dc6851f92df26e1d678346d292ddee6fc5354f6ee16bf629baecc46954",
}

func TestBaselineMigrationChecksumsRemainD432e5b(t *testing.T) {
	var runner Runner
	if err := runner.MigrateEmpty(); err != nil {
		t.Fatal(err)
	}
	if len(runner.Applied) != len(d432e5bBaselineChecksums) {
		t.Fatalf("baseline migration count=%d want immutable d432e5b count=%d", len(runner.Applied), len(d432e5bBaselineChecksums))
	}
	seen := make(map[string]bool, len(runner.Applied))
	for _, migration := range runner.Applied {
		want, ok := d432e5bBaselineChecksums[migration.Version]
		if !ok {
			t.Fatalf("baseline contains migration absent from d432e5b: %s", migration.Version)
		}
		if migration.Checksum != want {
			t.Fatalf("baseline migration %s checksum=%s want immutable d432e5b checksum=%s", migration.Version, migration.Checksum, want)
		}
		seen[migration.Version] = true
	}
	for version := range d432e5bBaselineChecksums {
		if !seen[version] {
			t.Fatalf("baseline migration from d432e5b disappeared: %s", version)
		}
	}
}

func TestNotificationDeliveryEvidenceMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0002_notification_delivery_evidence.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if fileSQL != notificationDeliveryEvidenceMigrationSQL {
		t.Fatalf("migration file/runtime drift\nfile: %q\nruntime: %q", fileSQL, notificationDeliveryEvidenceMigrationSQL)
	}
	if len(upgradeMigrations) != 14 || upgradeMigrations[0].Version != notificationDeliveryEvidenceMigrationVersion || upgradeMigrations[0].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[0].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestOIDCProtectedAttemptsMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0003_oidc_protected_attempts.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[1].Version != oidcProtectedAttemptsMigrationVersion || upgradeMigrations[1].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[1].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestSCIMResourcesMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0004_scim_resources.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[2].Version != scimResourcesMigrationVersion || upgradeMigrations[2].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[2].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestAppPasswordContractMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0005_app_password_contract.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[3].Version != appPasswordContractMigrationVersion || upgradeMigrations[3].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[3].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestOIDCSCIMIdentityBindingMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0006_oidc_scim_identity_binding.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[4].Version != oidcSCIMIdentityBindingMigrationVersion || upgradeMigrations[4].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[4].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestSCIMGroupMembersMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0007_scim_group_members.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[5].Version != scimGroupMembersMigrationVersion || upgradeMigrations[5].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[5].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestOutboundPolicyMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0008_outbound_policy.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[6].Version != outboundPolicyMigrationVersion || upgradeMigrations[6].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[6].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestOutboundQueueMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0009_outbound_queue.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[7].Version != outboundQueueMigrationVersion || upgradeMigrations[7].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[7].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestOutboundQueueReleaseMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0010_outbound_queue_release.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[8].Version != outboundQueueReleaseMigrationVersion || upgradeMigrations[8].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[8].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestWebmailCCBCCMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0011_webmail_cc_bcc.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[9].Version != webmailCCBCCMigrationVersion || upgradeMigrations[9].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[9].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestWebmailDeliveryUncertainMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0012_webmail_delivery_uncertain.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[10].Version != webmailDeliveryUncertainMigrationVersion || upgradeMigrations[10].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[10].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestNotificationApprovalBindingMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0013_notification_approval_binding.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[11].Version != notificationApprovalBindingMigrationVersion || upgradeMigrations[11].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[11].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestNotificationApprovalExecutionMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0014_notification_approval_execution.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[12].Version != notificationApprovalExecutionMigrationVersion || upgradeMigrations[12].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[12].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestNotificationTelegramUpdatesMigrationFileMatchesRuntime(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0015_notification_telegram_updates.sql")
	if err != nil {
		t.Fatal(err)
	}
	fileSQL := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 14 || upgradeMigrations[13].Version != notificationTelegramUpdatesMigrationVersion || upgradeMigrations[13].SQL != fileSQL {
		t.Fatalf("runtime migration registration drift: %#v", upgradeMigrations)
	}
	sum := sha256.Sum256([]byte(fileSQL))
	if got, want := upgradeMigrations[13].Checksum, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("runtime checksum=%q file checksum=%q", got, want)
	}
}

func TestOutboundPolicyMigrationPreservesUnrestrictedDefault(t *testing.T) {
	db := testpg.DB(t, func(ctx context.Context, db *sql.DB) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var runner Runner
		if err := runner.MigrateEmpty(); err != nil {
			return err
		}
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
		for _, migration := range upgradeMigrations[:6] {
			if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at, checksum, dirty) VALUES ($1,CURRENT_TIMESTAMP,$2,false)`, migration.Version, migration.Checksum); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000801','example.test',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
			return err
		}
		return tx.Commit()
	})
	if err := MigrateSQL(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var scope string
	var revision int64
	if err := db.QueryRow(`SELECT outbound_scope, outbound_policy_revision FROM domains WHERE name='example.test'`).Scan(&scope, &revision); err != nil {
		t.Fatal(err)
	}
	if scope != "unrestricted" || revision != 1 {
		t.Fatalf("scope=%q revision=%d, want unrestricted/1", scope, revision)
	}
	if _, err := db.Exec(`UPDATE domains SET outbound_scope='invalid' WHERE name='example.test'`); err == nil {
		t.Fatal("invalid outbound scope accepted")
	}
	if _, err := db.Exec(`UPDATE domains SET outbound_policy_revision=0 WHERE name='example.test'`); err == nil {
		t.Fatal("non-positive outbound policy revision accepted")
	}
}

func TestAppPasswordContractMigrationBackfillsLegacyPublicIDAndSeparatesLabel(t *testing.T) {
	db := testpg.DB(t, func(ctx context.Context, db *sql.DB) error {
		var runner Runner
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
		for _, migration := range upgradeMigrations[:3] {
			if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at, checksum, dirty) VALUES ($1,CURRENT_TIMESTAMP,$2,false)`, migration.Version, migration.Checksum); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tokens(id, subject_type, subject_id, kind, verifier, label, scope_json, created_at) VALUES ('00000000-0000-4000-8000-000000000501','mailbox','user@example.test','app_password','pbkdf2_sha256$1$salt$YQ==','app_legacy_public_id','[]',CURRENT_TIMESTAMP)`); err != nil {
			return err
		}
		return tx.Commit()
	})
	if err := MigrateSQL(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var publicID, label string
	if err := db.QueryRow(`SELECT public_id, label FROM tokens WHERE kind='app_password'`).Scan(&publicID, &label); err != nil {
		t.Fatal(err)
	}
	if publicID != "app_legacy_public_id" || label != "app_legacy_public_id" {
		t.Fatalf("public_id=%q label=%q", publicID, label)
	}
	if _, err := db.Exec(`UPDATE tokens SET label='phone' WHERE public_id='app_legacy_public_id'`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT public_id, label FROM tokens WHERE kind='app_password'`).Scan(&publicID, &label); err != nil {
		t.Fatal(err)
	}
	if publicID != "app_legacy_public_id" || label != "phone" {
		t.Fatalf("separated public_id=%q label=%q", publicID, label)
	}
}
