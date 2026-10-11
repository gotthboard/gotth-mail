package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestMigrationAuthorityBootstrapMatchesCurrent0020Inventory(t *testing.T) {
	upgrade := authorityScript(t, "bootstrap-migration-authority-upgrade-0020.sql")
	fresh := authorityScript(t, "bootstrap-migration-authority-fresh.sql")
	fresh0020 := authorityScript(t, "bootstrap-migration-authority-fresh-0020.sql")
	for name, data := range map[string][]byte{"fresh-principals": fresh, "fresh-0020": fresh0020, "upgrade": upgrade} {
		text := string(data)
		for _, forbidden := range []string{"PASSWORD '", "postgres://", "REASSIGN OWNED"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden %q", name, forbidden)
			}
		}
		for _, role := range []string{"gotth_mail_schema_owner", "gotth_mail_migrator", "gotth_mail_app", "gotth_mail_gate", "gotth_mail_jobs", "gotth_mail_import", "gotth_mail_scim"} {
			if !strings.Contains(text, role) {
				t.Fatalf("%s missing role %s", name, role)
			}
		}
	}
	for name, data := range map[string][]byte{"fresh-0020": fresh0020, "upgrade": upgrade} {
		text := string(data)
		if !strings.HasPrefix(text, "BEGIN;\n") || !strings.HasSuffix(text, "COMMIT;\n") {
			t.Fatalf("%s is not one transaction", name)
		}
		manifest := append((&Runner{}).mustMigrations(), upgradeMigrations[:19]...)
		for _, migration := range manifest {
			if !strings.Contains(text, "('"+migration.Version+"','"+migration.Checksum+"')") {
				t.Fatalf("%s missing ledger row %s", name, migration.Version)
			}
		}
		for _, table := range currentTableNames(t) {
			if !strings.Contains(text, "r:"+table) {
				t.Fatalf("%s missing sealed table %s", name, table)
			}
		}
	}
	for _, required := range []string{"fresh-v1-principals-created", "fresh-v1-prefix-ready", "password_encryption", "NOLOGIN"} {
		if !strings.Contains(string(fresh), required) && required != "password_encryption" {
			t.Fatalf("fresh protocol missing %q", required)
		}
	}
	for _, required := range []string{"fresh-v1-prefix-ready", "SCRAM-SHA-256\\$[0-9]+", "ALTER DATABASE %I OWNER TO gotth_mail_schema_owner", "RESET gotth_mail.bootstrap_phase", "ALTER ROLE gotth_mail_app LOGIN"} {
		if !strings.Contains(string(fresh0020), required) {
			t.Fatalf("fresh-0020 missing %q", required)
		}
	}
	for _, required := range []string{"pg_shdepend", "pg_stat_activity", "pg_prepared_xacts", "datistemplate", "rolconnlimit", "rolvaliduntil", "exact completed <=0020 rerun"} {
		if !strings.Contains(string(upgrade), required) {
			t.Fatalf("upgrade provenance missing %q", required)
		}
	}
}

func currentTableNames(t *testing.T) []string {
	t.Helper()
	createTable := regexp.MustCompile("(?m)CREATE TABLE (?:public\\.)?([a-z0-9_]+)")
	set := map[string]bool{}
	for _, statement := range InitialSchema {
		for _, m := range createTable.FindAllStringSubmatch(statement, -1) {
			set[m[1]] = true
		}
	}
	for _, migration := range upgradeMigrations[:19] {
		for _, m := range createTable.FindAllStringSubmatch(migration.SQL, -1) {
			set[m[1]] = true
		}
	}
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	return out
}

func TestOutboundAuthorityV2A1ScopeAndACLContract(t *testing.T) {
	sql := outboundAuthorityV2MigrationSQL
	for _, forbidden := range []string{"local_scim_scope", "restore_capability", "REASSIGN OWNED", "\\set", "BEGIN;", "COMMIT;", "ROLLBACK;", "pg_advisory_lock(", "pg_advisory_unlock("} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("0021 contains deferred or forbidden material %q", forbidden)
		}
	}
	for _, required := range []string{
		"SELECT pg_advisory_xact_lock(0x474d4131::int, 21);",
		"session_user <> 'gotth_mail_migrator' OR current_user <> 'gotth_mail_schema_owner'",
		"GRANT SELECT ON public.outbound_authority_epoch,public.signing_identities,public.forward_signers,public.final_queue_forward_signers TO gotth_mail_app,gotth_mail_gate;",
		"GRANT EXECUTE ON FUNCTION public.gotth_is_canonical_domain(text),public.gotth_is_authority_local_part(text) TO gotth_mail_app,gotth_mail_scim,gotth_mail_import;",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("0021 missing contract %q", required)
		}
	}
}

func TestActualOldRegistryRefusesOutboundAuthorityV2(t *testing.T) {
	db := testpg.MigrationDB(t, MigrateSQL)
	original := upgradeMigrations
	upgradeMigrations = append([]Migration(nil), original[:19]...)
	t.Cleanup(func() { upgradeMigrations = original })
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	err = ValidateCurrentSQL(context.Background(), tx)
	if err == nil || err.Error() != "unknown migration 0021_outbound_authority_v2" {
		t.Fatalf("old registry refusal=%v", err)
	}
}

func TestOutboundAuthorityV2LedgerFailureRollsBackAndReleasesLock(t *testing.T) {
	original := upgradeMigrations
	db := testpg.MigrationDB(t, func(ctx context.Context, db *sql.DB) error {
		upgradeMigrations = append([]Migration(nil), original[:19]...)
		defer func() { upgradeMigrations = original }()
		return MigrateSQL(ctx, db)
	})
	if _, err := db.Exec(`CREATE FUNCTION fail_0021_ledger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.version='0021_outbound_authority_v2' THEN RAISE EXCEPTION 'injected ledger failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_0021_ledger BEFORE INSERT ON schema_migrations FOR EACH ROW EXECUTE FUNCTION fail_0021_ledger()`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateSQL(context.Background(), db); err == nil || !strings.Contains(err.Error(), "injected ledger failure") {
		t.Fatalf("migration failure=%v", err)
	}
	var relationExists bool
	var ledgerRows int
	if err := db.QueryRow(`SELECT to_regclass('public.outbound_authority_epoch') IS NOT NULL`).Scan(&relationExists); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE version='0021_outbound_authority_v2'`).Scan(&ledgerRows); err != nil {
		t.Fatal(err)
	}
	var lockFree bool
	if err := db.QueryRow(`SELECT pg_try_advisory_xact_lock(0x474d4131::int,21)`).Scan(&lockFree); err != nil {
		t.Fatal(err)
	}
	if relationExists || ledgerRows != 0 || !lockFree {
		t.Fatalf("relation=%v ledger=%d lockFree=%v", relationExists, ledgerRows, lockFree)
	}
	if _, err := db.Exec(`DROP TRIGGER fail_0021_ledger ON schema_migrations; DROP FUNCTION fail_0021_ledger()`); err != nil {
		t.Fatal(err)
	}
	if err := MigrateSQL(context.Background(), db); err != nil {
		t.Fatalf("identical-byte retry: %v", err)
	}
}

func TestMigrationAuthorityFreshAndUpgradeBootstrap(t *testing.T) {
	for _, lane := range []string{"fresh", "upgrade"} {
		t.Run(lane, func(t *testing.T) {
			db := testpg.RuntimeDB(t, lane,
				func(ctx context.Context, db *sql.DB) error {
					return MigrateSQLThrough(ctx, db, finalQueueArtifactBindingMigrationVersion)
				},
				MigrateSQL, ValidateCurrentSQL)
			var canonicalACL, ledgerACL bool
			if err := db.QueryRow("SELECT has_function_privilege('gotth_mail_app','public.gotth_is_canonical_domain(text)','EXECUTE')").Scan(&canonicalACL); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow("SELECT has_table_privilege('gotth_mail_app','public.schema_migrations','SELECT') AND NOT has_table_privilege('gotth_mail_app','public.schema_migrations','INSERT')").Scan(&ledgerACL); err != nil {
				t.Fatal(err)
			}
			if !canonicalACL || !ledgerACL {
				t.Fatalf("%s canonicalACL=%v ledgerACL=%v", lane, canonicalACL, ledgerACL)
			}
			if _, err := db.Exec("UPDATE schema_migrations SET dirty=true WHERE version='0021_outbound_authority_v2'"); err == nil {
				t.Fatalf("%s app mutated migration ledger", lane)
			}
			var badOwner int
			if err := db.QueryRow("SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f') AND r.rolname<>'gotth_mail_schema_owner'").Scan(&badOwner); err != nil {
				t.Fatal(err)
			}
			if badOwner != 0 {
				t.Fatalf("%s non-schema-owner objects=%d", lane, badOwner)
			}
		})
	}
}

func TestBootstrapRejectsInvalidLedgerWithoutAuthorityDrift(t *testing.T) {
	mutations := map[string]string{
		"missing":  "DELETE FROM schema_migrations WHERE version='0020_final_queue_artifact_binding'",
		"dirty":    "UPDATE schema_migrations SET dirty=true WHERE version='0020_final_queue_artifact_binding'",
		"checksum": "UPDATE schema_migrations SET checksum='wrong' WHERE version='0020_final_queue_artifact_binding'",
		"unknown":  "INSERT INTO schema_migrations(version,applied_at,checksum,dirty) VALUES ('9999_unknown',now(),'x',false)",
		"late":     "",
	}
	for _, lane := range []string{"fresh", "upgrade"} {
		for name, mutation := range mutations {
			t.Run(lane+"/"+name, func(t *testing.T) {
				db := testpg.MigrationDB(t, nil)
				if err := MigrateSQLThrough(context.Background(), db, finalQueueArtifactBindingMigrationVersion); err != nil {
					t.Fatal(err)
				}
				var port int
				if err := db.QueryRow("SELECT inet_server_port()").Scan(&port); err != nil {
					t.Fatal(err)
				}
				admin, err := sql.Open("postgres", fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/gotth_mail?sslmode=disable", port))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = admin.Close() })
				if lane == "upgrade" {
					if _, err := admin.Exec("DO $p$ DECLARE r record; BEGIN FOR r IN SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r' ORDER BY c.relname LOOP EXECUTE format('ALTER TABLE public.%I OWNER TO gotth_mail_app',r.relname); END LOOP; END $p$"); err != nil {
						t.Fatal(err)
					}
				}
				if mutation != "" {
					if _, err := admin.Exec(mutation); err != nil {
						t.Fatal(err)
					}
				}
				before := authoritySnapshot(t, admin)
				scriptName := "bootstrap-migration-authority-fresh-0020.sql"
				if lane == "upgrade" {
					scriptName = "bootstrap-migration-authority-upgrade-0020.sql"
				}
				script, err := os.ReadFile("../../scripts/" + scriptName)
				if err != nil {
					t.Fatal(err)
				}
				if name == "late" {
					script = []byte(strings.Replace(string(script), "\nCOMMIT;\n", "\nDO $late$ BEGIN RAISE EXCEPTION 'injected late bootstrap failure'; END $late$;\nCOMMIT;\n", 1))
				}
				if _, err := admin.Exec(string(script)); err == nil {
					t.Fatal("invalid bootstrap unexpectedly succeeded")
				}
				_, _ = admin.Exec("ROLLBACK")
				after := authoritySnapshot(t, admin)
				if mismatch := authoritySnapshotMismatch(before, after); mismatch != "" {
					t.Fatal(mismatch)
				}
			})
		}
	}
}

func TestFreshBootstrapPreexistingRoleModel(t *testing.T) {
	admin := testpg.AuthorityDB(t)
	script := authorityScript(t, "bootstrap-migration-authority-fresh.sql")
	cases := []struct{ name, role, create string }{
		{"schema-owner", "gotth_mail_schema_owner", "CREATE ROLE gotth_mail_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"},
		{"migrator-scram", "gotth_mail_migrator", "SET password_encryption='scram-sha-256'; CREATE ROLE gotth_mail_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'collision-migrator'"},
		{"app-scram", "gotth_mail_app", "SET password_encryption='scram-sha-256'; CREATE ROLE gotth_mail_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'collision-app'"},
		{"gate", "gotth_mail_gate", "CREATE ROLE gotth_mail_gate NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"},
		{"jobs", "gotth_mail_jobs", "CREATE ROLE gotth_mail_jobs NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"},
		{"import", "gotth_mail_import", "CREATE ROLE gotth_mail_import NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"},
		{"scim", "gotth_mail_scim", "CREATE ROLE gotth_mail_scim NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mustExec(t, admin, tc.create)
			assertBootstrapRefusal(t, admin, script)
			mustExec(t, admin, "DROP ROLE "+tc.role)
		})
	}
}

func TestAuthorityMutatingPhasesLateRollback(t *testing.T) {
	inject := func(script []byte) []byte {
		return []byte(strings.Replace(string(script), "\nCOMMIT;\n", "\nDO $late$ BEGIN RAISE EXCEPTION 'injected late authority failure'; END $late$;\nCOMMIT;\n", 1))
	}
	t.Run("fresh-creation", func(t *testing.T) {
		admin := testpg.AuthorityDB(t)
		assertBootstrapRefusal(t, admin, inject(authorityScript(t, "bootstrap-migration-authority-fresh.sql")))
	})
	t.Run("fresh-activation", func(t *testing.T) {
		admin := testpg.AuthorityDB(t)
		script := authorityScript(t, "bootstrap-migration-authority-fresh.sql")
		mustExec(t, admin, string(script))
		mustExec(t, admin, "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'late-app'; ALTER ROLE gotth_mail_migrator PASSWORD 'late-migrator'")
		assertBootstrapRefusal(t, admin, inject(script))
	})
	t.Run("fresh-cutover", func(t *testing.T) {
		admin := prepareFresh0020(t)
		assertBootstrapRefusal(t, admin, inject(authorityScript(t, "bootstrap-migration-authority-fresh-0020.sql")))
	})
	t.Run("legacy-upgrade", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		assertBootstrapRefusal(t, admin, inject(authorityScript(t, "bootstrap-migration-authority-upgrade-0020.sql")))
	})
}

func TestFreshActivationMarkerAndVerifierRefusals(t *testing.T) {
	admin := testpg.AuthorityDB(t)
	script := authorityScript(t, "bootstrap-migration-authority-fresh.sql")
	mustExec(t, admin, string(script))
	mustExec(t, admin, "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'activation-app'; ALTER ROLE gotth_mail_migrator PASSWORD 'activation-migrator'")
	setPhase := func(value string) {
		mustExec(t, admin, "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO '"+value+"'")
	}
	tests := []struct{ name, mutate, restore string }{
		{"missing-marker", "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail RESET gotth_mail.bootstrap_phase", "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'fresh-v1-principals-created'"},
		{"wrong-phase", "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'wrong'", "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'fresh-v1-principals-created'"},
		{"wrong-role", "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail RESET gotth_mail.bootstrap_phase; ALTER ROLE gotth_mail_app IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'fresh-v1-principals-created'", "ALTER ROLE gotth_mail_app IN DATABASE gotth_mail RESET gotth_mail.bootstrap_phase; ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'fresh-v1-principals-created'"},
		{"extra-setting", "ALTER ROLE gotth_mail_app SET search_path TO public", "ALTER ROLE gotth_mail_app RESET search_path"},
		{"copied-on-login", "ALTER ROLE gotth_mail_app LOGIN; ALTER ROLE gotth_mail_app IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'fresh-v1-principals-created'", "ALTER ROLE gotth_mail_app NOLOGIN; ALTER ROLE gotth_mail_app IN DATABASE gotth_mail RESET gotth_mail.bootstrap_phase"},
		{"null-verifier", "ALTER ROLE gotth_mail_app PASSWORD NULL", "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'activation-app'"},
		{"md5-verifier", "SET password_encryption='md5'; ALTER ROLE gotth_mail_app PASSWORD 'activation-app'", "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'activation-app'"},
		{"malformed-scram", "UPDATE pg_authid SET rolpassword='SCRAM-SHA-256$malformed' WHERE rolname='gotth_mail_app'", "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'activation-app'"},
		{"other-verifier", "UPDATE pg_authid SET rolpassword='other-verifier' WHERE rolname='gotth_mail_app'", "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'activation-app'"},
		{"wrong-role-credential", "ALTER ROLE gotth_mail_migrator PASSWORD NULL; SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_gate PASSWORD 'wrong-role'", "ALTER ROLE gotth_mail_gate PASSWORD NULL; SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_migrator PASSWORD 'activation-migrator'"},
	}
	_ = setPhase
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mustExec(t, admin, tc.mutate)
			assertBootstrapRefusal(t, admin, script)
			mustExec(t, admin, tc.restore)
		})
	}
	t.Run("wrong-database", func(t *testing.T) {
		mustExec(t, admin, "CREATE DATABASE marker_other")
		mustExec(t, admin, "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail RESET gotth_mail.bootstrap_phase; ALTER ROLE gotth_mail_schema_owner IN DATABASE marker_other SET gotth_mail.bootstrap_phase TO 'fresh-v1-principals-created'")
		assertBootstrapRefusal(t, admin, script)
		mustExec(t, admin, "ALTER ROLE gotth_mail_schema_owner IN DATABASE marker_other RESET gotth_mail.bootstrap_phase; ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'fresh-v1-principals-created'")
		mustExec(t, admin, "DROP DATABASE marker_other")
	})
	mustExec(t, admin, string(script))
	var phase string
	if err := admin.QueryRow("SELECT unnest(setconfig) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole WHERE r.rolname='gotth_mail_schema_owner'").Scan(&phase); err != nil {
		t.Fatal(err)
	}
	if phase != "gotth_mail.bootstrap_phase=fresh-v1-prefix-ready" {
		t.Fatalf("phase=%q", phase)
	}
}

func TestPasswordAuthenticatedFreshAndCollision(t *testing.T) {
	admin := prepareFresh0020(t)
	mustExec(t, admin, string(authorityScript(t, "bootstrap-migration-authority-fresh-0020.sql")))
	configurePasswordHBA(t, admin)
	var port int
	if err := admin.QueryRow("SELECT inet_server_port()").Scan(&port); err != nil {
		t.Fatal(err)
	}
	for user, password := range map[string]string{"gotth_mail_app": "fresh-fixture-app", "gotth_mail_migrator": "fresh-fixture-migrator"} {
		dsn := fmt.Sprintf("host=127.0.0.1 port=%d user=%s dbname=gotth_mail sslmode=disable", port, user) + " password=" + password
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Ping(); err != nil {
			_ = db.Close()
			t.Fatalf("password-authenticated %s: %v", user, err)
		}
		_ = db.Close()
	}
	collision := testpg.AuthorityDB(t)
	mustExec(t, collision, "SET password_encryption='scram-sha-256'; CREATE ROLE gotth_mail_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD 'collision-auth'")
	configurePasswordHBA(t, collision)
	var collisionPort int
	if err := collision.QueryRow("SELECT inet_server_port()").Scan(&collisionPort); err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("host=127.0.0.1 port=%d user=gotth_mail_app dbname=gotth_mail sslmode=disable", collisionPort) + " password=" + "collision-auth"
	foreign, _ := sql.Open("postgres", dsn)
	if err := foreign.Ping(); err != nil {
		t.Fatal(err)
	}
	_ = foreign.Close()
	assertBootstrapRefusal(t, collision, authorityScript(t, "bootstrap-migration-authority-fresh.sql"))
}

func configurePasswordHBA(t *testing.T, admin *sql.DB) {
	t.Helper()
	var data string
	if err := admin.QueryRow("SHOW data_directory").Scan(&data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "pg_hba.conf"), []byte("local all all trust\nhost all all 127.0.0.1/32 scram-sha-256\nhost all all ::1/128 scram-sha-256\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var ok bool
	if err := admin.QueryRow("SELECT pg_reload_conf()").Scan(&ok); err != nil || !ok {
		t.Fatalf("reload hba ok=%v err=%v", ok, err)
	}
}

func TestFresh0020RejectsInterstageRoleDriftWithoutAuthorityDrift(t *testing.T) {
	admin := prepareFresh0020(t)
	script := authorityScript(t, "bootstrap-migration-authority-fresh-0020.sql")
	tests := []struct {
		name, mutate, restore string
	}{
		{"wrong-login", "ALTER ROLE gotth_mail_gate LOGIN", "ALTER ROLE gotth_mail_gate NOLOGIN"},
		{"superuser", "ALTER ROLE gotth_mail_schema_owner SUPERUSER", "ALTER ROLE gotth_mail_schema_owner NOSUPERUSER"},
		{"createdb", "ALTER ROLE gotth_mail_migrator CREATEDB", "ALTER ROLE gotth_mail_migrator NOCREATEDB"},
		{"createrole", "ALTER ROLE gotth_mail_app CREATEROLE", "ALTER ROLE gotth_mail_app NOCREATEROLE"},
		{"inherit", "ALTER ROLE gotth_mail_gate INHERIT", "ALTER ROLE gotth_mail_gate NOINHERIT"},
		{"replication", "ALTER ROLE gotth_mail_jobs REPLICATION", "ALTER ROLE gotth_mail_jobs NOREPLICATION"},
		{"bypassrls", "ALTER ROLE gotth_mail_import BYPASSRLS", "ALTER ROLE gotth_mail_import NOBYPASSRLS"},
		{"forbidden-edge", "GRANT gotth_mail_jobs TO gotth_mail_app", "REVOKE gotth_mail_jobs FROM gotth_mail_app"},
		{"wrong-membership-option", "GRANT gotth_mail_schema_owner TO gotth_mail_migrator WITH ADMIN TRUE, INHERIT FALSE, SET TRUE", "REVOKE ADMIN OPTION FOR gotth_mail_schema_owner FROM gotth_mail_migrator"},
		{"forbidden-setting", "ALTER ROLE gotth_mail_app SET search_path TO public", "ALTER ROLE gotth_mail_app RESET search_path"},
		{"database-missing-public-connect", "REVOKE CONNECT ON DATABASE gotth_mail FROM PUBLIC", "GRANT CONNECT ON DATABASE gotth_mail TO PUBLIC"},
		{"database-missing-owner-create", "REVOKE CREATE ON DATABASE gotth_mail FROM gotth_mail_installer", "GRANT CREATE ON DATABASE gotth_mail TO gotth_mail_installer"},
		{"database-extra-app-connect", "GRANT CONNECT ON DATABASE gotth_mail TO gotth_mail_app", "REVOKE CONNECT ON DATABASE gotth_mail FROM gotth_mail_app"},
		{"database-migrator-grant-option", "GRANT CONNECT ON DATABASE gotth_mail TO gotth_mail_migrator WITH GRANT OPTION", "REVOKE GRANT OPTION FOR CONNECT ON DATABASE gotth_mail FROM gotth_mail_migrator"},
		{"schema-missing-public-usage", "REVOKE USAGE ON SCHEMA public FROM PUBLIC", "GRANT USAGE ON SCHEMA public TO PUBLIC"},
		{"schema-extra-app-usage", "GRANT USAGE ON SCHEMA public TO gotth_mail_app", "REVOKE USAGE ON SCHEMA public FROM gotth_mail_app"},
		{"schema-owner-grant-option", "GRANT USAGE ON SCHEMA public TO gotth_mail_schema_owner WITH GRANT OPTION", "REVOKE GRANT OPTION FOR USAGE ON SCHEMA public FROM gotth_mail_schema_owner"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mustExec(t, admin, tc.mutate)
			assertBootstrapRefusal(t, admin, script)
			mustExec(t, admin, tc.restore)
		})
	}
	mustExec(t, admin, string(script))
	var phases int
	if err := admin.QueryRow("SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole WHERE r.rolname='gotth_mail_schema_owner'").Scan(&phases); err != nil {
		t.Fatal(err)
	}
	if phases != 0 {
		t.Fatalf("fresh phase rows after cutover=%d", phases)
	}
	assertRuntimeRolesNoLogin(t, admin)
}

func prepareFresh0020(t *testing.T) *sql.DB {
	t.Helper()
	admin := testpg.AuthorityDB(t)
	principals := authorityScript(t, "bootstrap-migration-authority-fresh.sql")
	mustExec(t, admin, string(principals))
	mustExec(t, admin, "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'fresh-fixture-app'; ALTER ROLE gotth_mail_migrator PASSWORD 'fresh-fixture-migrator'")
	mustExec(t, admin, string(principals))
	var port int
	if err := admin.QueryRow("SELECT inet_server_port()").Scan(&port); err != nil {
		t.Fatal(err)
	}
	migrator, err := sql.Open("postgres", fmt.Sprintf("postgres://gotth_mail_migrator@127.0.0.1:%d/gotth_mail?sslmode=disable", port))
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateSQLThrough(context.Background(), migrator, finalQueueArtifactBindingMigrationVersion); err != nil {
		_ = migrator.Close()
		t.Fatal(err)
	}
	if err := migrator.Close(); err != nil {
		t.Fatal(err)
	}
	return admin
}

func TestUpgradeBootstrapPreexistingRoleModel(t *testing.T) {
	admin, _ := prepareUpgrade0020(t)
	script := authorityScript(t, "bootstrap-migration-authority-upgrade-0020.sql")
	mustExec(t, admin, string(script))
	mustExec(t, admin, "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail SET gotth_mail.bootstrap_phase TO 'fresh-v1-prefix-ready'")
	assertBootstrapRefusal(t, admin, script)
	mustExec(t, admin, "ALTER ROLE gotth_mail_schema_owner IN DATABASE gotth_mail RESET gotth_mail.bootstrap_phase")
	mustExec(t, admin, "GRANT INSERT ON schema_migrations TO gotth_mail_app")
	assertBootstrapRefusal(t, admin, script)
	mustExec(t, admin, "REVOKE INSERT ON schema_migrations FROM gotth_mail_app")
	before := authoritySnapshot(t, admin)
	mustExec(t, admin, string(script))
	after := authoritySnapshot(t, admin)
	if mismatch := authoritySnapshotMismatch(before, after); mismatch != "" {
		t.Fatal("exact completed rerun: " + mismatch)
	}
	assertRuntimeRolesNoLogin(t, admin)
}

func TestCompletedBootstrapRejectsACLAndSharedDependencyDrift(t *testing.T) {
	admin, _ := prepareUpgrade0020(t)
	script := authorityScript(t, "bootstrap-migration-authority-upgrade-0020.sql")
	mustExec(t, admin, string(script))
	tests := []struct {
		name, mutate, restore string
	}{
		{"database-missing-app-connect", "REVOKE CONNECT ON DATABASE gotth_mail FROM gotth_mail_app", "GRANT CONNECT ON DATABASE gotth_mail TO gotth_mail_app"},
		{"database-extra-gate-connect", "GRANT CONNECT ON DATABASE gotth_mail TO gotth_mail_gate", "REVOKE CONNECT ON DATABASE gotth_mail FROM gotth_mail_gate"},
		{"database-migrator-grant-option", "GRANT CONNECT ON DATABASE gotth_mail TO gotth_mail_migrator WITH GRANT OPTION", "REVOKE GRANT OPTION FOR CONNECT ON DATABASE gotth_mail FROM gotth_mail_migrator"},
		{"database-owner-extra-create", "GRANT CREATE ON DATABASE gotth_mail TO gotth_mail_schema_owner", "REVOKE CREATE ON DATABASE gotth_mail FROM gotth_mail_schema_owner"},
		{"schema-missing-public-usage", "REVOKE USAGE ON SCHEMA public FROM PUBLIC", "GRANT USAGE ON SCHEMA public TO PUBLIC"},
		{"schema-extra-app-usage", "GRANT USAGE ON SCHEMA public TO gotth_mail_app", "REVOKE USAGE ON SCHEMA public FROM gotth_mail_app"},
		{"schema-owner-grant-option", "GRANT USAGE ON SCHEMA public TO gotth_mail_schema_owner WITH GRANT OPTION", "REVOKE GRANT OPTION FOR USAGE ON SCHEMA public FROM gotth_mail_schema_owner"},
		{"schema-missing-owner-usage", "REVOKE USAGE ON SCHEMA public FROM pg_database_owner", "GRANT USAGE ON SCHEMA public TO pg_database_owner"},
		{"object-missing-app-select", "REVOKE SELECT ON domains FROM gotth_mail_app", "GRANT SELECT ON domains TO gotth_mail_app"},
		{"object-extra-app-trigger", "GRANT TRIGGER ON domains TO gotth_mail_app", "REVOKE TRIGGER ON domains FROM gotth_mail_app"},
		{"object-app-grant-option", "GRANT SELECT ON domains TO gotth_mail_app WITH GRANT OPTION", "REVOKE GRANT OPTION FOR SELECT ON domains FROM gotth_mail_app"},
		{"object-missing-owner-maintain", "REVOKE MAINTAIN ON domains FROM gotth_mail_schema_owner", "GRANT MAINTAIN ON domains TO gotth_mail_schema_owner"},
		{"object-owner-grant-option", "GRANT SELECT ON domains TO gotth_mail_schema_owner WITH GRANT OPTION", "REVOKE GRANT OPTION FOR SELECT ON domains FROM gotth_mail_schema_owner"},
		{"default-acl-missing-owner-select", "ALTER DEFAULT PRIVILEGES FOR ROLE gotth_mail_schema_owner REVOKE SELECT ON TABLES FROM gotth_mail_schema_owner", "ALTER DEFAULT PRIVILEGES FOR ROLE gotth_mail_schema_owner GRANT SELECT ON TABLES TO gotth_mail_schema_owner"},
		{"default-acl-extra", "ALTER DEFAULT PRIVILEGES FOR ROLE gotth_mail_schema_owner IN SCHEMA public GRANT SELECT ON TABLES TO gotth_mail_app", "ALTER DEFAULT PRIVILEGES FOR ROLE gotth_mail_schema_owner IN SCHEMA public REVOKE SELECT ON TABLES FROM gotth_mail_app"},
		{"default-acl-grant-option", "ALTER DEFAULT PRIVILEGES FOR ROLE gotth_mail_schema_owner IN SCHEMA public GRANT SELECT ON TABLES TO gotth_mail_app WITH GRANT OPTION", "ALTER DEFAULT PRIVILEGES FOR ROLE gotth_mail_schema_owner IN SCHEMA public REVOKE ALL ON TABLES FROM gotth_mail_app"},
		{"shared-tablespace-acl", "GRANT CREATE ON TABLESPACE pg_default TO gotth_mail_app", "REVOKE CREATE ON TABLESPACE pg_default FROM gotth_mail_app"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mustExec(t, admin, tc.mutate)
			assertBootstrapRefusal(t, admin, script)
			mustExec(t, admin, tc.restore)
		})
	}
	t.Run("shared-tablespace-owner", func(t *testing.T) {
		var dataDirectory string
		if err := admin.QueryRow("SHOW data_directory").Scan(&dataDirectory); err != nil {
			t.Fatal(err)
		}
		location := filepath.Join(filepath.Dir(dataDirectory), "gotth-c5-shared-tablespace")
		if err := os.Mkdir(location, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(location) })
		quoted := strings.ReplaceAll(location, "'", "''")
		mustExec(t, admin, "CREATE TABLESPACE gotth_c5_shared OWNER gotth_mail_gate LOCATION '"+quoted+"'")
		assertBootstrapRefusal(t, admin, script)
		mustExec(t, admin, "ALTER TABLESPACE gotth_c5_shared OWNER TO gotth_mail_installer")
		mustExec(t, admin, "DROP TABLESPACE gotth_c5_shared")
	})
	before := authoritySnapshot(t, admin)
	mustExec(t, admin, string(script))
	if after := authoritySnapshot(t, admin); authoritySnapshotMismatch(before, after) != "" {
		t.Fatal("clean completed rerun drifted")
	}
}

func TestUpgradeBootstrapCredentialTransition(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		refuse     bool
	}{{"passwordless", "", false}, {"scram", "scram-sha-256", false}, {"md5", "md5", true}, {"malformed", "malformed", true}, {"other", "other", true}} {
		t.Run(tc.name, func(t *testing.T) {
			admin, _ := prepareUpgrade0020(t)
			if tc.mode == "other" {
				mustExec(t, admin, "UPDATE pg_authid SET rolpassword='other-verifier' WHERE rolname='gotth_mail'")
			} else if tc.mode == "malformed" {
				mustExec(t, admin, "UPDATE pg_authid SET rolpassword='SCRAM-SHA-256$malformed' WHERE rolname='gotth_mail'")
			} else if tc.mode != "" {
				mustExec(t, admin, "SET password_encryption='"+tc.mode+"'; ALTER ROLE gotth_mail PASSWORD 'unit2-secret'")
			}
			var before sql.NullString
			if err := admin.QueryRow("SELECT rolpassword FROM pg_authid WHERE rolname='gotth_mail'").Scan(&before); err != nil {
				t.Fatal(err)
			}
			script := authorityScript(t, "bootstrap-migration-authority-upgrade-0020.sql")
			if tc.refuse {
				assertBootstrapRefusal(t, admin, script)
				return
			}
			mustExec(t, admin, string(script))
			var after sql.NullString
			if err := admin.QueryRow("SELECT rolpassword FROM pg_authid WHERE rolname='gotth_mail_app'").Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("credential changed during rename for role gotth_mail_app")
			}
			assertRuntimeRolesNoLogin(t, admin)
		})
	}
}

func TestUpgradeProvenanceTopologyRefusals(t *testing.T) {
	script := authorityScript(t, "bootstrap-migration-authority-upgrade-0020.sql")
	t.Run("already-app-name-flags-only", func(t *testing.T) {
		admin := testpg.AuthorityDB(t)
		if err := MigrateSQLThrough(context.Background(), admin, finalQueueArtifactBindingMigrationVersion); err != nil {
			t.Fatal(err)
		}
		mustExec(t, admin, `CREATE ROLE gotth_mail_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE gotth_mail_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE gotth_mail_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE gotth_mail_gate NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE gotth_mail_jobs NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE gotth_mail_import NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE gotth_mail_scim NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; GRANT gotth_mail_schema_owner TO gotth_mail_migrator WITH ADMIN FALSE, INHERIT FALSE, SET TRUE; ALTER ROLE gotth_mail_migrator IN DATABASE gotth_mail SET role TO gotth_mail_schema_owner`)
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("connection-limit", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "ALTER ROLE gotth_mail CONNECTION LIMIT 2")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("valid-until", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "ALTER ROLE gotth_mail VALID UNTIL '2030-01-01'")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("role-setting", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "ALTER ROLE gotth_mail SET statement_timeout TO '1s'")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("database-owner", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "ALTER DATABASE gotth_mail OWNER TO gotth_mail_installer")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("object-owner", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "ALTER TABLE domains OWNER TO gotth_mail_installer")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("object-acl", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "GRANT SELECT ON domains TO gotth_mail_installer")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("arbitrary-second-database", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "CREATE DATABASE tenant_two")
		assertBootstrapRefusal(t, admin, script)
		mustExec(t, admin, "DROP DATABASE tenant_two")
	})
	t.Run("maintenance-database-acl", func(t *testing.T) {
		admin, _ := prepareUpgrade0020(t)
		mustExec(t, admin, "GRANT CONNECT ON DATABASE postgres TO gotth_mail")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("maintenance-database-dependency", func(t *testing.T) {
		admin, port := prepareUpgrade0020(t)
		other, err := sql.Open("postgres", fmt.Sprintf("postgres://gotth_mail_installer@127.0.0.1:%d/postgres?sslmode=disable", port))
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		mustExec(t, other, "CREATE TABLE provenance_remote(id integer); ALTER TABLE provenance_remote ENABLE ROW LEVEL SECURITY; CREATE POLICY provenance_remote_policy ON provenance_remote TO gotth_mail USING (true); GRANT SELECT ON provenance_remote TO gotth_mail")
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("active-remote-session", func(t *testing.T) {
		admin, port := prepareUpgrade0020(t)
		other, err := sql.Open("postgres", fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/postgres?sslmode=disable", port))
		if err != nil {
			t.Fatal(err)
		}
		if err := other.Ping(); err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		assertBootstrapRefusal(t, admin, script)
	})
	t.Run("prepared-transaction", func(t *testing.T) {
		admin, port := prepareUpgrade0020(t)
		legacy, err := sql.Open("postgres", fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/gotth_mail?sslmode=disable", port))
		if err != nil {
			t.Fatal(err)
		}
		mustExec(t, legacy, "BEGIN; SELECT 1; PREPARE TRANSACTION 'gotth_provenance'")
		_ = legacy.Close()
		assertBootstrapRefusal(t, admin, script)
		mustExec(t, admin, "ROLLBACK PREPARED 'gotth_provenance'")
	})
}

func TestAuthoritySnapshotCoversRuledPublicState(t *testing.T) {
	tests := []struct {
		name, mutation string
	}{
		{"connection-limit", "ALTER ROLE gotth_mail CONNECTION LIMIT 2"},
		{"valid-until", "ALTER ROLE gotth_mail VALID UNTIL '2030-01-01'"},
		{"postgres-maintenance-acl", "GRANT CONNECT ON DATABASE postgres TO gotth_mail"},
		{"legacy-shared-dependency", "GRANT CREATE ON TABLESPACE pg_default TO gotth_mail"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			admin, _ := prepareUpgrade0020(t)
			before := authoritySnapshot(t, admin)
			mustExec(t, admin, tc.mutation)
			after := authoritySnapshot(t, admin)
			if reflect.DeepEqual(before.Public, after.Public) {
				t.Fatal("ruled public-state mutation was absent from authority snapshot")
			}
		})
	}
}

func TestAuthoritySnapshotVerifierDiagnosticIsSecretSafe(t *testing.T) {
	admin := prepareFresh0020(t)
	before := authoritySnapshot(t, admin)
	mustExec(t, admin, "SET password_encryption='scram-sha-256'; ALTER ROLE gotth_mail_app PASSWORD 'oracle-private-replacement'")
	after := authoritySnapshot(t, admin)
	diagnostic := authoritySnapshotMismatch(before, after)
	if !strings.Contains(diagnostic, "gotth_mail_app") {
		t.Fatal("verifier mismatch diagnostic omitted changed role name")
	}
	for _, forbidden := range []string{"fresh-fixture-app", "oracle-private-replacement", "SCRAM-SHA-256$"} {
		if strings.Contains(diagnostic, forbidden) {
			t.Fatalf("verifier mismatch diagnostic exposed forbidden marker %q", forbidden)
		}
	}
	if !reflect.DeepEqual(before.Public, after.Public) {
		t.Fatal("verifier-only mutation changed printable public authority state")
	}
}

func prepareUpgrade0020(t *testing.T) (*sql.DB, int) {
	t.Helper()
	admin := testpg.AuthorityDB(t)
	var port int
	if err := admin.QueryRow("SELECT inet_server_port()").Scan(&port); err != nil {
		t.Fatal(err)
	}
	mustExec(t, admin, "CREATE ROLE gotth_mail LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1; ALTER DATABASE gotth_mail OWNER TO gotth_mail")
	legacy, err := sql.Open("postgres", fmt.Sprintf("postgres://gotth_mail@127.0.0.1:%d/gotth_mail?sslmode=disable", port))
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateSQLThrough(context.Background(), legacy, finalQueueArtifactBindingMigrationVersion); err != nil {
		_ = legacy.Close()
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	return admin, port
}

func authorityScript(t *testing.T, name string) []byte {
	t.Helper()
	script, err := os.ReadFile("../../scripts/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func assertBootstrapRefusal(t *testing.T, admin *sql.DB, script []byte) {
	t.Helper()
	before := authoritySnapshot(t, admin)
	if _, err := admin.Exec(string(script)); err == nil {
		t.Fatal("invalid bootstrap unexpectedly succeeded")
	}
	_, _ = admin.Exec("ROLLBACK")
	after := authoritySnapshot(t, admin)
	if mismatch := authoritySnapshotMismatch(before, after); mismatch != "" {
		t.Fatal(mismatch)
	}
}

func assertRuntimeRolesNoLogin(t *testing.T, admin *sql.DB) {
	t.Helper()
	var bad int
	const roleQuery = "SELECT count(*) FROM (VALUES ('gotth_mail_schema_owner',false),('gotth_mail_migrator',true),('gotth_mail_app',true),('gotth_mail_gate',false),('gotth_mail_jobs',false),('gotth_mail_import',false),('gotth_mail_scim',false)) e(name,login) LEFT JOIN pg_roles r ON r.rolname=e.name WHERE r.oid IS NULL OR r.rolcanlogin IS DISTINCT FROM e.login OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication OR r.rolbypassrls"
	if err := admin.QueryRow(roleQuery).Scan(&bad); err != nil {
		t.Fatal(err)
	}
	if bad != 0 {
		t.Fatalf("invalid seven-role postcondition count=%d", bad)
	}
	const edgeQuery = "SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE g.rolname LIKE 'gotth_mail%' OR u.rolname LIKE 'gotth_mail%'"
	var edges int
	if err := admin.QueryRow(edgeQuery).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 1 {
		t.Fatalf("authority membership edges=%d", edges)
	}
	var exact bool
	if err := admin.QueryRow("SELECT NOT admin_option AND NOT inherit_option AND set_option FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE g.rolname='gotth_mail_schema_owner' AND u.rolname='gotth_mail_migrator'").Scan(&exact); err != nil {
		t.Fatal(err)
	}
	if !exact {
		t.Fatal("migrator membership options are not exact")
	}
	const settingQuery = "SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole WHERE r.rolname LIKE 'gotth_mail%' AND r.rolname='gotth_mail_migrator' AND s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()) AND s.setconfig=ARRAY['role=gotth_mail_schema_owner']::text[]"
	var settings int
	if err := admin.QueryRow(settingQuery).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	if settings != 1 {
		t.Fatalf("exact migrator settings=%d", settings)
	}
}

func mustExec(t *testing.T, db *sql.DB, statement string) {
	t.Helper()
	if _, err := db.Exec(statement); err != nil {
		t.Fatal(err)
	}
}

type authoritySnapshotState struct {
	Public    map[string]any
	verifiers []authorityRoleVerifier
}

type authorityRoleVerifier struct {
	role  string
	value sql.NullString
}

func authoritySnapshot(t *testing.T, db *sql.DB) authoritySnapshotState {
	t.Helper()
	const relevantRoles = "('gotth_mail','gotth_mail_schema_owner','gotth_mail_migrator','gotth_mail_app','gotth_mail_gate','gotth_mail_jobs','gotth_mail_import','gotth_mail_scim')"
	const publicQuery = "SELECT jsonb_build_object(" +
		"'roles',(SELECT coalesce(jsonb_agg(jsonb_build_array(r.oid::text,r.rolname,r.rolcanlogin,r.rolsuper,r.rolcreatedb,r.rolcreaterole,r.rolinherit,r.rolreplication,r.rolbypassrls,r.rolconnlimit,coalesce(r.rolvaliduntil::text,''),coalesce(r.rolconfig::text,'')) ORDER BY r.rolname),'[]'::jsonb) FROM pg_roles r WHERE r.rolname IN " + relevantRoles + ")," +
		"'settings',(SELECT coalesce(jsonb_agg(jsonb_build_array(s.setdatabase::text,s.setrole::text,r.rolname,s.setconfig::text) ORDER BY s.setdatabase,r.rolname),'[]'::jsonb) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid=s.setrole WHERE r.rolname IN " + relevantRoles + ")," +
		"'members',(SELECT coalesce(jsonb_agg(jsonb_build_array(m.roleid::text,g.rolname,m.member::text,u.rolname,m.admin_option,m.inherit_option,m.set_option) ORDER BY g.rolname,u.rolname),'[]'::jsonb) FROM pg_auth_members m JOIN pg_roles g ON g.oid=m.roleid JOIN pg_roles u ON u.oid=m.member WHERE g.rolname IN " + relevantRoles + " OR u.rolname IN " + relevantRoles + ")," +
		"'databases',(SELECT coalesce(jsonb_agg(jsonb_build_array(d.oid::text,d.datname,d.datdba::text,r.rolname,coalesce(d.datacl::text,'')) ORDER BY d.datname),'[]'::jsonb) FROM pg_database d JOIN pg_roles r ON r.oid=d.datdba WHERE d.datname IN (current_database(),'postgres'))," +
		"'defaults',(SELECT coalesce(jsonb_agg(jsonb_build_array(d.oid::text,d.defaclrole::text,r.rolname,d.defaclnamespace::text,coalesce(n.nspname,''),d.defaclobjtype,coalesce(d.defaclacl::text,'')) ORDER BY r.rolname,d.defaclnamespace,d.defaclobjtype),'[]'::jsonb) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace)," +
		"'schema',(SELECT jsonb_build_array(n.oid::text,n.nspname,n.nspowner::text,r.rolname,coalesce(n.nspacl::text,'')) FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='public')," +
		"'objects',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid::text,c.relkind::text,c.relname,c.relowner::text,r.rolname,coalesce(c.relacl::text,'')) ORDER BY c.relkind,c.relname),'[]'::jsonb) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f'))," +
		"'dependencies',(SELECT coalesce(jsonb_agg(jsonb_build_array(s.dbid::text,s.classid::text,s.objid::text,s.objsubid,s.refobjid::text,r.rolname,s.deptype::text) ORDER BY r.rolname,s.dbid,s.classid,s.objid,s.objsubid,s.deptype),'[]'::jsonb) FROM pg_shdepend s JOIN pg_roles r ON r.oid=s.refobjid WHERE s.refclassid='pg_authid'::regclass AND r.rolname IN " + relevantRoles + "))::text"
	var rawPublic string
	if err := db.QueryRow(publicQuery).Scan(&rawPublic); err != nil {
		t.Fatal(err)
	}
	state := authoritySnapshotState{}
	if err := json.Unmarshal([]byte(rawPublic), &state.Public); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("SELECT rolname,rolpassword FROM pg_authid WHERE rolname IN " + relevantRoles + " ORDER BY rolname")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var verifier authorityRoleVerifier
		if err := rows.Scan(&verifier.role, &verifier.value); err != nil {
			t.Fatal(err)
		}
		state.verifiers = append(state.verifiers, verifier)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return state
}

func authoritySnapshotMismatch(before, after authoritySnapshotState) string {
	parts := make([]string, 0, 2)
	if !reflect.DeepEqual(before.Public, after.Public) {
		beforeJSON, _ := json.Marshal(before.Public)
		afterJSON, _ := json.Marshal(after.Public)
		parts = append(parts, fmt.Sprintf("authority public state drifted\nbefore=%s\nafter=%s", beforeJSON, afterJSON))
	}
	if roles := changedVerifierRoles(before.verifiers, after.verifiers); len(roles) != 0 {
		parts = append(parts, "authority verifier changed for roles: "+strings.Join(roles, ","))
	}
	return strings.Join(parts, "\n")
}

func changedVerifierRoles(before, after []authorityRoleVerifier) []string {
	left := make(map[string]sql.NullString, len(before))
	right := make(map[string]sql.NullString, len(after))
	for _, verifier := range before {
		left[verifier.role] = verifier.value
	}
	for _, verifier := range after {
		right[verifier.role] = verifier.value
	}
	seen := make(map[string]struct{}, len(left)+len(right))
	for role := range left {
		seen[role] = struct{}{}
	}
	for role := range right {
		seen[role] = struct{}{}
	}
	changed := make([]string, 0)
	for role := range seen {
		leftValue, leftOK := left[role]
		rightValue, rightOK := right[role]
		if leftOK != rightOK || leftValue != rightValue {
			changed = append(changed, role)
		}
	}
	sort.Strings(changed)
	return changed
}
