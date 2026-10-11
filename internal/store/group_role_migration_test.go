package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestGroupRoleProjectionMigrationParity(t *testing.T) {
	data, err := os.ReadFile("../../migrations/0019_group_role_projection.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlText := strings.TrimSpace(string(data))
	if len(upgradeMigrations) != 19 {
		t.Fatalf("upgrade count=%d want 19", len(upgradeMigrations))
	}
	migration := upgradeMigrations[17]
	sum := sha256.Sum256([]byte(sqlText))
	if migration.Version != "0019_group_role_projection" || migration.SQL != sqlText || migration.Checksum != hex.EncodeToString(sum[:]) {
		t.Fatal("file/runtime/ledger mismatch")
	}
}

func TestGroupRoleProjectionMigrationLegacyDefaults(t *testing.T) {
	db := testpg.DB(t, nil)
	ctx := context.Background()
	// Exercise the actual prior schema, including a legacy binding, before 0019.
	for _, stmt := range InitialSchema {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	for _, migration := range upgradeMigrations {
		if migration.Version == "0019_group_role_projection" {
			break
		}
		if _, err := db.Exec(migration.SQL); err != nil {
			t.Fatal(err)
		}
	}
	_, err := db.Exec(`INSERT INTO identity_refs(id,provider,subject,issuer,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000901','local','legacy','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
 INSERT INTO role_bindings(id,identity_ref_id,role,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000902','00000000-0000-4000-8000-000000000901','global_admin',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../migrations/0019_group_role_projection.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, string(data)); err != nil {
		t.Fatal(err)
	}
	var owned bool
	var revision int64
	if err := db.QueryRow("SELECT operator_owned, authority_revision FROM role_bindings").Scan(&owned, &revision); err != nil || !owned || revision != 1 {
		t.Fatalf("legacy owned=%v revision=%d err=%v", owned, revision, err)
	}
	// Omitted origin in a compatible legacy INSERT retains operator semantics.
	if _, err := db.Exec(`INSERT INTO identity_refs(id,provider,subject,issuer,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000904','local','new-legacy','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);
INSERT INTO role_bindings(id,identity_ref_id,role,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000905','00000000-0000-4000-8000-000000000904','global_admin',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT operator_owned, authority_revision FROM role_bindings WHERE id='00000000-0000-4000-8000-000000000905'").Scan(&owned, &revision); err != nil || !owned || revision != 1 {
		t.Fatalf("new legacy insert owned=%v revision=%d err=%v", owned, revision, err)
	}
	if _, err := db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000903','00000000-0000-4000-8000-000000000901','global_admin',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("0018 uniqueness lost")
	}
	if _, err := db.Exec("UPDATE role_bindings SET authority_revision=0"); err == nil {
		t.Fatal("zero revision accepted")
	}
	if _, err := db.Exec("UPDATE role_bindings SET operator_owned=NULL"); err == nil {
		t.Fatal("null origin accepted")
	}
}

func TestGroupRoleProjectionMappingConstraints(t *testing.T) {
	db := testpg.DB(t, MigrateSQL)
	const mapping = "00000000-0000-4000-8000-000000000911"
	const binding = "00000000-0000-4000-8000-000000000912"
	const identity = "00000000-0000-4000-8000-000000000913"
	_, err := db.Exec(`INSERT INTO identity_refs(id,provider,subject,issuer,created_at,updated_at) VALUES ($1,'local','test','local',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, identity)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,operator_owned,created_at,updated_at) VALUES ($1,$2,'global_admin',false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, binding, identity)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,created_at,updated_at) VALUES ($1,'https://issuer.test/','scope','group','global_admin',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, mapping)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"UPDATE identity_group_role_mappings SET issuer=''",
		"UPDATE identity_group_role_mappings SET scope=''",
		"UPDATE identity_group_role_mappings SET group_id=''",
		"UPDATE identity_group_role_mappings SET revision=0",
		"UPDATE identity_group_role_mappings SET role='domain_manager'",
		"UPDATE identity_group_role_mappings SET role='bogus'",
		"UPDATE identity_group_role_mappings SET group_deleted=true",
		"INSERT INTO identity_group_role_mappings SELECT '00000000-0000-4000-8000-000000000914',issuer,scope,group_id,role,domain_id,revision,enabled,group_deleted,created_at,updated_at FROM identity_group_role_mappings",
	} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatalf("invalid mapping admitted: %s", statement)
		}
	}
	if _, err := db.Exec("INSERT INTO role_binding_group_sources VALUES ($1,$2)", binding, mapping); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO role_binding_group_sources VALUES ($1,$2)", binding, mapping); err == nil {
		t.Fatal("duplicate source accepted")
	}
	if _, err := db.Exec("DELETE FROM identity_group_role_mappings"); err == nil {
		t.Fatal("referenced mapping deleted")
	}
	if _, err := db.Exec("DELETE FROM role_bindings"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM role_binding_group_sources").Scan(&count); err != nil || count != 0 {
		t.Fatalf("source cascade count=%d err=%v", count, err)
	}
}
