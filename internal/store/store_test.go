package store

import (
	"strings"
	"testing"
)

func TestMigrationsOnEmptyDB(t *testing.T) {
	var r Runner
	if err := r.MigrateEmpty(); err != nil {
		t.Fatal(err)
	}
	if len(r.Applied) != len(InitialSchema) {
		t.Fatalf("applied %d want %d", len(r.Applied), len(InitialSchema))
	}
	for _, m := range r.Applied {
		if m.Checksum == "" || m.Dirty {
			t.Fatalf("bad migration %#v", m)
		}
	}
}
func TestSchemaValidationHelpers(t *testing.T) {
	if !ValidateDomainName("example.test") {
		t.Fatal("valid domain rejected")
	}
	if ValidateDomainName("Example.Test") {
		t.Fatal("case-sensitive duplicate risk accepted")
	}
	if !ValidateTokenKind("plugin_service") || ValidateTokenKind("root") {
		t.Fatal("bad token kind validation")
	}
}
func TestPluginRegistrationRequiresServiceCredential(t *testing.T) {
	if err := ValidatePluginRegistration(true, "api"); err == nil {
		t.Fatal("expected rejection")
	}
	if err := ValidatePluginRegistration(true, "plugin_service"); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaIncludesDurableV2V3V4State(t *testing.T) {
	want := []string{"oidc_login_states", "sessions", "backup_artifacts", "backup_verifications", "snapshots", "webmail_drafts"}
	for _, table := range want {
		found := false
		for _, stmt := range InitialSchema {
			if strings.Contains(stmt, "CREATE TABLE "+table+" ") {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing durable table %s", table)
		}
	}
}
