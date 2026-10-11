package authn

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestBoundSessionGroupIssuerAndEnabledGuards(t *testing.T) {
	db := authnTestDB(t)
	ctx := context.Background()
	now := time.Unix(100, 0).UTC()
	issuer := "https://auth.example/application/o/mail/"
	seedSCIMMailbox(t, db, "scope-a", "scim-user-1", "subject", "member@example.test", true)
	s := SQLStore{DB: db, CurrentIssuer: issuer}
	session, err := s.PutIdentitySession(ctx, Identity{Issuer: issuer, Subject: "subject", Email: "member@example.test"}, Session{ID: "group-session", CSRFSecretHash: "hash", AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,operator_owned,created_at,updated_at) SELECT '00000000-0000-4000-8000-000000000931',$1,'domain_manager',id,false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM domains WHERE name='example.test'`, session.IdentityRefID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) SELECT '00000000-0000-4000-8000-000000000932',$1,'scope-a','group-a','domain_manager',id,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM domains WHERE name='example.test'`, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("INSERT INTO role_binding_group_sources VALUES ('00000000-0000-4000-8000-000000000931','00000000-0000-4000-8000-000000000932')"); err != nil {
		t.Fatal(err)
	}
	assert := func(store SQLStore, want int) {
		t.Helper()
		bound, ok := store.BoundSession(ctx, "group-session", now.Add(time.Minute))
		if !ok || len(bound.Roles) != want {
			t.Fatalf("issuer=%q roles=%+v ok=%v want=%d", store.CurrentIssuer, bound.Roles, ok, want)
		}
	}
	assert(s, 1)
	if os.Getenv("GOTTH_MAIL_IDENTITY_READ_COST") == "1" {
		// Diagnostic only:20 untimed warmups then exactly200 sequential reads.
		for range 20 {
			assert(s, 1)
		}
		start := time.Now()
		for range 200 {
			assert(s, 1)
		}
		t.Logf("BoundSession diagnostic reads=200 elapsed_ns=%d", time.Since(start).Nanoseconds())
	}
	assert(SQLStore{DB: db}, 0)
	assert(SQLStore{DB: db, CurrentIssuer: "https://other.example/"}, 0)
	assert(SQLStore{DB: db, CurrentIssuer: issuer}, 1)
	for _, sql := range []string{"UPDATE domains SET enabled=false", "UPDATE identity_group_role_mappings SET enabled=false", "UPDATE identity_group_role_mappings SET issuer='https://other.example/'", "UPDATE identity_group_role_mappings SET enabled=false,group_deleted=true"} {
		if _, err := db.Exec(sql); err != nil {
			t.Fatal(err)
		}
		assert(s, 0)
		if _, err := db.Exec("UPDATE domains SET enabled=true"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("UPDATE identity_group_role_mappings SET enabled=true,group_deleted=false,issuer=$1", issuer); err != nil {
			t.Fatal(err)
		}
		assert(s, 1)
	}
	if _, err := db.Exec("UPDATE mailboxes SET enabled=false"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.BoundSession(ctx, "group-session", now.Add(time.Minute)); ok {
		t.Fatal("disabled mailbox session accepted")
	}
	if _, err := db.Exec("UPDATE mailboxes SET enabled=true"); err != nil {
		t.Fatal(err)
	}
	assert(s, 1) // local toggle preserves existing session semantics, not SCIM revocation.
	if _, err := db.Exec("UPDATE role_bindings SET operator_owned=true; UPDATE domains SET enabled=false"); err != nil {
		t.Fatal(err)
	}
	assert(SQLStore{DB: db}, 1) // Group guards must not suppress operator origin.
	if _, err := db.Exec("UPDATE role_bindings SET operator_owned=false; DELETE FROM role_binding_group_sources; UPDATE domains SET enabled=true"); err != nil {
		t.Fatal(err)
	}
	assert(s, 0) // No source-less nonoperator row grants authority.
	if _, err := db.Exec("DROP TABLE role_binding_group_sources"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.BoundSession(ctx, "group-session", now.Add(time.Minute)); ok {
		t.Fatal("SQL error accepted")
	}
}
