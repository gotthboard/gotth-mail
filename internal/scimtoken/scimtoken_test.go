package scimtoken

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

var (
	firstSecret  = []byte("first-scim-bearer-0123456789ABCDEFG")
	secondSecret = []byte("second-scim-bearer-0123456789ABCDEF")
)

func TestReadSecretRequiresProtectedRegularBearerFile(t *testing.T) {
	root := t.TempDir()
	valid := filepath.Join(root, "valid")
	writeSecret(t, valid, firstSecret, 0o600)
	got, err := ReadSecret(valid)
	if err != nil || !bytes.Equal(got, firstSecret) {
		t.Fatalf("secret=%q err=%v", got, err)
	}
	clear(got)

	cases := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"weak", []byte("short"), 0o600},
		{"newline", append(append([]byte(nil), firstSecret...), '\n'), 0o600},
		{"space", append(append([]byte(nil), firstSecret...), ' '), 0o600},
		{"permissions", firstSecret, 0o640},
		{"oversized", bytes.Repeat([]byte{'a'}, maxSecretBytes+1), 0o600},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(root, test.name)
			writeSecret(t, path, test.data, test.mode)
			if _, err := ReadSecret(path); err == nil {
				t.Fatal("unsafe secret file accepted")
			}
		})
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSecret(link); err == nil {
		t.Fatal("symlink secret file accepted")
	}
	if _, err := ReadSecret(root); err == nil {
		t.Fatal("directory secret file accepted")
	}
}

func TestSCIMTokenCreateRotateReactivateAndNoop(t *testing.T) {
	db := tokenDB(t)
	service := Service{DB: db, Now: func() time.Time { return time.Unix(1700, 0).UTC() }}
	ctx := context.Background()

	create, err := service.Preview(ctx, "authentik-primary", firstSecret)
	if err != nil || create.Operation != "create" || create.PlanID == "" {
		t.Fatalf("create plan=%#v err=%v", create, err)
	}
	encoded, err := json.Marshal(create)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, firstSecret) || bytes.Contains(encoded, []byte("secret")) || bytes.Contains(encoded, []byte("verifier")) {
		t.Fatalf("plan disclosed credential material: %s", encoded)
	}
	if _, err := service.Apply(ctx, "authentik-primary", firstSecret, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong confirmation accepted")
	}
	assertCounts(t, db, 0, 0)

	created, err := service.Apply(ctx, "authentik-primary", firstSecret, create.PlanID)
	if err != nil || !created.Changed || created.Plan.Operation != "create" {
		t.Fatalf("created=%#v err=%v", created, err)
	}
	firstVerifier := tokenVerifier(t, db)
	if firstVerifier == string(firstSecret) || !strings.HasPrefix(firstVerifier, "pbkdf2_sha256$") {
		t.Fatalf("invalid stored verifier %q", firstVerifier)
	}
	assertBearer(t, db, firstSecret, true)
	assertCounts(t, db, 1, 1)

	unchanged, err := service.Preview(ctx, "authentik-primary", firstSecret)
	if err != nil || unchanged.Operation != "unchanged" {
		t.Fatalf("unchanged=%#v err=%v", unchanged, err)
	}
	result, err := service.Apply(ctx, "authentik-primary", firstSecret, unchanged.PlanID)
	if err != nil || result.Changed {
		t.Fatalf("no-op result=%#v err=%v", result, err)
	}
	if got := tokenVerifier(t, db); got != firstVerifier {
		t.Fatal("same-secret retry rewrote verifier")
	}
	assertCounts(t, db, 1, 1)

	rotate, err := service.Preview(ctx, "authentik-primary", secondSecret)
	if err != nil || rotate.Operation != "rotate" {
		t.Fatalf("rotate=%#v err=%v", rotate, err)
	}
	if _, err := service.Apply(ctx, "authentik-primary", secondSecret, rotate.PlanID); err != nil {
		t.Fatal(err)
	}
	assertBearer(t, db, firstSecret, false)
	assertBearer(t, db, secondSecret, true)
	assertCounts(t, db, 1, 2)

	if _, err := db.Exec(`UPDATE tokens SET revoked_at=CURRENT_TIMESTAMP`); err != nil {
		t.Fatal(err)
	}
	reactivate, err := service.Preview(ctx, "authentik-primary", secondSecret)
	if err != nil || reactivate.Operation != "reactivate" {
		t.Fatalf("reactivate=%#v err=%v", reactivate, err)
	}
	if _, err := service.Apply(ctx, "authentik-primary", secondSecret, reactivate.PlanID); err != nil {
		t.Fatal(err)
	}
	assertBearer(t, db, secondSecret, true)
	assertCounts(t, db, 1, 3)

	rows, err := db.Query(`SELECT action, resource_id, before_redacted_json, after_redacted_json FROM audit_events ORDER BY timestamp, action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var action, resource, before, after string
		if err := rows.Scan(&action, &resource, &before, &after); err != nil {
			t.Fatal(err)
		}
		joined := action + resource + before + after
		if resource != "authentik-primary" || bytes.Contains([]byte(joined), firstSecret) || bytes.Contains([]byte(joined), secondSecret) || strings.Contains(joined, "pbkdf2_sha256") {
			t.Fatalf("unsafe audit row action=%q resource=%q before=%q after=%q", action, resource, before, after)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSCIMTokenRejectsStalePlanKindConflictAndAuditFailure(t *testing.T) {
	t.Run("stale plan", func(t *testing.T) {
		db := tokenDB(t)
		service := Service{DB: db}
		ctx := context.Background()
		plan, err := service.Preview(ctx, "authentik-primary", firstSecret)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := identity.HashSecret(string(secondSecret))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO tokens(id,subject_type,subject_id,kind,verifier,label,scope_json,created_at) VALUES ($1,'token','authentik-primary','scim_client',$2,'authentik-primary','[]',CURRENT_TIMESTAMP)`, identity.TokenStorageID("authentik-primary"), verifier); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Apply(ctx, "authentik-primary", firstSecret, plan.PlanID); err == nil || !strings.Contains(err.Error(), "confirmation digest") {
			t.Fatalf("stale apply err=%v", err)
		}
		assertBearer(t, db, secondSecret, true)
		assertCounts(t, db, 1, 0)
	})

	t.Run("kind conflict", func(t *testing.T) {
		db := tokenDB(t)
		if _, err := db.Exec(`INSERT INTO tokens(id,subject_type,subject_id,kind,verifier,label,scope_json,created_at) VALUES ($1,'token','authentik-primary','api','verifier','authentik-primary','[]',CURRENT_TIMESTAMP)`, identity.TokenStorageID("authentik-primary")); err != nil {
			t.Fatal(err)
		}
		if _, err := (Service{DB: db}).Preview(context.Background(), "authentik-primary", firstSecret); err == nil || !strings.Contains(err.Error(), "different subject or kind") {
			t.Fatalf("kind conflict err=%v", err)
		}
	})

	t.Run("invalid verifier", func(t *testing.T) {
		db := tokenDB(t)
		if _, err := db.Exec(`INSERT INTO tokens(id,subject_type,subject_id,kind,verifier,label,scope_json,created_at) VALUES ($1,'token','authentik-primary','scim_client','garbage','authentik-primary','[]',CURRENT_TIMESTAMP)`, identity.TokenStorageID("authentik-primary")); err != nil {
			t.Fatal(err)
		}
		if _, err := (Service{DB: db}).Preview(context.Background(), "authentik-primary", firstSecret); err == nil || !strings.Contains(err.Error(), "verifier is invalid") {
			t.Fatalf("invalid verifier err=%v", err)
		}
	})

	t.Run("audit rollback", func(t *testing.T) {
		db := tokenDB(t)
		if _, err := db.Exec(`CREATE FUNCTION reject_scim_token_audit() RETURNS trigger AS $$ BEGIN IF NEW.action='scim.token.create' THEN RAISE EXCEPTION 'forced token audit failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql; CREATE TRIGGER reject_scim_token_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_scim_token_audit()`); err != nil {
			t.Fatal(err)
		}
		service := Service{DB: db}
		plan, err := service.Preview(context.Background(), "authentik-primary", firstSecret)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.Apply(context.Background(), "authentik-primary", firstSecret, plan.PlanID); err == nil || !strings.Contains(err.Error(), "forced token audit failure") {
			t.Fatalf("audit failure err=%v", err)
		}
		assertCounts(t, db, 0, 0)
	})

	db := tokenDB(t)
	for _, actorID := range []string{"", "UPPER", "space id", "-leading", strings.Repeat("a", 129)} {
		if _, err := (Service{DB: db}).Preview(context.Background(), actorID, firstSecret); err == nil {
			t.Fatalf("invalid actor ID %q accepted", actorID)
		}
	}
}

func tokenDB(t *testing.T) *sql.DB {
	t.Helper()
	return testpg.DB(t, store.MigrateSQL)
}

func writeSecret(t *testing.T, path string, value []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, value, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func tokenVerifier(t *testing.T, db *sql.DB) string {
	t.Helper()
	var verifier string
	if err := db.QueryRow(`SELECT verifier FROM tokens WHERE subject_id='authentik-primary'`).Scan(&verifier); err != nil {
		t.Fatal(err)
	}
	return verifier
}

func assertBearer(t *testing.T, db *sql.DB, secret []byte, accepted bool) {
	t.Helper()
	service, err := identity.NewSQLService(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := service.AuthenticateBearer("Bearer "+string(secret), "scim_client")
	if accepted && (err != nil || actor.ID != "authentik-primary" || actor.Type != "scim_client") {
		t.Fatalf("accepted=%v actor=%#v err=%v", accepted, actor, err)
	}
	if !accepted && err == nil {
		t.Fatalf("rejected secret authenticated actor=%#v", actor)
	}
}

func assertCounts(t *testing.T, db *sql.DB, tokens, events int) {
	t.Helper()
	for table, want := range map[string]int{"tokens": tokens, "audit_events": events} {
		var got int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&got); err != nil || got != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, got, want, err)
		}
	}
}
