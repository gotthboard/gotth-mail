package authn

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	gotthoidc "github.com/gotthboard/gotth-oidc/pkg/oidc"
	"strings"
	"testing"
	"time"
)

const projectedIssuer = "https://auth.example/application/o/gotth-mail/"

func projectionSeed(t *testing.T) *sql.DB {
	t.Helper()
	db := authnTestDB(t)
	seedSCIMMailbox(t, db, "scope-a", "projection-user", "subject", "member@example.test", true)
	for i := 1; i <= 2; i++ {
		g := fmt.Sprint("projection-group-", i)
		if _, e := db.Exec("INSERT INTO scim_resources(scope,resource_type,id,version,created_unix_nano,last_modified_unix_nano,data) VALUES ('scope-a','Group',$1,'v1',1,1,$2)", g, []byte(fmt.Sprintf(`{"id":%q,"members":[{"value":"projection-user"}]}`, g))); e != nil {
			t.Fatal(e)
		}
		if _, e := db.Exec("INSERT INTO scim_group_members(scope,group_id,user_id) VALUES ('scope-a',$1,'projection-user')", g); e != nil {
			t.Fatal(e)
		}
		if _, e := db.Exec("INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) SELECT $1,$2,'scope-a',$3,'domain_manager',id,now(),now() FROM domains WHERE name='example.test'", fmt.Sprintf("00000000-0000-4000-8000-%012d", 800+i), projectedIssuer, g); e != nil {
			t.Fatal(e)
		}
	}
	return db
}

type projectionOIDCClient struct {
	*fakeOIDCClient
	calls int
}

func (c *projectionOIDCClient) CompleteResponse(ctx context.Context, r gotthoidc.AuthorizationResponse, a gotthoidc.ProtectedAttempt) (gotthoidc.Identity, error) {
	c.calls++
	return c.fakeOIDCClient.CompleteResponse(ctx, r, a)
}
func projectionLogin(t *testing.T, db *sql.DB, state, authority string) (*projectionOIDCClient, SQLStore, CallbackInput, time.Time) {
	t.Helper()
	client := &projectionOIDCClient{fakeOIDCClient: testOIDCClient(state, "nonce")}
	email := "member@example.test"
	client.identity = gotthoidc.Identity{Issuer: projectedIssuer, Subject: "subject", Email: &email}
	s := SQLStore{DB: db, CurrentIssuer: authority}
	now := time.Now().UTC()
	start, e := StartLogin(context.Background(), client, s, "browser", "/", now, time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	return client, s, CallbackInput{Response: gotthoidc.AuthorizationResponse{State: start.StateID, Code: "synthetic-code"}, BrowserBinding: "browser"}, now.Add(time.Second)
}
func projectionRowCounts(t *testing.T, db *sql.DB, want map[string]int) {
	t.Helper()
	for table, n := range want {
		var got int
		if e := db.QueryRow("SELECT count(*) FROM " + table).Scan(&got); e != nil || got != n {
			t.Fatalf("%s=%d want=%d error=%v", table, got, n, e)
		}
	}
}
func TestOIDCProjectionPreexistingMembershipAndSpentFailure(t *testing.T) {
	db := projectionSeed(t)
	ctx := context.Background()
	if _, e := db.Exec(`CREATE TABLE oidc_projection_fail(action text); CREATE SEQUENCE oidc_projection_calls; CREATE FUNCTION fail_oidc_projection() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF EXISTS(SELECT 1 FROM oidc_projection_fail WHERE action=NEW.action) THEN PERFORM nextval('oidc_projection_calls'); RAISE EXCEPTION 'forced projection serialization failure' USING ERRCODE='40001'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_oidc_projection BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_oidc_projection()`); e != nil {
		t.Fatal(e)
	}
	for i, action := range []string{"identity.group_role_source.add", "oidc.session.create"} {
		if _, e := db.Exec("DELETE FROM oidc_projection_fail; ALTER SEQUENCE oidc_projection_calls RESTART WITH 1"); e != nil {
			t.Fatal(e)
		}
		if _, e := db.Exec("INSERT INTO oidc_projection_fail VALUES ($1)", action); e != nil {
			t.Fatal(e)
		}
		state := fmt.Sprint("failed-projection-", i)
		client, s, input, now := projectionLogin(t, db, state, projectedIssuer)
		if _, e := CompleteCallback(ctx, client, s, input, now); e == nil {
			t.Fatal("projection failure admitted session")
		}
		projectionRowCounts(t, db, map[string]int{"identity_refs": 0, "role_bindings": 0, "role_binding_group_sources": 0, "sessions": 0, "audit_events": 0})
		hash := sha256.Sum256([]byte(state))
		var spent bool
		if e := db.QueryRow("SELECT used_at IS NOT NULL FROM oidc_login_states WHERE state_hash=$1", hash[:]).Scan(&spent); e != nil || !spent {
			t.Fatal("failed projection unspent attempt", spent, e)
		}
		var calls int
		if e := db.QueryRow("SELECT last_value FROM oidc_projection_calls").Scan(&calls); e != nil || calls != 1 {
			t.Fatal("transaction replay", calls, e)
		}
		if _, e := CompleteCallback(ctx, client, s, input, now.Add(time.Second)); e != ErrInvalidOIDCState {
			t.Fatalf("spent callback replay=%v", e)
		}
		if client.calls != 1 {
			t.Fatal("exchange replayed", client.calls)
		}
	}
	if _, e := db.Exec("DELETE FROM oidc_projection_fail"); e != nil {
		t.Fatal(e)
	}
	client, s, input, now := projectionLogin(t, db, "fresh-projection", projectedIssuer)
	result, e := CompleteCallback(ctx, client, s, input, now)
	if e != nil {
		t.Fatal(e)
	}
	projectionRowCounts(t, db, map[string]int{"identity_refs": 1, "role_bindings": 1, "role_binding_group_sources": 2, "sessions": 1, "audit_events": 3})
	bound, ok := s.BoundSession(ctx, result.Session.ID, now)
	if !ok || len(bound.Roles) != 1 || bound.Roles[0].Role != "domain_manager" || bound.Roles[0].Domain != "example.test" {
		t.Fatalf("prelogin membership not converged %#v %v", bound, ok)
	}
	var leaked int
	if e = db.QueryRow("SELECT count(*) FROM audit_events WHERE action LIKE 'identity.group_role_source.%' AND (after_redacted_json LIKE '%subject%' OR after_redacted_json LIKE '%member@example.test%' OR after_redacted_json LIKE '%https://%')").Scan(&leaked); e != nil || leaked != 0 {
		t.Fatal("projection audit leaked provider claims", leaked, e)
	}
	if _, e = db.Exec("DELETE FROM scim_group_members"); e != nil {
		t.Fatal(e)
	}
	other, otherStore, otherInput, otherNow := projectionLogin(t, db, "other-issuer-retraction", "https://other.example/")
	if _, e = CompleteCallback(ctx, other, otherStore, otherInput, otherNow); e != nil {
		t.Fatal(e)
	}
	projectionRowCounts(t, db, map[string]int{"role_bindings": 0, "role_binding_group_sources": 0})
	bound, ok = s.BoundSession(ctx, result.Session.ID, now)
	if !ok || len(bound.Roles) != 0 {
		t.Fatal("restore issuer resurrected stale origin", bound, ok)
	}
}
func TestOIDCProjectionRequiresSerializableAdmission(t *testing.T) {
	db := projectionSeed(t)
	if _, e := db.Exec(`CREATE FUNCTION require_serializable_identity() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF current_setting('transaction_isolation') <> 'serializable' THEN RAISE EXCEPTION 'identity admission must be serializable'; END IF; RETURN NEW; END$$; CREATE TRIGGER require_serializable_identity BEFORE INSERT OR UPDATE ON identity_refs FOR EACH ROW EXECUTE FUNCTION require_serializable_identity()`); e != nil {
		t.Fatal(e)
	}
	client, s, input, now := projectionLogin(t, db, "serializable-projection", projectedIssuer)
	result, e := CompleteCallback(context.Background(), client, s, input, now)
	if e != nil {
		t.Fatal(e)
	}
	b, ok := s.BoundSession(context.Background(), result.Session.ID, now)
	if !ok || len(b.Roles) != 1 {
		t.Fatal("serializable projection failed", b, ok)
	}
}
func TestOIDCProjectionMalformedCanonicalUserRollsBackIdentity(t *testing.T) {
	db := projectionSeed(t)
	if _, e := db.Exec("UPDATE scim_resources SET data=$1 WHERE id='projection-user'", []byte(`{"active":"true"}`)); e != nil {
		t.Fatal(e)
	}
	client, s, input, now := projectionLogin(t, db, "invalid-active", projectedIssuer)
	if _, e := CompleteCallback(context.Background(), client, s, input, now); e == nil || !strings.Contains(e.Error(), "canonical SCIM active") {
		t.Fatalf("invalid canonical User admitted: %v", e)
	}
	projectionRowCounts(t, db, map[string]int{"identity_refs": 0, "sessions": 0, "role_bindings": 0, "role_binding_group_sources": 0, "audit_events": 0})
	var n int
	if e := db.QueryRow("SELECT count(*) FROM oidc_login_states WHERE used_at IS NOT NULL").Scan(&n); e != nil || n != 1 {
		t.Fatal("attempt not spent", n, e)
	}
}
