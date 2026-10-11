package api

import (
	"context"
	"errors"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"github.com/lib/pq"
	"testing"
	"time"
)

// This is the actual SQL login caller racing the actual SCIM HTTP caller, not
// two simulations of the leaf. A disposable SQL trigger establishes the order.
func TestSCIMProjectionLoginRemovalAbsentIdentityRace(t *testing.T) {
	db, _, h, u, groups := projectionFixture(t)
	projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(u), 200)
	projectionCounts(t, db, 0, 0)
	projectionExec(t, db, "CREATE SEQUENCE projection_login_calls; CREATE FUNCTION pause_projection_login() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('projection_login_calls'); PERFORM pg_advisory_xact_lock(20261003); RETURN NEW; END$$; CREATE TRIGGER pause_projection_login BEFORE INSERT ON identity_refs FOR EACH ROW EXECUTE FUNCTION pause_projection_login()")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner, e := db.Conn(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	if _, e = owner.ExecContext(ctx, "SELECT pg_advisory_lock(20261003)"); e != nil {
		t.Fatal(e)
	}
	defer owner.ExecContext(context.Background(), "SELECT pg_advisory_unlock(20261003)")
	s := authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}
	now := time.Now().UTC()
	result := make(chan error, 1)
	go func() {
		_, err := s.PutIdentitySession(ctx, authn.Identity{Issuer: projectionIssuer, Subject: "projection-subject", Email: "member@example.test"}, authn.Session{ID: "racing-login", CSRFSecretHash: "hash", AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now})
		result <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	waiting := false
	for time.Now().Before(deadline) {
		if e = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND classid=0 AND objid=20261003 AND NOT granted)").Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !waiting {
		t.Fatal("real login did not reach controlled insert barrier")
	}
	projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(""), 200)
	if _, e = owner.ExecContext(ctx, "SELECT pg_advisory_unlock(20261003)"); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-result:
	case <-ctx.Done():
		t.Fatal("login did not terminate after barrier release")
	}
	var pg *pq.Error
	if !errors.As(e, &pg) || pg.Code != "40001" {
		t.Fatalf("inconsistent login/removal must serialize-abort, got %v", e)
	}
	projectionCounts(t, db, 0, 0)
	for _, table := range []string{"identity_refs", "sessions"} {
		var count int
		if e = db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); e != nil || count != 0 {
			t.Fatal("aborted login leaked", table, count, e)
		}
	}
	var calls int
	if e = db.QueryRow("SELECT last_value FROM projection_login_calls").Scan(&calls); e != nil || calls != 1 {
		t.Fatal("login callback replay", calls, e)
	}
	projectionExec(t, db, "DROP TRIGGER pause_projection_login ON identity_refs")
	fresh := projectionSession(t, db, "fresh-after-race")
	bound, ok := s.BoundSession(context.Background(), fresh.ID, time.Now())
	if !ok || len(bound.Roles) != 0 {
		t.Fatal("fresh login resurrected removed membership", bound, ok)
	}
	t.Log("actual login snapshot versus committed SCIM member removal: SQLSTATE40001, one insert attempt, zero leaked authority; fresh login sees zero roles")
}
