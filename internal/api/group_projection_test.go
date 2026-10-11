package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/httpui"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/rolebinding"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const projectionIssuer = "https://auth.example/application/o/gotth-mail/"

func projectionRequest(t *testing.T, h http.Handler, method, path, body string, want int) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, authed(method, path, body, "scim-secret-token"))
	if rr.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, rr.Code, want, rr.Body.String())
	}
	return rr
}
func projectionExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, e := db.Exec(q, args...); e != nil {
		t.Fatal(e)
	}
}
func projectionHandler(t *testing.T, db *sql.DB, ids *identity.Service, issuer string) http.Handler {
	t.Helper()
	h, e := NewSCIMHandler("https://mail.example.test/scim/v2", db, ids, authz.StaticAuthorizer{}, audit.SQLWriter{DB: db}, issuer)
	if e != nil {
		t.Fatal(e)
	}
	return h
}
func projectionFixture(t *testing.T) (*sql.DB, *identity.Service, http.Handler, string, []string) {
	t.Helper()
	db, ids, _, _ := scimTestHandler(t, nil)
	h := projectionHandler(t, db, ids, projectionIssuer)
	u := responseID(t, projectionRequest(t, h, http.MethodPost, "/scim/v2/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"externalId":"projection-subject","userName":"member@example.test","active":true}`, 201).Body.String())
	var groups []string
	for i := 1; i <= 2; i++ {
		g := responseID(t, projectionRequest(t, h, http.MethodPost, "/scim/v2/Groups", fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Group%d","members":[]}`, i), 201).Body.String())
		groups = append(groups, g)
		projectionExec(t, db, "INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) SELECT $1,$2,$3,$4,'domain_manager',id,now(),now() FROM domains WHERE name='example.test'", fmt.Sprintf("00000000-0000-4000-8000-%012d", 900+i), projectionIssuer, provisioningScope("scim-test"), g)
	}
	return db, ids, h, u, groups
}
func projectionMembers(u string) string {
	value := "[]"
	if u != "" {
		value = fmt.Sprintf(`[{"value":%q}]`, u)
	}
	return fmt.Sprintf(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"members":%s}}]}`, value)
}
func projectionSession(t *testing.T, db *sql.DB, id string) authn.Session {
	t.Helper()
	now := time.Now().UTC()
	s, e := (authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}).PutIdentitySession(context.Background(), authn.Identity{Issuer: projectionIssuer, Subject: "projection-subject", Email: "member@example.test"}, authn.Session{ID: id, CSRFSecretHash: "hash", AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func projectionCounts(t *testing.T, db *sql.DB, b, s int) {
	t.Helper()
	for table, want := range map[string]int{"role_bindings": b, "role_binding_group_sources": s} {
		var n int
		if e := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != want {
			t.Fatalf("%s=%d want=%d err=%v", table, n, want, e)
		}
	}
}
func projectionSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	var out strings.Builder
	for _, table := range []string{"domains", "mailboxes", "identity_refs", "sessions", "scim_resources", "scim_resource_indexes", "scim_group_members", "scim_tombstones", "identity_group_role_mappings", "role_bindings", "role_binding_group_sources", "audit_events"} {
		var s string
		q := "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')::text FROM " + table + " t"
		if table == "audit_events" {
			q += " WHERE result='success'"
		}
		if e := db.QueryRow(q).Scan(&s); e != nil {
			t.Fatal(e)
		}
		out.WriteString(table + s)
	}
	return out.String()
}
func TestSCIMProjectionLifecycleAndIssuerRetraction(t *testing.T) {
	db, ids, h, u, groups := projectionFixture(t)
	projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(u), 200)
	projectionCounts(t, db, 0, 0)
	var n int
	if e := db.QueryRow("SELECT count(*) FROM identity_refs").Scan(&n); e != nil || n != 0 {
		t.Fatal("Group fabricated identity", n, e)
	}
	projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(""), 200)
	projectionSession(t, db, "session")
	projectionCounts(t, db, 0, 0)
	for _, g := range groups {
		projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+g, projectionMembers(u), 200)
	}
	projectionCounts(t, db, 1, 2)
	projectionRequest(t, h, "PATCH", "/scim/v2/Users/"+u, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`, 200)
	projectionCounts(t, db, 0, 0)
	if ids.Mailboxes["member@example.test"].Active {
		t.Fatal("memory projection did not follow successful disable")
	}
	if _, ok := (authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}).BoundSession(context.Background(), "session", time.Now()); ok {
		t.Fatal("SCIMdisable retained session")
	}
	projectionRequest(t, h, "PATCH", "/scim/v2/Users/"+u, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":true}]}`, 200)
	projectionCounts(t, db, 1, 2)
	if _, ok := (authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}).BoundSession(context.Background(), "session", time.Now()); ok {
		t.Fatal("SCIMreenable resurrected session")
	}
	projectionSession(t, db, "fresh-session")
	op := rolebinding.Service{DB: db, CurrentIssuer: projectionIssuer}
	request := rolebinding.Request{Operation: "grant", Issuer: projectionIssuer, Subject: "projection-subject", Mailbox: "member@example.test", Role: "domain_manager", Domain: "example.test"}
	plan, e := op.Preview(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = op.Apply(context.Background(), request, plan.PlanID); e != nil {
		t.Fatal(e)
	}
	var id string
	if e = db.QueryRow("SELECT id::text FROM role_bindings").Scan(&id); e != nil {
		t.Fatal(e)
	}
	other := projectionHandler(t, db, ids, "https://other.example/")
	projectionRequest(t, other, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(""), 200)
	projectionCounts(t, db, 1, 1)
	absent := projectionHandler(t, db, ids, "")
	projectionRequest(t, absent, "DELETE", "/scim/v2/Groups/"+groups[1], "", 204)
	projectionCounts(t, db, 1, 0)
	var same string
	var enabled, deleted, owned bool
	var revision int
	if e = db.QueryRow("SELECT id::text,operator_owned FROM role_bindings").Scan(&same, &owned); e != nil || same != id || !owned {
		t.Fatal("operator origin/UUID damaged", same, owned, e)
	}
	if e = db.QueryRow("SELECT enabled,group_deleted,revision FROM identity_group_role_mappings WHERE group_id=$1", groups[1]).Scan(&enabled, &deleted, &revision); e != nil || enabled || !deleted || revision != 2 {
		t.Fatal("mapping tombstone", enabled, deleted, revision, e)
	}
	request.Operation = "revoke"
	plan, e = op.Preview(context.Background(), request)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = op.Apply(context.Background(), request, plan.PlanID); e != nil {
		t.Fatal(e)
	}
	projectionCounts(t, db, 0, 0)
	bound, ok := (authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}).BoundSession(context.Background(), "fresh-session", time.Now())
	if !ok || len(bound.Roles) != 0 {
		t.Fatal("issuer restore resurrected stale origin", bound, ok)
	}
	projectionRequest(t, h, "DELETE", "/scim/v2/Users/"+u, "", 204)
	if _, ok := (authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}).BoundSession(context.Background(), "fresh-session", time.Now()); ok {
		t.Fatal("Userdelete retained session")
	}
}
func TestSCIMProjectionAuditRollbackAndExactlyOnce(t *testing.T) {
	db, ids, h, u, groups := projectionFixture(t)
	projectionSession(t, db, "session")
	projectionExec(t, db, `CREATE TABLE fail_projection_action(action text); CREATE SEQUENCE projection_callback_count; CREATE FUNCTION fail_projection_success() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF EXISTS(SELECT 1 FROM fail_projection_action WHERE action=NEW.action) THEN PERFORM nextval('projection_callback_count'); RAISE EXCEPTION 'forced serialization failure' USING ERRCODE='40001'; END IF; RETURN NEW; END$$; CREATE TRIGGER fail_projection_success BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_projection_success()`)
	fail := func(action, method, path, body string) {
		t.Helper()
		projectionExec(t, db, "DELETE FROM fail_projection_action; ALTER SEQUENCE projection_callback_count RESTART WITH 1")
		projectionExec(t, db, "INSERT INTO fail_projection_action VALUES ($1)", action)
		before := projectionSnapshot(t, db)
		active := ids.Mailboxes["member@example.test"].Active
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authed(method, path, body, "scim-secret-token"))
		if rr.Code < 500 {
			t.Fatalf("forced failure status=%d body=%s", rr.Code, rr.Body.String())
		}
		if projectionSnapshot(t, db) != before {
			t.Fatal("failed caller leaked canonical/role/session/success-audit state")
		}
		if ids.Mailboxes["member@example.test"].Active != active {
			t.Fatal("memory updated before failed commit")
		}
		var calls int
		if e := db.QueryRow("SELECT last_value FROM projection_callback_count").Scan(&calls); e != nil || calls != 1 {
			t.Fatal("callback replay", calls, e)
		}
		projectionExec(t, db, "DELETE FROM fail_projection_action")
	}
	fail("scim.group.replace", "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(u))
	projectionRequest(t, h, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(u), 200)
	projectionCounts(t, db, 1, 1)
	fail("scim.user.replace", "PATCH", "/scim/v2/Users/"+u, `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`)
	fail("scim.group.delete", "DELETE", "/scim/v2/Groups/"+groups[0], "")
	fail("identity.group_role_source.remove", "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(""))
}

// Test-only combined boundary: real SCIM/SQL sessions and existing protected UI.
// Fixed-size fixture; delegated SQL, HTTP rendering and crypto dominate time/space.
// No provider login, mutation-form or production scale/performance claim.
func TestIntegratedGroupSessionProtectedUI(t *testing.T) {
	db, ids, scim, user, groups := projectionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const sid = "integrated-ui-session"
	const csrf = "integrated-ui-csrf"
	digest := sha256.Sum256([]byte(csrf))
	sessions := authn.SQLStore{DB: db, CurrentIssuer: projectionIssuer}
	session, err := sessions.PutIdentitySession(ctx, authn.Identity{Issuer: projectionIssuer, Subject: "projection-subject", Email: "member@example.test"}, authn.Session{ID: sid, CSRFSecretHash: base64.RawURLEncoding.EncodeToString(digest[:]), AuthMethod: "oidc", CreatedAt: now, ExpiresAt: now.Add(time.Hour), LastSeenAt: now})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := extensionsadmin.NewService(db, []byte(strings.Repeat("k", 32)), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := func(issuer string, want int) {
		t.Helper()
		store := authn.SQLStore{DB: db, CurrentIssuer: issuer}
		h := httpui.HandlerWithAdminIdentitySessionsAndExtensions(admin.NewStore(), ids, authz.StaticAuthorizer{}, store, func() time.Time { return now.Add(time.Second) }, svc)
		r := httptest.NewRequest("GET", "/admin/extensions", nil)
		r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: sid})
		r.AddCookie(&http.Cookie{Name: "gotth_mail_csrf", Value: csrf})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("protected UI status=%d want=%d", w.Code, want)
		}
		if want == 200 && (!strings.Contains(w.Body.String(), "<!doctype html>") || !strings.Contains(w.Header().Get("Cache-Control"), "no-store")) {
			t.Fatal("missing real protected inventory document")
		}
	}
	request(projectionIssuer, 403)
	projectionRequest(t, scim, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(user), 200)
	request(projectionIssuer, 403) // exact domain_manager never becomes global ops admin.
	group := rolebinding.GroupService{DB: db, CurrentIssuer: projectionIssuer}
	grant := rolebinding.GroupRequest{Operation: "admit", Issuer: projectionIssuer, SCIMActor: "scim-test", GroupID: groups[0], Role: "global_admin"}
	plan, err := group.Preview(ctx, grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = group.Apply(ctx, grant, plan.PlanID); err != nil {
		t.Fatal(err)
	}
	request(projectionIssuer, 200)
	request("", 403)
	request("https://different.example/", 403)
	request(projectionIssuer, 200)
	// Real API session actor must remain mailbox-only despite effective global role.
	r := httptest.NewRequest("GET", "/api/v1/mailboxes/member@example.test/app-passwords", nil)
	r.AddCookie(&http.Cookie{Name: "gotth_mail_session", Value: sid})
	actor, bound, ok := (Server{OIDCStore: sessions, OIDCNow: func() time.Time { return now.Add(time.Second) }}).identityRequestActor(httptest.NewRecorder(), r, ids)
	if !ok || bound == nil || len(actor.Roles) != 0 || actor.Mailbox != "member@example.test" {
		t.Fatal("API session authority broadened")
	}
	projectionRequest(t, scim, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(""), 200)
	request(projectionIssuer, 403) // same durable session loses withdrawn Group authority.
	projectionRequest(t, scim, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(user), 200)
	request(projectionIssuer, 200)
	op := rolebinding.Service{DB: db, CurrentIssuer: projectionIssuer}
	o := rolebinding.Request{Operation: "grant", Issuer: projectionIssuer, Subject: "projection-subject", Mailbox: "member@example.test", Role: "global_admin"}
	p, err := op.Preview(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = op.Apply(ctx, o, p.PlanID); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = db.QueryRow("SELECT id::text FROM role_bindings WHERE identity_ref_id=$1 AND role='global_admin'", session.IdentityRefID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	projectionRequest(t, scim, "PATCH", "/scim/v2/Groups/"+groups[0], projectionMembers(""), 200)
	request(projectionIssuer, 200)
	request("", 200) // independent operator origin survives issuer loss and withdrawal.
	var after string
	var owned bool
	var sources int
	if err = db.QueryRow("SELECT id::text,operator_owned,(SELECT count(*) FROM role_binding_group_sources s WHERE s.binding_id=b.id) FROM role_bindings b WHERE identity_ref_id=$1 AND role='global_admin'", session.IdentityRefID).Scan(&after, &owned, &sources); err != nil || before != after || !owned || sources != 0 {
		t.Fatal("operator origin/UUID damaged", err)
	}
	o.Operation = "revoke"
	p, err = op.Preview(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = op.Apply(ctx, o, p.PlanID); err != nil {
		t.Fatal(err)
	}
	request(projectionIssuer, 403)
}
