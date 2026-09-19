package outboundpolicy

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

const policyDomainID = "00000000-0000-4000-8000-000000000811"

func TestAdminPreviewAndApplyAreRevisionBoundAndAudited(t *testing.T) {
	db := policyDB(t)
	insertPolicyDomain(t, db)
	insertPolicyAlias(t, db, "00000000-0000-4000-8000-000000000812", "team", `["local@example.test","outside@example.net"]`)
	insertPolicyAlias(t, db, "00000000-0000-4000-8000-000000000813", "local", `["other@example.test"]`)

	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	service := AdminService{DB: db, Now: func() time.Time { return now }}
	plan, err := service.Preview(context.Background(), "Example.TEST.", ScopeSameDomainOnly)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Domain != "example.test" || plan.CurrentScope != ScopeUnrestricted || plan.RequestedScope != ScopeSameDomainOnly || plan.Revision != 1 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.Impact.Aliases != 1 || plan.Impact.ExternalTargets != 1 || plan.Impact.QueuedRecipients != 0 {
		t.Fatalf("unexpected impact: %+v", plan.Impact)
	}
	if len(plan.Digest) != 64 {
		t.Fatalf("digest=%q", plan.Digest)
	}

	result, err := service.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "operator"}, "corr-policy-1", "example.test", ScopeSameDomainOnly, plan.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.Plan.Revision != 1 {
		t.Fatalf("result=%+v", result)
	}
	var scope string
	var revision int64
	if err := db.QueryRow(`SELECT outbound_scope,outbound_policy_revision FROM domains WHERE id=$1`, policyDomainID).Scan(&scope, &revision); err != nil {
		t.Fatal(err)
	}
	if scope != string(ScopeSameDomainOnly) || revision != 2 {
		t.Fatalf("scope=%q revision=%d", scope, revision)
	}
	var action, resourceID, before, after string
	if err := db.QueryRow(`SELECT action,resource_id,before_redacted_json,after_redacted_json FROM audit_events WHERE correlation_id='corr-policy-1'`).Scan(&action, &resourceID, &before, &after); err != nil {
		t.Fatal(err)
	}
	if action != "domain.outbound_scope.update" || resourceID != policyDomainID {
		t.Fatalf("action=%q resource=%q", action, resourceID)
	}
	if !contains(after, plan.Digest) {
		t.Fatalf("audit omitted confirmation digest %q: %s", plan.Digest, after)
	}
	for _, forbidden := range []string{"outside@example.net", "local@example.test", "other@example.test"} {
		if contains(before, forbidden) || contains(after, forbidden) {
			t.Fatalf("audit leaked address %q: before=%s after=%s", forbidden, before, after)
		}
	}
}

func TestAdminApplyRejectsStaleOrWrongConfirmation(t *testing.T) {
	db := policyDB(t)
	insertPolicyDomain(t, db)
	service := AdminService{DB: db}
	plan, err := service.Preview(context.Background(), "example.test", ScopeSameDomainOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "operator"}, "corr", "example.test", ScopeSameDomainOnly, "wrong"); err == nil {
		t.Fatal("wrong confirmation accepted")
	}
	if _, err := service.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "operator"}, "corr", "example.test", ScopeSameDomainOnly, strings.Repeat("a", 1<<20)); err == nil {
		t.Fatal("oversized confirmation accepted")
	}
	if _, err := db.Exec(`UPDATE domains SET outbound_policy_revision=outbound_policy_revision+1 WHERE id=$1`, policyDomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "operator"}, "corr", "example.test", ScopeSameDomainOnly, plan.Digest); err == nil {
		t.Fatal("stale confirmation accepted")
	}
}

func TestAdminApplyRollsBackWhenAuditFails(t *testing.T) {
	db := policyDB(t)
	insertPolicyDomain(t, db)
	service := AdminService{DB: db}
	plan, err := service.Preview(context.Background(), "example.test", ScopeSameDomainOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE FUNCTION reject_outbound_policy_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit unavailable'; END $$; CREATE TRIGGER reject_outbound_policy_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_outbound_policy_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "operator"}, "corr", "example.test", ScopeSameDomainOnly, plan.Digest); err == nil {
		t.Fatal("audit failure accepted")
	}
	var scope string
	var revision int64
	if err := db.QueryRow(`SELECT outbound_scope,outbound_policy_revision FROM domains WHERE id=$1`, policyDomainID).Scan(&scope, &revision); err != nil {
		t.Fatal(err)
	}
	if scope != string(ScopeUnrestricted) || revision != 1 {
		t.Fatalf("mutation escaped rollback: scope=%q revision=%d", scope, revision)
	}
}

func TestAdminApplySameScopeIsNoOp(t *testing.T) {
	db := policyDB(t)
	insertPolicyDomain(t, db)
	service := AdminService{DB: db}
	plan, err := service.Preview(context.Background(), "example.test", ScopeUnrestricted)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "operator"}, "corr-noop", "example.test", ScopeUnrestricted, plan.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Changed {
		t.Fatalf("same-scope apply changed state: %+v", result)
	}
	var revision, audits int
	if err := db.QueryRow(`SELECT outbound_policy_revision FROM domains WHERE id=$1`, policyDomainID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE correlation_id='corr-noop'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if revision != 1 || audits != 0 {
		t.Fatalf("same-scope apply revision=%d audits=%d, want 1/0", revision, audits)
	}
}

func TestAdminServiceRequiresDatabaseAndActor(t *testing.T) {
	service := AdminService{}
	if _, err := service.Preview(context.Background(), "example.test", ScopeUnrestricted); err == nil {
		t.Fatal("preview without database succeeded")
	}
	if _, err := service.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "operator"}, "corr", "example.test", ScopeUnrestricted, strings.Repeat("0", 64)); err == nil {
		t.Fatal("apply without database succeeded")
	}
	db := policyDB(t)
	service.DB = db
	if _, err := service.Apply(context.Background(), audit.ActorRef{}, "", "example.test", ScopeUnrestricted, strings.Repeat("0", 64)); err == nil {
		t.Fatal("apply without actor and correlation ID succeeded")
	}
}

func TestAdminPreviewRejectsCorruptStoredPolicy(t *testing.T) {
	db := policyDB(t)
	insertPolicyDomain(t, db)
	if _, err := db.Exec(`ALTER TABLE domains DROP CONSTRAINT domains_outbound_scope_check`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE domains SET outbound_scope='invalid' WHERE id=$1`, policyDomainID); err != nil {
		t.Fatal(err)
	}
	if _, err := (AdminService{DB: db}).Preview(context.Background(), "example.test", ScopeSameDomainOnly); err == nil {
		t.Fatal("corrupt stored scope accepted")
	}
}

func TestAdminPreviewRejectsInvalidRequests(t *testing.T) {
	db := policyDB(t)
	insertPolicyDomain(t, db)
	service := AdminService{DB: db}
	for _, tc := range []struct {
		domain string
		scope  Scope
	}{
		{domain: "missing.test", scope: ScopeSameDomainOnly},
		{domain: "bad_domain.test", scope: ScopeSameDomainOnly},
		{domain: "example.test", scope: "invalid"},
	} {
		if _, err := service.Preview(context.Background(), tc.domain, tc.scope); err == nil {
			t.Fatalf("Preview(%q,%q) succeeded", tc.domain, tc.scope)
		}
	}
}

func TestAdminPreviewRejectsUnboundedOrInvalidAliasTargets(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets string
	}{
		{name: "empty", targets: `[]`},
		{name: "invalid address", targets: `["not-an-address"]`},
		{name: "oversized document", targets: `["` + strings.Repeat("a", maxAliasTargetJSONBytes) + `@example.test"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := policyDB(t)
			insertPolicyDomain(t, db)
			insertPolicyAlias(t, db, "00000000-0000-4000-8000-000000000812", "team", tc.targets)
			if _, err := (AdminService{DB: db}).Preview(context.Background(), "example.test", ScopeSameDomainOnly); err == nil {
				t.Fatal("invalid alias target data accepted")
			}
		})
	}
}

func policyDB(t *testing.T) *sql.DB {
	t.Helper()
	return testpg.DB(t, store.MigrateSQL)
}

func insertPolicyDomain(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,'example.test',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, policyDomainID); err != nil {
		t.Fatal(err)
	}
}

func insertPolicyAlias(t *testing.T, db *sql.DB, id, localPart, targets string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO aliases(id,domain_id,local_part,targets_json,enabled,created_at,updated_at) VALUES ($1,$2,$3,$4,true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, id, policyDomainID, localPart, targets); err != nil {
		t.Fatal(err)
	}
}

func contains(s, part string) bool {
	for i := 0; i+len(part) <= len(s); i++ {
		if s[i:i+len(part)] == part {
			return true
		}
	}
	return false
}
