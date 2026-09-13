package identityadopt

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestAdoptLegacyMailboxUsesGotthSCIMAndPreservesMailbox(t *testing.T) {
	db := adoptionDB(t)
	mailboxID, created, updated := seedLegacyMailbox(t, db, "member@example.test", "Member", true, "preserved-verifier")
	service := Service{DB: db, Now: func() time.Time { return time.Unix(1700, 0).UTC() }, Entropy: bytes.NewReader(make([]byte, 16))}
	request := Request{Mailbox: "MEMBER@example.test", Subject: "authentik-subject-1", Scope: "authentik-primary", Manager: "gotth-authentik"}
	plan, err := service.Preview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if plan.MailboxID != mailboxID || plan.Mailbox != "member@example.test" || !plan.CreatedAt.Equal(created) || !plan.UpdatedAt.Equal(updated) || plan.PlanID == "" || plan.AlreadyAdopted {
		t.Fatalf("unexpected preview: %#v", plan)
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("preserved-verifier")) {
		t.Fatal("preview disclosed mailbox verifier")
	}
	if _, err := service.Apply(context.Background(), request, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong confirmation digest accepted")
	}
	result, err := service.Apply(context.Background(), request, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Created || result.ResourceID == "" || strings.Contains(result.ResourceID, "@") || result.ResourceID == plan.Mailbox {
		t.Fatalf("invalid adoption result: %#v", result)
	}
	var gotMailboxID, verifier, scimID string
	var gotCreated time.Time
	if err := db.QueryRow(`SELECT id::text, COALESCE(verifier,''), scim_resource_id, created_at FROM mailboxes WHERE lower(local_part || '@' || (SELECT name FROM domains WHERE id=domain_id))='member@example.test'`).Scan(&gotMailboxID, &verifier, &scimID, &gotCreated); err != nil {
		t.Fatal(err)
	}
	if gotMailboxID != mailboxID || verifier != "preserved-verifier" || scimID != result.ResourceID || !gotCreated.Equal(created) {
		t.Fatalf("mailbox identity changed id=%q verifier=%q scim=%q created=%v", gotMailboxID, verifier, scimID, gotCreated)
	}
	var resourceID, externalID, manager string
	if err := db.QueryRow(`SELECT id, external_id, manager FROM scim_resources WHERE scope='authentik-primary' AND resource_type='User'`).Scan(&resourceID, &externalID, &manager); err != nil {
		t.Fatal(err)
	}
	if resourceID != result.ResourceID || externalID != request.Subject || manager != request.Manager {
		t.Fatalf("wrong SCIM ownership id=%q external=%q manager=%q", resourceID, externalID, manager)
	}
	for table, want := range map[string]int{"identity_refs": 0, "sessions": 0, "audit_events": 1} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != want {
			t.Fatalf("%s count=%d want=%d err=%v", table, count, want, err)
		}
	}
	restarted, err := identity.NewSQLService(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	mailbox, ok := restarted.GetUser("member@example.test")
	if !ok || mailbox.ID != result.ResourceID || mailbox.Verifier != "preserved-verifier" {
		t.Fatalf("restart projection=%#v ok=%v", mailbox, ok)
	}
	idempotentPlan, err := service.Preview(context.Background(), request)
	if err != nil || !idempotentPlan.AlreadyAdopted || idempotentPlan.ExistingResourceID != result.ResourceID {
		t.Fatalf("idempotent preview=%#v err=%v", idempotentPlan, err)
	}
	idempotent, err := service.Apply(context.Background(), request, idempotentPlan.PlanID)
	if err != nil || idempotent.Created || idempotent.ResourceID != result.ResourceID {
		t.Fatalf("idempotent apply=%#v err=%v", idempotent, err)
	}
}

func TestAdoptionRejectsStaleStateOwnershipAndTombstone(t *testing.T) {
	t.Run("stale plan", func(t *testing.T) {
		db := adoptionDB(t)
		seedLegacyMailbox(t, db, "member@example.test", "Member", true, "verifier")
		service := Service{DB: db}
		request := Request{Mailbox: "member@example.test", Subject: "subject", Scope: "scope", Manager: "manager"}
		plan, err := service.Preview(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE mailboxes SET updated_at=updated_at + interval '1 second'`); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Apply(context.Background(), request, plan.PlanID); err == nil || !strings.Contains(err.Error(), "confirmation digest") {
			t.Fatalf("stale plan err=%v", err)
		}
	})
	t.Run("different mailbox ownership", func(t *testing.T) {
		db := adoptionDB(t)
		seedLegacyMailbox(t, db, "member@example.test", "Member", true, "")
		if _, err := db.Exec(`INSERT INTO scim_resources(scope,resource_type,id,external_id,manager,version,credential_version,created_unix_nano,last_modified_unix_nano,data) VALUES ('scope','User','opaque-other','other-subject','manager','v1','',1,1,'{}'); UPDATE mailboxes SET scim_resource_id='opaque-other'`); err != nil {
			t.Fatal(err)
		}
		_, err := (Service{DB: db}).Preview(context.Background(), Request{Mailbox: "member@example.test", Subject: "subject", Scope: "scope", Manager: "manager"})
		if err == nil || !strings.Contains(err.Error(), "different SCIM ownership") {
			t.Fatalf("different ownership err=%v", err)
		}
	})
	t.Run("subject conflict", func(t *testing.T) {
		db := adoptionDB(t)
		seedLegacyMailbox(t, db, "member@example.test", "Member", true, "")
		if _, err := db.Exec(`INSERT INTO scim_resources(scope,resource_type,id,external_id,manager,version,credential_version,created_unix_nano,last_modified_unix_nano,data) VALUES ('other','User','opaque-other','subject','manager','v1','',1,1,'{}')`); err != nil {
			t.Fatal(err)
		}
		_, err := (Service{DB: db}).Preview(context.Background(), Request{Mailbox: "member@example.test", Subject: "subject", Scope: "scope", Manager: "manager"})
		if err == nil || !strings.Contains(err.Error(), "already owns") {
			t.Fatalf("subject conflict err=%v", err)
		}
	})
	t.Run("tombstone", func(t *testing.T) {
		db := adoptionDB(t)
		seedLegacyMailbox(t, db, "member@example.test", "Member", true, "")
		if _, err := db.Exec(`INSERT INTO scim_tombstones(scope,resource_type,id,external_id,manager,version,deleted_unix_nano) VALUES ('scope','User','opaque-deleted','subject','manager','v1',1)`); err != nil {
			t.Fatal(err)
		}
		_, err := (Service{DB: db}).Preview(context.Background(), Request{Mailbox: "member@example.test", Subject: "subject", Scope: "scope", Manager: "manager"})
		if err == nil || !strings.Contains(err.Error(), "tombstoned") {
			t.Fatalf("tombstone err=%v", err)
		}
	})
}

func TestAdoptionAuditFailureRollsBackEverything(t *testing.T) {
	db := adoptionDB(t)
	seedLegacyMailbox(t, db, "member@example.test", "Member", true, "verifier")
	if _, err := db.Exec(`CREATE FUNCTION reject_adoption_audit() RETURNS trigger AS $$ BEGIN IF NEW.action='scim.user.create' THEN RAISE EXCEPTION 'forced adoption audit failure'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql; CREATE TRIGGER reject_adoption_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_adoption_audit()`); err != nil {
		t.Fatal(err)
	}
	service := Service{DB: db, Entropy: bytes.NewReader(make([]byte, 16))}
	request := Request{Mailbox: "member@example.test", Subject: "subject", Scope: "scope", Manager: "manager"}
	plan, err := service.Preview(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Apply(context.Background(), request, plan.PlanID); err == nil || !strings.Contains(err.Error(), "forced adoption audit failure") {
		t.Fatalf("audit failure err=%v", err)
	}
	var scimID sql.NullString
	if err := db.QueryRow(`SELECT scim_resource_id FROM mailboxes`).Scan(&scimID); err != nil || scimID.Valid {
		t.Fatalf("mailbox ownership survived rollback valid=%v err=%v", scimID.Valid, err)
	}
	for _, table := range []string{"scim_resources", "audit_events"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s count=%d err=%v", table, count, err)
		}
	}
}

func adoptionDB(t *testing.T) *sql.DB {
	t.Helper()
	return testpg.DB(t, store.MigrateSQL)
}

func seedLegacyMailbox(t *testing.T, db *sql.DB, address, display string, active bool, verifier string) (string, time.Time, time.Time) {
	t.Helper()
	local, domain, ok := strings.Cut(address, "@")
	if !ok {
		t.Fatal("invalid seed address")
	}
	created := time.Unix(1000, 0).UTC()
	updated := time.Unix(1100, 0).UTC()
	domainID := "11111111-1111-4111-8111-111111111111"
	mailboxID := "22222222-2222-4222-8222-222222222222"
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,created_at,updated_at) VALUES ($1,$2,true,$3,$3)`, domainID, domain, created); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO mailboxes(id,domain_id,local_part,display_name,enabled,verifier,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, mailboxID, domainID, local, display, active, sql.NullString{String: verifier, Valid: verifier != ""}, created, updated); err != nil {
		t.Fatal(err)
	}
	return mailboxID, created, updated
}
