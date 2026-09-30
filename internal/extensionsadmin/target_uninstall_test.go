package extensionsadmin

import (
	"context"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestUninstallTargetCompatibility(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture error type=%T", err)
		}
	}
	var version int
	check(db.QueryRow("SHOW server_version_num").Scan(&version))
	t.Logf("PostgreSQL=%d", version)
	runtime := &recordingRuntime{}
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	check(err)
	now := time.Date(2026, 9, 28, 23, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	actor := audit.ActorRef{Type: "api_token", ID: "uninstall-compatibility"}
	for n, mode := range []string{"canonical", "alias", "wrong-target", "confirmation", "actor", "expired", "stale", "enabled", "retained-secret", "audit-failure"} {
		t.Run(mode, func(t *testing.T) {
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("fixture error type=%T", err)
				}
			}
			a := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", n*2+1)
			b := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012x", n*2+2)
			for i, id := range []string{a, b} {
				_, err := svc.Install(context.Background(), actor, InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.uninstall%d-%d", n, i), Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), SecretSlots: []string{"retained.key"}, Metadata: Metadata{Schema: MetadataSchema}})
				check(err)
			}
			if mode == "retained-secret" {
				input := ConfigureInput{Secrets: map[string]string{"retained.key": "synthetic-retained-value"}}
				p, err := svc.PreviewConfigure(context.Background(), actor, b, input)
				check(err)
				_, err = svc.ApplyConfigure(context.Background(), actor, b, p.ID, p.Confirmation, input)
				check(err)
				// Fixture state models a slot retained after removal from the current manifest.
				_, err = db.Exec("UPDATE extension_instances SET secret_slots_json='[]' WHERE instance_id=$1", b)
				check(err)
			}
			p, err := svc.PreviewUninstall(context.Background(), actor, b)
			check(err)
			_, err = svc.PreviewUninstall(context.Background(), actor, b)
			check(err) // sibling cascade oracle
			target, confirmation, who := b, p.Confirmation, actor
			var want error
			switch mode {
			case "alias":
				target = "{" + strings.ToUpper(b) + "}"
			case "wrong-target":
				target = a
				want = ErrConfirmation
			case "confirmation":
				confirmation = "wrong"
				want = ErrConfirmation
			case "actor":
				who.ID = "other"
				want = ErrConfirmation
			case "expired":
				svc.Now = func() time.Time { return now.Add(11 * time.Minute) }
				defer func() { svc.Now = func() time.Time { return now } }()
				want = ErrConfirmation
			case "stale":
				_, err = db.Exec("UPDATE extension_instances SET configuration_revision=configuration_revision+1 WHERE instance_id=$1", b)
				check(err)
				want = ErrConflict
			case "enabled":
				_, err = db.Exec("UPDATE extension_instances SET enabled=true WHERE instance_id=$1", b)
				check(err)
				want = ErrConflict
			case "retained-secret":
				want = ErrConflict
			case "audit-failure":
				_, err = db.Exec("ALTER TABLE audit_events ADD CONSTRAINT uninstall_fault CHECK(action <> 'extension.uninstall') NOT VALID")
				check(err)
				defer func() { _, err := db.Exec("ALTER TABLE audit_events DROP CONSTRAINT uninstall_fault"); check(err) }()
			}
			before := targetSnapshot(t, db)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err = svc.ApplyUninstall(ctx, who, target, p.ID, confirmation)
			success := mode == "canonical" || mode == "alias"
			if success {
				check(err)
			} else {
				if mode == "audit-failure" {
					var pe *pq.Error
					if !errors.As(err, &pe) || pe.Code != "23514" || pe.Constraint != "uninstall_fault" {
						t.Error("audit failure classification")
					}
				} else if !errors.Is(err, want) {
					t.Errorf("denial class type=%T", err)
				}
				targetUnchanged(t, db, before)
			}
			if len(runtime.calls) != 0 {
				t.Fatal("unexpected runtime effects")
			}
			if t.Failed() {
				return
			}
			if mode == "wrong-target" || mode == "confirmation" || mode == "actor" {
				check(svc.ApplyUninstall(context.Background(), actor, b, p.ID, p.Confirmation))
				success = true
			}
			if !success {
				return
			}
			if _, err = svc.Get(context.Background(), b); !errors.Is(err, ErrNotFound) {
				t.Error("uninstall target still exists")
			}
			if _, err = svc.Get(context.Background(), a); err != nil {
				t.Error("unrelated target changed")
			}
			var count int
			check(db.QueryRow("SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", b).Scan(&count))
			if count != 0 {
				t.Error("sibling preview cascade failed")
			}
			check(db.QueryRow("SELECT count(*) FROM audit_events WHERE action='extension.uninstall' AND resource_id=$1", b).Scan(&count))
			if count != 1 {
				t.Error("uninstall audit not exactly once")
			}
			after := targetSnapshot(t, db)
			if err = svc.ApplyUninstall(context.Background(), actor, b, p.ID, p.Confirmation); !errors.Is(err, ErrConfirmation) {
				t.Error("replay accepted")
			}
			targetUnchanged(t, db, after)
		})
	}
}
