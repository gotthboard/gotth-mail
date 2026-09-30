package extensionsadmin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"github.com/lib/pq"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Compare full durable rows including nulls, ciphertext and timestamps without logging values.
func targetSnapshot(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{"extension_instances", "extension_secrets", "extension_operation_previews", "audit_events", "tokens", "sessions", "identity_refs", "role_bindings"} {
		var rows string
		if err := db.QueryRow("SELECT COALESCE(jsonb_agg(v ORDER BY v::text)::text,'[]') FROM (SELECT to_jsonb(r) v FROM " + table + " r) q").Scan(&rows); err != nil {
			t.Fatal("snapshot failed: " + table)
		}
		out[table] = rows
	}
	return out
}
func targetUnchanged(t *testing.T, db *sql.DB, before map[string]string) {
	t.Helper()
	after := targetSnapshot(t, db)
	for table, want := range before {
		if want != after[table] {
			t.Errorf("denial changed table %s", table)
		}
	}
}

func TestApplyTargetMatrix(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	var version int
	if err := db.QueryRow("SHOW server_version_num").Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL=%d", version)
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), &recordingRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	svc.Now = func() time.Time { return now }
	actor := audit.ActorRef{Type: "api_token", ID: "target-matrix"}
	metadata := Metadata{Schema: MetadataSchema, Fields: []Field{{Name: "config.text", Label: "Text", Kind: FieldString}, {Name: "secret.key", Label: "Key", Kind: FieldSecret}}}
	input := ConfigureInput{Configuration: map[string]any{"config.text": "accepted"}, Secrets: map[string]string{"secret.key": "synthetic-secret"}}
	update := UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: metadata, SecretSlots: []string{"secret.key"}}
	seq := 0
	for _, op := range []string{"configure", "update", "delete_secrets", "uninstall"} {
		for _, mode := range []string{"wrong-target", "empty", "invalid", "long", "nonexistent", "alias-other", "wrong-actor", "bad-confirmation", "blank-confirmation", "missing-preview", "expired", "consumed", "wrong-operation", "stale", "enabled", "routed", "cancelled", "audit-rollback", "alias-braces", "alias-upper", "alias-compact", "alias-four"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				check := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatalf("fixture failure type=%T", err)
					}
				}

				seq++
				a := fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012x", seq*2)
				b := fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012x", seq*2+1)
				for i, id := range []string{a, b} {
					_, err := svc.Install(context.Background(), actor, InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.matrix%d-%d", seq, i), Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: metadata, SecretSlots: []string{"secret.key"}})
					check(err)
				}
				if op == "delete_secrets" {
					seed, err := svc.PreviewConfigure(context.Background(), actor, b, input)
					check(err)
					_, err = svc.ApplyConfigure(context.Background(), actor, b, seed.ID, seed.Confirmation, input)
					check(err)
					_, err = db.Exec("UPDATE extension_instances SET secret_slots_json='[]' WHERE instance_id=$1", b)
					check(err)
				}
				var p Preview
				switch op {
				case "configure":
					p, err = svc.PreviewConfigure(context.Background(), actor, b, input)
				case "update":
					p, err = svc.PreviewUpdate(context.Background(), actor, b, update)
				case "delete_secrets":
					p, err = svc.PreviewDeleteSecrets(context.Background(), actor, b)
				case "uninstall":
					p, err = svc.PreviewUninstall(context.Background(), actor, b)
				}
				check(err)
				target, pid, confirmation, who := b, p.ID, p.Confirmation, actor
				want := ErrConfirmation
				run := func(q string, args ...any) { _, err := db.Exec(q, args...); check(err) }
				switch mode {
				case "wrong-target":
					target = a
				case "empty":
					target = ""
				case "invalid":
					target = "invalid"
				case "long":
					target = strings.Repeat("a", 65536)
				case "nonexistent":
					target = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
				case "alias-other":
					target = "{" + a + "}"
				case "wrong-actor":
					who.ID = "different"
				case "bad-confirmation":
					confirmation = "wrong"
				case "blank-confirmation":
					confirmation = ""
				case "missing-preview":
					pid = "extp_000000000000000000000000"
				case "expired":
					svc.Now = func() time.Time { return now.Add(11 * time.Minute) }
					defer func() { svc.Now = func() time.Time { return now } }()
				case "consumed":
					run("UPDATE extension_operation_previews SET consumed_at=created_at WHERE id=$1", p.ID)
				case "wrong-operation":
					other := "uninstall"
					if op == "uninstall" {
						other = "configure"
					}
					run("UPDATE extension_operation_previews SET operation=$2 WHERE id=$1", p.ID, other)
				case "stale":
					run("UPDATE extension_instances SET configuration_revision=configuration_revision+1 WHERE instance_id=$1", b)
					want = ErrConflict
				case "enabled":
					run("UPDATE extension_instances SET enabled=true WHERE instance_id=$1", b)
					want = ErrConflict
				case "routed":
					run("UPDATE extension_instances SET enabled=true,routed=true WHERE instance_id=$1", b)
					want = ErrConflict
				case "audit-rollback":
					run("ALTER TABLE audit_events ADD CONSTRAINT target_fail CHECK (action NOT IN ('extension.configure','extension.update','extension.secrets.delete','extension.uninstall')) NOT VALID")
					defer run("ALTER TABLE audit_events DROP CONSTRAINT target_fail")
					want = nil
				case "alias-braces":
					target = "{" + b + "}"
					want = nil
				case "alias-upper":
					target = strings.ToUpper(b)
					want = nil
				case "alias-compact":
					target = strings.ReplaceAll(b, "-", "")
					want = nil
				case "alias-four":
					d := strings.ReplaceAll(b, "-", "")
					var parts []string
					for i := 0; i < 32; i += 4 {
						parts = append(parts, d[i:i+4])
					}
					target = "{" + strings.Join(parts, "-") + "}"
					want = nil
				}
				apply := func(ctx context.Context, id string, who audit.ActorRef, pid, confirm string) error {
					switch op {
					case "configure":
						_, err := svc.ApplyConfigure(ctx, who, id, pid, confirm, input)
						return err
					case "update":
						_, err := svc.ApplyUpdate(ctx, who, id, pid, confirm)
						return err
					case "delete_secrets":
						_, err := svc.ApplyDeleteSecrets(ctx, who, id, pid, confirm)
						return err
					case "uninstall":
						return svc.ApplyUninstall(ctx, who, id, pid, confirm)
					}
					panic("unknown operation")
				}
				unrelated, err := svc.Get(context.Background(), a)
				check(err)
				before := targetSnapshot(t, db)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if mode == "cancelled" {
					cancel()
					want = context.Canceled
				}
				err = apply(ctx, target, who, pid, confirmation)
				success := strings.HasPrefix(mode, "alias-") && mode != "alias-other"
				if success {
					check(err)
				} else {
					if want != nil && !errors.Is(err, want) || want == nil && err == nil {
						t.Errorf("denial class incorrect: type=%T", err)
					}
					if mode == "audit-rollback" {
						var pe *pq.Error
						if !errors.As(err, &pe) || pe.Code != "23514" || pe.Constraint != "target_fail" {
							t.Error("wrong injected audit error")
						}
					}
					targetUnchanged(t, db, before)
				}
				if len(svc.Runtime.(*recordingRuntime).calls) != 0 {
					t.Fatal("runtime side effect")
				}
				if t.Failed() {
					return
				}
				// Target-only denials leave the exact original preview reusable.
				if mode == "wrong-target" || mode == "empty" || mode == "invalid" || mode == "long" || mode == "nonexistent" || mode == "alias-other" {
					check(apply(context.Background(), b, actor, p.ID, p.Confirmation))
					success = true
				}
				if success {
					afterA, err := svc.Get(context.Background(), a)
					check(err)
					if !reflect.DeepEqual(unrelated, afterA) {
						t.Error("success changed unrelated instance")
					}
					var auditCount int
					action := map[string]string{"configure": "extension.configure", "update": "extension.update", "delete_secrets": "extension.secrets.delete", "uninstall": "extension.uninstall"}[op]
					check(db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action=$2", b, action).Scan(&auditCount))
					if auditCount != 1 {
						t.Error("operation audit not once")
					}
					if len(svc.Runtime.(*recordingRuntime).calls) != 0 {
						t.Error("runtime on success")
					}
					after := targetSnapshot(t, db)
					if err := apply(context.Background(), b, actor, p.ID, p.Confirmation); !errors.Is(err, ErrConfirmation) {
						t.Error("successful preview replay accepted")
					}
					targetUnchanged(t, db, after)
					if op == "uninstall" {
						if _, err := svc.Get(context.Background(), b); !errors.Is(err, ErrNotFound) {
							t.Error("uninstall target remains")
						}
						var count int
						check(db.QueryRow("SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", b).Scan(&count))
						if count != 0 {
							t.Error("preview cascade missing")
						}
						return
					}
					item, err := svc.Get(context.Background(), b)
					check(err)
					expected := int64(2)
					if op == "delete_secrets" {
						expected = 3
						var count int
						check(db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", b).Scan(&count))
						if count != 0 {
							t.Error("retained secrets remain")
						}
					}
					if item.ConfigurationRev != expected {
						t.Error("revision not advanced exactly once")
					}
					if op == "configure" && !reflect.DeepEqual(item.Configuration, map[string]any{"config.text": "accepted"}) {
						t.Error("bound configuration lost")
					}
					if op == "update" && (item.ArtifactPin != update.ArtifactPin || item.PreviousArtifact != "sha256:"+strings.Repeat("1", 64)) {
						t.Error("stored update target/snapshot lost")
					}
				}
			})
		}
	}
}
