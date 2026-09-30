package extensionsadmin

import (
	"context"
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

func TestApplyTargetConcurrent(t *testing.T) {
	for _, op := range []string{"configure", "update", "delete_secrets", "uninstall"} {
		for _, mode := range []string{"duplicate", "target-isolation"} {
			t.Run(op+"/"+mode, func(t *testing.T) {
				check := func(err error) {
					t.Helper()
					if err != nil {
						t.Fatalf("fixture type=%T", err)
					}
				}
				db := testpg.DB(t, store.MigrateSQL)
				db.SetMaxOpenConns(6)
				runtime := &recordingRuntime{}
				svc, err := NewService(db, []byte(strings.Repeat("k", 32)), runtime)
				check(err)
				actor := audit.ActorRef{Type: "api_token", ID: "concurrent-owner"}
				const a = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				const b = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
				metadata := Metadata{Schema: MetadataSchema, Fields: []Field{{Name: "config.text", Kind: FieldString, Label: "Text"}}}
				for i, id := range []string{a, b} {
					_, err := svc.Install(context.Background(), actor, InstallRequest{InstanceID: id, ExtensionID: fmt.Sprintf("notification.concurrent%d", i), Repository: "https://github.com/gotthboard/gotth-extension-target", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: metadata, SecretSlots: []string{"retained.key"}})
					check(err)
				}
				if op == "delete_secrets" {
					for _, id := range []string{a, b} {
						input := ConfigureInput{Secrets: map[string]string{"retained.key": "synthetic-retained"}}
						p, err := svc.PreviewConfigure(context.Background(), actor, id, input)
						check(err)
						_, err = svc.ApplyConfigure(context.Background(), actor, id, p.ID, p.Confirmation, input)
						check(err)
						_, err = db.Exec("UPDATE extension_instances SET secret_slots_json='[]' WHERE instance_id=$1", id)
						check(err)
					}
				}
				input := ConfigureInput{Configuration: map[string]any{"config.text": "bound-value"}}
				update := UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: metadata}
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
				if op == "uninstall" {
					_, err = svc.PreviewUninstall(context.Background(), actor, b)
					check(err)
				}
				snapshotA := func() map[string]string {
					t.Helper()
					out := map[string]string{}
					for table, column := range map[string]string{"extension_instances": "instance_id", "extension_secrets": "instance_id", "extension_operation_previews": "instance_id", "audit_events": "resource_id"} {
						var rows string
						check(db.QueryRow("SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text)::text,'[]') FROM "+table+" r WHERE "+column+"=$1", a).Scan(&rows))
						out[table] = rows
					}
					all := targetSnapshot(t, db)
					for _, table := range []string{"tokens", "sessions", "identity_refs", "role_bindings"} {
						out[table] = all[table]
					}
					return out
				}
				beforeA := snapshotA()
				beforeB, err := svc.Get(context.Background(), b)
				check(err)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				apply := func(target string) error {
					switch op {
					case "configure":
						_, err := svc.ApplyConfigure(ctx, actor, target, p.ID, p.Confirmation, input)
						return err
					case "update":
						_, err := svc.ApplyUpdate(ctx, actor, target, p.ID, p.Confirmation)
						return err
					case "delete_secrets":
						_, err := svc.ApplyDeleteSecrets(ctx, actor, target, p.ID, p.Confirmation)
						return err
					default:
						return svc.ApplyUninstall(ctx, actor, target, p.ID, p.Confirmation)
					}
				}
				blocker, err := db.BeginTx(ctx, nil)
				check(err)
				defer blocker.Rollback()
				var locked string
				check(blocker.QueryRowContext(ctx, "SELECT id FROM extension_operation_previews WHERE id=$1 FOR UPDATE", p.ID).Scan(&locked))
				type result struct {
					worker int
					err    error
				}
				ready := make(chan struct{}, 2)
				start := make(chan struct{})
				done := make(chan result, 2)
				for i := 0; i < 2; i++ {
					go func(worker int) {
						ready <- struct{}{}
						<-start
						target := b
						if mode == "target-isolation" && worker == 0 {
							target = a
						}
						done <- result{worker, apply(target)}
					}(i)
				}
				<-ready
				<-ready
				close(start)
				// Both actual SQL backends must be waiting on the fixture lock before release.
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				waiting := 0
				var barrierErr error
				for waiting < 2 && barrierErr == nil {
					barrierErr = db.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE 'SELECT id, instance_id, operation,%'").Scan(&waiting)
					if waiting < 2 && barrierErr == nil {
						select {
						case <-ticker.C:
						case <-ctx.Done():
							barrierErr = ctx.Err()
						}
					}
				}
				releaseErr := blocker.Rollback()
				results := []result{<-done, <-done}
				check(barrierErr)
				check(releaseErr)
				if waiting < 2 {
					t.Fatal("concurrency barrier not established")
				}
				check(ctx.Err())
				t.Log("two simultaneous SQL lock waiters observed")
				wins := 0
				for _, r := range results {
					if r.err == nil {
						wins++
						t.Logf("worker%d committed", r.worker)
						if mode == "target-isolation" && r.worker == 0 {
							t.Error("wrong target committed")
						}
						continue
					}
					// loadPreview errors already map to ErrConfirmation in production. A later
					// serializable conflict may retain40001. Unmasked operational errors fail;
					// underlying errors already masked by loadPreview cannot be classified here.
					t.Logf("worker%d denial class=%T confirmation=%t", r.worker, r.err, errors.Is(r.err, ErrConfirmation))
					var pe *pq.Error
					if !errors.Is(r.err, ErrConfirmation) && !(errors.As(r.err, &pe) && pe.Code == "40001") {
						t.Errorf("unexpected concurrent error type=%T", r.err)
					}
				}
				if wins != 1 {
					t.Errorf("committed successes=%d want1", wins)
				}
				if !reflect.DeepEqual(beforeA, snapshotA()) {
					t.Error("unrelated authoritative rows changed")
				}
				if len(runtime.calls) != 0 {
					t.Error("runtime side effects")
				}
				action := map[string]string{"configure": "extension.configure", "update": "extension.update", "delete_secrets": "extension.secrets.delete", "uninstall": "extension.uninstall"}[op]
				var count int
				check(db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action=$2", b, action).Scan(&count))
				if count != 1 {
					t.Error("audit not exactly once")
				}
				if op == "uninstall" {
					_, err := svc.Get(context.Background(), b)
					if !errors.Is(err, ErrNotFound) {
						t.Error("uninstall row survived")
					}
					check(db.QueryRow("SELECT count(*) FROM extension_operation_previews WHERE instance_id=$1", b).Scan(&count))
					if count != 0 {
						t.Error("preview cascade incomplete")
					}
				} else {
					got, err := svc.Get(context.Background(), b)
					check(err)
					if got.ConfigurationRev != beforeB.ConfigurationRev+1 {
						t.Error("revision not exactly once")
					}
					if op == "configure" && got.Configuration["config.text"] != "bound-value" {
						t.Error("configuration missing")
					}
					if op == "update" && (got.ArtifactPin != update.ArtifactPin || got.PreviousArtifact != beforeB.ArtifactPin) {
						t.Error("update snapshot wrong")
					}
					if op == "delete_secrets" {
						check(db.QueryRow("SELECT count(*) FROM extension_secrets WHERE instance_id=$1", b).Scan(&count))
						if count != 0 {
							t.Error("retained secrets survived")
						}
					}
					check(db.QueryRow("SELECT count(*) FROM extension_operation_previews WHERE id=$1 AND consumed_at IS NOT NULL", p.ID).Scan(&count))
					if count != 1 {
						t.Error("preview not consumed")
					}
				}
				after := targetSnapshot(t, db)
				if !errors.Is(apply(b), ErrConfirmation) {
					t.Error("replay accepted")
				}
				targetUnchanged(t, db, after)
			})
		}
	}
}
