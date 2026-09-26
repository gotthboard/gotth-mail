package extensionsadmin

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func restartFixture(t *testing.T) (*Service, *recordingRuntime, audit.ActorRef, string) {
	t.Helper()
	db := testpg.DB(t, store.MigrateSQL)
	r := &recordingRuntime{health: Health{Healthy: true, Code: "extension.ready"}}
	s, err := NewService(db, []byte("0123456789abcdef0123456789abcdef"), r)
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.ActorRef{Type: "api_token", ID: "restart-admin"}
	id := "00000000-0000-4000-8000-000000000026"
	_, err = s.Install(context.Background(), actor, InstallRequest{InstanceID: id, ExtensionID: "notification.restart", Repository: "https://github.com/gotthboard/gotth-extension-restart", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: Metadata{Schema: MetadataSchema, Fields: []Field{{Name: "restart.secret", Label: "Restart secret", Kind: FieldSecret, Required: true}}}, SecretSlots: []string{"restart.secret"}})
	if err != nil {
		t.Fatal(err)
	}
	input := ConfigureInput{Secrets: map[string]string{"restart.secret": "retained-owned-secret"}}
	p, err := s.PreviewConfigure(context.Background(), actor, id, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApplyConfigure(context.Background(), actor, p.ID, p.Confirmation, input); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Test(context.Background(), actor, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Enable(context.Background(), actor, id); err != nil {
		t.Fatal(err)
	}
	r.calls = nil
	return s, r, actor, id
}

func TestEnableRestart(t *testing.T) {
	s, r, actor, id := restartFixture(t)
	for i := 0; i < 2; i++ {
		r.calls = nil
		got, err := s.Enable(context.Background(), actor, id)
		if err != nil || !got.Routed || !reflect.DeepEqual(r.calls, []string{"start", "probe", "admit"}) {
			t.Fatalf("enable %d routed=%v calls=%v err=%v", i, got.Routed, r.calls, err)
		}
	}
	fresh := &recordingRuntime{health: r.health}
	s.Runtime = fresh
	if _, err := s.Enable(context.Background(), actor, id); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fresh.calls, []string{"start", "probe", "admit"}) || fresh.secrets["restart.secret"] != "retained-owned-secret" {
		t.Fatalf("fresh runtime was not restored: %v", fresh.calls)
	}
}

func TestEnableInvalid(t *testing.T) {
	for _, tc := range []struct{ name, sql, fail string }{
		{"stale-test", "UPDATE extension_instances SET configuration_revision=configuration_revision+1", ""},
		{"missing-secret", "DELETE FROM extension_secrets", ""},
		{"corrupt-secret", "UPDATE extension_secrets SET ciphertext=decode(repeat('00',32),'hex')", ""},
		{"bad-config", "UPDATE extension_instances SET configuration_json='{\"unknown\":true}'", ""},
		{"start", "", "start"}, {"probe", "", "probe"}, {"admit", "", "admit"},
		{"audit", "ALTER TABLE audit_events ADD CONSTRAINT reject_enable CHECK (action <> 'extension.enable') NOT VALID", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, r, actor, id := restartFixture(t)
			if tc.sql != "" {
				if _, err := s.DB.Exec(tc.sql); err != nil {
					t.Fatal(err)
				}
			}
			r.errAt = tc.fail
			if _, err := s.Enable(context.Background(), actor, id); err == nil {
				t.Fatal("unverified persisted route reported success")
			}
			for _, call := range r.calls {
				if call == "admit" && tc.fail != "admit" && tc.name != "audit" {
					t.Fatalf("invalid state admitted: %v", r.calls)
				}
			}
		})
	}
}

func TestRestartState(t *testing.T) {
	s, r, actor, id := restartFixture(t)
	before, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRestart(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), id)
	if err != nil || got.Routed || !got.Enabled || got.ConfigurationRev != before.ConfigurationRev || got.TestedRevision != before.TestedRevision || got.ArtifactPin != before.ArtifactPin || !reflect.DeepEqual(got.Secrets, before.Secrets) || len(r.calls) != 0 {
		t.Fatalf("restart altered intent or secrets: %#v calls=%v err=%v", got, r.calls, err)
	}
	if err := s.ReconcileRestart(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='extension.reconcile'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate startup audit %d %v", count, err)
	}
	if _, err := s.Enable(context.Background(), actor, id); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.calls, []string{"start", "probe", "admit"}) {
		t.Fatal(r.calls)
	}
	if _, err := s.Disable(context.Background(), actor, id); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRestart(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get(context.Background(), id)
	if err != nil || got.Enabled || got.Routed || got.Lifecycle != "stopped" {
		t.Fatalf("disabled state changed %#v %v", got, err)
	}
}

func TestRestartAuditFailure(t *testing.T) {
	s, _, _, id := restartFixture(t)
	if _, err := s.DB.Exec("ALTER TABLE audit_events ADD CONSTRAINT reject_reconcile CHECK (action <> 'extension.reconcile') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileRestart(context.Background()); err == nil {
		t.Fatal("audit failure ignored")
	}
	got, err := s.Get(context.Background(), id)
	if err != nil || !got.Routed || !got.Enabled {
		t.Fatalf("unaudited state committed %#v %v", got, err)
	}
}

func TestDisableRestartAudit(t *testing.T) {
	s, r, actor, id := restartFixture(t)
	if err := s.ReconcileRestart(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("ALTER TABLE audit_events ADD CONSTRAINT reject_disable CHECK (action <> 'extension.disable') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Disable(context.Background(), actor, id); err == nil {
		t.Fatal("audit failure ignored")
	}
	if !reflect.DeepEqual(r.calls, []string{"stop"}) {
		t.Fatalf("failed disable launched runtime: %v", r.calls)
	}
}

type mutateRuntime struct {
	*recordingRuntime
	probe func()
}

func (r *mutateRuntime) Probe(ctx context.Context, i Instance) (Health, error) {
	r.probe()
	return r.recordingRuntime.Probe(ctx, i)
}

func TestEnableStaleDuringProbe(t *testing.T) {
	s, r, actor, id := restartFixture(t)
	s.Runtime = &mutateRuntime{recordingRuntime: r, probe: func() {
		if _, err := s.DB.Exec("UPDATE extension_instances SET configuration_revision=configuration_revision+1"); err != nil {
			t.Fatal(err)
		}
	}}
	if _, err := s.Enable(context.Background(), actor, id); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale runtime accepted: %v", err)
	}
	if !reflect.DeepEqual(r.calls, []string{"start", "probe", "admit", "revoke", "stop"}) {
		t.Fatalf("stale cleanup %v", r.calls)
	}
}

func TestEnableCleanupFailure(t *testing.T) {
	s, r, actor, id := restartFixture(t)
	r.health = Health{Healthy: false, Code: "extension.degraded"}
	r.errAt = "revoke"
	_, err := s.Enable(context.Background(), actor, id)
	if !errors.Is(err, ErrUnhealthy) || !strings.Contains(err.Error(), "runtime failure") {
		t.Fatalf("cleanup error hidden: %v", err)
	}
	if !reflect.DeepEqual(r.calls, []string{"start", "probe", "revoke"}) {
		t.Fatalf("stop despite failed revoke: %v", r.calls)
	}
}

func TestDisableStopFailure(t *testing.T) {
	s, r, actor, id := restartFixture(t)
	r.errAt = "stop"
	if _, err := s.Disable(context.Background(), actor, id); err == nil {
		t.Fatal("stop failure ignored")
	}
	if !reflect.DeepEqual(r.calls, []string{"revoke", "stop"}) {
		t.Fatalf("route restored after stop failure: %v", r.calls)
	}
}

func TestEnableReturnsCommitted(t *testing.T) {
	s, r, actor, id := restartFixture(t)
	// The deferred trigger changes the later read projection at commit, after
	// the Enable CAS/audit succeeded. Enable must return its own committed state
	// rather than let an unrelated response read undo the successful transition.
	_, err := s.DB.Exec("CREATE FUNCTION corrupt_projection() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='extension.enable' THEN UPDATE extension_instances SET metadata_json='[]' WHERE instance_id='" + id + "'; END IF; RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER corrupt_after_enable AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION corrupt_projection()")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Enable(context.Background(), actor, id)
	if err != nil || !got.Enabled || !got.Routed || !reflect.DeepEqual(r.calls, []string{"start", "probe", "admit"}) {
		t.Fatalf("committed enable undone: routed=%v calls=%v err=%v", got.Routed, r.calls, err)
	}
}
