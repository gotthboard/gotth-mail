package extensionsadmin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

type recordingRuntime struct {
	calls   []string
	secrets map[string]string
	health  Health
	errAt   string
}

func (r *recordingRuntime) record(name string) error {
	r.calls = append(r.calls, name)
	if r.errAt == name {
		return errors.New("runtime failure")
	}
	return nil
}

func (r *recordingRuntime) Start(_ context.Context, _ Instance, secrets map[string][]byte) error {
	r.secrets = map[string]string{}
	for slot, value := range secrets {
		r.secrets[slot] = string(value)
	}
	return r.record("start")
}
func (r *recordingRuntime) Probe(context.Context, Instance) (Health, error) {
	if err := r.record("probe"); err != nil {
		return Health{}, err
	}
	return r.health, nil
}
func (r *recordingRuntime) AdmitRouting(context.Context, Instance) error {
	return r.record("admit")
}
func (r *recordingRuntime) RevokeRouting(context.Context, Instance) error {
	return r.record("revoke")
}
func (r *recordingRuntime) Stop(context.Context, Instance) error { return r.record("stop") }

func TestExtensionLifecyclePreservesSecretsAndRollbackState(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recordingRuntime{health: Health{Healthy: true, Code: "extension.ready"}}
	service, err := NewService(db, []byte("0123456789abcdef0123456789abcdef"), runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := audit.ActorRef{Type: "api_token", ID: "alpha-admin"}
	metadata := Metadata{Schema: MetadataSchema, Fields: []Field{
		{Name: "telegram.chat-id", Label: "Telegram chat ID", Kind: FieldString, Required: true},
		{Name: "telegram.bot-token", Label: "Telegram bot token", Kind: FieldSecret, Required: true},
	}}
	installed, err := service.Install(ctx, actor, InstallRequest{
		InstanceID:     "00000000-0000-4000-8000-000000000017",
		ExtensionID:    "notification.telegram",
		Repository:     "https://github.com/gotthboard/gotth-extension-telegram",
		ArtifactPin:    "sha256:" + strings.Repeat("1", 64),
		ManifestDigest: strings.Repeat("2", 64),
		GrantDigest:    strings.Repeat("3", 64),
		SessionDigest:  strings.Repeat("4", 64),
		Capabilities:   []string{"notification.send"},
		Interfaces:     []string{"notification.v1"},
		SecretSlots:    []string{"telegram.bot-token"},
		Metadata:       metadata,
		CorrelationID:  "alpha-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if installed.Product != Product || installed.Enabled || installed.Routed {
		t.Fatalf("bad installation projection: %#v", installed)
	}
	listed, err := service.List(ctx)
	if err != nil || len(listed) != 1 || listed[0].InstanceID != installed.InstanceID {
		t.Fatalf("list err=%v items=%#v", err, listed)
	}

	configure := ConfigureInput{Configuration: map[string]any{"telegram.chat-id": "12345"}, Secrets: map[string]string{"telegram.bot-token": "never-render-this-token"}}
	preview, err := service.PreviewConfigure(ctx, actor, installed.InstanceID, configure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyConfigure(ctx, actor, installed.InstanceID, preview.ID, "wrong-confirmation", configure); !errors.Is(err, ErrConfirmation) {
		t.Fatalf("wrong confirmation err=%v", err)
	}
	configured, err := service.ApplyConfigure(ctx, actor, installed.InstanceID, preview.ID, preview.Confirmation, configure)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(configured)
	if strings.Contains(string(encoded), "never-render-this-token") || len(configured.Secrets) != 1 || !configured.Secrets[0].Configured {
		t.Fatalf("secret escaped projection: %s", encoded)
	}
	var persistedPreview, auditJSON string
	if err := db.QueryRow(`SELECT payload_json::text FROM extension_operation_previews WHERE id=$1`, preview.ID).Scan(&persistedPreview); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT after_redacted_json FROM audit_events WHERE action='extension.configure'`).Scan(&auditJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persistedPreview, "never-render-this-token") || strings.Contains(auditJSON, "never-render-this-token") {
		t.Fatal("plaintext secret persisted in preview or audit")
	}

	runtime.calls = nil
	tested, err := service.Test(ctx, actor, installed.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runtime.calls, []string{"start", "probe", "stop"}) || runtime.secrets["telegram.bot-token"] != "never-render-this-token" || tested.TestedRevision != tested.ConfigurationRev {
		t.Fatalf("bad test sequence calls=%v tested=%#v secrets=%v", runtime.calls, tested, runtime.secrets)
	}
	runtime.calls = nil
	enabled, err := service.Enable(ctx, actor, installed.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runtime.calls, []string{"start", "probe", "admit"}) || !enabled.Enabled || !enabled.Routed {
		t.Fatalf("bad enable sequence calls=%v instance=%#v", runtime.calls, enabled)
	}
	runtime.calls = nil
	disabled, err := service.Disable(ctx, actor, installed.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(runtime.calls, []string{"revoke", "stop"}) || disabled.Enabled || disabled.Routed {
		t.Fatalf("bad disable sequence calls=%v instance=%#v", runtime.calls, disabled)
	}

	updatedMetadata := metadata
	updatedMetadata.Fields = append(append([]Field(nil), metadata.Fields...), Field{Name: "telegram.topic", Label: "Telegram topic", Kind: FieldString}, Field{Name: "telegram.secondary-token", Label: "Secondary bot token", Kind: FieldSecret})
	update := UpdateInput{
		ArtifactPin:    "sha256:" + strings.Repeat("a", 64),
		ManifestDigest: strings.Repeat("b", 64),
		GrantDigest:    strings.Repeat("c", 64),
		SessionDigest:  strings.Repeat("d", 64),
		Capabilities:   []string{"notification.send", "notification.status"},
		Interfaces:     []string{"notification.v1"},
		SecretSlots:    []string{"telegram.bot-token", "telegram.secondary-token"},
		Metadata:       updatedMetadata,
	}
	updatePreview, err := service.PreviewUpdate(ctx, actor, installed.InstanceID, update)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(updatePreview.PrivilegeDiff, []string{"+notification.status"}) {
		t.Fatalf("privilege diff=%v", updatePreview.PrivilegeDiff)
	}
	if !reflect.DeepEqual(updatePreview.ConfigurationDiff, []string{"+telegram.secondary-token", "+telegram.topic"}) || !reflect.DeepEqual(updatePreview.SecretSlotDiff, []string{"+telegram.secondary-token"}) {
		t.Fatalf("configuration diff=%v secret diff=%v", updatePreview.ConfigurationDiff, updatePreview.SecretSlotDiff)
	}
	updated, err := service.ApplyUpdate(ctx, actor, installed.InstanceID, updatePreview.ID, updatePreview.Confirmation)
	if err != nil {
		t.Fatal(err)
	}
	if updated.PreviousArtifact != installed.ArtifactPin || updated.ArtifactPin != update.ArtifactPin {
		t.Fatalf("bad update pins: %#v", updated)
	}
	rolledBack, err := service.Rollback(ctx, actor, installed.InstanceID, "rollback notification.telegram to "+installed.ArtifactPin)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.ArtifactPin != installed.ArtifactPin || rolledBack.ManifestDigest != strings.Repeat("2", 64) || rolledBack.GrantDigest != strings.Repeat("3", 64) || rolledBack.Configuration["telegram.chat-id"] != "12345" || !rolledBack.Secrets[0].Configured {
		t.Fatalf("rollback did not restore version: %#v", rolledBack)
	}

	if uninstall, err := service.PreviewUninstall(ctx, actor, installed.InstanceID); err != nil {
		t.Fatal(err)
	} else if err := service.ApplyUninstall(ctx, actor, installed.InstanceID, uninstall.ID, uninstall.Confirmation); !errors.Is(err, ErrConflict) {
		t.Fatalf("uninstall with retained secrets err=%v", err)
	}
	deletePreview, err := service.PreviewDeleteSecrets(ctx, actor, installed.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	withoutSecrets, err := service.ApplyDeleteSecrets(ctx, actor, installed.InstanceID, deletePreview.ID, deletePreview.Confirmation)
	if err != nil {
		t.Fatal(err)
	}
	if withoutSecrets.Secrets[0].Configured {
		t.Fatal("secret deletion did not clear status")
	}
	uninstall, err := service.PreviewUninstall(ctx, actor, installed.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ApplyUninstall(ctx, actor, installed.InstanceID, uninstall.ID, uninstall.Confirmation); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(ctx, installed.InstanceID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after uninstall err=%v", err)
	}
}

func TestMetadataIsClosedAndHostilePresentationIsRejected(t *testing.T) {
	bad := []string{
		`{"schema":"gotth.mail.extension.config.v1","schema":"duplicate","fields":[]}`,
		`{"schema":"gotth.mail.extension.config.v1","fields":[{"name":"safe.field","label":"<script>","kind":"string"}]}`,
		`{"schema":"gotth.mail.extension.config.v1","fields":[{"name":"safe.field","label":"Safe","kind":"html"}]}`,
		`{"schema":"gotth.mail.extension.config.v1","fields":[],"action":"https://attacker.invalid"}`,
		`{"schema":"gotth.mail.extension.config.v1","fields":[{"name":"safe.field","label":"https://attacker.invalid","kind":"string"}]}`,
	}
	for _, input := range bad {
		if _, err := DecodeMetadata([]byte(input)); err == nil {
			t.Fatalf("accepted hostile metadata: %s", input)
		}
	}

	minimum, maximum := int64(1), int64(3)
	valid := Metadata{Schema: MetadataSchema, Fields: []Field{
		{Name: "config.string", Label: "String", Kind: FieldString, Required: true, Min: &minimum, Max: &maximum},
		{Name: "config.integer", Label: "Integer", Kind: FieldInteger, Min: &minimum, Max: &maximum},
		{Name: "config.boolean", Label: "Boolean", Kind: FieldBoolean},
		{Name: "config.enum", Label: "Enum", Kind: FieldEnum, Options: []string{"one", "two"}},
		{Name: "config.secret", Label: "Secret", Kind: FieldSecret},
	}}
	if err := ValidateMetadata(valid); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateConfiguration(valid, map[string]any{"config.string": "ab", "config.integer": int64(2), "config.boolean": true, "config.enum": "two"}, []string{"config.secret"}); err != nil {
		t.Fatal(err)
	}
	invalidValues := []map[string]any{
		{"config.string": ""},
		{"config.string": "abcd"},
		{"config.string": "ab", "config.integer": 2.5},
		{"config.string": "ab", "config.boolean": "true"},
		{"config.string": "ab", "config.enum": "three"},
		{"config.string": "ab", "config.secret": "forbidden"},
		{"config.string": "ab", "config.unknown": "forbidden"},
	}
	for _, configuration := range invalidValues {
		if _, err := ValidateConfiguration(valid, configuration, []string{"config.secret"}); err == nil {
			t.Fatalf("accepted invalid configuration: %#v", configuration)
		}
	}
	if _, err := NewService(nil, make([]byte, 32), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil database err=%v", err)
	}
	if _, err := NewService(&sql.DB{}, make([]byte, 31), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("short key err=%v", err)
	}
}

func TestRuntimeFailuresNeverAdmitOrSilentlyStopRouting(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recordingRuntime{health: Health{Healthy: false, Code: "extension.degraded"}}
	service, err := NewService(db, []byte("abcdef0123456789abcdef0123456789"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := audit.ActorRef{Type: "api_token", ID: "failure-admin"}
	metadata := Metadata{Schema: MetadataSchema, Fields: []Field{{Name: "config.channel", Label: "Channel", Kind: FieldString, Required: true}}}
	instance, err := service.Install(ctx, actor, InstallRequest{InstanceID: "00000000-0000-4000-8000-000000000020", ExtensionID: "notification.failure-test", Repository: "https://github.com/gotthboard/gotth-extension-failure-test", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Capabilities: []string{"notification.send"}, Interfaces: []string{"notification.v1"}, Metadata: metadata})
	if err != nil {
		t.Fatal(err)
	}
	input := ConfigureInput{Configuration: map[string]any{"config.channel": "primary"}}
	preview, err := service.PreviewConfigure(ctx, actor, instance.InstanceID, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyConfigure(ctx, actor, instance.InstanceID, preview.ID, preview.Confirmation, input); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Test(ctx, actor, instance.InstanceID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil runtime test err=%v", err)
	}
	service.Runtime = runtime
	if _, err := service.Test(ctx, actor, instance.InstanceID); !errors.Is(err, ErrUnhealthy) {
		t.Fatalf("unhealthy test err=%v", err)
	}
	if !reflect.DeepEqual(runtime.calls, []string{"start", "probe", "stop"}) {
		t.Fatalf("unhealthy test calls=%v", runtime.calls)
	}
	runtime.calls = nil
	runtime.health = Health{Healthy: true, Code: "extension.ready"}
	if _, err := service.Test(ctx, actor, instance.InstanceID); err != nil {
		t.Fatal(err)
	}
	runtime.calls = nil
	runtime.errAt = "probe"
	if _, err := service.Enable(ctx, actor, instance.InstanceID); err == nil {
		t.Fatal("probe failure admitted extension")
	}
	if !reflect.DeepEqual(runtime.calls, []string{"start", "probe", "stop"}) {
		t.Fatalf("probe failure calls=%v", runtime.calls)
	}
	state, err := service.Get(ctx, instance.InstanceID)
	if err != nil || state.Enabled || state.Routed {
		t.Fatalf("probe failure persisted routing state=%#v err=%v", state, err)
	}
	runtime.calls = nil
	runtime.errAt = ""
	if _, err := service.Enable(ctx, actor, instance.InstanceID); err != nil {
		t.Fatal(err)
	}
	runtime.calls = nil
	runtime.errAt = "revoke"
	if _, err := service.Disable(ctx, actor, instance.InstanceID); err == nil {
		t.Fatal("revoke failure reported successful disable")
	}
	if !reflect.DeepEqual(runtime.calls, []string{"revoke"}) {
		t.Fatalf("revoke failure should not stop process: %v", runtime.calls)
	}
	state, err = service.Get(ctx, instance.InstanceID)
	if err != nil || !state.Enabled || !state.Routed {
		t.Fatalf("revoke failure corrupted routing state=%#v err=%v", state, err)
	}
	runtime.errAt = ""
	if _, err := service.Disable(ctx, actor, instance.InstanceID); err != nil {
		t.Fatal(err)
	}

	first, err := service.PreviewConfigure(ctx, actor, instance.InstanceID, ConfigureInput{Configuration: map[string]any{"config.channel": "secondary"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.PreviewConfigure(ctx, actor, instance.InstanceID, ConfigureInput{Configuration: map[string]any{"config.channel": "tertiary"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyConfigure(ctx, actor, instance.InstanceID, second.ID, second.Confirmation, ConfigureInput{Configuration: map[string]any{"config.channel": "tertiary"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyConfigure(ctx, actor, instance.InstanceID, first.ID, first.Confirmation, ConfigureInput{Configuration: map[string]any{"config.channel": "secondary"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale preview err=%v", err)
	}
	if _, err := db.Exec(`INSERT INTO extension_instances(instance_id,product,extension_id,repository,artifact_pin,manifest_sha256,grant_sha256,session_sha256,metadata_json,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000021','other-product','other.extension','https://github.com/gotthboard/gotth-extension-other','sha256:` + strings.Repeat("1", 64) + `','` + strings.Repeat("2", 64) + `','` + strings.Repeat("3", 64) + `','` + strings.Repeat("4", 64) + `','{"schema":"gotth.mail.extension.config.v1","fields":[]}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("database admitted a cross-product extension")
	}
}

// Exact rational comparison never truncates a float to int64 or rounds an expected
// fixture. Dynamic float64 versus int64 alone is not a regression.
func metadataExactDefault(t *testing.T, stage string, got any, want string) {
	t.Helper()
	var r *big.Rat
	switch v := got.(type) {
	case float64:
		r = new(big.Rat).SetFloat64(v)
	case int64:
		r = new(big.Rat).SetInt64(v)
	case int:
		r = new(big.Rat).SetInt64(int64(v))
	case json.Number:
		r, _ = new(big.Rat).SetString(string(v))
	}
	if r == nil {
		t.Errorf("PRECISION %s: nonnumeric default", stage)
		return
	}
	expected, ok := new(big.Rat).SetString(want)
	if !ok {
		t.Fatal("fixture numeric literal invalid")
	}
	if r.Cmp(expected) != 0 {
		t.Errorf("PRECISION %s: got=%s want=%s", stage, r.RatString(), want)
	}
}
func metadataIntegerFixture(t *testing.T, number string) Metadata {
	t.Helper()
	raw := fmt.Sprintf("{\"schema\":\"%s\",\"fields\":[{\"name\":\"config.number\",\"label\":\"Number\",\"kind\":\"integer\",\"required\":true,\"min\":%s,\"max\":%s,\"default\":%s}]}", MetadataSchema, number, number, number)
	m, err := DecodeMetadata([]byte(raw))
	if err != nil {
		t.Fatal("fixture metadata admission failed")
	}
	if _, ok := m.Fields[0].Default.(json.Number); !ok {
		t.Fatal("fixture did not retain raw number")
	}
	return m
}
func TestMetadataStoredIntegerPrecision(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recordingRuntime{}
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := audit.ActorRef{Type: "api_token", ID: "precision-fixture"}
	for i, n := range []string{"9007199254740991", "9007199254740992", "9007199254740993", "-9223372036854775808", "9223372036854775807"} {
		t.Run(n, func(t *testing.T) {
			m := metadataIntegerFixture(t, n)
			want, _ := strconv.ParseInt(n, 10, 64)
			in := InstallRequest{InstanceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 9100+i), ExtensionID: fmt.Sprintf("precision.number%d", i), Repository: "https://github.com/gotthboard/gotth-extension-precision", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: m}
			installed, err := svc.Install(ctx, actor, in)
			if err != nil {
				t.Fatal("SETUP install failed")
			}
			var def, min, max string
			if err := db.QueryRow("SELECT metadata_json#>>'{fields,0,default}',metadata_json#>>'{fields,0,min}',metadata_json#>>'{fields,0,max}' FROM extension_instances WHERE instance_id=$1", in.InstanceID).Scan(&def, &min, &max); err != nil {
				t.Fatal("SETUP SQL read failed")
			}
			if def != n || min != n || max != n {
				t.Fatal("SQL numeric admission changed")
			}
			t.Logf("SQL exact default/min/max=%s", n)
			baseline := targetSnapshot(t, db)
			get, err := svc.Get(ctx, in.InstanceID)
			if err != nil {
				t.Fatal("Get failed")
			}
			list, err := svc.List(ctx)
			if err != nil {
				t.Fatal("List failed")
			}
			values := []Instance{installed, get}
			for _, v := range list {
				if v.InstanceID == in.InstanceID {
					values = append(values, v)
				}
			}
			if len(values) != 3 {
				t.Fatal("list target cardinality")
			}
			for j, v := range values {
				if len(v.Metadata.Fields) != 1 {
					t.Fatal("metadata field missing")
				}
				f := v.Metadata.Fields[0]
				if f.Min == nil || f.Max == nil || *f.Min != want || *f.Max != want {
					t.Fatal("typed bounds changed")
				}
				metadataExactDefault(t, []string{"Install", "Get", "List"}[j], f.Default, n)
				if len(v.Configuration) != 0 {
					t.Error("default inserted into configuration")
				}
			}
			targetUnchanged(t, db, baseline)
			if len(runtime.calls) != 0 {
				t.Error("read invoked runtime")
			}
		})
	}
}

func TestMetadataVersionIntegerPrecision(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recordingRuntime{}
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := audit.ActorRef{Type: "api_token", ID: "precision-version"}
	seq := 0
	for _, seam := range []string{"incoming-update", "outgoing-snapshot", "rollback-decode"} {
		for _, n := range []string{"9007199254740991", "9007199254740993"} {
			t.Run(seam+"/"+n, func(t *testing.T) {
				seq++
				initial := metadataIntegerFixture(t, "7")
				target := metadataIntegerFixture(t, "9")
				if seam == "incoming-update" {
					target = metadataIntegerFixture(t, n)
				}
				if seam == "outgoing-snapshot" {
					initial = metadataIntegerFixture(t, n)
				}
				in := InstallRequest{InstanceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 9200+seq), ExtensionID: fmt.Sprintf("precision.version%d", seq), Repository: "https://github.com/gotthboard/gotth-extension-precision", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: initial}
				_, err := svc.Install(ctx, actor, in)
				if err != nil {
					t.Fatal("SETUP install failed")
				}
				input := UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: target}
				preview, err := svc.PreviewUpdate(ctx, actor, in.InstanceID, input)
				if err != nil {
					t.Fatal("SETUP real PreviewUpdate failed")
				}
				encoded, err := json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(encoded)
				var sqlTarget, sqlActor, sqlType, sqlHash, sqlDefault string
				var rev int64
				var consumed bool
				err = db.QueryRow("SELECT instance_id::text,actor_id,actor_type,base_revision,payload_sha256,payload_json#>>'{metadata,fields,0,default}',consumed_at IS NOT NULL FROM extension_operation_previews WHERE id=$1", preview.ID).Scan(&sqlTarget, &sqlActor, &sqlType, &rev, &sqlHash, &sqlDefault, &consumed)
				if err != nil || sqlTarget != in.InstanceID || sqlActor != actor.ID || sqlType != actor.Type || rev != 1 || sqlHash != fmt.Sprintf("%x", sum) || sqlHash != preview.PayloadSHA256 || consumed || sqlDefault != string(target.Fields[0].Default.(json.Number)) {
					t.Fatal("SETUP accepted preview binding mismatch")
				}
				before := targetSnapshot(t, db)
				for _, bad := range []string{"actor", "target", "confirmation"} {
					a, id, c := actor, in.InstanceID, preview.Confirmation
					if bad == "actor" {
						a.ID = "other"
					}
					if bad == "target" {
						id = "00000000-0000-4000-8000-000000999999"
					}
					if bad == "confirmation" {
						c = "wrong"
					}
					if _, err := svc.ApplyUpdate(ctx, a, id, preview.ID, c); !errors.Is(err, ErrConfirmation) {
						t.Fatal("bound denial changed")
					}
					targetUnchanged(t, db, before)
				}
				updated, err := svc.ApplyUpdate(ctx, actor, in.InstanceID, preview.ID, preview.Confirmation)
				if err != nil {
					t.Errorf("PRECISION accepted update failed at %s", seam)
					targetUnchanged(t, db, before)
					return
				}
				if updated.ArtifactPin != input.ArtifactPin || updated.PreviousArtifact != in.ArtifactPin || updated.ConfigurationRev != 2 || len(updated.Configuration) != 0 {
					t.Fatal("update identity/revision/config changed")
				}
				var audits int
				if err := db.QueryRow("SELECT consumed_at IS NOT NULL FROM extension_operation_previews WHERE id=$1", preview.ID).Scan(&consumed); err != nil || !consumed {
					t.Fatal("preview not consumed")
				}
				if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='extension.update'", in.InstanceID).Scan(&audits); err != nil || audits != 1 {
					t.Fatal("update audit count")
				}
				currentWant := string(target.Fields[0].Default.(json.Number))
				metadataExactDefault(t, "ApplyUpdate result", updated.Metadata.Fields[0].Default, currentWant)
				previousWant := string(initial.Fields[0].Default.(json.Number))
				if seam == "rollback-decode" {
					// DIRECT DB SETUP, not a credited product write: isolate rollback decode
					// from an already-rounded outgoing snapshot. All other snapshot fields stay.
					exact, _ := json.Marshal(metadataIntegerFixture(t, n))
					if _, err := db.Exec("UPDATE extension_instances SET previous_version_json=jsonb_set(previous_version_json,'{metadata}',$1::jsonb) WHERE instance_id=$2", exact, in.InstanceID); err != nil {
						t.Fatal("SETUP previous metadata injection failed")
					}
					previousWant = n
					t.Log("DIRECT DB SETUP: exact previous metadata only")
				}
				var stored string
				if err := db.QueryRow("SELECT previous_version_json#>>'{metadata,fields,0,default}' FROM extension_instances WHERE instance_id=$1", in.InstanceID).Scan(&stored); err != nil {
					t.Fatal("snapshot SQL read")
				}
				if stored != previousWant {
					t.Errorf("PRECISION previous snapshot SQL got=%s want=%s", stored, previousWant)
				}
				before = targetSnapshot(t, db)
				if _, err := svc.Rollback(ctx, actor, in.InstanceID, "wrong"); !errors.Is(err, ErrConfirmation) {
					t.Fatal("rollback confirmation changed")
				}
				targetUnchanged(t, db, before)
				rolled, err := svc.Rollback(ctx, actor, in.InstanceID, "rollback "+in.ExtensionID+" to "+in.ArtifactPin)
				if err != nil {
					t.Errorf("PRECISION exact previous metadata rollback failed at %s", seam)
					targetUnchanged(t, db, before)
					return
				}
				if rolled.ConfigurationRev != 3 || rolled.ArtifactPin != in.ArtifactPin || rolled.PreviousArtifact != input.ArtifactPin || len(rolled.Configuration) != 0 {
					t.Fatal("rollback identity/revision/config changed")
				}
				metadataExactDefault(t, "Rollback", rolled.Metadata.Fields[0].Default, previousWant)
				if err := db.QueryRow("SELECT previous_version_json#>>'{metadata,fields,0,default}' FROM extension_instances WHERE instance_id=$1", in.InstanceID).Scan(&stored); err != nil || stored != currentWant {
					t.Fatal("reverse snapshot current metadata changed")
				}
				reversed, err := svc.Rollback(ctx, actor, in.InstanceID, "rollback "+in.ExtensionID+" to "+input.ArtifactPin)
				if err != nil {
					t.Fatal("reverse rollback failed")
				}
				metadataExactDefault(t, "ReverseRollback", reversed.Metadata.Fields[0].Default, currentWant)
				if reversed.ConfigurationRev != 4 || reversed.ArtifactPin != input.ArtifactPin {
					t.Fatal("reverse identity/revision")
				}
				if err := db.QueryRow("SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='extension.rollback'", in.InstanceID).Scan(&audits); err != nil || audits != 2 {
					t.Fatal("rollback audit count")
				}
				if len(runtime.calls) != 0 {
					t.Fatal("version operation invoked runtime")
				}
			})
		}
	}
}

func TestMetadataLegacyDecodeClasses(t *testing.T) {
	prefix := fmt.Sprintf("{\"schema\":\"%s\",\"fields\":[{\"name\":\"config.number\",\"label\":\"Number\",\"kind\":\"integer\"", MetadataSchema)
	for _, tc := range []struct {
		name, tail        string
		legacy, admission bool
	}{
		{"missing", "}]}", true, true}, {"null", ",\"default\":null}]}", true, true}, {"integer", ",\"default\":7}]}", true, true},
		{"decimal", ",\"default\":1.0}]}", true, false}, {"exponent", ",\"default\":1e0}]}", true, false}, {"fraction", ",\"default\":1.5}]}", true, false},
		{"int64-overflow", ",\"default\":9223372036854775808}]}", true, false}, {"float-overflow", ",\"default\":1e400}]}", false, false},
		{"typed-bound-overflow", ",\"min\":9223372036854775808}]}", false, false}, {"object-default", ",\"default\":{\"x\":7}}]}", true, false},
		{"array-default", ",\"default\":[7]}]}", true, false}, {"unknown-key", ",\"surprise\":true}]}", true, false},
		{"duplicate-default", ",\"default\":7,\"default\":8}]}", true, false}, {"case-default", ",\"default\":7,\"Default\":8}]}", true, true},
		{"malformed", ",", false, false}, {"trailing", "}]} {}", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(prefix + tc.tail)
			var m Metadata
			err := json.Unmarshal(raw, &m)
			if (err == nil) != tc.legacy {
				t.Fatal("legacy decode class changed")
			}
			if tc.legacy {
				var want Metadata
				if err := json.Unmarshal(raw, &want); err != nil {
					t.Fatal(err)
				}
				switch tc.name {
				case "integer":
					want.Fields[0].Default = int64(7)
				case "duplicate-default", "case-default":
					want.Fields[0].Default = int64(8)
				}
				var defaults metadataDefaults
				if err := json.Unmarshal(raw, &defaults); err != nil {
					t.Fatal("production projection newly rejected legacy metadata")
				}
				if err := restoreMetadataIntegerDefaults(&m, defaults); err != nil {
					t.Fatal("production restore rejected legacy metadata")
				}
				if !reflect.DeepEqual(m, want) {
					t.Fatal("production restore changed legacy default class/other metadata")
				}
			}

			_, err = DecodeMetadata(raw)
			if (err == nil) != tc.admission {
				t.Fatal("current admission class changed")
			}
			if tc.name == "decimal" || tc.name == "exponent" {
				if err := ValidateMetadata(m); err != nil {
					t.Fatal("legacy integral float acceptance changed")
				}
			}
			if tc.name == "duplicate-default" || tc.name == "case-default" {
				metadataExactDefault(t, "last default", m.Fields[0].Default, "8")
			}
		})
	}
	for _, tc := range []struct {
		name, raw string
		fields    int
		admission bool
	}{
		{"schema-invalid", "{\"schema\":\"old\",\"fields\":[]}", 0, false},
		{"duplicate-field-names", prefix + "},{\"name\":\"config.number\",\"label\":\"Second\",\"kind\":\"integer\"}]}", 2, false},
		{"case-fields-null", prefix + "}],\"Fields\":null}", 0, true},
		{"case-fields-empty", prefix + "}],\"Fields\":[]}", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m Metadata
			if err := json.Unmarshal([]byte(tc.raw), &m); err != nil || len(m.Fields) != tc.fields {
				t.Fatal("legacy field/schema shape changed")
			}
			var defaults metadataDefaults
			if err := json.Unmarshal([]byte(tc.raw), &defaults); err != nil {
				t.Fatal("production projection rejected legacy field/schema shape")
			}
			before, _ := json.Marshal(m)
			if err := restoreMetadataIntegerDefaults(&m, defaults); err != nil {
				t.Fatal("production restore rejected legacy field/schema shape")
			}
			after, _ := json.Marshal(m)
			if string(before) != string(after) {
				t.Fatal("production restore changed legacy field/schema shape")
			}

			_, err := DecodeMetadata([]byte(tc.raw))
			if (err == nil) != tc.admission {
				t.Fatal("field admission class changed")
			}
		})
	}
	// Configuration VALUE decoding is deliberately untouched by a default repair.
	var config map[string]any
	if err := json.Unmarshal([]byte("{\"config.number\":7}"), &config); err != nil {
		t.Fatal(err)
	}
	if _, ok := config["config.number"].(float64); !ok {
		t.Fatal("configuration value representation changed")
	}
}

func TestMetadataLegacyNestedMerge(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	full, err := json.Marshal(metadataIntegerFixture(t, "7"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, first, last string
		fields            int
		rawLoses          bool
	}{
		{"empty-after", string(full), "{}", 1, true},
		{"null-after", string(full), "null", 1, true},
		{"full-after", "{}", string(full), 1, false},
		{"clear-fields", string(full), "{\"fields\":[]}", 0, false},
	} {
		for _, stored := range []bool{false, true} {
			suffix := "raw"
			if stored {
				suffix = "jsonb"
			}
			t.Run(tc.name+"/"+suffix, func(t *testing.T) {
				raw := fmt.Sprintf("{\"Metadata\":%s,\"metadata\":%s}", tc.first, tc.last)
				if stored {
					var canonical string
					if err := db.QueryRow("SELECT $1::jsonb::text", raw).Scan(&canonical); err != nil {
						t.Fatal("SETUP jsonb canonicalization failed")
					}
					raw = canonical
				}
				var update UpdateInput
				var snapshot versionSnapshot
				if json.Unmarshal([]byte(raw), &update) != nil || json.Unmarshal([]byte(raw), &snapshot) != nil {
					t.Fatal("typed envelope decode failed")
				}
				for _, m := range []Metadata{update.Metadata, snapshot.Metadata} {
					if m.Schema != MetadataSchema || len(m.Fields) != tc.fields {
						t.Fatal("typed nested merge changed")
					}
					if tc.fields == 1 {
						metadataExactDefault(t, "typed nested merge", m.Fields[0].Default, "7")
					}
				}

				var defaults struct{ Metadata metadataDefaults }
				if err := json.Unmarshal([]byte(raw), &defaults); err != nil {
					t.Fatal("production nested projection rejected typed merge")
				}
				for _, m := range []*Metadata{&update.Metadata, &snapshot.Metadata} {
					if err := restoreMetadataIntegerDefaults(m, defaults.Metadata); err != nil {
						t.Fatal("production nested restore lost merge")
					}
					if len(m.Fields) != tc.fields || m.Schema != MetadataSchema {
						t.Fatal("production merge changed schema/field shape")
					}
					if tc.fields == 1 {
						if value, ok := m.Fields[0].Default.(int64); !ok || value != 7 {
							t.Fatal("production merged default not restored")
						}
					}
				}
				// Counterexample only: proposed last-RawMessage extraction, NOT production.
				var last struct{ Metadata json.RawMessage }
				if json.Unmarshal([]byte(raw), &last) != nil {
					t.Fatal("raw envelope fixture")
				}
				var projected Metadata
				if json.Unmarshal(last.Metadata, &projected) != nil {
					t.Fatal("raw metadata fixture")
				}
				if (len(projected.Fields) != len(update.Metadata.Fields)) != tc.rawLoses {
					t.Fatal("last-blob projection characterization changed")
				}
				t.Logf("typed field count=%d last-blob loses retained fields=%t", len(update.Metadata.Fields), tc.rawLoses)
			})
		}
	}
}

func TestMetadataProductionFieldProjection(t *testing.T) {
	first := "\"fields\":[{\"kind\":\"integer\",\"default\":9007199254740993}]"
	for _, tc := range []struct {
		name, suffix string
		restore      bool
	}{
		{"reuse-empty-element", ",\"Fields\":[{}]", true},
		{"reuse-null-element", ",\"Fields\":[null]", true},
		{"change-kind", ",\"Fields\":[{\"kind\":\"string\"}]", false},
		{"clear-default", ",\"Fields\":[{\"default\":null}]", false},
		{"reset-null", ",\"Fields\":null", false},
		{"reset-empty", ",\"Fields\":[]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte("{" + first + tc.suffix + "}")
			var got, want Metadata
			var defaults metadataDefaults
			if json.Unmarshal(raw, &got) != nil || json.Unmarshal(raw, &want) != nil || json.Unmarshal(raw, &defaults) != nil {
				t.Fatal("projection fixture decode")
			}
			if tc.restore {
				want.Fields[0].Default = int64(9007199254740993)
			}
			if err := restoreMetadataIntegerDefaults(&got, defaults); err != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("production projection changed field merge/reset")
			}
		})
	}
	for _, kind := range []FieldKind{FieldString, FieldBoolean, FieldEnum, FieldSecret, "future"} {
		t.Run(string(kind), func(t *testing.T) {
			raw := []byte(fmt.Sprintf("{\"fields\":[{\"kind\":%q,\"default\":7}]}", kind))
			var got, want Metadata
			var defaults metadataDefaults
			if json.Unmarshal(raw, &got) != nil || json.Unmarshal(raw, &want) != nil || json.Unmarshal(raw, &defaults) != nil {
				t.Fatal("kind fixture decode")
			}
			if restoreMetadataIntegerDefaults(&got, defaults) != nil || !reflect.DeepEqual(got, want) {
				t.Fatal("noninteger kind changed")
			}
		})
	}
	t.Run("shape-invariant", func(t *testing.T) {
		m := metadataIntegerFixture(t, "7")
		before, _ := json.Marshal(m)
		if restoreMetadataIntegerDefaults(&m, metadataDefaults{}) == nil {
			t.Fatal("mismatched internal projection accepted")
		}
		after, _ := json.Marshal(m)
		if string(before) != string(after) {
			t.Fatal("mismatch partially changed metadata")
		}
	})
}

func TestMetadataProductionNestedCallers(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	runtime := &recordingRuntime{}
	svc, err := NewService(db, []byte(strings.Repeat("k", 32)), runtime)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	actor := audit.ActorRef{Type: "api_token", ID: "nested-projection"}
	for i, tail := range []string{"{}", "null"} {
		t.Run(tail, func(t *testing.T) {
			initial := metadataIntegerFixture(t, "7")
			extra := Field{Name: "config.value", Label: "Value", Kind: FieldInteger}
			initial.Fields = append(initial.Fields, extra)
			in := InstallRequest{InstanceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 9400+i), ExtensionID: fmt.Sprintf("precision.nested%d", i), Repository: "https://github.com/gotthboard/gotth-extension-precision", ArtifactPin: "sha256:" + strings.Repeat("1", 64), ManifestDigest: strings.Repeat("2", 64), GrantDigest: strings.Repeat("3", 64), SessionDigest: strings.Repeat("4", 64), Metadata: initial}
			if _, err := svc.Install(ctx, actor, in); err != nil {
				t.Fatal("SETUP install")
			}
			config := ConfigureInput{Configuration: map[string]any{"config.value": int64(7)}}
			cp, err := svc.PreviewConfigure(ctx, actor, in.InstanceID, config)
			if err != nil {
				t.Fatal("SETUP configure preview")
			}
			if _, err := svc.ApplyConfigure(ctx, actor, in.InstanceID, cp.ID, cp.Confirmation, config); err != nil {
				t.Fatal("SETUP configure apply")
			}
			target := metadataIntegerFixture(t, "9007199254740993")
			target.Fields = append(target.Fields, extra)
			input := UpdateInput{ArtifactPin: "sha256:" + strings.Repeat("5", 64), ManifestDigest: strings.Repeat("6", 64), GrantDigest: strings.Repeat("7", 64), SessionDigest: strings.Repeat("8", 64), Metadata: target}
			preview, err := svc.PreviewUpdate(ctx, actor, in.InstanceID, input)
			if err != nil {
				t.Fatal("SETUP update preview")
			}
			// DIRECT DB legacy-representation setup only; unchanged actor/target/hash and
			// semantic update metadata. JSONB preserves both case-variant keys.
			if _, err := db.Exec("UPDATE extension_operation_previews SET payload_json=(payload_json-'metadata')||jsonb_build_object('Metadata',payload_json->'metadata','metadata',$1::jsonb) WHERE id=$2", tail, preview.ID); err != nil {
				t.Fatal("SETUP legacy update shape")
			}
			t.Log("DIRECT DB SETUP: typed nested legacy representation")
			updated, err := svc.ApplyUpdate(ctx, actor, in.InstanceID, preview.ID, preview.Confirmation)
			if err != nil {
				t.Fatal("production ApplyUpdate lost nested merge")
			}
			metadataExactDefault(t, "nested ApplyUpdate", updated.Metadata.Fields[0].Default, "9007199254740993")
			if v, ok := updated.Configuration["config.value"].(float64); !ok || v != 7 || updated.ConfigurationRev != 3 {
				t.Fatal("update changed configuration value representation/revision")
			}
			// DIRECT DB previous-metadata setup isolates Rollback. A legacy decimal
			// configuration VALUE must still follow old float64 decoding, not UseNumber.
			exact, _ := json.Marshal(target)
			if _, err := db.Exec("UPDATE extension_instances SET previous_version_json=jsonb_set((previous_version_json-'metadata')||jsonb_build_object('Metadata',$1::jsonb,'metadata',$2::jsonb),'{configuration,config.value}','7.0'::jsonb) WHERE instance_id=$3", exact, tail, in.InstanceID); err != nil {
				t.Fatal("SETUP legacy previous shape")
			}
			rolled, err := svc.Rollback(ctx, actor, in.InstanceID, "rollback "+in.ExtensionID+" to "+in.ArtifactPin)
			if err != nil {
				t.Fatal("production Rollback lost nested merge or decimal configuration compatibility")
			}
			metadataExactDefault(t, "nested Rollback", rolled.Metadata.Fields[0].Default, "9007199254740993")
			if v, ok := rolled.Configuration["config.value"].(float64); !ok || v != 7 || rolled.ConfigurationRev != 4 || len(runtime.calls) != 0 {
				t.Fatal("rollback changed configuration/runtime/revision")
			}
		})
	}
}
