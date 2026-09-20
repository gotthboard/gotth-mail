package extensionsadmin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
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
	if _, err := service.ApplyConfigure(ctx, actor, preview.ID, "wrong-confirmation", configure); !errors.Is(err, ErrConfirmation) {
		t.Fatalf("wrong confirmation err=%v", err)
	}
	configured, err := service.ApplyConfigure(ctx, actor, preview.ID, preview.Confirmation, configure)
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
	updated, err := service.ApplyUpdate(ctx, actor, updatePreview.ID, updatePreview.Confirmation)
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
	} else if err := service.ApplyUninstall(ctx, actor, uninstall.ID, uninstall.Confirmation); !errors.Is(err, ErrConflict) {
		t.Fatalf("uninstall with retained secrets err=%v", err)
	}
	deletePreview, err := service.PreviewDeleteSecrets(ctx, actor, installed.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	withoutSecrets, err := service.ApplyDeleteSecrets(ctx, actor, deletePreview.ID, deletePreview.Confirmation)
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
	if err := service.ApplyUninstall(ctx, actor, uninstall.ID, uninstall.Confirmation); err != nil {
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
	if _, err := service.ApplyConfigure(ctx, actor, preview.ID, preview.Confirmation, input); err != nil {
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
	if _, err := service.ApplyConfigure(ctx, actor, second.ID, second.Confirmation, ConfigureInput{Configuration: map[string]any{"config.channel": "tertiary"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ApplyConfigure(ctx, actor, first.ID, first.Confirmation, ConfigureInput{Configuration: map[string]any{"config.channel": "secondary"}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale preview err=%v", err)
	}
	if _, err := db.Exec(`INSERT INTO extension_instances(instance_id,product,extension_id,repository,artifact_pin,manifest_sha256,grant_sha256,session_sha256,metadata_json,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000021','other-product','other.extension','https://github.com/gotthboard/gotth-extension-other','sha256:` + strings.Repeat("1", 64) + `','` + strings.Repeat("2", 64) + `','` + strings.Repeat("3", 64) + `','` + strings.Repeat("4", 64) + `','{"schema":"gotth.mail.extension.config.v1","fields":[]}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err == nil {
		t.Fatal("database admitted a cross-product extension")
	}
}
