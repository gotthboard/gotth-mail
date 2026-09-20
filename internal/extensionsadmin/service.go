package extensionsadmin

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"forgejo/gotthboard/gotth-mail/internal/audit"
)

const previewTTL = 10 * time.Minute

var (
	repositoryPattern = regexp.MustCompile(`^https://github\.com/gotthboard/gotth-extension-[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	artifactPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	digestPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Service struct {
	DB      *sql.DB
	Runtime Runtime
	Now     func() time.Time
	Rand    io.Reader
	key     []byte
}

func NewService(db *sql.DB, key []byte, runtime Runtime) (*Service, error) {
	if db == nil || len(key) != 32 {
		return nil, ErrUnavailable
	}
	return &Service{DB: db, key: append([]byte(nil), key...), Runtime: runtime}, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) random() io.Reader {
	if s.Rand != nil {
		return s.Rand
	}
	return rand.Reader
}

func validateInstall(in InstallRequest) (InstallRequest, error) {
	if !validUUID(in.InstanceID) || !validDottedToken(in.ExtensionID) || !repositoryPattern.MatchString(in.Repository) || !artifactPattern.MatchString(in.ArtifactPin) ||
		!digestPattern.MatchString(in.ManifestDigest) || !digestPattern.MatchString(in.GrantDigest) || !digestPattern.MatchString(in.SessionDigest) || in.CorrelationID != "" && !validScalarText(in.CorrelationID, 256) {
		return InstallRequest{}, errors.New("invalid extension installation")
	}
	var err error
	if in.Capabilities, err = canonicalTokens(in.Capabilities); err != nil {
		return InstallRequest{}, err
	}
	if in.Interfaces, err = canonicalTokens(in.Interfaces); err != nil {
		return InstallRequest{}, err
	}
	if in.SecretSlots, err = canonicalTokens(in.SecretSlots); err != nil {
		return InstallRequest{}, err
	}
	if err := ValidateMetadata(in.Metadata); err != nil {
		return InstallRequest{}, err
	}
	if in.AvailableUpdate != "" && !artifactPattern.MatchString(in.AvailableUpdate) {
		return InstallRequest{}, errors.New("invalid available extension update")
	}
	return in, nil
}

func (s *Service) Install(ctx context.Context, actor audit.ActorRef, in InstallRequest) (Instance, error) {
	if err := validateActor(actor); err != nil {
		return Instance{}, err
	}
	in, err := validateInstall(in)
	if err != nil {
		return Instance{}, err
	}
	metadata, _ := json.Marshal(in.Metadata)
	capabilities, _ := json.Marshal(in.Capabilities)
	interfaces, _ := json.Marshal(in.Interfaces)
	slots, _ := json.Marshal(in.SecretSlots)
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO extension_instances(instance_id, product, extension_id, repository, artifact_pin, available_update_pin, manifest_sha256, grant_sha256, session_sha256, capabilities_json, interfaces_json, secret_slots_json, metadata_json, configuration_json, configuration_revision, lifecycle, health_code, enabled, routed, last_correlation_id, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'{}',1,'discovered','extension.unknown',false,false,$14,$15,$15)`, in.InstanceID, Product, in.ExtensionID, in.Repository, in.ArtifactPin, nullText(in.AvailableUpdate), in.ManifestDigest, in.GrantDigest, in.SessionDigest, capabilities, interfaces, slots, metadata, in.CorrelationID, now)
	if err != nil {
		return Instance{}, err
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{Actor: actor, Action: "extension.install", Resource: audit.ResourceRef{Type: "extension", ID: in.InstanceID}, AfterRedacted: map[string]any{"extension_id": in.ExtensionID, "artifact_pin": in.ArtifactPin}, CorrelationID: in.CorrelationID, Result: "success"}); err != nil {
		return Instance{}, err
	}
	if err := tx.Commit(); err != nil {
		return Instance{}, err
	}
	return s.Get(ctx, in.InstanceID)
}

const instanceColumns = `instance_id, product, extension_id, repository, artifact_pin, previous_artifact_pin, available_update_pin, manifest_sha256, grant_sha256, session_sha256, capabilities_json, interfaces_json, secret_slots_json, metadata_json, configuration_json, configuration_revision, lifecycle, health_code, tested_revision, enabled, routed, last_correlation_id, created_at, updated_at`

type rowScanner interface{ Scan(...any) error }

func scanInstance(row rowScanner) (Instance, error) {
	var out Instance
	var previous, available sql.NullString
	var tested sql.NullInt64
	var capabilities, interfaces, slots, metadata, configuration []byte
	err := row.Scan(&out.InstanceID, &out.Product, &out.ExtensionID, &out.Repository, &out.ArtifactPin, &previous, &available, &out.ManifestDigest, &out.GrantDigest, &out.SessionDigest, &capabilities, &interfaces, &slots, &metadata, &configuration, &out.ConfigurationRev, &out.Lifecycle, &out.HealthCode, &tested, &out.Enabled, &out.Routed, &out.LastCorrelationID, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Instance{}, ErrNotFound
	}
	if err != nil {
		return Instance{}, err
	}
	out.PreviousArtifact = previous.String
	out.AvailableUpdate = available.String
	out.TestedRevision = tested.Int64
	if err := json.Unmarshal(capabilities, &out.Capabilities); err != nil {
		return Instance{}, err
	}
	if err := json.Unmarshal(interfaces, &out.Interfaces); err != nil {
		return Instance{}, err
	}
	if err := json.Unmarshal(slots, &out.SecretSlots); err != nil {
		return Instance{}, err
	}
	if err := json.Unmarshal(metadata, &out.Metadata); err != nil {
		return Instance{}, err
	}
	if err := json.Unmarshal(configuration, &out.Configuration); err != nil {
		return Instance{}, err
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id string) (Instance, error) {
	out, err := scanInstance(s.DB.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM extension_instances WHERE instance_id=$1 AND product=$2`, id, Product))
	if err != nil {
		return Instance{}, err
	}
	if err := s.loadSecretStatus(ctx, &out); err != nil {
		return Instance{}, err
	}
	return out, nil
}

func (s *Service) List(ctx context.Context) ([]Instance, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+instanceColumns+` FROM extension_instances WHERE product=$1 ORDER BY extension_id`, Product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Instance
	for rows.Next() {
		item, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range result {
		if err := s.loadSecretStatus(ctx, &result[i]); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (s *Service) loadSecretStatus(ctx context.Context, instance *Instance) error {
	rows, err := s.DB.QueryContext(ctx, `SELECT slot, rotated_at FROM extension_secrets WHERE instance_id=$1 ORDER BY slot`, instance.InstanceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	configured := map[string]time.Time{}
	for rows.Next() {
		var slot string
		var rotated time.Time
		if err := rows.Scan(&slot, &rotated); err != nil {
			return err
		}
		configured[slot] = rotated
	}
	if err := rows.Err(); err != nil {
		return err
	}
	instance.Secrets = make([]SecretStatus, 0, len(instance.SecretSlots))
	for _, slot := range instance.SecretSlots {
		rotated, ok := configured[slot]
		instance.Secrets = append(instance.Secrets, SecretStatus{Slot: slot, Configured: ok, RotatedAt: rotated})
	}
	return nil
}

func (s *Service) PreviewConfigure(ctx context.Context, actor audit.ActorRef, id string, input ConfigureInput) (Preview, error) {
	instance, err := s.Get(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	if instance.Enabled || instance.Routed {
		return Preview{}, ErrConflict
	}
	configuration, err := ValidateConfiguration(instance.Metadata, input.Configuration, instance.SecretSlots)
	if err != nil {
		return Preview{}, err
	}
	if err := validateSecrets(input.Secrets, instance.SecretSlots); err != nil {
		return Preview{}, err
	}
	return s.createPreview(ctx, actor, instance, "configure", configuration, input.Secrets, nil, configurationValueDiff(instance.Configuration, input.Configuration), nil)
}

func (s *Service) PreviewUpdate(ctx context.Context, actor audit.ActorRef, id string, input UpdateInput) (Preview, error) {
	instance, err := s.Get(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	if instance.Enabled || instance.Routed || !artifactPattern.MatchString(input.ArtifactPin) || !digestPattern.MatchString(input.ManifestDigest) || !digestPattern.MatchString(input.GrantDigest) || !digestPattern.MatchString(input.SessionDigest) {
		return Preview{}, ErrConflict
	}
	if input.ArtifactPin == instance.ArtifactPin {
		return Preview{}, ErrConflict
	}
	if input.Capabilities, err = canonicalTokens(input.Capabilities); err != nil {
		return Preview{}, err
	}
	if input.Interfaces, err = canonicalTokens(input.Interfaces); err != nil {
		return Preview{}, err
	}
	if input.SecretSlots, err = canonicalTokens(input.SecretSlots); err != nil {
		return Preview{}, err
	}
	if err := ValidateMetadata(input.Metadata); err != nil {
		return Preview{}, err
	}
	if _, err := ValidateConfiguration(input.Metadata, instance.Configuration, input.SecretSlots); err != nil {
		return Preview{}, errors.New("existing configuration is incompatible with extension update")
	}
	payload, _ := json.Marshal(input)
	diff := privilegeDiff(instance.Capabilities, input.Capabilities)
	return s.createPreview(ctx, actor, instance, "update", payload, nil, diff, metadataDiff(instance.Metadata, input.Metadata), tokenDiff(instance.SecretSlots, input.SecretSlots))
}

func (s *Service) PreviewDeleteSecrets(ctx context.Context, actor audit.ActorRef, id string) (Preview, error) {
	instance, err := s.Get(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	if instance.Enabled || instance.Routed {
		return Preview{}, ErrConflict
	}
	return s.createPreview(ctx, actor, instance, "delete_secrets", []byte(`{}`), nil, nil, nil, nil)
}

func (s *Service) PreviewUninstall(ctx context.Context, actor audit.ActorRef, id string) (Preview, error) {
	instance, err := s.Get(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	if instance.Enabled || instance.Routed {
		return Preview{}, ErrConflict
	}
	return s.createPreview(ctx, actor, instance, "uninstall", []byte(`{}`), nil, nil, nil, nil)
}

func (s *Service) createPreview(ctx context.Context, actor audit.ActorRef, instance Instance, operation string, payload []byte, secrets map[string]string, privilege, configuration, secretSlots []string) (Preview, error) {
	if actor.Type == "" || actor.ID == "" {
		return Preview{}, ErrConfirmation
	}
	idBytes := make([]byte, 12)
	confirmationBytes := make([]byte, 16)
	if _, err := io.ReadFull(s.random(), idBytes); err != nil {
		return Preview{}, err
	}
	if _, err := io.ReadFull(s.random(), confirmationBytes); err != nil {
		return Preview{}, err
	}
	now := s.now()
	p := Preview{ID: "extp_" + hex.EncodeToString(idBytes), InstanceID: instance.InstanceID, Operation: operation, BaseRevision: instance.ConfigurationRev, PayloadSHA256: shaHex(payload), Confirmation: "confirm-" + hex.EncodeToString(confirmationBytes), PrivilegeDiff: privilege, ConfigurationDiff: configuration, SecretSlotDiff: secretSlots, ExpiresAt: now.Add(previewTTL)}
	privilegeJSON, _ := json.Marshal(privilege)
	configurationJSON, _ := json.Marshal(configuration)
	secretSlotsJSON, _ := json.Marshal(secretSlots)
	_, err := s.DB.ExecContext(ctx, `INSERT INTO extension_operation_previews(id, instance_id, operation, actor_type, actor_id, base_revision, payload_json, payload_sha256, secret_binding_sha256, confirmation_sha256, privilege_diff_json, configuration_diff_json, secret_slot_diff_json, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, p.ID, p.InstanceID, p.Operation, actor.Type, actor.ID, p.BaseRevision, payload, p.PayloadSHA256, s.secretBinding(secrets), s.confirmationDigest(p.Confirmation), privilegeJSON, configurationJSON, secretSlotsJSON, now, p.ExpiresAt)
	if err != nil {
		return Preview{}, err
	}
	return p, nil
}

type storedPreview struct {
	Preview
	ActorType, ActorID, SecretBinding, ConfirmationDigest string
	Payload                                               []byte
}

func (s *Service) loadPreview(ctx context.Context, tx *sql.Tx, id string) (storedPreview, error) {
	var p storedPreview
	var consumed sql.NullTime
	var privilegeDiffJSON, configurationDiffJSON, secretSlotDiffJSON []byte
	err := tx.QueryRowContext(ctx, `SELECT id, instance_id, operation, actor_type, actor_id, base_revision, payload_json, payload_sha256, secret_binding_sha256, confirmation_sha256, privilege_diff_json, configuration_diff_json, secret_slot_diff_json, expires_at, consumed_at FROM extension_operation_previews WHERE id=$1 FOR UPDATE`, id).Scan(&p.ID, &p.InstanceID, &p.Operation, &p.ActorType, &p.ActorID, &p.BaseRevision, &p.Payload, &p.PayloadSHA256, &p.SecretBinding, &p.ConfirmationDigest, &privilegeDiffJSON, &configurationDiffJSON, &secretSlotDiffJSON, &p.ExpiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return storedPreview{}, ErrConfirmation
	}
	if err != nil {
		return storedPreview{}, err
	}
	if err := json.Unmarshal(privilegeDiffJSON, &p.PrivilegeDiff); err != nil {
		return storedPreview{}, err
	}
	if err := json.Unmarshal(configurationDiffJSON, &p.ConfigurationDiff); err != nil {
		return storedPreview{}, err
	}
	if err := json.Unmarshal(secretSlotDiffJSON, &p.SecretSlotDiff); err != nil {
		return storedPreview{}, err
	}
	if consumed.Valid || !p.ExpiresAt.After(s.now()) {
		return storedPreview{}, ErrConfirmation
	}
	return p, nil
}

func (s *Service) verifyPreview(p storedPreview, actor audit.ActorRef, operation, confirmation string, secrets map[string]string) error {
	if p.Operation != operation || p.ActorType != actor.Type || p.ActorID != actor.ID || subtle.ConstantTimeCompare([]byte(p.ConfirmationDigest), []byte(s.confirmationDigest(confirmation))) != 1 || subtle.ConstantTimeCompare([]byte(p.SecretBinding), []byte(s.secretBinding(secrets))) != 1 {
		return ErrConfirmation
	}
	return nil
}

func (s *Service) ApplyConfigure(ctx context.Context, actor audit.ActorRef, previewID, confirmation string, input ConfigureInput) (Instance, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	defer tx.Rollback()
	p, err := s.loadPreview(ctx, tx, previewID)
	if err != nil || s.verifyPreview(p, actor, "configure", confirmation, input.Secrets) != nil {
		return Instance{}, ErrConfirmation
	}
	instance, err := scanInstance(tx.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM extension_instances WHERE instance_id=$1 AND product=$2 FOR UPDATE`, p.InstanceID, Product))
	if err != nil {
		return Instance{}, err
	}
	if instance.ConfigurationRev != p.BaseRevision || instance.Enabled || instance.Routed {
		return Instance{}, ErrConflict
	}
	configuration, err := ValidateConfiguration(instance.Metadata, input.Configuration, instance.SecretSlots)
	if err != nil || shaHex(configuration) != p.PayloadSHA256 {
		return Instance{}, ErrConfirmation
	}
	if err := validateSecrets(input.Secrets, instance.SecretSlots); err != nil {
		return Instance{}, err
	}
	now := s.now()
	for slot, value := range input.Secrets {
		nonce, ciphertext, err := s.encrypt(instance.InstanceID, slot, []byte(value))
		if err != nil {
			return Instance{}, err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO extension_secrets(instance_id, slot, nonce, ciphertext, key_version, configured_at, rotated_at) VALUES ($1,$2,$3,$4,1,$5,$5) ON CONFLICT(instance_id,slot) DO UPDATE SET nonce=excluded.nonce, ciphertext=excluded.ciphertext, key_version=excluded.key_version, rotated_at=excluded.rotated_at`, instance.InstanceID, slot, nonce, ciphertext, now)
		if err != nil {
			return Instance{}, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE extension_instances SET configuration_json=$1, configuration_revision=configuration_revision+1, tested_revision=NULL, health_code='extension.unknown', lifecycle='stopped', updated_at=$2 WHERE instance_id=$3`, configuration, now, instance.InstanceID); err != nil {
		return Instance{}, err
	}
	if err := s.consumeAndAudit(ctx, tx, p, actor, "extension.configure", map[string]any{"configuration_revision": instance.ConfigurationRev + 1, "configured_secret_slots": sortedKeys(input.Secrets)}); err != nil {
		return Instance{}, err
	}
	if err := tx.Commit(); err != nil {
		return Instance{}, err
	}
	return s.Get(ctx, instance.InstanceID)
}

func (s *Service) ApplyUpdate(ctx context.Context, actor audit.ActorRef, previewID, confirmation string) (Instance, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	defer tx.Rollback()
	p, err := s.loadPreview(ctx, tx, previewID)
	if err != nil || s.verifyPreview(p, actor, "update", confirmation, nil) != nil {
		return Instance{}, ErrConfirmation
	}
	instance, err := scanInstance(tx.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM extension_instances WHERE instance_id=$1 AND product=$2 FOR UPDATE`, p.InstanceID, Product))
	if err != nil {
		return Instance{}, err
	}
	if instance.ConfigurationRev != p.BaseRevision || instance.Enabled || instance.Routed {
		return Instance{}, ErrConflict
	}
	var in UpdateInput
	if err := json.Unmarshal(p.Payload, &in); err != nil {
		return Instance{}, ErrConfirmation
	}
	validated := InstallRequest{InstanceID: instance.InstanceID, ExtensionID: instance.ExtensionID, Repository: instance.Repository, ArtifactPin: in.ArtifactPin, ManifestDigest: in.ManifestDigest, GrantDigest: in.GrantDigest, SessionDigest: in.SessionDigest, Capabilities: in.Capabilities, Interfaces: in.Interfaces, SecretSlots: in.SecretSlots, Metadata: in.Metadata}
	if _, err := validateInstall(validated); err != nil {
		return Instance{}, err
	}
	capabilities, _ := json.Marshal(in.Capabilities)
	interfaces, _ := json.Marshal(in.Interfaces)
	slots, _ := json.Marshal(in.SecretSlots)
	metadata, _ := json.Marshal(in.Metadata)
	now := s.now()
	previousVersion, err := json.Marshal(versionSnapshotFrom(instance))
	if err != nil {
		return Instance{}, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE extension_instances SET previous_artifact_pin=artifact_pin, previous_version_json=$1, artifact_pin=$2, available_update_pin=NULL, manifest_sha256=$3, grant_sha256=$4, session_sha256=$5, capabilities_json=$6, interfaces_json=$7, secret_slots_json=$8, metadata_json=$9, configuration_revision=configuration_revision+1, tested_revision=NULL, health_code='extension.unknown', lifecycle='stopped', updated_at=$10 WHERE instance_id=$11`, previousVersion, in.ArtifactPin, in.ManifestDigest, in.GrantDigest, in.SessionDigest, capabilities, interfaces, slots, metadata, now, instance.InstanceID)
	if err != nil {
		return Instance{}, err
	}
	if err := s.consumeAndAudit(ctx, tx, p, actor, "extension.update", map[string]any{"from": instance.ArtifactPin, "to": in.ArtifactPin, "privilege_diff": p.PrivilegeDiff, "configuration_diff": p.ConfigurationDiff, "secret_slot_diff": p.SecretSlotDiff}); err != nil {
		return Instance{}, err
	}
	if err := tx.Commit(); err != nil {
		return Instance{}, err
	}
	return s.Get(ctx, instance.InstanceID)
}

func (s *Service) ApplyDeleteSecrets(ctx context.Context, actor audit.ActorRef, previewID, confirmation string) (Instance, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	defer tx.Rollback()
	p, err := s.loadPreview(ctx, tx, previewID)
	if err != nil || s.verifyPreview(p, actor, "delete_secrets", confirmation, nil) != nil {
		return Instance{}, ErrConfirmation
	}
	instance, err := scanInstance(tx.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM extension_instances WHERE instance_id=$1 AND product=$2 FOR UPDATE`, p.InstanceID, Product))
	if err != nil {
		return Instance{}, err
	}
	if instance.ConfigurationRev != p.BaseRevision || instance.Enabled || instance.Routed {
		return Instance{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM extension_secrets WHERE instance_id=$1`, instance.InstanceID); err != nil {
		return Instance{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE extension_instances SET configuration_revision=configuration_revision+1, tested_revision=NULL, health_code='extension.unknown', updated_at=$1 WHERE instance_id=$2`, s.now(), instance.InstanceID); err != nil {
		return Instance{}, err
	}
	if err := s.consumeAndAudit(ctx, tx, p, actor, "extension.secrets.delete", map[string]any{"deleted_secret_slots": instance.SecretSlots}); err != nil {
		return Instance{}, err
	}
	if err := tx.Commit(); err != nil {
		return Instance{}, err
	}
	return s.Get(ctx, instance.InstanceID)
}

func (s *Service) ApplyUninstall(ctx context.Context, actor audit.ActorRef, previewID, confirmation string) error {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	p, err := s.loadPreview(ctx, tx, previewID)
	if err != nil || s.verifyPreview(p, actor, "uninstall", confirmation, nil) != nil {
		return ErrConfirmation
	}
	instance, err := scanInstance(tx.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM extension_instances WHERE instance_id=$1 AND product=$2 FOR UPDATE`, p.InstanceID, Product))
	if err != nil {
		return err
	}
	if instance.ConfigurationRev != p.BaseRevision || instance.Enabled || instance.Routed {
		return ErrConflict
	}
	var secretCount int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM extension_secrets WHERE instance_id=$1`, instance.InstanceID).Scan(&secretCount); err != nil {
		return err
	}
	if secretCount != 0 {
		return ErrConflict
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{Actor: actor, Action: "extension.uninstall", Resource: audit.ResourceRef{Type: "extension", ID: instance.InstanceID}, BeforeRedacted: instance, Result: "success"}); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM extension_instances WHERE instance_id=$1 AND product=$2`, instance.InstanceID, Product); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) consumeAndAudit(ctx context.Context, tx *sql.Tx, p storedPreview, actor audit.ActorRef, action string, after any) error {
	if _, err := tx.ExecContext(ctx, `UPDATE extension_operation_previews SET consumed_at=$1 WHERE id=$2 AND consumed_at IS NULL`, s.now(), p.ID); err != nil {
		return err
	}
	return audit.WriteSQL(ctx, tx, audit.Event{Actor: actor, Action: action, Resource: audit.ResourceRef{Type: "extension", ID: p.InstanceID}, AfterRedacted: after, Result: "success"})
}

func (s *Service) Test(ctx context.Context, actor audit.ActorRef, id string) (Instance, error) {
	if err := validateActor(actor); err != nil {
		return Instance{}, err
	}
	if s.Runtime == nil {
		return Instance{}, ErrUnavailable
	}
	instance, err := s.Get(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	if instance.Enabled || instance.Routed || !requiredSecretsConfigured(instance) {
		return Instance{}, ErrConflict
	}
	secrets, err := s.readSecrets(ctx, instance)
	if err != nil {
		return Instance{}, err
	}
	defer clearSecrets(secrets)
	if err := s.Runtime.Start(ctx, instance, secrets); err != nil {
		return Instance{}, err
	}
	health, probeErr := s.Runtime.Probe(ctx, instance)
	stopErr := s.Runtime.Stop(ctx, instance)
	if probeErr != nil {
		return Instance{}, probeErr
	}
	if stopErr != nil {
		return Instance{}, stopErr
	}
	if !health.Healthy || !validDottedToken(health.Code) {
		return Instance{}, ErrUnhealthy
	}
	now := s.now()
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE extension_instances SET tested_revision=configuration_revision, health_code=$1, lifecycle='stopped', updated_at=$2 WHERE instance_id=$3 AND product=$4 AND configuration_revision=$5 AND enabled=false AND routed=false`, health.Code, now, id, Product, instance.ConfigurationRev)
	if err != nil {
		return Instance{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return Instance{}, ErrConflict
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{Actor: actor, Action: "extension.test", Resource: audit.ResourceRef{Type: "extension", ID: id}, AfterRedacted: map[string]any{"health_code": health.Code, "configuration_revision": instance.ConfigurationRev}, Result: "success"}); err != nil {
		return Instance{}, err
	}
	if err := tx.Commit(); err != nil {
		return Instance{}, err
	}
	return s.Get(ctx, id)
}

func (s *Service) Enable(ctx context.Context, actor audit.ActorRef, id string) (Instance, error) {
	if err := validateActor(actor); err != nil {
		return Instance{}, err
	}
	if s.Runtime == nil {
		return Instance{}, ErrUnavailable
	}
	instance, err := s.Get(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	if instance.Enabled && instance.Routed {
		return instance, nil
	}
	if instance.Enabled || instance.Routed || instance.TestedRevision != instance.ConfigurationRev || !requiredSecretsConfigured(instance) {
		return Instance{}, ErrConflict
	}
	secrets, err := s.readSecrets(ctx, instance)
	if err != nil {
		return Instance{}, err
	}
	defer clearSecrets(secrets)
	if err := s.Runtime.Start(ctx, instance, secrets); err != nil {
		return Instance{}, err
	}
	health, err := s.Runtime.Probe(ctx, instance)
	if err != nil || !health.Healthy || !validDottedToken(health.Code) {
		_ = s.Runtime.Stop(ctx, instance)
		if err != nil {
			return Instance{}, err
		}
		return Instance{}, ErrUnhealthy
	}
	if err := s.Runtime.AdmitRouting(ctx, instance); err != nil {
		_ = s.Runtime.Stop(ctx, instance)
		return Instance{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err == nil {
		defer tx.Rollback()
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE extension_instances SET enabled=true, routed=true, lifecycle='ready', health_code=$1, updated_at=$2 WHERE instance_id=$3 AND product=$4 AND configuration_revision=$5 AND tested_revision=$5 AND enabled=false AND routed=false`, health.Code, s.now(), id, Product, instance.ConfigurationRev)
		if err == nil {
			if n, _ := result.RowsAffected(); n != 1 {
				err = ErrConflict
			}
		}
		if err == nil {
			err = audit.WriteSQL(ctx, tx, audit.Event{Actor: actor, Action: "extension.enable", Resource: audit.ResourceRef{Type: "extension", ID: id}, AfterRedacted: map[string]any{"routed": true, "health_code": health.Code}, Result: "success"})
		}
		if err == nil {
			err = tx.Commit()
		}
	}
	if err != nil {
		_ = s.Runtime.RevokeRouting(ctx, instance)
		_ = s.Runtime.Stop(ctx, instance)
		return Instance{}, err
	}
	return s.Get(ctx, id)
}

func (s *Service) Disable(ctx context.Context, actor audit.ActorRef, id string) (Instance, error) {
	if err := validateActor(actor); err != nil {
		return Instance{}, err
	}
	if s.Runtime == nil {
		return Instance{}, ErrUnavailable
	}
	instance, err := s.Get(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	if !instance.Enabled && !instance.Routed {
		return instance, nil
	}
	if instance.Routed {
		if err := s.Runtime.RevokeRouting(ctx, instance); err != nil {
			return Instance{}, err
		}
	}
	if err := s.Runtime.Stop(ctx, instance); err != nil {
		if instance.Routed {
			_ = s.Runtime.AdmitRouting(ctx, instance)
		}
		return Instance{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err == nil {
		defer tx.Rollback()
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE extension_instances SET enabled=false, routed=false, lifecycle='stopped', updated_at=$1 WHERE instance_id=$2 AND product=$3 AND configuration_revision=$4`, s.now(), id, Product, instance.ConfigurationRev)
		if err == nil {
			if n, _ := result.RowsAffected(); n != 1 {
				err = ErrConflict
			}
		}
		if err == nil {
			err = audit.WriteSQL(ctx, tx, audit.Event{Actor: actor, Action: "extension.disable", Resource: audit.ResourceRef{Type: "extension", ID: id}, AfterRedacted: map[string]any{"routed": false, "enabled": false}, Result: "success"})
		}
		if err == nil {
			err = tx.Commit()
		}
	}
	if err != nil {
		secrets, readErr := s.readSecrets(ctx, instance)
		if readErr == nil && s.Runtime.Start(ctx, instance, secrets) == nil && instance.Routed {
			_ = s.Runtime.AdmitRouting(ctx, instance)
		}
		clearSecrets(secrets)
		return Instance{}, err
	}
	return s.Get(ctx, id)
}

func (s *Service) Rollback(ctx context.Context, actor audit.ActorRef, id, confirmation string) (Instance, error) {
	if err := validateActor(actor); err != nil {
		return Instance{}, err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Instance{}, err
	}
	defer tx.Rollback()
	instance, err := scanInstance(tx.QueryRowContext(ctx, `SELECT `+instanceColumns+` FROM extension_instances WHERE instance_id=$1 AND product=$2 FOR UPDATE`, id, Product))
	if err != nil {
		return Instance{}, err
	}
	if instance.Enabled || instance.Routed || instance.PreviousArtifact == "" || confirmation != "rollback "+instance.ExtensionID+" to "+instance.PreviousArtifact {
		return Instance{}, ErrConfirmation
	}
	var previousJSON []byte
	if err := tx.QueryRowContext(ctx, `SELECT previous_version_json FROM extension_instances WHERE instance_id=$1`, id).Scan(&previousJSON); err != nil {
		return Instance{}, err
	}
	var previous versionSnapshot
	if err := json.Unmarshal(previousJSON, &previous); err != nil || !artifactPattern.MatchString(previous.ArtifactPin) {
		return Instance{}, ErrConflict
	}
	currentJSON, err := json.Marshal(versionSnapshotFrom(instance))
	if err != nil {
		return Instance{}, err
	}
	capabilities, _ := json.Marshal(previous.Capabilities)
	interfaces, _ := json.Marshal(previous.Interfaces)
	slots, _ := json.Marshal(previous.SecretSlots)
	metadata, _ := json.Marshal(previous.Metadata)
	configuration, err := ValidateConfiguration(previous.Metadata, previous.Configuration, previous.SecretSlots)
	if err != nil {
		return Instance{}, ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE extension_instances SET artifact_pin=$1, previous_artifact_pin=$2, previous_version_json=$3, manifest_sha256=$4, grant_sha256=$5, session_sha256=$6, capabilities_json=$7, interfaces_json=$8, secret_slots_json=$9, metadata_json=$10, configuration_json=$11, configuration_revision=configuration_revision+1, tested_revision=NULL, health_code='extension.unknown', lifecycle='stopped', updated_at=$12 WHERE instance_id=$13 AND product=$14 AND configuration_revision=$15 AND enabled=false AND routed=false`, previous.ArtifactPin, instance.ArtifactPin, currentJSON, previous.ManifestDigest, previous.GrantDigest, previous.SessionDigest, capabilities, interfaces, slots, metadata, configuration, s.now(), id, Product, instance.ConfigurationRev)
	if err != nil {
		return Instance{}, err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return Instance{}, ErrConflict
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{Actor: actor, Action: "extension.rollback", Resource: audit.ResourceRef{Type: "extension", ID: id}, BeforeRedacted: map[string]any{"artifact_pin": instance.ArtifactPin}, AfterRedacted: map[string]any{"artifact_pin": instance.PreviousArtifact}, Result: "success"}); err != nil {
		return Instance{}, err
	}
	if err := tx.Commit(); err != nil {
		return Instance{}, err
	}
	return s.Get(ctx, id)
}

type versionSnapshot struct {
	ArtifactPin    string         `json:"artifact_pin"`
	ManifestDigest string         `json:"manifest_sha256"`
	GrantDigest    string         `json:"grant_sha256"`
	SessionDigest  string         `json:"session_sha256"`
	Capabilities   []string       `json:"capabilities"`
	Interfaces     []string       `json:"interfaces"`
	SecretSlots    []string       `json:"secret_slots"`
	Metadata       Metadata       `json:"metadata"`
	Configuration  map[string]any `json:"configuration"`
}

func versionSnapshotFrom(instance Instance) versionSnapshot {
	return versionSnapshot{ArtifactPin: instance.ArtifactPin, ManifestDigest: instance.ManifestDigest, GrantDigest: instance.GrantDigest, SessionDigest: instance.SessionDigest, Capabilities: instance.Capabilities, Interfaces: instance.Interfaces, SecretSlots: instance.SecretSlots, Metadata: instance.Metadata, Configuration: instance.Configuration}
}

func (s *Service) readSecrets(ctx context.Context, instance Instance) (map[string][]byte, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT slot, nonce, ciphertext FROM extension_secrets WHERE instance_id=$1 AND slot = ANY($2::text[])`, instance.InstanceID, postgresTextArray(instance.SecretSlots))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string][]byte{}
	for rows.Next() {
		var slot string
		var nonce, ciphertext []byte
		if err := rows.Scan(&slot, &nonce, &ciphertext); err != nil {
			clearSecrets(result)
			return nil, err
		}
		plaintext, err := s.decrypt(instance.InstanceID, slot, nonce, ciphertext)
		if err != nil {
			clearSecrets(result)
			return nil, err
		}
		result[slot] = plaintext
	}
	if err := rows.Err(); err != nil {
		clearSecrets(result)
		return nil, err
	}
	return result, nil
}

func (s *Service) encrypt(instanceID, slot string, plaintext []byte) ([]byte, []byte, error) {
	gcm, err := s.gcm()
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(s.random(), nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, []byte(instanceID+"\x00"+slot)), nil
}

func (s *Service) decrypt(instanceID, slot string, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := s.gcm()
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, []byte(instanceID+"\x00"+slot))
}

func (s *Service) gcm() (cipher.AEAD, error) {
	if len(s.key) != 32 {
		return nil, ErrUnavailable
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *Service) secretBinding(secrets map[string]string) string {
	mac := hmac.New(sha256.New, s.key)
	for _, key := range sortedKeys(secrets) {
		mac.Write([]byte(key))
		mac.Write([]byte{0})
		digest := sha256.Sum256([]byte(secrets[key]))
		mac.Write(digest[:])
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Service) confirmationDigest(value string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("extension-preview-confirmation\x00"))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func validateSecrets(secrets map[string]string, slots []string) error {
	allowed := map[string]bool{}
	for _, slot := range slots {
		allowed[slot] = true
	}
	for slot, value := range secrets {
		if !allowed[slot] || value == "" || len(value) > maxSecretBytes || !utf8.ValidString(value) {
			return errors.New("invalid extension secret")
		}
	}
	return nil
}

func requiredSecretsConfigured(instance Instance) bool {
	configured := map[string]bool{}
	for _, status := range instance.Secrets {
		configured[status.Slot] = status.Configured
	}
	for _, field := range instance.Metadata.Fields {
		if field.Kind == FieldSecret && field.Required && !configured[field.Name] {
			return false
		}
	}
	return true
}

func privilegeDiff(before, after []string) []string {
	return tokenDiff(before, after)
}

func tokenDiff(before, after []string) []string {
	b := map[string]bool{}
	a := map[string]bool{}
	for _, value := range before {
		b[value] = true
	}
	for _, value := range after {
		a[value] = true
	}
	var result []string
	for value := range a {
		if !b[value] {
			result = append(result, "+"+value)
		}
	}
	for value := range b {
		if !a[value] {
			result = append(result, "-"+value)
		}
	}
	sort.Strings(result)
	return result
}

func configurationValueDiff(before, after map[string]any) []string {
	keys := map[string]bool{}
	for key := range before {
		keys[key] = true
	}
	for key := range after {
		keys[key] = true
	}
	var result []string
	for key := range keys {
		beforeValue, beforeOK := before[key]
		afterValue, afterOK := after[key]
		switch {
		case !beforeOK:
			result = append(result, "+"+key)
		case !afterOK:
			result = append(result, "-"+key)
		default:
			beforeJSON, _ := json.Marshal(beforeValue)
			afterJSON, _ := json.Marshal(afterValue)
			if shaHex(beforeJSON) != shaHex(afterJSON) {
				result = append(result, "~"+key)
			}
		}
	}
	sort.Strings(result)
	return result
}

func metadataDiff(before, after Metadata) []string {
	beforeFields := map[string]Field{}
	afterFields := map[string]Field{}
	for _, field := range before.Fields {
		beforeFields[field.Name] = field
	}
	for _, field := range after.Fields {
		afterFields[field.Name] = field
	}
	keys := map[string]bool{}
	for key := range beforeFields {
		keys[key] = true
	}
	for key := range afterFields {
		keys[key] = true
	}
	var result []string
	for key := range keys {
		beforeField, beforeOK := beforeFields[key]
		afterField, afterOK := afterFields[key]
		switch {
		case !beforeOK:
			result = append(result, "+"+key)
		case !afterOK:
			result = append(result, "-"+key)
		default:
			beforeJSON, _ := json.Marshal(beforeField)
			afterJSON, _ := json.Marshal(afterField)
			if shaHex(beforeJSON) != shaHex(afterJSON) {
				result = append(result, "~"+key)
			}
		}
	}
	sort.Strings(result)
	return result
}

func clearSecrets(values map[string][]byte) {
	for _, value := range values {
		for i := range value {
			value[i] = 0
		}
	}
}

func sortedKeys[V any](values map[string]V) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func shaHex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func nullText(value string) sql.NullString { return sql.NullString{String: value, Valid: value != ""} }

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func validateActor(actor audit.ActorRef) error {
	if !validScalarText(actor.Type, 64) || !validScalarText(actor.ID, 1024) {
		return ErrConfirmation
	}
	return nil
}

func postgresTextArray(values []string) string {
	escaped := make([]string, len(values))
	for i, value := range values {
		escaped[i] = `"` + strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`) + `"`
	}
	return `{` + strings.Join(escaped, ",") + `}`
}
