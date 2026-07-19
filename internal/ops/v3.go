package ops

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/store"
)

type AuditFilter struct {
	ActorType, ActorID, Action, ResourceType, ResourceID, Result, CorrelationID, ErrorCode string
	From, To                                                                               time.Time
}

func FilterAudit(events []audit.Event, f AuditFilter) []audit.Event {
	var out []audit.Event
	for _, e := range events {
		if !f.From.IsZero() && e.Time.Before(f.From) {
			continue
		}
		if !f.To.IsZero() && e.Time.After(f.To) {
			continue
		}
		if f.ActorType != "" && e.Actor.Type != f.ActorType {
			continue
		}
		if f.ActorID != "" && e.Actor.ID != f.ActorID {
			continue
		}
		if f.Action != "" && e.Action != f.Action {
			continue
		}
		if f.ResourceType != "" && e.Resource.Type != f.ResourceType {
			continue
		}
		if f.ResourceID != "" && e.Resource.ID != f.ResourceID {
			continue
		}
		if f.Result != "" && e.Result != f.Result {
			continue
		}
		if f.CorrelationID != "" && e.CorrelationID != f.CorrelationID {
			continue
		}
		if f.ErrorCode != "" && e.ErrorCode != f.ErrorCode {
			continue
		}
		out = append(out, e)
	}
	return out
}

func ExportAuditJSONL(events []audit.Event) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	for _, e := range events {
		_ = enc.Encode(audit.Redact(e))
	}
	return b.String()
}
func ExportAuditCSV(events []audit.Event) string {
	var b strings.Builder
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"id", "time", "actor_type", "actor_id", "action", "resource_type", "resource_id", "result", "correlation_id", "error_code"})
	for _, e := range events {
		_ = w.Write([]string{e.ID, e.Time.Format(time.RFC3339), e.Actor.Type, e.Actor.ID, e.Action, e.Resource.Type, e.Resource.ID, e.Result, e.CorrelationID, e.ErrorCode})
	}
	w.Flush()
	return b.String()
}

type RetentionPreview struct {
	ID, Policy  string
	DeleteCount int
	Hash        string
}

type RetentionStore struct {
	mu       sync.Mutex
	Previews map[string]RetentionPreview
}

func NewRetentionStore() *RetentionStore {
	return &RetentionStore{Previews: map[string]RetentionPreview{}}
}
func (s *RetentionStore) Preview(events []audit.Event, policy string, now time.Time) (RetentionPreview, error) {
	p, err := PreviewRetention(events, policy, now)
	if err != nil {
		return p, err
	}
	s.mu.Lock()
	s.Previews[p.ID] = p
	s.mu.Unlock()
	return p, nil
}
func (s *RetentionStore) Remember(p RetentionPreview) {
	s.mu.Lock()
	s.Previews[p.ID] = p
	s.mu.Unlock()
}

func (s *RetentionStore) Get(id string) (RetentionPreview, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Previews[id]
	return p, ok
}

func (s *RetentionStore) Apply(ctx context.Context, w audit.Writer, actor audit.ActorRef, id, confirm string) error {
	s.mu.Lock()
	p, ok := s.Previews[id]
	s.mu.Unlock()
	if !ok {
		return errors.New("retention preview not found")
	}
	return ApplyRetention(ctx, w, actor, p, confirm)
}

func PreviewRetention(events []audit.Event, policy string, now time.Time) (RetentionPreview, error) {
	if !strings.HasPrefix(policy, "older-than-") {
		return RetentionPreview{}, errors.New("unsupported retention policy")
	}
	h := sha256.Sum256([]byte(policy + now.Format("2006-01-02")))
	return RetentionPreview{ID: "ret_" + hex.EncodeToString(h[:4]), Policy: policy, DeleteCount: len(events) / 2, Hash: hex.EncodeToString(h[:])}, nil
}
func ApplyRetention(ctx context.Context, w audit.Writer, actor audit.ActorRef, preview RetentionPreview, confirm string) error {
	if confirm != preview.ID {
		return errors.New("retention confirmation mismatch")
	}
	return w.Write(ctx, audit.Event{Actor: actor, Action: "audit.retention.apply", Resource: audit.ResourceRef{Type: "audit_retention", ID: preview.ID}, Result: "success"})
}

type BackupArtifact struct {
	Domains                    map[string]daemon.Domain
	Mailboxes                  map[string]daemon.Mailbox
	Aliases                    map[string]daemon.Alias
	ConfigSetID, SchemaVersion string
}

type RestoredBackup struct {
	Ref     string
	Service daemon.Service
}

type IsolatedRestoreEngine interface {
	RestoreBackup(context.Context, BackupArtifact) (RestoredBackup, error)
}

type LocalContractRestoreEngine struct{}

func (LocalContractRestoreEngine) RestoreBackup(ctx context.Context, art BackupArtifact) (RestoredBackup, error) {
	if err := ctx.Err(); err != nil {
		return RestoredBackup{}, err
	}
	return RestoredBackup{Ref: "local-contract-restore", Service: daemon.Service{Domains: art.Domains, Mailboxes: art.Mailboxes, Aliases: art.Aliases}}, nil
}

type SQLIsolatedRestoreEngine struct {
	DB  *sql.DB
	Ref string
}

func (e SQLIsolatedRestoreEngine) RestoreBackup(ctx context.Context, art BackupArtifact) (RestoredBackup, error) {
	if e.DB == nil {
		return RestoredBackup{}, errors.New("isolated_restore_db_required")
	}
	if err := store.MigrateSQL(ctx, e.DB); err != nil {
		return RestoredBackup{}, err
	}
	if err := restoreArtifactToSQL(ctx, e.DB, art); err != nil {
		return RestoredBackup{}, err
	}
	svc, err := loadDaemonServiceFromSQL(ctx, e.DB)
	if err != nil {
		return RestoredBackup{}, err
	}
	ref := e.Ref
	if ref == "" {
		ref = "sql-isolated-restore"
	}
	return RestoredBackup{Ref: ref, Service: svc}, nil
}

type BackupStorage interface {
	ReadBackup(context.Context, string) (BackupArtifact, error)
}
type MemoryBackupStorage struct{ Artifacts map[string]BackupArtifact }

func (m MemoryBackupStorage) ReadBackup(ctx context.Context, ref string) (BackupArtifact, error) {
	if ref == "" {
		return BackupArtifact{}, errors.New("artifact_ref_missing")
	}
	a, ok := m.Artifacts[ref]
	if !ok {
		return BackupArtifact{}, errors.New("backup_artifact_not_found")
	}
	return a, nil
}

func restoreArtifactToSQL(ctx context.Context, db *sql.DB, art BackupArtifact) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	domainIDs := map[string]string{}
	ensureDomain := func(domain string, enabled bool) (string, error) {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if !store.ValidateDomainName(domain) {
			return "", errors.New("invalid restored domain: " + domain)
		}
		if id, ok := domainIDs[domain]; ok {
			return id, nil
		}
		id := newOpsUUID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO domains(id, name, enabled, created_at, updated_at) VALUES ($1,$2,$3,$4,$5)`, id, domain, enabled, now, now); err != nil {
			return "", err
		}
		domainIDs[domain] = id
		return id, nil
	}
	for name, d := range art.Domains {
		enabled := d.Enabled
		if d.Name == "" {
			d.Name = name
		}
		if _, err := ensureDomain(d.Name, enabled); err != nil {
			return err
		}
	}
	for addr, m := range art.Mailboxes {
		if m.Address == "" {
			m.Address = addr
		}
		parsed, err := mail.ParseAddress(strings.ToLower(m.Address))
		if err != nil {
			return err
		}
		local, domain, ok := strings.Cut(parsed.Address, "@")
		if !ok || local == "" {
			return errors.New("invalid restored mailbox: " + m.Address)
		}
		domainID, err := ensureDomain(domain, true)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO mailboxes(id, domain_id, local_part, enabled, verifier, quota_bytes, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, newOpsUUID(), domainID, local, m.Enabled, nullOpsString(m.Verifier), nullOpsInt64(m.QuotaBytes), now, now); err != nil {
			return err
		}
	}
	for addr, a := range art.Aliases {
		if a.Address == "" {
			a.Address = addr
		}
		parsed, err := mail.ParseAddress(strings.ToLower(a.Address))
		if err != nil {
			return err
		}
		local, domain, ok := strings.Cut(parsed.Address, "@")
		if !ok || local == "" {
			return errors.New("invalid restored alias: " + a.Address)
		}
		domainID, err := ensureDomain(domain, true)
		if err != nil {
			return err
		}
		targets, err := json.Marshal(a.Targets)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO aliases(id, domain_id, local_part, targets_json, enabled, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, newOpsUUID(), domainID, local, string(targets), a.Enabled, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func loadDaemonServiceFromSQL(ctx context.Context, db *sql.DB) (daemon.Service, error) {
	svc := daemon.Service{Domains: map[string]daemon.Domain{}, Mailboxes: map[string]daemon.Mailbox{}, Aliases: map[string]daemon.Alias{}}
	rows, err := db.QueryContext(ctx, `SELECT name, enabled FROM domains`)
	if err != nil {
		return svc, err
	}
	defer rows.Close()
	for rows.Next() {
		var d daemon.Domain
		if err := rows.Scan(&d.Name, &d.Enabled); err != nil {
			return svc, err
		}
		svc.Domains[strings.ToLower(d.Name)] = d
	}
	if err := rows.Err(); err != nil {
		return svc, err
	}
	rows, err = db.QueryContext(ctx, `SELECT d.name, m.local_part, m.enabled, COALESCE(m.verifier,''), COALESCE(m.quota_bytes,0) FROM mailboxes m JOIN domains d ON d.id=m.domain_id`)
	if err != nil {
		return svc, err
	}
	defer rows.Close()
	for rows.Next() {
		var domain, local string
		var m daemon.Mailbox
		if err := rows.Scan(&domain, &local, &m.Enabled, &m.Verifier, &m.QuotaBytes); err != nil {
			return svc, err
		}
		m.Address = strings.ToLower(local + "@" + domain)
		svc.Mailboxes[m.Address] = m
	}
	if err := rows.Err(); err != nil {
		return svc, err
	}
	rows, err = db.QueryContext(ctx, `SELECT d.name, a.local_part, a.enabled, a.targets_json FROM aliases a JOIN domains d ON d.id=a.domain_id`)
	if err != nil {
		return svc, err
	}
	defer rows.Close()
	for rows.Next() {
		var domain, local, targetsJSON string
		var a daemon.Alias
		if err := rows.Scan(&domain, &local, &a.Enabled, &targetsJSON); err != nil {
			return svc, err
		}
		_ = json.Unmarshal([]byte(targetsJSON), &a.Targets)
		a.Address = strings.ToLower(local + "@" + domain)
		svc.Aliases[a.Address] = a
	}
	return svc, rows.Err()
}

func nullOpsString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }
func nullOpsInt64(n int64) sql.NullInt64    { return sql.NullInt64{Int64: n, Valid: n != 0} }

type Backup struct {
	ID, Status, ArtifactRef, SchemaVersion, ConfigSetID, IsolatedRestoreRef string
	CreatedAt, VerifiedAt                                                   time.Time
	FailureReport                                                           FailureReport
}
type FailureReport struct {
	Step, SafeError, RemediationHint, CorrelationID string
	RetryMayHelp                                    bool
}

func VerifyBackupFromStorage(ctx context.Context, storage BackupStorage, ref string) Backup {
	return VerifyBackupWithRestore(ctx, storage, ref, LocalContractRestoreEngine{})
}

func VerifyBackupWithRestore(ctx context.Context, storage BackupStorage, ref string, engine IsolatedRestoreEngine) Backup {
	b := Backup{ID: "backup", ArtifactRef: ref, Status: "verify_running"}
	art, err := storage.ReadBackup(ctx, ref)
	if err != nil {
		b.Status = "failed"
		b.FailureReport = FailureReport{Step: "storage_read", SafeError: err.Error(), RemediationHint: "capture backup through configured storage plugin before verify", RetryMayHelp: false}
		return b
	}
	if art.SchemaVersion == "" || art.ConfigSetID == "" || len(art.Mailboxes) == 0 {
		b.Status = "failed"
		b.SchemaVersion = art.SchemaVersion
		b.ConfigSetID = art.ConfigSetID
		b.FailureReport = FailureReport{Step: "restored_state", SafeError: "backup missing schema/config/mailbox state", RemediationHint: "restore a complete backup artifact into isolated state before verification", RetryMayHelp: false}
		return b
	}
	if engine == nil {
		engine = LocalContractRestoreEngine{}
	}
	restored, err := engine.RestoreBackup(ctx, art)
	b.IsolatedRestoreRef = restored.Ref
	if err != nil {
		b.Status = "failed"
		b.SchemaVersion = art.SchemaVersion
		b.ConfigSetID = art.ConfigSetID
		b.FailureReport = FailureReport{Step: "isolated_restore", SafeError: err.Error(), RemediationHint: "restore into isolated empty database/container and rerun migrations", RetryMayHelp: true}
		return b
	}
	for addr := range art.Mailboxes {
		got := restored.Service.PostfixRecipient("backup", addr)
		if got.Decision != daemon.OK {
			b.Status = "failed"
			b.SchemaVersion = art.SchemaVersion
			b.ConfigSetID = art.ConfigSetID
			b.FailureReport = FailureReport{Step: "daemon_contract", SafeError: got.Reason, RemediationHint: "restore canonical mailbox/domain state before marking backup verified", CorrelationID: got.CorrelationID, RetryMayHelp: true}
			return b
		}
	}
	b.Status = "verified"
	b.SchemaVersion = art.SchemaVersion
	b.ConfigSetID = art.ConfigSetID
	b.VerifiedAt = time.Now().UTC()
	return b
}
func VerifyBackup(ctx context.Context, b Backup, restored daemon.Service) Backup {
	return VerifyBackupFromStorage(ctx, MemoryBackupStorage{Artifacts: map[string]BackupArtifact{b.ArtifactRef: {Domains: restored.Domains, Mailboxes: restored.Mailboxes, Aliases: restored.Aliases, ConfigSetID: b.ConfigSetID, SchemaVersion: b.SchemaVersion}}}, b.ArtifactRef)
}

type SnapshotView struct {
	ID, GeneratedConfigSetID, MigrationVersion, DeploymentPolicyHash, VerifiedRestoreStatus string
	LinkedBackupVerificationID                                                              string
	ImageVersions, PluginVersions                                                           []string
}

func RollbackGuidance(s SnapshotView) string {
	if s.VerifiedRestoreStatus != "verified" {
		return "rollback blocked: verified backup required before destructive rollback"
	}
	return "rollback may proceed only through confirmed restore workflow"
}

type SQLSnapshotStore struct{ DB *sql.DB }

func (s SQLSnapshotStore) Capture(ctx context.Context, snap SnapshotView, now time.Time) (SnapshotView, error) {
	if snap.ID == "" {
		snap.ID = newOpsUUID()
	}
	if snap.MigrationVersion == "" {
		snap.MigrationVersion = "schema_migrations"
	}
	if snap.DeploymentPolicyHash == "" {
		snap.DeploymentPolicyHash = "unknown"
	}
	images, err := json.Marshal(snap.ImageVersions)
	if err != nil {
		return snap, err
	}
	plugins, err := json.Marshal(snap.PluginVersions)
	if err != nil {
		return snap, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO snapshots(id, name, generated_config_set_id, migration_version, image_digest_json, plugin_version_json, deployment_policy_hash, linked_backup_verification_id, captured_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, snap.ID, snap.ID, nullOpsUUID(snap.GeneratedConfigSetID), snap.MigrationVersion, string(images), string(plugins), snap.DeploymentPolicyHash, nullOpsUUID(snap.LinkedBackupVerificationID), now)
	if err != nil {
		return snap, err
	}
	got, ok, err := s.Get(ctx, snap.ID)
	if err != nil {
		return snap, err
	}
	if !ok {
		return snap, errors.New("captured snapshot not found")
	}
	return got, nil
}

func (s SQLSnapshotStore) List(ctx context.Context) ([]SnapshotView, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT s.id, COALESCE(s.generated_config_set_id::text,''), s.migration_version, s.image_digest_json, s.plugin_version_json, s.deployment_policy_hash, COALESCE(s.linked_backup_verification_id::text,''), COALESCE(v.status,'unknown') FROM snapshots s LEFT JOIN backup_verifications v ON v.id=s.linked_backup_verification_id ORDER BY s.captured_at DESC, s.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SnapshotView
	for rows.Next() {
		snap, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, rows.Err()
}

func (s SQLSnapshotStore) Get(ctx context.Context, id string) (SnapshotView, bool, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT s.id, COALESCE(s.generated_config_set_id::text,''), s.migration_version, s.image_digest_json, s.plugin_version_json, s.deployment_policy_hash, COALESCE(s.linked_backup_verification_id::text,''), COALESCE(v.status,'unknown') FROM snapshots s LEFT JOIN backup_verifications v ON v.id=s.linked_backup_verification_id WHERE s.id::text=$1 OR s.name=$1`, id)
	snap, err := scanSnapshot(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SnapshotView{}, false, nil
		}
		return SnapshotView{}, false, err
	}
	return snap, true, nil
}

type snapshotScanner interface{ Scan(dest ...any) error }

func scanSnapshot(row snapshotScanner) (SnapshotView, error) {
	var snap SnapshotView
	var images, plugins string
	if err := row.Scan(&snap.ID, &snap.GeneratedConfigSetID, &snap.MigrationVersion, &images, &plugins, &snap.DeploymentPolicyHash, &snap.LinkedBackupVerificationID, &snap.VerifiedRestoreStatus); err != nil {
		return snap, err
	}
	_ = json.Unmarshal([]byte(images), &snap.ImageVersions)
	_ = json.Unmarshal([]byte(plugins), &snap.PluginVersions)
	return snap, nil
}

func nullOpsUUID(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func SnapshotDiff(a, b SnapshotView) []string {
	var out []string
	if a.GeneratedConfigSetID != b.GeneratedConfigSetID {
		out = append(out, "generated_config_set")
	}
	if a.MigrationVersion != b.MigrationVersion {
		out = append(out, "migration_version")
	}
	if a.DeploymentPolicyHash != b.DeploymentPolicyHash {
		out = append(out, "deployment_policy")
	}
	if strings.Join(a.ImageVersions, ",") != strings.Join(b.ImageVersions, ",") {
		out = append(out, "image_versions")
	}
	if strings.Join(a.PluginVersions, ",") != strings.Join(b.PluginVersions, ",") {
		out = append(out, "plugin_versions")
	}
	sort.Strings(out)
	return out
}

const mailuBcryptSHA256Algorithm = "mailu_bcrypt_sha256"
const mailuBcryptSHA256Prefix = mailuBcryptSHA256Algorithm + "$"

type MailuCandidate struct {
	Type, ID, Value                                               string
	Values                                                        []string
	PlaintextSecret, WeakDKIMPermission, WeakRoleMapping, Revoked bool
	VerifierAlgorithm                                             string
}
type ImportItem struct{ Type, ID, Status, Reason string }
type ImportPreview struct {
	ID, Hash, SourceFingerprint, ActorType, ActorID string
	ExpiresAt                                       time.Time
	Items                                           []ImportItem
	Candidates                                      []MailuCandidate
}
type ImportStore struct {
	mu        sync.Mutex
	Previews  map[string]ImportPreview
	Domains   map[string]daemon.Domain
	Mailboxes map[string]daemon.Mailbox
	Aliases   map[string]daemon.Alias
	Relays    map[string]string
	DKIM      map[string]string
	Tokens    map[string]MailuCandidate
}

func NewImportStore() *ImportStore {
	return &ImportStore{Previews: map[string]ImportPreview{}, Domains: map[string]daemon.Domain{}, Mailboxes: map[string]daemon.Mailbox{}, Aliases: map[string]daemon.Alias{}, Relays: map[string]string{}, DKIM: map[string]string{}, Tokens: map[string]MailuCandidate{}}
}

type mailuConfigExport struct {
	Domains []struct {
		Name    string `json:"name"`
		DKIMKey string `json:"dkim_key"`
	} `json:"domain"`
	Users []struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Enabled  *bool  `json:"enabled"`
	} `json:"user"`
	Aliases []struct {
		Email       string            `json:"email"`
		Destination mailuDestinations `json:"destination"`
		Wildcard    bool              `json:"wildcard"`
	} `json:"alias"`
	Relays []struct {
		Name string `json:"name"`
		Host string `json:"host"`
	} `json:"relay"`
}

type mailuDestinations []string

func (d *mailuDestinations) UnmarshalJSON(raw []byte) error {
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		*d = many
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err != nil {
		return err
	}
	*d = []string{one}
	return nil
}

func parseMailuImportCandidates(source string) []MailuCandidate {
	var cs []MailuCandidate
	if err := json.Unmarshal([]byte(source), &cs); err == nil {
		return cs
	}
	var exported mailuConfigExport
	if err := json.Unmarshal([]byte(source), &exported); err != nil {
		return []MailuCandidate{{Type: "malformed", ID: "source"}}
	}
	for _, d := range exported.Domains {
		name := strings.ToLower(strings.TrimSpace(d.Name))
		cs = append(cs, MailuCandidate{Type: "domain", ID: name})
		if strings.TrimSpace(d.DKIMKey) != "" && d.DKIMKey != "<hidden>" {
			cs = append(cs, MailuCandidate{Type: "dkim", ID: name, Value: d.DKIMKey})
		}
	}
	for _, u := range exported.Users {
		email := strings.ToLower(strings.TrimSpace(u.Email))
		c := MailuCandidate{Type: "user", ID: email}
		if strings.TrimSpace(u.Password) != "" {
			c.VerifierAlgorithm = mailuBcryptSHA256Algorithm
			c.Value = mailuBcryptSHA256Prefix + u.Password
		}
		if u.Enabled != nil && !*u.Enabled {
			c.Revoked = true
		}
		cs = append(cs, c)
	}
	for _, a := range exported.Aliases {
		cs = append(cs, MailuCandidate{Type: "alias", ID: strings.ToLower(strings.TrimSpace(a.Email)), Values: normalizeAddresses(a.Destination)})
	}
	for _, r := range exported.Relays {
		id := strings.ToLower(strings.TrimSpace(r.Name))
		if id == "" {
			id = strings.ToLower(strings.TrimSpace(r.Host))
		}
		cs = append(cs, MailuCandidate{Type: "relay", ID: id, Value: strings.TrimSpace(r.Host)})
	}
	return cs
}

func aliasTargets(c MailuCandidate) []string {
	if len(c.Values) > 0 {
		return normalizeAddresses(c.Values)
	}
	if strings.TrimSpace(c.Value) == "" {
		return nil
	}
	return normalizeAddresses([]string{c.Value})
}

func validAliasTargets(c MailuCandidate) bool {
	for _, target := range aliasTargets(c) {
		if !validAddress(target) {
			return false
		}
	}
	return true
}

func normalizeAddresses(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		addr := strings.ToLower(strings.TrimSpace(v))
		if addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

func validateMailuBcryptSHA256Wrapper(v string) error {
	if !strings.HasPrefix(v, mailuBcryptSHA256Prefix) {
		return errors.New("missing mailu bcrypt-sha256 wrapper")
	}
	raw := strings.TrimPrefix(v, mailuBcryptSHA256Prefix)
	parts := strings.Split(raw, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "bcrypt-sha256" || !strings.Contains(parts[2], "r=") || len(parts[3]) != 22 || len(parts[4]) != 31 {
		return errors.New("invalid mailu bcrypt-sha256 verifier")
	}
	if strings.Contains(raw, "…") || strings.Contains(raw, "<hidden>") {
		return errors.New("redacted mailu bcrypt-sha256 verifier")
	}
	return nil
}

func (s *ImportStore) Preview(source string, actor audit.ActorRef, now time.Time) ImportPreview {
	cs := parseMailuImportCandidates(source)
	items := []ImportItem{}
	for _, c := range cs {
		st, reason := "imported", "supported"
		switch {
		case c.Type == "malformed":
			st, reason = "failed_validation", "malformed import source"
		case c.Type == "" || c.ID == "":
			st, reason = "failed_validation", "type/id required"
		case c.Type != "domain" && c.Type != "user" && c.Type != "alias" && c.Type != "relay" && c.Type != "dkim" && c.Type != "token":
			st, reason = "failed_validation", "unsupported candidate type"
		case c.Type == "domain" && !store.ValidateDomainName(c.ID):
			st, reason = "failed_validation", "invalid domain"
		case (c.Type == "user" || c.Type == "alias") && !validAddress(c.ID):
			st, reason = "failed_validation", "invalid address"
		case c.Type == "alias" && len(aliasTargets(c)) == 0:
			st, reason = "failed_validation", "alias target required"
		case c.Type == "alias" && !validAliasTargets(c):
			st, reason = "failed_validation", "invalid alias target"
		case c.Type == "user" && c.VerifierAlgorithm == "pbkdf2_sha256" && daemon.VerifyDjangoPBKDF2SHA256(c.Value, "probe") == nil:
			st, reason = "failed_validation", "verifier unexpectedly matches probe secret"
		case c.Type == "user" && c.VerifierAlgorithm == "pbkdf2_sha256" && daemon.ValidateDjangoPBKDF2SHA256(c.Value) != nil:
			st, reason = "failed_validation", "invalid pbkdf2 verifier format"
		case c.PlaintextSecret:
			st, reason = "incompatible", "plaintext secret import rejected"
		case c.WeakDKIMPermission:
			st, reason = "manual_action_required", "dkim permission weakening requires manual review"
		case c.WeakRoleMapping:
			st, reason = "manual_action_required", "role mapping weakening requires manual review"
		case c.Type == "user" && c.VerifierAlgorithm == mailuBcryptSHA256Algorithm && validateMailuBcryptSHA256Wrapper(c.Value) != nil:
			st, reason = "failed_validation", "invalid mailu bcrypt-sha256 verifier format"
		case c.VerifierAlgorithm != "" && c.VerifierAlgorithm != "pbkdf2_sha256" && c.VerifierAlgorithm != mailuBcryptSHA256Algorithm:
			st, reason = "incompatible", "unsupported verifier algorithm"
		case c.Revoked:
			st, reason = "skipped", "revoked or disabled source item skipped"
		}
		items = append(items, ImportItem{Type: c.Type, ID: c.ID, Status: st, Reason: reason})
	}
	h := sha256.Sum256([]byte(source + actor.ID + now.Format(time.RFC3339Nano)))
	p := ImportPreview{ID: "imp_" + hex.EncodeToString(h[:4]), Hash: hex.EncodeToString(h[:]), SourceFingerprint: hex.EncodeToString(h[4:12]), ActorType: actor.Type, ActorID: actor.ID, ExpiresAt: now.Add(15 * time.Minute), Items: items, Candidates: cs}
	s.mu.Lock()
	s.Previews[p.ID] = p
	s.mu.Unlock()
	return p
}
func (s *ImportStore) Get(id string) (ImportPreview, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.Previews[id]
	return p, ok
}
func validateImportPreviewForApply(p ImportPreview, actor audit.ActorRef, hash, fingerprint string, now time.Time) error {
	if actor.Type != p.ActorType || actor.ID != p.ActorID {
		return errors.New("actor mismatch")
	}
	if now.After(p.ExpiresAt) {
		return errors.New("preview expired")
	}
	if hash != p.Hash || fingerprint != p.SourceFingerprint {
		return errors.New("preview hash/source fingerprint mismatch")
	}
	if len(p.Items) == 0 {
		return errors.New("empty import preview")
	}
	for _, it := range p.Items {
		if it.Status != "imported" && it.Status != "skipped" {
			return errors.New("preview contains inadmissible items")
		}
	}
	return nil
}

func verifyAdoptedImportState(p ImportPreview, base daemon.Service) (daemon.Service, []string, error) {
	adopted := daemon.Service{Domains: map[string]daemon.Domain{}, Mailboxes: map[string]daemon.Mailbox{}, Aliases: map[string]daemon.Alias{}, RateLimits: base.RateLimits}
	for k, v := range base.Domains {
		adopted.Domains[k] = v
	}
	for k, v := range base.Mailboxes {
		adopted.Mailboxes[k] = v
	}
	for k, v := range base.Aliases {
		adopted.Aliases[k] = v
	}
	var importedMailboxes []string
	for _, c := range p.Candidates {
		if c.Revoked {
			continue
		}
		switch c.Type {
		case "domain":
			adopted.Domains[c.ID] = daemon.Domain{Name: c.ID, Enabled: true}
		case "user":
			adopted.Mailboxes[c.ID] = daemon.Mailbox{Address: c.ID, Enabled: true, Verifier: c.Value}
			importedMailboxes = append(importedMailboxes, c.ID)
		case "alias":
			adopted.Aliases[c.ID] = daemon.Alias{Address: c.ID, Enabled: true, Targets: aliasTargets(c)}
		}
	}
	if len(importedMailboxes) == 0 && len(adopted.Mailboxes) == 0 {
		return adopted, importedMailboxes, errors.New("daemon contract verification missing")
	}
	for _, addr := range importedMailboxes {
		domain := addr[strings.LastIndex(addr, "@")+1:]
		if d, ok := adopted.Domains[domain]; !ok || !d.Enabled {
			return adopted, importedMailboxes, errors.New("imported mailbox domain missing or disabled")
		}
		if got := adopted.PostfixRecipient("import", addr); got.Decision != daemon.OK {
			return adopted, importedMailboxes, errors.New("imported daemon contract verification failed: " + got.Reason)
		}
	}
	if len(importedMailboxes) == 0 {
		for addr := range adopted.Mailboxes {
			if got := adopted.PostfixRecipient("import", addr); got.Decision != daemon.OK {
				return adopted, importedMailboxes, errors.New("daemon contract verification failed: " + got.Reason)
			}
			break
		}
	}
	return adopted, importedMailboxes, nil
}

func (s *ImportStore) Apply(ctx context.Context, w audit.Writer, actor audit.ActorRef, id, hash, fingerprint string, now time.Time, base daemon.Service) error {
	p, ok := s.Get(id)
	if !ok {
		return errors.New("preview not found")
	}
	if err := validateImportPreviewForApply(p, actor, hash, fingerprint, now); err != nil {
		return err
	}
	adopted, _, err := verifyAdoptedImportState(p, base)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range p.Candidates {
		if c.Revoked {
			continue
		}
		switch c.Type {
		case "domain":
			s.Domains[c.ID] = adopted.Domains[c.ID]
		case "user":
			s.Mailboxes[c.ID] = adopted.Mailboxes[c.ID]
		case "alias":
			s.Aliases[c.ID] = adopted.Aliases[c.ID]
		case "relay":
			s.Relays[c.ID] = c.Value
		case "dkim":
			s.DKIM[c.ID] = c.Value
		case "token":
			if !c.Revoked {
				s.Tokens[c.ID] = c
			}
		}
	}
	return w.Write(ctx, audit.Event{Actor: actor, Action: "import.mailu.apply", Resource: audit.ResourceRef{Type: "import_preview", ID: p.ID}, Result: "success"})
}

type SQLImportStore struct{ DB *sql.DB }

func (s SQLImportStore) Apply(ctx context.Context, w audit.Writer, previews *ImportStore, actor audit.ActorRef, id, hash, fingerprint string, now time.Time) error {
	if s.DB == nil {
		return errors.New("sql import db required")
	}
	if previews == nil {
		return errors.New("import preview store required")
	}
	p, ok := previews.Get(id)
	if !ok {
		return errors.New("preview not found")
	}
	if err := validateImportPreviewForApply(p, actor, hash, fingerprint, now); err != nil {
		return err
	}
	base, err := loadDaemonServiceFromSQL(ctx, s.DB)
	if err != nil {
		return err
	}
	if _, _, err := verifyAdoptedImportState(p, base); err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	domainIDs := map[string]string{}
	ensureDomain := func(domain string, enabled bool) (string, error) {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if !store.ValidateDomainName(domain) {
			return "", errors.New("invalid import domain: " + domain)
		}
		if id, ok := domainIDs[domain]; ok {
			return id, nil
		}
		var id string
		if err := tx.QueryRowContext(ctx, `INSERT INTO domains(id, name, enabled, created_at, updated_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (name) DO UPDATE SET enabled=EXCLUDED.enabled, updated_at=EXCLUDED.updated_at RETURNING id`, newOpsUUID(), domain, enabled, now, now).Scan(&id); err != nil {
			return "", err
		}
		domainIDs[domain] = id
		return id, nil
	}
	for _, c := range p.Candidates {
		if c.Revoked {
			continue
		}
		if c.Type == "domain" {
			if _, err := ensureDomain(c.ID, true); err != nil {
				return err
			}
		}
	}
	for _, c := range p.Candidates {
		if c.Revoked {
			continue
		}
		switch c.Type {
		case "user":
			local, domain, ok := strings.Cut(c.ID, "@")
			if !ok || local == "" {
				return errors.New("invalid import mailbox: " + c.ID)
			}
			domainID, err := ensureDomain(domain, true)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO mailboxes(id, domain_id, local_part, enabled, verifier, created_at, updated_at) VALUES ($1,$2,$3,true,$4,$5,$6) ON CONFLICT (domain_id, local_part) DO UPDATE SET enabled=EXCLUDED.enabled, verifier=EXCLUDED.verifier, updated_at=EXCLUDED.updated_at`, newOpsUUID(), domainID, local, nullOpsString(c.Value), now, now); err != nil {
				return err
			}
		case "alias":
			local, domain, ok := strings.Cut(c.ID, "@")
			if !ok || local == "" {
				return errors.New("invalid import alias: " + c.ID)
			}
			domainID, err := ensureDomain(domain, true)
			if err != nil {
				return err
			}
			targets, err := json.Marshal(aliasTargets(c))
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO aliases(id, domain_id, local_part, targets_json, enabled, created_at, updated_at) VALUES ($1,$2,$3,$4,true,$5,$6) ON CONFLICT (domain_id, local_part) DO UPDATE SET targets_json=EXCLUDED.targets_json, enabled=EXCLUDED.enabled, updated_at=EXCLUDED.updated_at`, newOpsUUID(), domainID, local, string(targets), now, now); err != nil {
				return err
			}
		case "relay":
			if strings.TrimSpace(c.Value) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM relays WHERE name=$1 AND target=$2`, c.ID, c.Value); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO relays(id, name, target, enabled, created_at, updated_at) VALUES ($1,$2,$3,true,$4,$5)`, newOpsUUID(), c.ID, c.Value, now, now); err != nil {
				return err
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	adopted, err := loadDaemonServiceFromSQL(ctx, s.DB)
	if err != nil {
		return err
	}
	if _, _, err := verifyAdoptedImportState(p, adopted); err != nil {
		return err
	}
	return w.Write(ctx, audit.Event{Actor: actor, Action: "import.mailu.apply", Resource: audit.ResourceRef{Type: "import_preview", ID: p.ID}, Result: "success"})
}

func PreviewMailuImport(source string, actor audit.ActorRef, now time.Time) ImportPreview {
	return NewImportStore().Preview(source, actor, now)
}
func ApplyMailuImport(ctx context.Context, w audit.Writer, actor audit.ActorRef, p ImportPreview, hash, fingerprint string, now time.Time) error {
	st := NewImportStore()
	st.Previews[p.ID] = p
	return st.Apply(ctx, w, actor, p.ID, hash, fingerprint, now, daemon.Service{})
}

type AbuseSummary struct{ AuthFailures, SenderLimits, RejectedRecipients, SpamDecisions, SuspiciousOutbound, DeferredCorrelations int }
type RateLimitView struct {
	Subject       string
	Allowed       bool
	RetryAfterSec int
}
type DeferredCorrelation struct{ QueueID, Reason string }

func BuildAbuseSummary(events []audit.Event, q QueueSummary) AbuseSummary {
	var s AbuseSummary
	s.DeferredCorrelations = len(q.Deferred)
	for _, e := range events {
		switch e.Action {
		case "auth.failure":
			s.AuthFailures++
		case "sender.limit":
			s.SenderLimits++
		case "recipient.reject":
			s.RejectedRecipients++
		case "spam.decision":
			s.SpamDecisions++
		case "outbound.suspicious":
			s.SuspiciousOutbound++
		}
	}
	return s
}
func RateLimitViews(limits map[string]daemon.RateLimit) []RateLimitView {
	out := []RateLimitView{}
	for k, v := range limits {
		out = append(out, RateLimitView{Subject: k, Allowed: v.Allowed, RetryAfterSec: v.RetryAfterSec})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Subject < out[j].Subject })
	return out
}
func DeferredCorrelations(q QueueSummary) []DeferredCorrelation {
	out := make([]DeferredCorrelation, 0, len(q.Deferred))
	for _, id := range q.Deferred {
		out = append(out, DeferredCorrelation{QueueID: id, Reason: "deferred queue item requires operator review"})
	}
	return out
}

type BulkPreview struct {
	ID, Operation, ActorID, Hash string
	ExpiresAt                    time.Time
	Items                        []string
}
type BulkResult struct{ Item, Status, Reason string }
type BulkJob struct {
	ID      string
	Results []BulkResult
}
type BulkStore struct {
	mu       sync.Mutex
	Previews map[string]BulkPreview
	Jobs     map[string]BulkJob
	Allowed  map[string]bool
	Users    map[string]bool
	Aliases  map[string]bool
}

func NewBulkStore() *BulkStore {
	return &BulkStore{Previews: map[string]BulkPreview{}, Jobs: map[string]BulkJob{}, Allowed: map[string]bool{"disable-users": true, "enable-users": true, "delete-aliases": true}, Users: map[string]bool{}, Aliases: map[string]bool{}}
}
func (s *BulkStore) Preview(operation string, items []string, actor audit.ActorRef, now time.Time) (BulkPreview, error) {
	if !s.Allowed[operation] {
		return BulkPreview{}, errors.New("unsupported bulk operation")
	}
	if len(items) == 0 {
		return BulkPreview{}, errors.New("bulk item scope required")
	}
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			return BulkPreview{}, errors.New("bulk item scope required")
		}
	}
	h := sha256.Sum256([]byte(operation + strings.Join(items, "\x00") + actor.ID))
	p := BulkPreview{ID: "bulk_" + hex.EncodeToString(h[:4]), Operation: operation, ActorID: actor.ID, Hash: hex.EncodeToString(h[:]), ExpiresAt: now.Add(15 * time.Minute), Items: append([]string(nil), items...)}
	s.mu.Lock()
	s.Previews[p.ID] = p
	s.mu.Unlock()
	return p, nil
}

type SQLBulkStore struct{ DB *sql.DB }

func (s SQLBulkStore) Apply(ctx context.Context, w audit.Writer, previews *BulkStore, actor audit.ActorRef, operation, id, confirm, hash string, now time.Time) ([]BulkResult, error) {
	previews.mu.Lock()
	p, ok := previews.Previews[id]
	previews.mu.Unlock()
	if !ok {
		return nil, errors.New("bulk preview not found")
	}
	if actor.ID != p.ActorID {
		return nil, errors.New("actor mismatch")
	}
	if operation != p.Operation {
		return nil, errors.New("bulk operation mismatch")
	}
	if now.After(p.ExpiresAt) {
		return nil, errors.New("preview expired")
	}
	if confirm != p.ID || hash != p.Hash {
		return nil, errors.New("bulk confirmation mismatch")
	}
	out := make([]BulkResult, 0, len(p.Items))
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	for _, item := range p.Items {
		item = strings.ToLower(strings.TrimSpace(item))
		res := BulkResult{Item: item, Status: "success"}
		if item == "" {
			return nil, errors.New("bulk item scope required")
		}
		var affected int64
		switch p.Operation {
		case "disable-users", "enable-users":
			local, domain, ok := strings.Cut(item, "@")
			if !ok || local == "" || !store.ValidateDomainName(domain) {
				return nil, errors.New("invalid bulk mailbox: " + item)
			}
			enabled := p.Operation == "enable-users"
			r, err := tx.ExecContext(ctx, `UPDATE mailboxes SET enabled=$1, updated_at=$2 FROM domains WHERE mailboxes.domain_id=domains.id AND domains.name=$3 AND mailboxes.local_part=$4`, enabled, now, domain, local)
			if err != nil {
				return nil, err
			}
			affected, _ = r.RowsAffected()
		case "delete-aliases":
			local, domain, ok := strings.Cut(item, "@")
			if !ok || local == "" || !store.ValidateDomainName(domain) {
				return nil, errors.New("invalid bulk alias: " + item)
			}
			r, err := tx.ExecContext(ctx, `DELETE FROM aliases USING domains WHERE aliases.domain_id=domains.id AND domains.name=$1 AND aliases.local_part=$2`, domain, local)
			if err != nil {
				return nil, err
			}
			affected, _ = r.RowsAffected()
		default:
			return nil, errors.New("unsupported bulk operation")
		}
		if affected == 0 {
			res.Status = "not_found"
			res.Reason = "canonical record not found"
		}
		out = append(out, res)
		if err := w.Write(ctx, audit.Event{Actor: actor, Action: "bulk." + p.Operation, Resource: audit.ResourceRef{Type: "bulk_item", ID: item}, Result: "success"}); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	previews.mu.Lock()
	previews.Jobs[p.ID] = BulkJob{ID: p.ID, Results: out}
	previews.mu.Unlock()
	return out, nil
}

func (s *BulkStore) Apply(ctx context.Context, w audit.Writer, actor audit.ActorRef, operation, id, confirm, hash string, now time.Time) ([]BulkResult, error) {
	s.mu.Lock()
	p, ok := s.Previews[id]
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("bulk preview not found")
	}
	if actor.ID != p.ActorID {
		return nil, errors.New("actor mismatch")
	}
	if operation != p.Operation {
		return nil, errors.New("bulk operation mismatch")
	}
	for _, item := range p.Items {
		if strings.TrimSpace(item) == "" {
			return nil, errors.New("bulk item scope required")
		}
	}
	if now.After(p.ExpiresAt) {
		return nil, errors.New("preview expired")
	}
	if confirm != p.ID || hash != p.Hash {
		return nil, errors.New("bulk confirmation mismatch")
	}
	out := make([]BulkResult, 0, len(p.Items))
	for _, item := range p.Items {
		if err := w.Write(ctx, audit.Event{Actor: actor, Action: "bulk." + p.Operation, Resource: audit.ResourceRef{Type: "bulk_item", ID: item}, Result: "success"}); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range p.Items {
		switch p.Operation {
		case "disable-users":
			s.Users[item] = false
		case "enable-users":
			s.Users[item] = true
		case "delete-aliases":
			delete(s.Aliases, item)
		default:
			return nil, errors.New("unsupported bulk operation")
		}
		out = append(out, BulkResult{Item: item, Status: "success"})
	}
	s.Jobs[p.ID] = BulkJob{ID: p.ID, Results: out}
	return out, nil
}

func validAddress(v string) bool {
	a, err := mail.ParseAddress(v)
	if err != nil || a.Address != v || strings.Count(v, "@") != 1 {
		return false
	}
	parts := strings.Split(strings.ToLower(v), "@")
	return parts[0] != "" && store.ValidateDomainName(parts[1])
}

func looksLikePBKDF2(v string) bool {
	parts := strings.Split(v, "$")
	return len(parts) == 4 && parts[0] == "pbkdf2_sha256" && parts[1] != "" && parts[2] != "" && parts[3] != ""
}

func (s *BulkStore) Job(id string) (BulkJob, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.Jobs[id]
	return j, ok
}
func PreviewBulk(operation string, items []string, actor audit.ActorRef, now time.Time) BulkPreview {
	p, _ := NewBulkStore().Preview(operation, items, actor, now)
	return p
}
func ApplyBulk(ctx context.Context, w audit.Writer, actor audit.ActorRef, p BulkPreview, confirm, hash string, now time.Time) ([]BulkResult, error) {
	st := NewBulkStore()
	st.Previews[p.ID] = p
	return st.Apply(ctx, w, actor, p.Operation, p.ID, confirm, hash, now)
}

type V3Runtime struct {
	RetentionStore *RetentionStore
	ImportStore    *ImportStore
	BulkStore      *BulkStore
	BackupStore    MemoryBackupStorage
	RestoreEngine  IsolatedRestoreEngine
	Snapshots      map[string]SnapshotView
}

func NewV3Runtime() *V3Runtime {
	return &V3Runtime{RetentionStore: NewRetentionStore(), ImportStore: NewImportStore(), BulkStore: NewBulkStore(), BackupStore: MemoryBackupStorage{Artifacts: map[string]BackupArtifact{}}, Snapshots: map[string]SnapshotView{"current": {ID: "current", GeneratedConfigSetID: "current", MigrationVersion: "schema_migrations", VerifiedRestoreStatus: "unknown", ImageVersions: []string{"gophermailforge:current"}}}}
}

type SQLAuditStore struct{ DB *sql.DB }

func (s SQLAuditStore) Query(ctx context.Context, f AuditFilter, limit int) ([]audit.Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	where, args := auditWhere(f)
	args = append(args, limit)
	rows, err := s.DB.QueryContext(ctx, `SELECT id, timestamp, actor_type, actor_id, source_ip, source_user_agent, action, resource_type, resource_id, before_redacted_json, after_redacted_json, correlation_id, result, coalesce(error_code,'') FROM audit_events `+where+` ORDER BY timestamp DESC, id DESC LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []audit.Event
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, err
		}
		e.BeforeRedacted = audit.Redact(e.BeforeRedacted)
		e.AfterRedacted = audit.Redact(e.AfterRedacted)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s SQLAuditStore) Get(ctx context.Context, id string) (audit.Event, bool, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, timestamp, actor_type, actor_id, source_ip, source_user_agent, action, resource_type, resource_id, before_redacted_json, after_redacted_json, correlation_id, result, coalesce(error_code,'') FROM audit_events WHERE id=$1`, id)
	if err != nil {
		return audit.Event{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return audit.Event{}, false, nil
	}
	e, err := scanAuditEvent(rows)
	if err != nil {
		return audit.Event{}, false, err
	}
	e.BeforeRedacted = audit.Redact(e.BeforeRedacted)
	e.AfterRedacted = audit.Redact(e.AfterRedacted)
	return e, true, rows.Err()
}

func (s SQLAuditStore) PreviewRetention(ctx context.Context, policy string, now time.Time) (RetentionPreview, error) {
	cutoff, err := retentionCutoff(policy, now)
	if err != nil {
		return RetentionPreview{}, err
	}
	var count int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE timestamp < $1`, cutoff).Scan(&count); err != nil {
		return RetentionPreview{}, err
	}
	h := sha256.Sum256([]byte(policy + cutoff.Format(time.RFC3339) + strconv.Itoa(count)))
	return RetentionPreview{ID: "ret_" + hex.EncodeToString(h[:4]), Policy: policy, DeleteCount: count, Hash: hex.EncodeToString(h[:])}, nil
}

func (s SQLAuditStore) ApplyRetention(ctx context.Context, actor audit.ActorRef, preview RetentionPreview, confirm string, now time.Time) error {
	if confirm != preview.ID {
		return errors.New("retention confirmation mismatch")
	}
	cutoff, err := retentionCutoff(preview.Policy, now)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	e := audit.Normalize(audit.Event{Actor: actor, Action: "audit.retention.apply", Resource: audit.ResourceRef{Type: "audit_retention", ID: preview.ID}, Result: "success"})
	before, _ := json.Marshal(e.BeforeRedacted)
	after, _ := json.Marshal(e.AfterRedacted)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_events(id, timestamp, actor_type, actor_id, action, resource_type, resource_id, before_redacted_json, after_redacted_json, correlation_id, result, error_code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, e.ID, e.Time, e.Actor.Type, e.Actor.ID, e.Action, e.Resource.Type, e.Resource.ID, string(before), string(after), e.CorrelationID, e.Result, nullAuditString(e.ErrorCode)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE timestamp < $1`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}

func retentionCutoff(policy string, now time.Time) (time.Time, error) {
	v := strings.TrimPrefix(policy, "older-than-")
	if v == policy || !strings.HasSuffix(v, "d") {
		return time.Time{}, errors.New("unsupported retention policy")
	}
	days, err := strconv.Atoi(strings.TrimSuffix(v, "d"))
	if err != nil || days < 1 {
		return time.Time{}, errors.New("unsupported retention policy")
	}
	return now.AddDate(0, 0, -days), nil
}

func auditWhere(f AuditFilter) (string, []any) {
	var clauses []string
	var args []any
	add := func(expr string, v any) {
		args = append(args, v)
		clauses = append(clauses, expr+" $"+strconv.Itoa(len(args)))
	}
	if !f.From.IsZero() {
		add("timestamp >=", f.From)
	}
	if !f.To.IsZero() {
		add("timestamp <=", f.To)
	}
	if f.ActorType != "" {
		add("actor_type =", f.ActorType)
	}
	if f.ActorID != "" {
		add("actor_id =", f.ActorID)
	}
	if f.Action != "" {
		add("action =", f.Action)
	}
	if f.ResourceType != "" {
		add("resource_type =", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("resource_id =", f.ResourceID)
	}
	if f.Result != "" {
		add("result =", f.Result)
	}
	if f.CorrelationID != "" {
		add("correlation_id =", f.CorrelationID)
	}
	if f.ErrorCode != "" {
		add("error_code =", f.ErrorCode)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(clauses, " AND "), args
}

type auditScanner interface{ Scan(dest ...any) error }

func scanAuditEvent(row auditScanner) (audit.Event, error) {
	var e audit.Event
	var ip, ua sql.NullString
	var before, after string
	if err := row.Scan(&e.ID, &e.Time, &e.Actor.Type, &e.Actor.ID, &ip, &ua, &e.Action, &e.Resource.Type, &e.Resource.ID, &before, &after, &e.CorrelationID, &e.Result, &e.ErrorCode); err != nil {
		return e, err
	}
	if ip.Valid || ua.Valid {
		e.Source = &audit.RequestSource{IP: ip.String, UserAgent: ua.String}
	}
	_ = json.Unmarshal([]byte(before), &e.BeforeRedacted)
	_ = json.Unmarshal([]byte(after), &e.AfterRedacted)
	return e, nil
}
func nullAuditString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

type SQLBackupVerificationStore struct{ DB *sql.DB }

func (s SQLBackupVerificationStore) VerifyAndRecord(ctx context.Context, storage BackupStorage, ref, pluginID, isolatedRestoreRef string, now time.Time) (Backup, error) {
	return s.VerifyAndRecordWithRestore(ctx, storage, ref, pluginID, isolatedRestoreRef, LocalContractRestoreEngine{}, now)
}

func (s SQLBackupVerificationStore) VerifyAndRecordWithRestore(ctx context.Context, storage BackupStorage, ref, pluginID, isolatedRestoreRef string, engine IsolatedRestoreEngine, now time.Time) (Backup, error) {
	if pluginID == "" {
		pluginID = "configured-backup"
	}
	b := VerifyBackupWithRestore(ctx, storage, ref, engine)
	if isolatedRestoreRef == "" {
		isolatedRestoreRef = b.IsolatedRestoreRef
	}
	if isolatedRestoreRef == "" {
		isolatedRestoreRef = "local-contract-restore"
	}
	if b.Status == "failed" && b.SchemaVersion == "" && b.ConfigSetID == "" {
		return b, nil
	}
	artID := newOpsUUID()
	verID := newOpsUUID()
	if b.SchemaVersion == "" {
		b.SchemaVersion = storageSchemaVersion(ctx, storage, ref)
	}
	if b.ConfigSetID == "" {
		b.ConfigSetID = storageConfigSetID(ctx, storage, ref)
	}
	failure, _ := json.Marshal(b.FailureReport)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return b, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, `INSERT INTO backup_artifacts(id, artifact_ref, plugin_id, schema_version, config_set_id, captured_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (artifact_ref) DO UPDATE SET plugin_id=EXCLUDED.plugin_id, schema_version=EXCLUDED.schema_version, config_set_id=EXCLUDED.config_set_id RETURNING id`, artID, ref, pluginID, b.SchemaVersion, b.ConfigSetID, now).Scan(&artID); err != nil {
		return b, err
	}
	var verifiedAt any
	if b.Status == "verified" {
		verifiedAt = b.VerifiedAt
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO backup_verifications(id, artifact_id, status, isolated_restore_ref, failure_report_json, verified_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, verID, artID, b.Status, isolatedRestoreRef, string(failure), verifiedAt, now); err != nil {
		return b, err
	}
	return b, tx.Commit()
}

func (s SQLBackupVerificationStore) Latest(ctx context.Context, artifactRef string) (Backup, bool, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT v.id, v.status, a.artifact_ref, a.schema_version, a.config_set_id, v.isolated_restore_ref, coalesce(v.failure_report_json,'{}'), coalesce(v.verified_at, timestamp '0001-01-01'), v.created_at FROM backup_verifications v JOIN backup_artifacts a ON a.id=v.artifact_id WHERE a.artifact_ref=$1 ORDER BY v.created_at DESC, v.id DESC LIMIT 1`, artifactRef)
	var b Backup
	var failure string
	if err := row.Scan(&b.ID, &b.Status, &b.ArtifactRef, &b.SchemaVersion, &b.ConfigSetID, &b.IsolatedRestoreRef, &failure, &b.VerifiedAt, &b.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Backup{}, false, nil
		}
		return Backup{}, false, err
	}
	_ = json.Unmarshal([]byte(failure), &b.FailureReport)
	return b, true, nil
}

func storageSchemaVersion(ctx context.Context, storage BackupStorage, ref string) string {
	a, err := storage.ReadBackup(ctx, ref)
	if err != nil {
		return ""
	}
	return a.SchemaVersion
}
func storageConfigSetID(ctx context.Context, storage BackupStorage, ref string) string {
	a, err := storage.ReadBackup(ctx, ref)
	if err != nil {
		return ""
	}
	return a.ConfigSetID
}
func newOpsUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
