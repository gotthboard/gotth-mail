package outboundpolicy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

const maxOutboundBackupObjects = 100_000

type BackupDomain struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	Scope    Scope  `json:"outbound_scope"`
	Revision uint64 `json:"outbound_policy_revision"`
}

type BackupMailbox struct {
	ID         string `json:"id"`
	DomainID   string `json:"domain_id"`
	LocalPart  string `json:"local_part"`
	Enabled    bool   `json:"enabled"`
	Verifier   string `json:"verifier,omitempty"`
	QuotaBytes int64  `json:"quota_bytes,omitempty"`
}

type BackupAlias struct {
	ID        string   `json:"id"`
	DomainID  string   `json:"domain_id"`
	LocalPart string   `json:"local_part"`
	Enabled   bool     `json:"enabled"`
	Targets   []string `json:"targets"`
}

type BackupState struct {
	Domains       []BackupDomain        `json:"domains"`
	Mailboxes     []BackupMailbox       `json:"mailboxes"`
	Aliases       []BackupAlias         `json:"aliases"`
	SystemSenders []SystemSenderBinding `json:"system_senders"`
	Queues        []QueueRecord         `json:"queues"`
}

// CaptureBackupState reads the complete policy authority and durable queue
// provenance in deterministic order without message bodies or credentials.
// Complexity: time O(d+m+a+y+q*(r+s+b)), Omega(d+m+a+y+q); auxiliary space
// O(d+m+a+y+q*(r+s+b)), bounded by maxOutboundBackupObjects and QueueStore
// limits; database streaming and queue reloads are additive.
func CaptureBackupState(ctx context.Context, db *sql.DB) (BackupState, error) {
	if db == nil {
		return BackupState{}, errors.New("outbound backup database is unavailable")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return BackupState{}, err
	}
	defer tx.Rollback()
	var state BackupState
	domainRows, err := tx.QueryContext(ctx, `SELECT id::text,name,enabled,outbound_scope,outbound_policy_revision FROM domains ORDER BY name,id`)
	if err != nil {
		return state, err
	}
	for domainRows.Next() {
		if len(state.Domains) >= maxOutboundBackupObjects {
			domainRows.Close()
			return BackupState{}, errors.New("outbound backup domain limit exceeded")
		}
		var row BackupDomain
		var revision int64
		if err := domainRows.Scan(&row.ID, &row.Name, &row.Enabled, &row.Scope, &revision); err != nil {
			domainRows.Close()
			return BackupState{}, err
		}
		if revision <= 0 {
			domainRows.Close()
			return BackupState{}, errors.New("invalid outbound backup domain revision")
		}
		row.Revision = uint64(revision)
		state.Domains = append(state.Domains, row)
	}
	if err := closeBackupRows(domainRows); err != nil {
		return BackupState{}, err
	}
	mailboxRows, err := tx.QueryContext(ctx, `SELECT id::text,domain_id::text,local_part,enabled,COALESCE(verifier,''),COALESCE(quota_bytes,0) FROM mailboxes ORDER BY domain_id,local_part,id`)
	if err != nil {
		return BackupState{}, err
	}
	for mailboxRows.Next() {
		if len(state.Mailboxes) >= maxOutboundBackupObjects {
			mailboxRows.Close()
			return BackupState{}, errors.New("outbound backup mailbox limit exceeded")
		}
		var row BackupMailbox
		if err := mailboxRows.Scan(&row.ID, &row.DomainID, &row.LocalPart, &row.Enabled, &row.Verifier, &row.QuotaBytes); err != nil {
			mailboxRows.Close()
			return BackupState{}, err
		}
		state.Mailboxes = append(state.Mailboxes, row)
	}
	if err := closeBackupRows(mailboxRows); err != nil {
		return BackupState{}, err
	}
	aliasRows, err := tx.QueryContext(ctx, `SELECT id::text,domain_id::text,local_part,enabled,targets_json FROM aliases ORDER BY domain_id,local_part,id`)
	if err != nil {
		return BackupState{}, err
	}
	for aliasRows.Next() {
		if len(state.Aliases) >= maxOutboundBackupObjects {
			aliasRows.Close()
			return BackupState{}, errors.New("outbound backup alias limit exceeded")
		}
		var row BackupAlias
		var targets string
		if err := aliasRows.Scan(&row.ID, &row.DomainID, &row.LocalPart, &row.Enabled, &targets); err != nil {
			aliasRows.Close()
			return BackupState{}, err
		}
		if err := json.Unmarshal([]byte(targets), &row.Targets); err != nil {
			aliasRows.Close()
			return BackupState{}, errors.New("invalid outbound backup alias targets")
		}
		state.Aliases = append(state.Aliases, row)
	}
	if err := closeBackupRows(aliasRows); err != nil {
		return BackupState{}, err
	}
	senderRows, err := tx.QueryContext(ctx, `SELECT id,domain_id::text,address,enabled,revision FROM outbound_system_senders ORDER BY id`)
	if err != nil {
		return BackupState{}, err
	}
	for senderRows.Next() {
		if len(state.SystemSenders) >= maxOutboundBackupObjects {
			senderRows.Close()
			return BackupState{}, errors.New("outbound backup system-sender limit exceeded")
		}
		var row SystemSenderBinding
		var revision int64
		if err := senderRows.Scan(&row.ID, &row.DomainID, &row.Address, &row.Enabled, &revision); err != nil {
			senderRows.Close()
			return BackupState{}, err
		}
		if revision <= 0 {
			senderRows.Close()
			return BackupState{}, errors.New("invalid outbound backup system-sender revision")
		}
		row.Revision = uint64(revision)
		state.SystemSenders = append(state.SystemSenders, row)
	}
	if err := closeBackupRows(senderRows); err != nil {
		return BackupState{}, err
	}
	queueRows, err := tx.QueryContext(ctx, `SELECT queue_id FROM outbound_queue_messages ORDER BY queue_id`)
	if err != nil {
		return BackupState{}, err
	}
	var queueIDs []string
	for queueRows.Next() {
		if len(queueIDs) >= maxOutboundBackupObjects {
			queueRows.Close()
			return BackupState{}, errors.New("outbound backup queue limit exceeded")
		}
		var queueID string
		if err := queueRows.Scan(&queueID); err != nil {
			queueRows.Close()
			return BackupState{}, err
		}
		queueIDs = append(queueIDs, queueID)
	}
	if err := closeBackupRows(queueRows); err != nil {
		return BackupState{}, err
	}
	for _, queueID := range queueIDs {
		record, err := loadQueueRecord(ctx, tx, queueID)
		if err != nil {
			return BackupState{}, err
		}
		state.Queues = append(state.Queues, record)
	}
	if err := tx.Commit(); err != nil {
		return BackupState{}, err
	}
	return state, nil
}

// RestoreBackupState writes one validated policy/queue snapshot into an empty
// migrated transaction while preserving immutable object IDs and queue state.
// Complexity: time O(d+m+a*t+y+q*(r+s+b)), Omega(d+m+a+y+q); auxiliary space
// O(d+m+a+y+q*(r+s+b)), under the capture bounds.
func RestoreBackupState(ctx context.Context, tx *sql.Tx, state BackupState, now time.Time) error {
	if tx == nil || len(state.Domains) == 0 || len(state.Domains) > maxOutboundBackupObjects || len(state.Mailboxes) > maxOutboundBackupObjects || len(state.Aliases) > maxOutboundBackupObjects || len(state.SystemSenders) > maxOutboundBackupObjects || len(state.Queues) > maxOutboundBackupObjects {
		return errors.New("invalid outbound backup state")
	}
	now = now.UTC()
	domains := make(map[string]BackupDomain, len(state.Domains))
	for _, row := range state.Domains {
		canonical, err := NormalizeDomain(row.Name)
		if err != nil || canonical != row.Name || !validScope(row.Scope) || row.Revision == 0 || !validQueueObjectID(row.ID) {
			return errors.New("invalid outbound backup domain")
		}
		if _, duplicate := domains[row.ID]; duplicate {
			return errors.New("duplicate outbound backup domain")
		}
		domains[row.ID] = row
		if _, err := tx.ExecContext(ctx, `INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6)`, row.ID, row.Name, row.Enabled, string(row.Scope), row.Revision, now); err != nil {
			return err
		}
	}
	objects := make(map[string]bool, 2*len(state.Mailboxes)+4*len(state.Aliases)+len(state.SystemSenders))
	for _, row := range state.Mailboxes {
		domain, ok := domains[row.DomainID]
		address, _, addressErr := normalizeQueueRecipient(row.LocalPart + "@" + domain.Name)
		if !ok || addressErr != nil || address != row.LocalPart+"@"+domain.Name || !validQueueObjectID(row.ID) || !validBackupLocalPart(row.LocalPart) || row.QuotaBytes < 0 {
			return errors.New("invalid outbound backup mailbox")
		}
		objects[string(SourceAuthenticatedMailbox)+"\x00"+row.ID] = true
		objects[string(SourceEnvelopeSender)+"\x00"+row.ID] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO mailboxes(id,domain_id,local_part,enabled,verifier,quota_bytes,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`, row.ID, row.DomainID, row.LocalPart, row.Enabled, nullBackupString(row.Verifier), nullBackupInt64(row.QuotaBytes), now); err != nil {
			return err
		}
	}
	for _, row := range state.Aliases {
		domain, ok := domains[row.DomainID]
		address, _, addressErr := normalizeQueueRecipient(row.LocalPart + "@" + domain.Name)
		if !ok || addressErr != nil || address != row.LocalPart+"@"+domain.Name || !validQueueObjectID(row.ID) || !validBackupLocalPart(row.LocalPart) || len(row.Targets) == 0 || len(row.Targets) > maxQueueRecipients {
			return errors.New("invalid outbound backup alias")
		}
		for _, target := range row.Targets {
			if _, _, err := normalizeQueueRecipient(target); err != nil {
				return errors.New("invalid outbound backup alias target")
			}
		}
		for _, kind := range []SourceKind{SourceAlias, SourceForward, SourceList, SourceCatchAll} {
			objects[string(kind)+"\x00"+row.ID] = true
		}
		targets, _ := json.Marshal(row.Targets)
		if _, err := tx.ExecContext(ctx, `INSERT INTO aliases(id,domain_id,local_part,targets_json,enabled,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6)`, row.ID, row.DomainID, row.LocalPart, string(targets), row.Enabled, now); err != nil {
			return err
		}
	}
	for _, row := range state.SystemSenders {
		canonical, _, err := normalizeQueueRecipient(row.Address)
		if _, ok := domains[row.DomainID]; !ok || err != nil || canonical != row.Address || !validQueueObjectID(row.ID) || row.Revision == 0 {
			return errors.New("invalid outbound backup system sender")
		}
		objects[string(SourceSystemSender)+"\x00"+row.ID] = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbound_system_senders(id,domain_id,address,enabled,revision,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$6)`, row.ID, row.DomainID, row.Address, row.Enabled, row.Revision, now); err != nil {
			return err
		}
	}
	for _, record := range state.Queues {
		if err := restoreBackupQueue(ctx, tx, record, objects); err != nil {
			return err
		}
	}
	return nil
}

// VerifyBackupState reloads policy rows, immutable object IDs, queue records,
// and current policy sources so missing state or digest drift fails verification.
// Complexity: time O(d+m+a+y+q*(r+s+b+s log N)), Omega(d+m+a+y+q);
// auxiliary space O(r+s+b) per queue, under capture and QueueStore bounds.
func VerifyBackupState(ctx context.Context, db *sql.DB, state BackupState) error {
	if db == nil {
		return errors.New("outbound restore verification database is unavailable")
	}
	for _, expected := range state.Domains {
		var enabled bool
		var scope Scope
		var revision uint64
		if err := db.QueryRowContext(ctx, `SELECT enabled,outbound_scope,outbound_policy_revision FROM domains WHERE id=$1 AND name=$2`, expected.ID, expected.Name).Scan(&enabled, &scope, &revision); err != nil || enabled != expected.Enabled || scope != expected.Scope || revision != expected.Revision {
			return errors.New("restored outbound domain policy mismatch")
		}
	}
	for _, expected := range state.Mailboxes {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM mailboxes WHERE id=$1 AND domain_id=$2 AND local_part=$3 AND enabled=$4`, expected.ID, expected.DomainID, expected.LocalPart, expected.Enabled).Scan(&count); err != nil || count != 1 {
			return errors.New("restored outbound mailbox authority mismatch")
		}
	}
	for _, expected := range state.Aliases {
		var encoded string
		if err := db.QueryRowContext(ctx, `SELECT targets_json FROM aliases WHERE id=$1 AND domain_id=$2 AND local_part=$3 AND enabled=$4`, expected.ID, expected.DomainID, expected.LocalPart, expected.Enabled).Scan(&encoded); err != nil {
			return errors.New("restored outbound alias authority mismatch")
		}
		var targets []string
		if json.Unmarshal([]byte(encoded), &targets) != nil || digestStrings(targets) != digestStrings(expected.Targets) {
			return errors.New("restored outbound alias target mismatch")
		}
	}
	for _, expected := range state.SystemSenders {
		var domainID, address string
		var enabled bool
		var revision uint64
		if err := db.QueryRowContext(ctx, `SELECT domain_id::text,address,enabled,revision FROM outbound_system_senders WHERE id=$1`, expected.ID).Scan(&domainID, &address, &enabled, &revision); err != nil || domainID != expected.DomainID || address != expected.Address || enabled != expected.Enabled || revision != expected.Revision {
			return errors.New("restored outbound system-sender mismatch")
		}
	}
	store := QueueStore{DB: db}
	for _, expected := range state.Queues {
		restored, err := store.Load(ctx, expected.QueueID)
		if err != nil || !sameQueueIdentity(restored, expected) || restored.HoldState != expected.HoldState || restored.ReconciliationAttempts != expected.ReconciliationAttempts || restored.LastErrorCode != expected.LastErrorCode || restored.PolicyReason != expected.PolicyReason || !revisionMapsEqual(restored.PolicyRevisions, expected.PolicyRevisions) {
			return errors.New("restored outbound queue state mismatch")
		}
		if _, err := resolvePolicySources(ctx, db, restored.Sources); err != nil {
			return errors.New("restored outbound queue authority is invalid")
		}
	}
	return nil
}

// restoreBackupQueue validates and inserts one parent plus immutable child
// sets without reinterpreting its durable hold state.
// Complexity: time O(r log r+s log s+b), Omega(r+s); auxiliary space O(r+s+b).
func restoreBackupQueue(ctx context.Context, tx *sql.Tx, record QueueRecord, objects map[string]bool) error {
	normalized, err := normalizeQueueRegistration(QueueRegistration{QueueID: record.QueueID, ArrivalFingerprint: record.ArrivalFingerprint, EnvelopeSender: record.EnvelopeSender, Recipients: record.Recipients, Sources: record.Sources})
	if err != nil || !sameQueueIdentity(record, normalized) || !validHoldState(record.HoldState) || record.ReconciliationAttempts > uint64(^uint64(0)>>1) || !validQueuePolicyState(record.HoldState, record.PolicyReason != "", record.PolicyReason, record.PolicyRevisions) || record.FirstSeenAt.IsZero() || record.UpdatedAt.Before(record.FirstSeenAt) || (record.LastErrorCode != "" && !validQueueErrorCode(record.LastErrorCode)) {
		return errors.New("invalid outbound backup queue")
	}
	for _, source := range record.Sources {
		if !objects[string(source.Kind)+"\x00"+source.ObjectID] {
			return errors.New("outbound backup queue source is missing")
		}
	}
	revisions, err := json.Marshal(record.PolicyRevisions)
	if err != nil {
		return err
	}
	var reason, lastError any
	if record.PolicyReason != "" {
		reason = string(record.PolicyReason)
	}
	if record.LastErrorCode != "" {
		lastError = record.LastErrorCode
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO outbound_queue_messages(queue_id,arrival_fingerprint,envelope_sender,recipient_set_digest,source_set_digest,hold_state,policy_reason,policy_revisions_json,reconciliation_attempts,last_error_code,first_seen_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, record.QueueID, record.ArrivalFingerprint, record.EnvelopeSender, record.RecipientSetDigest, record.SourceSetDigest, string(record.HoldState), reason, revisions, record.ReconciliationAttempts, lastError, record.FirstSeenAt.UTC(), record.UpdatedAt.UTC()); err != nil {
		return err
	}
	for _, recipient := range record.Recipients {
		_, domain, _ := normalizeQueueRecipient(recipient)
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbound_queue_recipients(queue_id,recipient,recipient_domain) VALUES ($1,$2,$3)`, record.QueueID, recipient, domain); err != nil {
			return err
		}
	}
	for _, source := range record.Sources {
		if _, err := tx.ExecContext(ctx, `INSERT INTO outbound_queue_sources(queue_id,source_kind,object_id) VALUES ($1,$2,$3)`, record.QueueID, string(source.Kind), source.ObjectID); err != nil {
			return err
		}
	}
	return nil
}

// closeBackupRows preserves both iteration and close errors.
// Complexity: time and auxiliary space O(1).
func closeBackupRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	return rows.Close()
}

// validBackupLocalPart rejects empty, noncanonical, and control-bearing local
// parts before SQL insertion.
// Complexity: time O(n), Omega(1); auxiliary space O(1), where n is bounded.
func validBackupLocalPart(value string) bool {
	if value == "" || len(value) > 64 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "@\r\n\x00") {
		return false
	}
	return true
}

// nullBackupString preserves the existing nullable verifier representation.
// Complexity: time and auxiliary space O(1).
func nullBackupString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

// nullBackupInt64 preserves the existing nullable quota representation.
// Complexity: time and auxiliary space O(1).
func nullBackupInt64(value int64) sql.NullInt64 {
	return sql.NullInt64{Int64: value, Valid: value != 0}
}
