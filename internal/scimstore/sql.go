package scimstore

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
	"github.com/lib/pq"
)

type requestMetadata struct {
	Actor         authz.Actor
	CorrelationID string
	SourceIP      string
	UserAgent     string
}

type requestMetadataKey struct{}

type legacyMailboxAdoption struct {
	MailboxID string
	Mailbox   string
	UpdatedAt time.Time
	consumed  bool
}

type legacyMailboxAdoptionKey struct{}

func WithRequestMetadata(ctx context.Context, actor authz.Actor, correlationID, sourceIP, userAgent string) context.Context {
	return context.WithValue(ctx, requestMetadataKey{}, requestMetadata{Actor: actor, CorrelationID: correlationID, SourceIP: sourceIP, UserAgent: userAgent})
}

// WithLegacyMailboxAdoption admits one exact existing mailbox as the target of
// the next gotth-scim User create in this transaction. Ordinary SCIM creates
// never receive this claim and therefore retain conflict-on-address behavior.
func WithLegacyMailboxAdoption(ctx context.Context, mailboxID, mailbox string, updatedAt time.Time) context.Context {
	claim := legacyMailboxAdoption{MailboxID: mailboxID, Mailbox: strings.ToLower(mailbox), UpdatedAt: updatedAt.UTC()}
	return context.WithValue(ctx, legacyMailboxAdoptionKey{}, claim)
}

// SQLStore implements gotth-scim's exact-once transaction contract. The
// mutex keeps commit order identical to the in-process passdb projection order;
// PostgreSQL constraints remain authoritative across processes.
type SQLStore struct {
	DB       *sql.DB
	Identity *identity.Service
	mu       sync.Mutex
}

func (*SQLStore) SupportsPasswordTransactions() {}

type transaction struct {
	ctx       context.Context
	tx        *sql.Tx
	identity  *identity.Service
	metadata  requestMetadata
	passwords map[string]passwordChange
	project   []mailboxProjection
	adoption  *legacyMailboxAdoption
}

type passwordChange struct {
	verifier string
	revision string
}

type mailboxProjection struct {
	previousEmail string
	mailbox       identity.Mailbox
}

func (store *SQLStore) Transact(ctx context.Context, fn func(gotthscim.Transaction) error) error {
	if store == nil || store.DB == nil || fn == nil {
		return fmt.Errorf("SCIM SQL store and transaction callback are required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	dbtx, err := store.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer dbtx.Rollback()
	metadata, _ := ctx.Value(requestMetadataKey{}).(requestMetadata)
	tx := &transaction{ctx: ctx, tx: dbtx, identity: store.Identity, metadata: metadata, passwords: map[string]passwordChange{}}
	if claim, ok := ctx.Value(legacyMailboxAdoptionKey{}).(legacyMailboxAdoption); ok {
		tx.adoption = &claim
	}
	if err := fn(tx); err != nil {
		return mapStoreError(err)
	}
	if tx.adoption != nil && !tx.adoption.consumed {
		return fmt.Errorf("legacy mailbox adoption claim was not consumed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := dbtx.Commit(); err != nil {
		return mapStoreError(err)
	}
	if store.Identity != nil {
		for _, projection := range tx.project {
			store.Identity.ApplySCIMMailbox(projection.previousEmail, projection.mailbox)
		}
	}
	return nil
}

func (tx *transaction) Get(scope, resourceType, id string) (gotthscim.Record, error) {
	record, err := scanRecord(tx.tx.QueryRowContext(tx.ctx, `SELECT scope, resource_type, id, external_id, manager, version, credential_version, created_unix_nano, last_modified_unix_nano, data FROM scim_resources WHERE scope=$1 AND resource_type=$2 AND id=$3`, scope, resourceType, id))
	if errors.Is(err, sql.ErrNoRows) {
		return gotthscim.Record{}, gotthscim.ErrNotFound
	}
	if err != nil {
		return gotthscim.Record{}, err
	}
	record.Indexes, err = tx.loadIndexes(scope, resourceType, []string{id})
	return cloneRecord(record), err
}

func (tx *transaction) List(query gotthscim.Query) ([]gotthscim.Record, error) {
	if query.Scope == "" || query.ResourceType == "" || query.Limit < 1 {
		return nil, fmt.Errorf("SCIM store query is invalid")
	}
	args := []any{query.Scope, query.ResourceType, query.Limit + 1}
	statement := `SELECT r.scope, r.resource_type, r.id, r.external_id, r.manager, r.version, r.credential_version, r.created_unix_nano, r.last_modified_unix_nano, r.data FROM scim_resources r WHERE r.scope=$1 AND r.resource_type=$2`
	if query.Attribute != "" {
		args = append(args, query.Value)
		if strings.EqualFold(query.Attribute, "externalId") {
			statement += ` AND r.external_id=$4`
		} else {
			args = append(args, strings.ToLower(query.Attribute))
			statement += ` AND EXISTS (SELECT 1 FROM scim_resource_indexes i WHERE i.scope=r.scope AND i.resource_type=r.resource_type AND i.resource_id=r.id AND i.name_folded=$5 AND ((i.case_exact AND i.value=$4) OR (NOT i.case_exact AND lower(i.value)=lower($4))))`
		}
	}
	statement += ` ORDER BY r.id LIMIT $3`
	rows, err := tx.tx.QueryContext(tx.ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []gotthscim.Record
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(records) > query.Limit {
		return nil, gotthscim.ErrTooMany
	}
	ids := make([]string, len(records))
	for index := range records {
		ids[index] = records[index].ID
	}
	indexes, err := tx.loadIndexesByID(query.Scope, query.ResourceType, ids)
	if err != nil {
		return nil, err
	}
	for index := range records {
		records[index].Indexes = indexes[records[index].ID]
		records[index] = cloneRecord(records[index])
	}
	return records, nil
}

func (tx *transaction) Create(record gotthscim.Record) error {
	if err := validateRecordShape(record); err != nil {
		return err
	}
	if tx.adoption != nil && record.ResourceType == "User" {
		var subjectOwned bool
		if err := tx.tx.QueryRowContext(tx.ctx, `SELECT EXISTS (SELECT 1 FROM scim_resources WHERE resource_type='User' AND external_id=$1)`, record.ExternalID).Scan(&subjectOwned); err != nil {
			return err
		}
		if subjectOwned {
			return gotthscim.ErrConflict
		}
	}
	var reserved bool
	err := tx.tx.QueryRowContext(tx.ctx, `SELECT EXISTS (SELECT 1 FROM scim_tombstones WHERE id=$1 OR ($2<>'' AND scope=$3 AND resource_type=$4 AND external_id=$2))`, record.ID, record.ExternalID, record.Scope, record.ResourceType).Scan(&reserved)
	if err != nil {
		return err
	}
	if reserved {
		return gotthscim.ErrTombstoned
	}
	if _, err := tx.tx.ExecContext(tx.ctx, `INSERT INTO scim_resources(scope, resource_type, id, external_id, manager, version, credential_version, created_unix_nano, last_modified_unix_nano, data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, record.Scope, record.ResourceType, record.ID, record.ExternalID, record.Manager, record.Version, record.CredentialVersion, record.Created.UnixNano(), record.LastModified.UnixNano(), record.Data); err != nil {
		return mapStoreError(err)
	}
	if err := tx.replaceIndexes(record); err != nil {
		return err
	}
	return tx.projectRecord(scimAction(record.ResourceType, "create"), gotthscim.Record{}, record)
}

func (tx *transaction) Replace(record gotthscim.Record, expectedVersion string) error {
	if err := validateRecordShape(record); err != nil {
		return err
	}
	current, err := tx.Get(record.Scope, record.ResourceType, record.ID)
	if err != nil {
		return err
	}
	if expectedVersion == "" || current.Version != expectedVersion {
		return gotthscim.ErrPrecondition
	}
	if !record.Created.Equal(current.Created) || record.Manager != current.Manager {
		return fmt.Errorf("SCIM record creation time and manager are immutable")
	}
	if current.ExternalID != record.ExternalID {
		var bound bool
		if err := tx.tx.QueryRowContext(tx.ctx, `SELECT EXISTS (
			SELECT 1 FROM identity_refs ir
			JOIN mailboxes m ON m.id=ir.mailbox_id
			WHERE ir.provider='authentik' AND m.scim_resource_id=$1
		)`, record.ID).Scan(&bound); err != nil {
			return err
		}
		if bound {
			return gotthscim.ErrConflict
		}
	}
	if _, err := tx.tx.ExecContext(tx.ctx, `UPDATE scim_resources SET external_id=$1, version=$2, credential_version=$3, last_modified_unix_nano=$4, data=$5 WHERE scope=$6 AND resource_type=$7 AND id=$8`, record.ExternalID, record.Version, record.CredentialVersion, record.LastModified.UnixNano(), record.Data, record.Scope, record.ResourceType, record.ID); err != nil {
		return err
	}
	if err := tx.replaceIndexes(record); err != nil {
		return err
	}
	return tx.projectRecord(scimAction(record.ResourceType, "replace"), current, record)
}

func (tx *transaction) Delete(scope, resourceType, id, expectedVersion string, tombstone gotthscim.Tombstone) error {
	current, err := tx.Get(scope, resourceType, id)
	if err != nil {
		return err
	}
	if expectedVersion == "" || current.Version != expectedVersion {
		return gotthscim.ErrPrecondition
	}
	if tombstone.Scope != scope || tombstone.ResourceType != resourceType || tombstone.ID != id || tombstone.ExternalID != current.ExternalID || tombstone.Manager != current.Manager || tombstone.Version != current.Version || tombstone.DeletedAt.IsZero() {
		return fmt.Errorf("SCIM tombstone does not match deleted resource")
	}
	if resourceType == "User" {
		var groupID string
		err := tx.tx.QueryRowContext(tx.ctx, `SELECT group_id FROM scim_group_members WHERE scope=$1 AND user_id=$2 ORDER BY group_id LIMIT 1`, scope, id).Scan(&groupID)
		switch {
		case err == nil:
			return &gotthscim.ProtocolError{Status: 409, Detail: "User remains referenced by a Group"}
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		}
	}
	if err := tx.disableProjection(current, tombstone.DeletedAt); err != nil {
		return err
	}
	if _, err := tx.tx.ExecContext(tx.ctx, `DELETE FROM scim_resources WHERE scope=$1 AND resource_type=$2 AND id=$3`, scope, resourceType, id); err != nil {
		return mapStoreError(err)
	}
	if _, err := tx.tx.ExecContext(tx.ctx, `INSERT INTO scim_tombstones(scope, resource_type, id, external_id, manager, version, deleted_unix_nano) VALUES ($1,$2,$3,$4,$5,$6,$7)`, tombstone.Scope, tombstone.ResourceType, tombstone.ID, tombstone.ExternalID, tombstone.Manager, tombstone.Version, tombstone.DeletedAt.UnixNano()); err != nil {
		return mapStoreError(err)
	}
	return tx.audit(scimAction(resourceType, "delete"), current, gotthscim.Record{})
}

func (tx *transaction) Tombstones(scope, resourceType string) ([]gotthscim.Tombstone, error) {
	rows, err := tx.tx.QueryContext(tx.ctx, `SELECT scope, resource_type, id, external_id, manager, version, deleted_unix_nano FROM scim_tombstones WHERE scope=$1 AND resource_type=$2 ORDER BY id`, scope, resourceType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []gotthscim.Tombstone
	for rows.Next() {
		var tombstone gotthscim.Tombstone
		var deletedUnixNano int64
		if err := rows.Scan(&tombstone.Scope, &tombstone.ResourceType, &tombstone.ID, &tombstone.ExternalID, &tombstone.Manager, &tombstone.Version, &deletedUnixNano); err != nil {
			return nil, err
		}
		tombstone.DeletedAt = time.Unix(0, deletedUnixNano).UTC()
		result = append(result, tombstone)
	}
	return result, rows.Err()
}

func (tx *transaction) SetPassword(scope, resourceType, id string, password []byte) (string, error) {
	if scope == "" || resourceType != "User" || id == "" || len(password) == 0 {
		return "", fmt.Errorf("SCIM password target is invalid")
	}
	verifier, err := identity.HashSecretBytes(password)
	if err != nil {
		return "", &gotthscim.ProtocolError{Status: 400, SCIMType: "invalidValue", Detail: "password does not meet mailbox policy"}
	}
	digest := sha256.Sum256([]byte(verifier))
	change := passwordChange{verifier: verifier, revision: base64.RawURLEncoding.EncodeToString(digest[:])}
	tx.passwords[recordPasswordKey(scope, resourceType, id)] = change
	return change.revision, nil
}

func (tx *transaction) replaceIndexes(record gotthscim.Record) error {
	if _, err := tx.tx.ExecContext(tx.ctx, `DELETE FROM scim_resource_indexes WHERE scope=$1 AND resource_type=$2 AND resource_id=$3`, record.Scope, record.ResourceType, record.ID); err != nil {
		return err
	}
	for ordinal, index := range record.Indexes {
		folded := strings.ToLower(index.Name)
		_, err := tx.tx.ExecContext(tx.ctx, `INSERT INTO scim_index_contracts(scope, resource_type, name_folded, case_exact, unique_value) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, record.Scope, record.ResourceType, folded, index.CaseExact, index.Unique)
		if err != nil {
			return err
		}
		var caseExact, unique bool
		if err := tx.tx.QueryRowContext(tx.ctx, `SELECT case_exact, unique_value FROM scim_index_contracts WHERE scope=$1 AND resource_type=$2 AND name_folded=$3`, record.Scope, record.ResourceType, folded).Scan(&caseExact, &unique); err != nil {
			return err
		}
		if caseExact != index.CaseExact || unique != index.Unique {
			return gotthscim.ErrConflict
		}
		if _, err := tx.tx.ExecContext(tx.ctx, `INSERT INTO scim_resource_indexes(scope, resource_type, resource_id, name, name_folded, value, ordinal, case_exact, unique_value) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.Scope, record.ResourceType, record.ID, index.Name, folded, index.Value, ordinal, index.CaseExact, index.Unique); err != nil {
			return mapStoreError(err)
		}
	}
	return nil
}

func (tx *transaction) loadIndexes(scope, resourceType string, ids []string) ([]gotthscim.IndexKey, error) {
	byID, err := tx.loadIndexesByID(scope, resourceType, ids)
	if err != nil || len(ids) == 0 {
		return nil, err
	}
	return byID[ids[0]], nil
}

func (tx *transaction) loadIndexesByID(scope, resourceType string, ids []string) (map[string][]gotthscim.IndexKey, error) {
	result := make(map[string][]gotthscim.IndexKey, len(ids))
	if len(ids) == 0 {
		return result, nil
	}
	rows, err := tx.tx.QueryContext(tx.ctx, `SELECT resource_id, name, value, case_exact, unique_value FROM scim_resource_indexes WHERE scope=$1 AND resource_type=$2 AND resource_id=ANY($3) ORDER BY resource_id, ordinal`, scope, resourceType, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var index gotthscim.IndexKey
		if err := rows.Scan(&id, &index.Name, &index.Value, &index.CaseExact, &index.Unique); err != nil {
			return nil, err
		}
		result[id] = append(result[id], index)
	}
	return result, rows.Err()
}

func (tx *transaction) projectRecord(action string, before, after gotthscim.Record) error {
	if after.ResourceType == "Group" {
		if err := tx.replaceGroupMembers(after); err != nil {
			return err
		}
		return tx.audit(action, before, after)
	}
	if tx.identity == nil || after.ResourceType != "User" {
		return nil
	}
	mailbox, previousEmail, err := tx.mailboxFromRecord(after)
	if err != nil {
		return err
	}
	if err := tx.identity.AuthorizeProvision(tx.ctx, tx.metadata.Actor, mailbox.Email); err != nil {
		return &gotthscim.ProtocolError{Status: 403, Detail: "provisioning scope is not authorized"}
	}
	if err := tx.identity.ValidateMailbox(mailbox.Email); err != nil {
		return &gotthscim.ProtocolError{Status: 400, SCIMType: "invalidValue", Detail: "userName violates mailbox policy"}
	}
	if err := tx.persistMailbox(after, previousEmail, &mailbox); err != nil {
		return err
	}
	tx.project = append(tx.project, mailboxProjection{previousEmail: previousEmail, mailbox: mailbox})
	return tx.audit(action, before, after)
}

func (tx *transaction) replaceGroupMembers(record gotthscim.Record) error {
	document, err := gotthscim.DecodeDocument(record.Data)
	if err != nil {
		return err
	}
	values, exists := document["members"]
	members := make([]string, 0)
	seen := make(map[string]struct{})
	if exists {
		items, ok := values.([]any)
		if !ok {
			return &gotthscim.ProtocolError{Status: 400, SCIMType: "invalidValue", Detail: "Group members are invalid"}
		}
		members = make([]string, 0, len(items))
		for _, item := range items {
			member, ok := item.(map[string]any)
			if !ok {
				return &gotthscim.ProtocolError{Status: 400, SCIMType: "invalidValue", Detail: "Group member is invalid"}
			}
			id, ok := member["value"].(string)
			kind, _ := member["type"].(string)
			if !ok || id == "" || kind != "" && kind != "User" {
				return &gotthscim.ProtocolError{Status: 400, SCIMType: "invalidValue", Detail: "Group members must reference Users"}
			}
			if _, duplicate := seen[id]; duplicate {
				return &gotthscim.ProtocolError{Status: 409, SCIMType: "uniqueness", Detail: "Group member is duplicated"}
			}
			seen[id] = struct{}{}
			members = append(members, id)
		}
	}
	if len(members) > 0 {
		rows, err := tx.tx.QueryContext(tx.ctx, `SELECT id FROM scim_resources WHERE scope=$1 AND resource_type='User' AND id=ANY($2)`, record.Scope, pq.Array(members))
		if err != nil {
			return err
		}
		found := make(map[string]struct{}, len(members))
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			found[id] = struct{}{}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(found) != len(members) {
			return &gotthscim.ProtocolError{Status: 409, SCIMType: "invalidValue", Detail: "Group member is not a live User in this scope"}
		}
	}
	if _, err := tx.tx.ExecContext(tx.ctx, `DELETE FROM scim_group_members WHERE scope=$1 AND group_id=$2`, record.Scope, record.ID); err != nil {
		return err
	}
	if len(members) == 0 {
		return nil
	}
	_, err = tx.tx.ExecContext(tx.ctx, `INSERT INTO scim_group_members(scope, group_id, user_id) SELECT $1,$2,unnest($3::text[])`, record.Scope, record.ID, pq.Array(members))
	return mapStoreError(err)
}

func (tx *transaction) mailboxFromRecord(record gotthscim.Record) (identity.Mailbox, string, error) {
	document, err := gotthscim.DecodeDocument(record.Data)
	if err != nil {
		return identity.Mailbox{}, "", err
	}
	userName, ok := document["userName"].(string)
	if !ok || userName == "" {
		return identity.Mailbox{}, "", fmt.Errorf("SCIM userName is required")
	}
	displayName, _ := document["displayName"].(string)
	if displayName == "" {
		if name, ok := document["name"].(map[string]any); ok {
			displayName, _ = name["formatted"].(string)
		}
	}
	active := true
	if value, exists := document["active"]; exists {
		active, ok = value.(bool)
		if !ok {
			return identity.Mailbox{}, "", fmt.Errorf("SCIM active value is invalid")
		}
	}
	mailbox := identity.Mailbox{ID: record.ID, Email: strings.ToLower(userName), DisplayName: displayName, Active: active, CreatedAt: record.Created, UpdatedAt: record.LastModified}
	var previousEmail string
	var verifier string
	err = tx.tx.QueryRowContext(tx.ctx, `SELECT m.local_part || '@' || d.name, COALESCE(m.verifier,'') FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.scim_resource_id=$1 FOR UPDATE`, record.ID).Scan(&previousEmail, &verifier)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return identity.Mailbox{}, "", err
	}
	if errors.Is(err, sql.ErrNoRows) && tx.adoption != nil {
		var existingEmail, existingDisplay, existingVerifier, existingSCIMID string
		var existingEnabled, domainEnabled bool
		var existingCreated, existingUpdated time.Time
		err = tx.tx.QueryRowContext(tx.ctx, `SELECT lower(m.local_part || '@' || d.name), COALESCE(m.display_name,''), m.enabled, d.enabled, COALESCE(m.verifier,''), COALESCE(m.scim_resource_id,''), m.created_at, m.updated_at FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.id=$1 FOR UPDATE`, tx.adoption.MailboxID).Scan(&existingEmail, &existingDisplay, &existingEnabled, &domainEnabled, &existingVerifier, &existingSCIMID, &existingCreated, &existingUpdated)
		if err != nil {
			return identity.Mailbox{}, "", fmt.Errorf("legacy adoption mailbox is unavailable: %w", err)
		}
		if !strings.EqualFold(existingEmail, tx.adoption.Mailbox) || !strings.EqualFold(existingEmail, mailbox.Email) || !existingUpdated.Equal(tx.adoption.UpdatedAt) || existingSCIMID != "" || !domainEnabled {
			return identity.Mailbox{}, "", gotthscim.ErrConflict
		}
		if existingEnabled != mailbox.Active || existingDisplay != mailbox.DisplayName {
			return identity.Mailbox{}, "", gotthscim.ErrConflict
		}
		previousEmail = existingEmail
		verifier = existingVerifier
		mailbox.CreatedAt = existingCreated
		tx.adoption.consumed = true
	}
	if change, exists := tx.passwords[recordPasswordKey(record.Scope, record.ResourceType, record.ID)]; exists {
		verifier = change.verifier
	}
	mailbox.Verifier = verifier
	return mailbox, previousEmail, nil
}

func (tx *transaction) persistMailbox(record gotthscim.Record, previousEmail string, mailbox *identity.Mailbox) error {
	address, err := mail.ParseAddress(mailbox.Email)
	if err != nil || address.Address != mailbox.Email {
		return fmt.Errorf("SCIM mailbox address is invalid")
	}
	local, domain, ok := strings.Cut(mailbox.Email, "@")
	if !ok {
		return fmt.Errorf("SCIM mailbox address is invalid")
	}
	domainID := stableUUID("domain:" + domain)
	mailboxID := stableUUID("scim-mailbox:" + record.ID)
	if tx.adoption != nil && tx.adoption.consumed && strings.EqualFold(previousEmail, tx.adoption.Mailbox) {
		mailboxID = tx.adoption.MailboxID
		result, err := tx.tx.ExecContext(tx.ctx, `UPDATE mailboxes SET display_name=$1, enabled=$2, verifier=$3, updated_at=$4, scim_resource_id=$5 WHERE id=$6 AND scim_resource_id IS NULL`, nullableString(mailbox.DisplayName), mailbox.Active, nullableString(mailbox.Verifier), mailbox.UpdatedAt, record.ID, mailboxID)
		if err != nil {
			return mapStoreError(err)
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return gotthscim.ErrConflict
		}
		return nil
	}
	if previousEmail != "" {
		if err := tx.tx.QueryRowContext(tx.ctx, `SELECT id FROM mailboxes WHERE scim_resource_id=$1`, record.ID).Scan(&mailboxID); err != nil {
			return err
		}
	}
	if _, err := tx.tx.ExecContext(tx.ctx, `INSERT INTO domains(id, name, enabled, created_at, updated_at) VALUES ($1,$2,true,$3,$4) ON CONFLICT (name) DO UPDATE SET updated_at=EXCLUDED.updated_at`, domainID, domain, mailbox.CreatedAt, mailbox.UpdatedAt); err != nil {
		return err
	}
	if _, err = tx.tx.ExecContext(tx.ctx, `INSERT INTO mailboxes(id, domain_id, local_part, display_name, enabled, verifier, created_at, updated_at, scim_resource_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO UPDATE SET domain_id=EXCLUDED.domain_id, local_part=EXCLUDED.local_part, display_name=EXCLUDED.display_name, enabled=EXCLUDED.enabled, verifier=EXCLUDED.verifier, updated_at=EXCLUDED.updated_at, scim_resource_id=EXCLUDED.scim_resource_id`, mailboxID, domainID, local, nullableString(mailbox.DisplayName), mailbox.Active, nullableString(mailbox.Verifier), mailbox.CreatedAt, mailbox.UpdatedAt, record.ID); err != nil {
		return mapStoreError(err)
	}
	if !mailbox.Active {
		if err := tx.revokeSessionsForSCIMID(record.ID, mailbox.UpdatedAt); err != nil {
			return err
		}
	}
	if previousEmail != "" && !strings.EqualFold(previousEmail, mailbox.Email) {
		scopeJSON, err := json.Marshal([]string{"mailbox:" + mailbox.Email + ":app_password"})
		if err != nil {
			return err
		}
		if _, err := tx.tx.ExecContext(tx.ctx, `UPDATE tokens SET subject_id=$1, scope_json=$2 WHERE kind='app_password' AND lower(subject_id)=lower($3)`, mailbox.Email, string(scopeJSON), previousEmail); err != nil {
			return err
		}
	}
	return nil
}

func (tx *transaction) disableProjection(record gotthscim.Record, now time.Time) error {
	if tx.identity == nil || record.ResourceType != "User" {
		return nil
	}
	mailbox, previousEmail, err := tx.mailboxFromRecord(record)
	if err != nil {
		return err
	}
	if err := tx.identity.AuthorizeProvision(tx.ctx, tx.metadata.Actor, mailbox.Email); err != nil {
		return &gotthscim.ProtocolError{Status: 403, Detail: "provisioning scope is not authorized"}
	}
	mailbox.Active = false
	mailbox.UpdatedAt = now
	if _, err := tx.tx.ExecContext(tx.ctx, `UPDATE mailboxes SET enabled=false, updated_at=$1 WHERE scim_resource_id=$2`, now, record.ID); err != nil {
		return err
	}
	if err := tx.revokeSessionsForSCIMID(record.ID, now); err != nil {
		return err
	}
	tx.project = append(tx.project, mailboxProjection{previousEmail: previousEmail, mailbox: mailbox})
	return nil
}

func (tx *transaction) revokeSessionsForSCIMID(resourceID string, now time.Time) error {
	_, err := tx.tx.ExecContext(tx.ctx, `UPDATE sessions
		SET revoked_at=$1
		WHERE revoked_at IS NULL AND identity_ref_id IN (
			SELECT ir.id FROM identity_refs ir
			JOIN mailboxes m ON m.id=ir.mailbox_id
			WHERE ir.provider='authentik' AND m.scim_resource_id=$2
		)`, now, resourceID)
	return err
}

func (tx *transaction) audit(action string, before, after gotthscim.Record) error {
	if tx.identity == nil {
		return nil
	}
	if tx.metadata.Actor.Type != "scim_client" || tx.metadata.Actor.ID == "" {
		return fmt.Errorf("authenticated SCIM actor is required")
	}
	id, err := randomUUID()
	if err != nil {
		return err
	}
	resourceID := after.ID
	if resourceID == "" {
		resourceID = before.ID
	}
	var beforeJSON, afterJSON sql.NullString
	if len(before.Data) > 0 {
		beforeJSON = sql.NullString{String: string(before.Data), Valid: true}
	}
	if len(after.Data) > 0 {
		afterJSON = sql.NullString{String: string(after.Data), Valid: true}
	}
	_, err = tx.tx.ExecContext(tx.ctx, `INSERT INTO audit_events(id, timestamp, actor_type, actor_id, source_ip, source_user_agent, action, resource_type, resource_id, before_redacted_json, after_redacted_json, correlation_id, result, error_code) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'success',NULL)`, id, time.Now().UTC(), tx.metadata.Actor.Type, tx.metadata.Actor.ID, nullableString(tx.metadata.SourceIP), nullableString(tx.metadata.UserAgent), action, "identity", resourceID, beforeJSON, afterJSON, tx.metadata.CorrelationID)
	return err
}

type scanner interface{ Scan(...any) error }

func scanRecord(row scanner) (gotthscim.Record, error) {
	var record gotthscim.Record
	var createdUnixNano, modifiedUnixNano int64
	err := row.Scan(&record.Scope, &record.ResourceType, &record.ID, &record.ExternalID, &record.Manager, &record.Version, &record.CredentialVersion, &createdUnixNano, &modifiedUnixNano, &record.Data)
	if err == nil {
		record.Created = time.Unix(0, createdUnixNano).UTC()
		record.LastModified = time.Unix(0, modifiedUnixNano).UTC()
	}
	return record, err
}

func validateRecordShape(record gotthscim.Record) error {
	if record.Scope == "" || record.ResourceType == "" || record.ID == "" || record.Version == "" || record.Created.IsZero() || record.LastModified.Before(record.Created) || len(record.Data) == 0 || len(record.Data) > 1<<20 {
		return fmt.Errorf("SCIM record shape is invalid")
	}
	return nil
}

func cloneRecord(record gotthscim.Record) gotthscim.Record {
	record.Data = append([]byte(nil), record.Data...)
	record.Indexes = append([]gotthscim.IndexKey(nil), record.Indexes...)
	return record
}

func recordPasswordKey(scope, resourceType, id string) string {
	return scope + "\x00" + resourceType + "\x00" + id
}

func mapStoreError(err error) error {
	var postgresError *pq.Error
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23503":
			return &gotthscim.ProtocolError{Status: 409, Detail: "SCIM resource remains referenced by existing state"}
		case "23505":
			return gotthscim.ErrConflict
		}
	}
	return err
}

func scimAction(resourceType, verb string) string {
	return "scim." + strings.ToLower(resourceType) + "." + verb
}

func stableUUID(seed string) string {
	digest := sha1.Sum([]byte(seed))
	value := digest[:16]
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32]
}

func randomUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}

var _ gotthscim.PasswordStore = (*SQLStore)(nil)
var _ gotthscim.PasswordTransaction = (*transaction)(nil)
