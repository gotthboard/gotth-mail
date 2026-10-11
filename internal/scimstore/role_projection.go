package scimstore

import (
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/roleprojection"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
	"time"
)

// roleProjector copies immutable authority and authenticated request attribution.
// Complexity: time and auxiliary space O(1), Omega(1), Theta(1); copies string
// headers, not provider documents. No I/O or authority derived from request URLs.
func (tx *transaction) roleProjector() roleprojection.Projector {
	return roleprojection.Projector{CurrentIssuer: tx.currentIssuer, Actor: audit.ActorRef{Type: tx.metadata.Actor.Type, ID: tx.metadata.Actor.ID}, Source: &audit.RequestSource{IP: tx.metadata.SourceIP, UserAgent: tx.metadata.UserAgent}, CorrelationID: tx.metadata.CorrelationID}
}

// syncUserRoles only visits identities already bound to this exact mailbox User.
// Complexity: I identity IDs, P/S delegated leaf work/space, Q SQL work: time
// O(I+P+Q), Omega(I+P+Q), Theta(I+P+Q); auxiliary O(I+S), Omega(I), no tight
// Theta established. It neither creates identities nor revives revoked sessions.
func (tx *transaction) syncUserRoles(resourceID string) error {
	rows, err := tx.tx.QueryContext(tx.ctx, `SELECT ir.id::text FROM identity_refs ir JOIN mailboxes m ON m.id=ir.mailbox_id WHERE m.scim_resource_id=$1 ORDER BY ir.id`, resourceID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	p := tx.roleProjector()
	for _, id := range ids {
		if err = p.SyncIdentity(tx.ctx, tx.tx, id); err != nil {
			return err
		}
	}
	return nil
}

// tombstoneGroupMappings runs before membership cascades, retaining mapping
// history and invalidating every old origin even without configured issuer.
// Complexity: M mappings, P delegated leaf work, Q SQL/audit work: successful
// time O(M+P+Q), Omega(M+P+Q), Theta(M+P+Q); auxiliary O(M+S), Omega(M),
// tight Theta not established; S delegated leaf/SQL storage. No retries.
func (tx *transaction) tombstoneGroupMappings(record gotthscim.Record, now time.Time) error {
	rows, err := tx.tx.QueryContext(tx.ctx, "SELECT id::text,enabled,group_deleted FROM identity_group_role_mappings WHERE scope=$1 AND group_id=$2 ORDER BY id FOR UPDATE", record.Scope, record.ID)
	if err != nil {
		return err
	}
	type oldMapping struct {
		id               string
		enabled, deleted bool
	}
	var mappings []oldMapping
	for rows.Next() {
		var m oldMapping
		if err = rows.Scan(&m.id, &m.enabled, &m.deleted); err != nil {
			break
		}
		mappings = append(mappings, m)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	p := tx.roleProjector()
	for _, m := range mappings {
		changed := m.enabled || !m.deleted
		if changed {
			result, err := tx.tx.ExecContext(tx.ctx, "UPDATE identity_group_role_mappings SET enabled=false,group_deleted=true,revision=revision+1,updated_at=$2 WHERE id=$1", m.id, now)
			if err != nil {
				return err
			}
			n, err := result.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return fmt.Errorf("Group mapping tombstone did not affect one exact row")
			}
		}
		if err = p.RemoveMappingSources(tx.ctx, tx.tx, m.id); err != nil {
			return err
		}
		if changed {
			if err = audit.WriteSQL(tx.ctx, tx.tx, audit.Event{Time: now, Actor: p.Actor, Source: p.Source, CorrelationID: p.CorrelationID, Action: "identity.group_role_mapping.tombstone", Resource: audit.ResourceRef{Type: "identity_group_role_mapping", ID: m.id}, BeforeRedacted: map[string]bool{"enabled": m.enabled, "group_deleted": m.deleted}, AfterRedacted: map[string]bool{"enabled": false, "group_deleted": true}, Result: "success"}); err != nil {
				return err
			}
		}
	}
	return nil
}
