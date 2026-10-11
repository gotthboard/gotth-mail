// Package roleprojection reconciles durable Group role origins inside a
// caller-owned SERIALIZABLE transaction. Callers MUST roll back on any error;
// this package never commits, retries, creates identities, or performs network work.
package roleprojection

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"sort"
	"time"
)

// Projector carries immutable deployment authority and caller audit metadata.
// An empty CurrentIssuer prevents additions, not structural retractions.
type Projector struct {
	CurrentIssuer string
	Actor         audit.ActorRef
	Source        *audit.RequestSource
	CorrelationID string
}
type binding struct {
	id, role, domain string
	operator         bool
	sources          map[string]struct{}
}
type mapping struct{ id, role, domain string }

// SyncIdentity diffs current membership AND prior origins for one verified row.
// Valid structural origins survive a mere issuer/local-enabled change. New
// origins require CurrentIssuer equality. Unsupported mapped roles fail closed.
// Complexity: successful time O(B+E log E+Q), Omega(B+E+Q), tight Theta not
// established; auxiliary O(B+E+S), Omega(B+E), tight Theta not established.
// B is decoded User bytes, E bindings/mappings/origins, Q delegated SQL/locks/
// audit/entropy work, S delegated SQL space. Early errors have Omega(1).
func (p Projector) SyncIdentity(ctx context.Context, tx *sql.Tx, identityID string) error {
	if err := p.validate(ctx, tx); err != nil {
		return err
	}
	return p.syncIdentity(ctx, tx, identityID)
}

// validate rejects missing attribution and non-SERIALIZABLE callers.
// Complexity: time O(Q), Omega(Q), Theta(Q); auxiliary O(S+1), Omega(1),
// tight Theta not established; Q/S are the delegated isolation-query costs.
func (p Projector) validate(ctx context.Context, tx *sql.Tx) error {
	if tx == nil || p.Actor.Type == "" || p.Actor.ID == "" {
		return errors.New("projection transaction and audit actor are required")
	}
	var isolation string
	if err := tx.QueryRowContext(ctx, "SHOW transaction_isolation").Scan(&isolation); err != nil {
		return err
	}
	if isolation != "serializable" {
		return errors.New("projection requires caller SERIALIZABLE transaction")
	}
	return nil
}

// syncIdentity implements the validated leaf; costs are those of SyncIdentity.
// Complexity: time O(B+E log E+Q), Omega(B+E+Q), tight Theta not established;
// auxiliary O(B+E+S), Omega(B+E), tight Theta not established; variables above.
func (p Projector) syncIdentity(ctx context.Context, tx *sql.Tx, identityID string) error {
	eligibility, err := ReadEligibility(ctx, tx, identityID, true)
	if err != nil {
		return err
	}
	if !eligibility.Found {
		return nil
	}
	bindings, err := loadBindings(ctx, tx, identityID)
	if err != nil {
		return err
	}
	issuer := eligibility.Issuer
	desired := map[string]mapping{}
	for _, m := range eligibility.Mappings {
		desired[m.ID] = mapping{id: m.ID, role: m.Role, domain: m.Domain}
	}
	byRoleDomain := map[string]*binding{}
	for _, b := range bindings {
		byRoleDomain[b.role+"\x00"+b.domain] = b
		ids := make([]string, 0, len(b.sources))
		for id := range b.sources {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			m, keep := desired[id]
			if keep && m.role == b.role && m.domain == b.domain {
				continue
			}
			if err = p.changeSource(ctx, tx, b.id, id, b.role, false); err != nil {
				return err
			}
			delete(b.sources, id)
		}
	}
	if p.CurrentIssuer != "" && p.CurrentIssuer == issuer {
		ids := make([]string, 0, len(desired))
		for id := range desired {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			m := desired[id]
			key := m.role + "\x00" + m.domain
			b := byRoleDomain[key]
			if b == nil {
				uuid, err := newUUID()
				if err != nil {
					return err
				}
				now := time.Now().UTC()
				var domain any
				if m.domain != "" {
					domain = m.domain
				}
				if _, err = tx.ExecContext(ctx, `INSERT INTO role_bindings(id,identity_ref_id,role,domain_id,operator_owned,created_at,updated_at) VALUES ($1,$2,$3,$4,FALSE,$5,$5)`, uuid, identityID, m.role, domain, now); err != nil {
					return err
				}
				b = &binding{id: uuid, role: m.role, domain: m.domain, sources: map[string]struct{}{}}
				bindings = append(bindings, b)
				byRoleDomain[key] = b
			}
			if _, exists := b.sources[id]; exists {
				continue
			}
			if err = p.changeSource(ctx, tx, b.id, id, b.role, true); err != nil {
				return err
			}
			b.sources[id] = struct{}{}
		}
	}
	// Cleanup is after the entire diff: replacing the last old origin with a new
	// origin for the same role/domain must not replace the effective binding UUID.
	for _, b := range bindings {
		if !b.operator && len(b.sources) == 0 {
			if _, err = tx.ExecContext(ctx, "DELETE FROM role_bindings WHERE id=$1 AND NOT operator_owned AND NOT EXISTS (SELECT 1 FROM role_binding_group_sources WHERE binding_id=$1)", b.id); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadBindings locks ordered effective rows and validates every existing source
// against its mapping. Corrupt cross-role/domain edges or orphan rows reject
// before this identity is mutated; neither is silently converted to an operator.
// Complexity: time O(E+Q), Omega(E+Q), Theta(E+Q) on success; auxiliary
// O(E+S), Omega(E), tight Theta not established. E rows/edges; Q/S SQL costs.
func loadBindings(ctx context.Context, tx *sql.Tx, identityID string) ([]*binding, error) {
	rows, err := tx.QueryContext(ctx, "SELECT id::text,role,COALESCE(domain_id::text,''),operator_owned FROM role_bindings WHERE identity_ref_id=$1 ORDER BY id FOR UPDATE", identityID)
	if err != nil {
		return nil, err
	}
	var all []*binding
	byID := map[string]*binding{}
	for rows.Next() {
		b := &binding{sources: map[string]struct{}{}}
		if err = rows.Scan(&b.id, &b.role, &b.domain, &b.operator); err != nil {
			break
		}
		all = append(all, b)
		byID[b.id] = b
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	rows, err = tx.QueryContext(ctx, `SELECT s.binding_id::text,gm.id::text,gm.role,COALESCE(gm.domain_id::text,'') FROM role_binding_group_sources s JOIN role_bindings rb ON rb.id=s.binding_id JOIN identity_group_role_mappings gm ON gm.id=s.mapping_id WHERE rb.identity_ref_id=$1 ORDER BY s.binding_id,gm.id`, identityID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var bindingID, id, role, domain string
		if err = rows.Scan(&bindingID, &id, &role, &domain); err != nil {
			break
		}
		b := byID[bindingID]
		if b == nil || !ValidRoleDomain(role, domain) || role != b.role || domain != b.domain {
			err = errors.New("projection source role/domain invariant violated")
			break
		}
		b.sources[id] = struct{}{}
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr = rows.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	for _, b := range all {
		if !b.operator && len(b.sources) == 0 {
			return nil, errors.New("projection encountered source-less nonoperator binding")
		}
	}
	return all, nil
}

// changeSource performs one exact origin change, revision increment and redacted
// success audit. The caller owns rollback even if a later origin/audit fails.
// Complexity: time O(Q), Omega(Q), Theta(Q); auxiliary O(S+1), Omega(1),
// tight Theta not established; Q/S include SQL, audit encoding and entropy.
func (p Projector) changeSource(ctx context.Context, tx *sql.Tx, bindingID, mappingID, role string, add bool) error {
	var result sql.Result
	var err error
	operation := "remove"
	if add {
		operation = "add"
		result, err = tx.ExecContext(ctx, `INSERT INTO role_binding_group_sources(binding_id,mapping_id) SELECT rb.id,gm.id FROM role_bindings rb JOIN identity_group_role_mappings gm ON gm.id=$2 WHERE rb.id=$1 AND rb.role=gm.role AND rb.domain_id IS NOT DISTINCT FROM gm.domain_id AND gm.role IN ('global_admin','domain_manager','scoped_domain_access')`, bindingID, mappingID)
	} else {
		result, err = tx.ExecContext(ctx, "DELETE FROM role_binding_group_sources WHERE binding_id=$1 AND mapping_id=$2", bindingID, mappingID)
	}
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("projection source change did not affect one exact row")
	}
	now := time.Now().UTC()
	result, err = tx.ExecContext(ctx, "UPDATE role_bindings SET authority_revision=authority_revision+1,updated_at=$2 WHERE id=$1", bindingID, now)
	if err != nil {
		return err
	}
	n, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("projection binding revision did not affect one exact row")
	}
	return audit.WriteSQL(ctx, tx, audit.Event{Time: now, Actor: p.Actor, Source: p.Source, CorrelationID: p.CorrelationID, Action: "identity.group_role_source." + operation, Resource: audit.ResourceRef{Type: "role_binding", ID: bindingID}, AfterRedacted: map[string]any{"mapping_id": mappingID, "role": role, "present": add}, Result: "success"})
}

// SyncGroup includes prior source owners even after the last membership was
// removed or the Group disappeared. Each affected verified identity is diffed.
// Complexity: time O(I+sum(B+E log E)+Q), Omega(I+sum(B+E)+Q), tight Theta
// not established; auxiliary O(I+max(B+E)+S), Omega(I), tight Theta not
// established. I affected identities; B/E as SyncIdentity; Q/S delegated SQL.
func (p Projector) SyncGroup(ctx context.Context, tx *sql.Tx, scope, groupID string) error {
	if err := p.validate(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT ir.id::text FROM identity_refs ir
 JOIN mailboxes m ON m.id=ir.mailbox_id
 JOIN scim_resources u ON u.id=m.scim_resource_id AND u.resource_type='User' AND u.external_id=ir.subject
 JOIN scim_group_members edge ON edge.scope=u.scope AND edge.user_id=u.id
 JOIN identity_group_role_mappings gm ON gm.scope=edge.scope AND gm.group_id=edge.group_id AND gm.issuer=ir.issuer
 WHERE ir.provider='authentik' AND edge.scope=$1 AND edge.group_id=$2
 UNION SELECT rb.identity_ref_id::text FROM role_binding_group_sources s JOIN role_bindings rb ON rb.id=s.binding_id JOIN identity_group_role_mappings gm ON gm.id=s.mapping_id WHERE gm.scope=$1 AND gm.group_id=$2 ORDER BY 1`, scope, groupID)
	if err != nil {
		return err
	}
	ids, err := readIDs(rows)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = p.syncIdentity(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}

// RemoveMappingSources removes only this mapping's origins, preserving operator
// and other Group origins. Caller must disable/tombstone the mapping in the same
// transaction when revoking its delegation; this leaf does not edit mappings.
// Complexity: time O(I+T+Q), Omega(I+T+Q), Theta(I+T+Q) on success; auxiliary
// O(I+M+S), Omega(I+M), tight Theta not established. I identity IDs, T total
// loaded binding/origin rows, M maximum rows retained for one identity, Q/S
// delegated SQL/audit/lock costs. No current issuer or live Group is required.
func (p Projector) RemoveMappingSources(ctx context.Context, tx *sql.Tx, mappingID string) error {
	if err := p.validate(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT rb.identity_ref_id::text FROM role_binding_group_sources s JOIN role_bindings rb ON rb.id=s.binding_id WHERE s.mapping_id=$1 ORDER BY 1", mappingID)
	if err != nil {
		return err
	}
	ids, err := readIDs(rows)
	if err != nil {
		return err
	}
	for _, id := range ids {
		all, err := loadBindings(ctx, tx, id)
		if err != nil {
			return err
		}
		for _, b := range all {
			if _, exists := b.sources[mappingID]; !exists {
				continue
			}
			if err = p.changeSource(ctx, tx, b.id, mappingID, b.role, false); err != nil {
				return err
			}
			if !b.operator && len(b.sources) == 1 {
				if _, err = tx.ExecContext(ctx, "DELETE FROM role_bindings WHERE id=$1 AND NOT operator_owned AND NOT EXISTS (SELECT 1 FROM role_binding_group_sources WHERE binding_id=$1)", b.id); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// readIDs drains and closes one ordered ID query before subsequent SQL work.
// Complexity: time O(I+Q), Omega(I+Q), Theta(I+Q); auxiliary O(I+S),
// Omega(I), tight Theta not established; I ID bytes, Q/S delegated row costs.
func readIDs(rows *sql.Rows) ([]string, error) {
	var ids []string
	var err error
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
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return ids, nil
}

// newUUID uses fixed-size OS-backed entropy, propagating entropy failure.
// Complexity: time O(R), Omega(R), Theta(R), auxiliary O(1), Omega(1),
// Theta(1); R is delegated entropy latency for exactly16bytes.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
