package rolebinding

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/identityruntime"
	"forgejo/gotthboard/gotth-mail/internal/roleprojection"
	"sort"
	"strings"
	"time"
)

const groupPlanSchema = "gotth-mail/group-role-plan/v2"

type GroupRequest struct{ Operation, Issuer, SCIMActor, GroupID, Role, Domain string }
type GroupImpact struct {
	IdentityID     string `json:"identity_id"`
	BindingID      string `json:"binding_id,omitempty"`
	Role           string `json:"role"`
	DomainID       string `json:"domain_id,omitempty"`
	OperatorOwned  bool   `json:"operator_owned"`
	SourcesBefore  int    `json:"sources_before"`
	SourcesAfter   int    `json:"sources_after"`
	EffectiveAfter bool   `json:"effective_after"`
}
type GroupPlan struct {
	GroupID                string        `json:"group_id"`
	Scope                  string        `json:"scope"`
	Schema                 string        `json:"schema"`
	PlanID                 string        `json:"plan_id"`
	MappingID              string        `json:"mapping_id,omitempty"`
	Operation              string        `json:"operation"`
	Role                   string        `json:"role"`
	Domain                 string        `json:"domain"`
	EnabledBefore          bool          `json:"enabled_before"`
	EnabledAfter           bool          `json:"enabled_after"`
	FutureMemberDelegation bool          `json:"future_member_delegation"`
	MemberCount            int           `json:"member_count"`
	AddedSources           int           `json:"added_sources"`
	RemovedSources         int           `json:"removed_sources"`
	EffectiveAfter         bool          `json:"effective_after"`
	Impacts                []GroupImpact `json:"origins"`
}
type GroupResult struct {
	Plan      GroupPlan `json:"plan"`
	Changed   bool      `json:"changed"`
	MappingID string    `json:"mapping_id,omitempty"`
}
type GroupService struct {
	DB            *sql.DB
	CurrentIssuer string
}
type groupMappingState struct {
	ID, Issuer, Scope, GroupID, Role, Domain, GroupVersion string
	Revision                                               int64
	Enabled, Deleted                                       bool
	Updated                                                time.Time
}
type groupMemberState struct{ ID, Scope, ExternalID, Version, DocumentHash string }
type groupBindingState struct {
	ID, Role, Domain        string
	Operator, DomainEnabled bool
	Revision                int64
	Updated                 time.Time
	Sources                 []groupMappingState
}
type groupIdentityState struct {
	ID          string
	Eligibility roleprojection.Eligibility
	Bindings    []groupBindingState
}
type groupState struct {
	Scope, DomainID, GroupVersion, Operation string
	DomainEnabled, GroupExists, Tombstone    bool
	Mapping                                  groupMappingState
	Members                                  []groupMemberState
	Identities                               []groupIdentityState
}

// Preview is a pure read-only repeatable snapshot, never a write/savepoint simulation.
// Complexity: B snapshot/encoded bytes, E origins, Q/S SQL work/space: successful
// time O(B+E log E+Q), Omega(B+E+Q), no tight Theta established; auxiliary
// O(B+E+S), Omega(B+E), no tight Theta established. Errors may stop at Omega(1).
func (s GroupService) Preview(ctx context.Context, r GroupRequest) (GroupPlan, error) {
	r, err := s.normalizeGroup(r)
	if err != nil {
		return GroupPlan{}, err
	}
	s.CurrentIssuer = identityruntime.NormalizeIssuer(s.CurrentIssuer)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return GroupPlan{}, err
	}
	defer tx.Rollback()
	state, err := loadGroupState(ctx, tx, r, s.CurrentIssuer)
	if err != nil {
		return GroupPlan{}, err
	}
	p, err := buildGroupPlan(r, s.CurrentIssuer, state)
	if err != nil {
		return GroupPlan{}, err
	}
	if err = tx.Commit(); err != nil {
		return GroupPlan{}, err
	}
	return p, nil
}

// Apply re-reads/recomputes one SERIALIZABLE snapshot before exact confirmation.
// Absent-row protection is the predicate snapshot plus tuple uniqueness, not an
// imaginary row lock. No-op never reconciles; mutations and all audits share tx.
// Complexity: B/E as Preview, Q/W/S delegated SQL/projection/audit costs: time
// O(B+E log E+Q+W), Omega(B+E+Q+W), no tight Theta established; auxiliary
// O(B+E+S), Omega(B+E), no tight Theta established. No retry/network.
func (s GroupService) Apply(ctx context.Context, r GroupRequest, confirmation string) (GroupResult, error) {
	r, err := s.normalizeGroup(r)
	if err != nil {
		return GroupResult{}, err
	}
	s.CurrentIssuer = identityruntime.NormalizeIssuer(s.CurrentIssuer)
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return GroupResult{}, err
	}
	defer tx.Rollback()
	state, err := loadGroupState(ctx, tx, r, s.CurrentIssuer)
	if err != nil {
		return GroupResult{}, err
	}
	p, err := buildGroupPlan(r, s.CurrentIssuer, state)
	if err != nil {
		return GroupResult{}, err
	}
	if !equalDigest(p.PlanID, strings.TrimSpace(confirmation)) {
		return GroupResult{}, errors.New("confirmation digest does not match current group mapping state")
	}
	result := GroupResult{Plan: p, MappingID: state.Mapping.ID}
	if p.Operation == "unchanged" {
		if err = tx.Commit(); err != nil {
			return GroupResult{}, err
		}
		return result, nil
	}
	now := time.Now().UTC()
	if state.Mapping.ID == "" {
		id, err := randomUUID(nil)
		if err != nil {
			return GroupResult{}, err
		}
		result.MappingID = id
		var domain any
		if state.DomainID != "" {
			domain = state.DomainID
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO identity_group_role_mappings(id,issuer,scope,group_id,role,domain_id,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`, id, r.Issuer, state.Scope, r.GroupID, r.Role, domain, now); err != nil {
			return GroupResult{}, err
		}
	} else {
		v, err := tx.ExecContext(ctx, "UPDATE identity_group_role_mappings SET enabled=$2,revision=revision+1,updated_at=$3 WHERE id=$1", state.Mapping.ID, r.Operation == "admit", now)
		if err != nil {
			return GroupResult{}, err
		}
		n, err := v.RowsAffected()
		if err != nil {
			return GroupResult{}, err
		}
		if n != 1 {
			return GroupResult{}, errors.New("group mapping did not affect one exact row")
		}
	}
	projector := roleprojection.Projector{CurrentIssuer: s.CurrentIssuer, Actor: audit.ActorRef{Type: "local_admin", ID: "cli"}, CorrelationID: "gotth-mailctl-group-role"}
	if r.Operation == "admit" {
		err = projector.SyncGroup(ctx, tx, state.Scope, r.GroupID)
	} else {
		err = projector.RemoveMappingSources(ctx, tx, result.MappingID)
	}
	if err != nil {
		return GroupResult{}, err
	}
	redacted := map[string]any{"group_id": r.GroupID, "scope": state.Scope, "role": r.Role, "domain": r.Domain, "enabled_before": p.EnabledBefore, "enabled_after": p.EnabledAfter, "future_member_delegation": p.FutureMemberDelegation, "added_sources": p.AddedSources, "removed_sources": p.RemovedSources, "effective_after": p.EffectiveAfter}
	if err = audit.WriteSQL(ctx, tx, audit.Event{Time: now, Actor: projector.Actor, CorrelationID: projector.CorrelationID, Action: "identity.group_role_mapping." + r.Operation, Resource: audit.ResourceRef{Type: "identity_group_role_mapping", ID: result.MappingID}, AfterRedacted: redacted, Result: "success"}); err != nil {
		return GroupResult{}, err
	}
	if err = tx.Commit(); err != nil {
		return GroupResult{}, err
	}
	result.Changed = true
	return result, nil
}

// normalizeGroup reuses operator domain/issuer/text rules and canonical issuer
// normalization. Scope has no input field. Empty authority is recovery-only.
// Complexity: n input bytes, time/space O(n), Omega(1), no uniform tight Theta;
// successful validation reads all strings, giving time Theta(n).
func (s GroupService) normalizeGroup(r GroupRequest) (GroupRequest, error) {
	if s.DB == nil {
		return r, errors.New("group mapping database is unavailable")
	}
	r.Operation = strings.TrimSpace(r.Operation)
	r.Issuer = identityruntime.NormalizeIssuer(r.Issuer)
	r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
	r.Role = strings.TrimSpace(r.Role)
	authority := identityruntime.NormalizeIssuer(s.CurrentIssuer)
	if authority != "" && !validIssuer(authority) {
		return r, errors.New("configured identity authority is invalid")
	}
	if (r.Operation != "admit" && r.Operation != "disable") || !validIssuer(r.Issuer) || !roleprojection.ValidRoleDomain(r.Role, r.Domain) || (r.Domain != "" && !validDomain(r.Domain)) || !validText(r.SCIMActor, 1, 1024) || r.SCIMActor != strings.TrimSpace(r.SCIMActor) || !validText(r.GroupID, 1, 1024) || r.GroupID != strings.TrimSpace(r.GroupID) {
		return r, errors.New("group mapping request is invalid")
	}
	if r.Operation == "admit" && (authority == "" || r.Issuer != authority) {
		return r, errors.New("admit requires exact configured issuer")
	}
	return r, nil
}

// loadGroupState reads canonical typed Group/member and exact affected provenance.
// Disable/no-op uses metadata only, never admission-only User parsing. New mapping
// candidates plus every existing Group source owner match SyncGroup's scope.
// Complexity: B returned User/snapshot bytes, I identities, Q/S SQL: successful
// time O(B+I+Q), Omega(B+I+Q), Theta(B+I+Q); auxiliary O(B+I+S), Omega(I),
// no tight Theta established. Fingerprints retain hashes, not User payloads.
func loadGroupState(ctx context.Context, tx *sql.Tx, r GroupRequest, authority string) (groupState, error) {
	st := groupState{Scope: identityruntime.Scope(r.SCIMActor)}
	var err error
	st.DomainEnabled = r.Role == RoleGlobalAdmin
	if r.Domain != "" {
		err = tx.QueryRowContext(ctx, "SELECT id::text,enabled FROM domains WHERE name=$1", r.Domain).Scan(&st.DomainID, &st.DomainEnabled)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}
	var domain any
	if st.DomainID != "" {
		domain = st.DomainID
	}
	st.Mapping = groupMappingState{Issuer: r.Issuer, Scope: st.Scope, GroupID: r.GroupID, Role: r.Role, Domain: st.DomainID}
	err = tx.QueryRowContext(ctx, "SELECT id::text,revision,enabled,group_deleted,updated_at FROM identity_group_role_mappings WHERE issuer=$1 AND scope=$2 AND group_id=$3 AND role=$4 AND domain_id IS NOT DISTINCT FROM $5::uuid", r.Issuer, st.Scope, r.GroupID, r.Role, domain).Scan(&st.Mapping.ID, &st.Mapping.Revision, &st.Mapping.Enabled, &st.Mapping.Deleted, &st.Mapping.Updated)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}
	err = tx.QueryRowContext(ctx, "SELECT version FROM scim_resources WHERE scope=$1 AND resource_type='Group' AND id=$2", st.Scope, r.GroupID).Scan(&st.GroupVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return st, err
	}
	st.GroupExists = err == nil
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM scim_tombstones WHERE scope=$1 AND resource_type='Group' AND id=$2 UNION ALL SELECT 1 FROM identity_group_role_mappings WHERE scope=$1 AND group_id=$2 AND group_deleted)", st.Scope, r.GroupID).Scan(&st.Tombstone); err != nil {
		return st, err
	}
	if r.Operation == "admit" && (!st.GroupExists || st.Tombstone || st.Mapping.Deleted || (r.Role != RoleGlobalAdmin && st.DomainID == "") || !st.DomainEnabled) {
		return st, errors.New("admit requires live untombstoned Group and enabled exact domain")
	}
	st.Operation = r.Operation
	if r.Operation == "admit" && st.Mapping.Enabled || r.Operation == "disable" && !st.Mapping.Enabled {
		st.Operation = "unchanged"
	}
	rows, err := tx.QueryContext(ctx, `SELECT u.id,u.scope,u.external_id,u.version,u.data FROM scim_group_members edge JOIN scim_resources u ON u.resource_type='User' AND u.scope=edge.scope AND u.id=edge.user_id WHERE edge.scope=$1 AND edge.group_id=$2 ORDER BY u.id`, st.Scope, r.GroupID)
	if err != nil {
		return st, err
	}
	for rows.Next() {
		var m groupMemberState
		var data []byte
		if err = rows.Scan(&m.ID, &m.Scope, &m.ExternalID, &m.Version, &data); err != nil {
			break
		}
		sum := sha256.Sum256(data)
		m.DocumentHash = hex.EncodeToString(sum[:])
		st.Members = append(st.Members, m)
	}
	if err == nil {
		err = rows.Err()
	}
	closeErr := rows.Close()
	if err != nil {
		return st, err
	}
	if closeErr != nil {
		return st, closeErr
	}
	rows, err = tx.QueryContext(ctx, `SELECT ir.id::text FROM identity_refs ir JOIN mailboxes m ON m.id=ir.mailbox_id JOIN scim_resources u ON u.id=m.scim_resource_id AND u.resource_type='User' AND u.external_id=ir.subject JOIN scim_group_members edge ON edge.scope=u.scope AND edge.user_id=u.id WHERE ir.provider='authentik' AND edge.scope=$1 AND edge.group_id=$2 AND (ir.issuer=$3 OR EXISTS(SELECT 1 FROM identity_group_role_mappings gm WHERE gm.scope=edge.scope AND gm.group_id=edge.group_id AND gm.issuer=ir.issuer)) UNION SELECT rb.identity_ref_id::text FROM role_binding_group_sources src JOIN role_bindings rb ON rb.id=src.binding_id JOIN identity_group_role_mappings gm ON gm.id=src.mapping_id WHERE gm.scope=$1 AND gm.group_id=$2 ORDER BY 1`, st.Scope, r.GroupID, r.Issuer)
	if err != nil {
		return st, err
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
	closeErr = rows.Close()
	if err != nil {
		return st, err
	}
	if closeErr != nil {
		return st, closeErr
	}
	for _, id := range ids {
		item := groupIdentityState{ID: id}
		if st.Operation == "admit" {
			item.Eligibility, err = roleprojection.ReadEligibility(ctx, tx, id, false)
		} else {
			item.Eligibility, err = roleprojection.ReadIdentityMetadata(ctx, tx, id)
		}
		if err != nil {
			return st, err
		}
		item.Bindings, err = readGroupBindings(ctx, tx, id)
		if err != nil {
			return st, err
		}
		st.Identities = append(st.Identities, item)
	}
	return st, nil
}

// readGroupBindings binds all origin revisions/flags/role-domain predicates and
// local target flags, including independent sources that survive a disable.
// Complexity: E returned bytes, Q/S SQL: time O(E+Q), Omega(E+Q), Theta(E+Q);
// auxiliary O(E+S), Omega(E), no tight Theta established on successful reads.
func readGroupBindings(ctx context.Context, tx *sql.Tx, id string) ([]groupBindingState, error) {
	rows, err := tx.QueryContext(ctx, "SELECT rb.id::text,rb.role,COALESCE(rb.domain_id::text,''),rb.operator_owned,rb.authority_revision,rb.updated_at,COALESCE(d.enabled,true) FROM role_bindings rb LEFT JOIN domains d ON d.id=rb.domain_id WHERE rb.identity_ref_id=$1 ORDER BY rb.id", id)
	if err != nil {
		return nil, err
	}
	var out []groupBindingState
	for rows.Next() {
		var b groupBindingState
		if err = rows.Scan(&b.ID, &b.Role, &b.Domain, &b.Operator, &b.Revision, &b.Updated, &b.DomainEnabled); err != nil {
			break
		}
		out = append(out, b)
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
	for i := range out {
		rows, err = tx.QueryContext(ctx, `SELECT gm.id::text,gm.issuer,gm.scope,gm.group_id,gm.role,COALESCE(gm.domain_id::text,''),gm.revision,gm.enabled,gm.group_deleted,gm.updated_at,COALESCE(g.version,'') FROM role_binding_group_sources src JOIN identity_group_role_mappings gm ON gm.id=src.mapping_id LEFT JOIN scim_resources g ON g.scope=gm.scope AND g.resource_type='Group' AND g.id=gm.group_id WHERE src.binding_id=$1 ORDER BY gm.id`, out[i].ID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var m groupMappingState
			if err = rows.Scan(&m.ID, &m.Issuer, &m.Scope, &m.GroupID, &m.Role, &m.Domain, &m.Revision, &m.Enabled, &m.Deleted, &m.Updated, &m.GroupVersion); err != nil {
				break
			}
			out[i].Sources = append(out[i].Sources, m)
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
	}
	return out, nil
}

// buildGroupPlan models exactly the selected writer: full affected identity diff
// for changed admit; target-only removal for disable; no reconciliation for no-op.
// It is pure and never assigns a fabricated identity or effective binding UUID.
// Complexity: B encoded snapshot bytes, E origins: expected time O(B+E log E),
// Omega(B+E), no tight Theta established; auxiliary O(B+E), Omega(B+E),
// Theta(B+E). Maps use expected constant lookup; SQL work belongs to the reader.
func buildGroupPlan(r GroupRequest, authority string, st groupState) (GroupPlan, error) {
	p := GroupPlan{GroupID: r.GroupID, Scope: st.Scope, Schema: groupPlanSchema, MappingID: st.Mapping.ID, Operation: st.Operation, Role: r.Role, Domain: r.Domain, EnabledBefore: st.Mapping.Enabled, EnabledAfter: r.Operation == "admit", MemberCount: len(st.Members), Impacts: []GroupImpact{}}
	if st.Operation == "unchanged" {
		p.EnabledAfter = st.Mapping.Enabled
	}
	p.FutureMemberDelegation = p.EnabledAfter && !st.Mapping.Deleted
	members := map[string]bool{}
	for _, m := range st.Members {
		members[m.ID] = true
	}
	target := st.Mapping
	if target.ID == "" {
		target.ID = "prospective-mapping"
	}
	target.Enabled = true
	target.Deleted = false
	for _, identity := range st.Identities {
		e := identity.Eligibility
		bindings := map[string]groupBindingState{}
		after := map[string]map[string]groupMappingState{}
		selected := false
		for _, b := range identity.Bindings {
			key := b.Role + "\x00" + b.Domain
			bindings[key] = b
			after[key] = map[string]groupMappingState{}
			for _, src := range b.Sources {
				after[key][src.ID] = src
				if src.ID == st.Mapping.ID {
					selected = true
				}
			}
		}
		if st.Operation == "admit" || st.Operation == "disable" && selected {
			for _, b := range identity.Bindings {
				if !b.Operator && len(b.Sources) == 0 {
					return p, errors.New("projection encountered source-less nonoperator binding")
				}
				for _, m := range b.Sources {
					if !roleprojection.ValidRoleDomain(m.Role, m.Domain) || m.Role != b.Role || m.Domain != b.Domain {
						return p, errors.New("projection source role/domain invariant violated")
					}
				}
			}
		}
		if st.Operation == "admit" {
			desired := map[string]groupMappingState{}
			domains := map[string]bool{}
			for _, m := range e.Mappings {
				desired[m.ID] = groupMappingState{ID: m.ID, Issuer: m.Issuer, Scope: m.Scope, GroupID: m.GroupID, Role: m.Role, Domain: m.Domain, Revision: m.Revision, Enabled: true, GroupVersion: m.GroupVersion}
				domains[m.Domain] = m.DomainEnabled
			}
			if e.Active && e.Provider == "authentik" && e.Issuer == r.Issuer && e.Scope == st.Scope && e.ExternalID == e.Subject && members[e.UserID] {
				desired[target.ID] = target
				domains[target.Domain] = st.DomainEnabled
			}
			for key, sources := range after {
				for id := range sources {
					m, keep := desired[id]
					if !keep || m.Role != bindings[key].Role || m.Domain != bindings[key].Domain {
						delete(sources, id)
						p.RemovedSources++
					} else {
						sources[id] = m
					}
				}
			}
			if authority != "" && authority == e.Issuer {
				for id, m := range desired {
					key := m.Role + "\x00" + m.Domain
					if _, ok := after[key]; !ok {
						after[key] = map[string]groupMappingState{}
						bindings[key] = groupBindingState{Role: m.Role, Domain: m.Domain, DomainEnabled: domains[m.Domain]}
					}
					if _, ok := after[key][id]; !ok {
						after[key][id] = m
						p.AddedSources++
					}
				}
			}
		} else if st.Operation == "disable" {
			for _, sources := range after {
				if _, ok := sources[st.Mapping.ID]; ok {
					delete(sources, st.Mapping.ID)
					p.RemovedSources++
				}
			}
		}
		keys := make([]string, 0, len(bindings))
		for key := range bindings {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			b := bindings[key]
			sources := after[key]
			effective := e.MailboxEnabled && b.Operator
			if e.MailboxEnabled && e.MailboxDomainEnabled && b.DomainEnabled && e.Provider == "authentik" && authority != "" && authority == e.Issuer {
				for _, m := range sources {
					if m.Enabled && !m.Deleted && m.Issuer == authority && m.Role == b.Role && m.Domain == b.Domain {
						effective = true
					}
				}
			}
			p.Impacts = append(p.Impacts, GroupImpact{IdentityID: identity.ID, BindingID: b.ID, Role: b.Role, DomainID: b.Domain, OperatorOwned: b.Operator, SourcesBefore: len(b.Sources), SourcesAfter: len(sources), EffectiveAfter: effective})
			if b.Role == r.Role && b.Domain == st.DomainID && effective {
				p.EffectiveAfter = true
			}
		}
	}
	raw, err := json.Marshal(struct {
		Schema, Authority string
		Request           GroupRequest
		State             groupState
	}{groupPlanSchema, authority, r, st})
	if err != nil {
		return p, err
	}
	sum := sha256.Sum256(raw)
	p.PlanID = hex.EncodeToString(sum[:])
	return p, nil
}
