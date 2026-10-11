package rolebinding

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/roleprojection"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"reflect"
	"strings"
	"time"
)

const recoverySchema = "gotth-mail/group-feature-disable-plan/v1"

type GroupRecoveryService struct{ DB *sql.DB }
type RecoveryMapping struct {
	ID             string  `json:"mapping_id"`
	Role           string  `json:"role"`
	DomainID       *string `json:"domain_id"`
	Revision       int64   `json:"revision"`
	EnabledBefore  bool    `json:"enabled_before"`
	RemovedSources int     `json:"removed_sources"`
	Changed        bool    `json:"changed"`
}
type RecoveryBinding struct {
	ID             string  `json:"binding_id"`
	Role           string  `json:"role"`
	DomainID       *string `json:"domain_id"`
	Revision       int64   `json:"revision"`
	OperatorOwned  bool    `json:"operator_owned"`
	RemovedSources int     `json:"removed_sources"`
	Preserved      bool    `json:"preserved"`
}
type RecoveryPlan struct {
	Schema          string            `json:"schema"`
	PlanID          string            `json:"plan_id"`
	ChangedMappings int               `json:"changed_mappings"`
	RemovedSources  int               `json:"removed_sources"`
	Mappings        []RecoveryMapping `json:"mappings"`
	Bindings        []RecoveryBinding `json:"bindings"`
}
type RecoveryResult struct {
	Plan    RecoveryPlan `json:"plan"`
	Changed bool         `json:"changed"`
}
type recoveryMapping struct {
	ID, Issuer, Scope, GroupID, Role string
	Domain                           *string
	Revision                         int64
	Enabled, Deleted                 bool
	Created, Updated                 time.Time
}
type recoveryBinding struct {
	ID, IdentityID, Role string
	Domain               *string
	Operator             bool
	Revision             int64
	Created, Updated     time.Time
}
type recoverySource struct{ BindingID, MappingID string }
type recoveryLedger struct {
	Version, Checksum string
	Dirty             bool
	Applied           time.Time
}
type recoveryState struct {
	Database, User string
	Mappings       []recoveryMapping
	Bindings       []recoveryBinding
	Sources        []recoverySource
	Ledger         []recoveryLedger
}

// Preview observes one read-only repeatable snapshot; private authority never
// escapes through the returned plan. The digest confirms state, not a fence.
// Complexity: N snapshot bytes, Q/S SQL; time O(N+Q), Omega(N), space O(N+S),
// Omega(N); no tight bound for delegated Q/S. No writes/retries/provider calls.
func (s GroupRecoveryService) Preview(ctx context.Context) (RecoveryPlan, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, e := s.begin(ctx, false)
	if e != nil {
		return RecoveryPlan{}, e
	}
	defer tx.Rollback()
	st, e := readRecovery(ctx, tx)
	if e != nil {
		return RecoveryPlan{}, e
	}
	p, e := planRecovery(st)
	if e != nil {
		return p, e
	}
	e = tx.Commit()
	return p, e
}

// Apply owns exactly one SERIALIZABLE transaction. External namespace trust and
// writer quiescence are prerequisites, never inferred from locks or confirmation.
// Complexity: M mappings,B bindings,E origins,N bytes; time O(N+M*(B+E)+Q),
// Omega(N), auxiliary O(N+S), Omega(N). Leaf rereads and SQL/locks/audits Q/S
// remain explicit. No tight delegated bound; timeout never creates partial batches.
func (s GroupRecoveryService) Apply(ctx context.Context, confirmation string) (RecoveryResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	tx, e := s.begin(ctx, true)
	if e != nil {
		return RecoveryResult{}, e
	}
	defer tx.Rollback()
	st, e := readRecovery(ctx, tx)
	if e != nil {
		return RecoveryResult{}, e
	}
	p, e := planRecovery(st)
	if e != nil {
		return RecoveryResult{}, e
	}
	if !equalDigest(p.PlanID, strings.TrimSpace(confirmation)) {
		return RecoveryResult{}, errors.New("recovery confirmation is stale")
	}
	result := RecoveryResult{Plan: p}
	if p.ChangedMappings == 0 {
		if e = tx.Commit(); e != nil {
			return result, fmt.Errorf("recovery commit outcome requires inspection: %w", e)
		}
		return result, nil
	}
	now := time.Now().UTC()
	actor := audit.ActorRef{Type: "local_admin", ID: "cli"}
	projector := roleprojection.Projector{Actor: actor, CorrelationID: "gotth-mailctl-group-feature-disable"}
	for _, m := range p.Mappings {
		if !m.Changed {
			continue
		}
		v, err := tx.ExecContext(ctx, "UPDATE public.identity_group_role_mappings SET enabled=false,revision=revision+1,updated_at=$2 WHERE id=$1", m.ID, now)
		if err != nil {
			return result, err
		}
		n, err := v.RowsAffected()
		if err != nil || n != 1 {
			return result, errors.New("recovery mapping update did not affect one row")
		}
		if m.RemovedSources > 0 {
			if err = projector.RemoveMappingSources(ctx, tx, m.ID); err != nil {
				return result, err
			}
		}
		if err = audit.WriteSQL(ctx, tx, audit.Event{Time: now, Actor: actor, CorrelationID: projector.CorrelationID, Action: "identity.group_role_mapping.disable", Resource: audit.ResourceRef{Type: "identity_group_role_mapping", ID: m.ID}, BeforeRedacted: map[string]any{"enabled": m.EnabledBefore, "revision": m.Revision}, AfterRedacted: map[string]any{"enabled": false, "revision": m.Revision + 1, "removed_sources": m.RemovedSources, "reason": "feature_disable"}, Result: "success"}); err != nil {
			return result, err
		}
	}
	after, e := readRecovery(ctx, tx)
	if e != nil {
		return result, e
	}
	if e = verifyRecovery(st, after, p); e != nil {
		return result, e
	}
	if e = audit.WriteSQL(ctx, tx, audit.Event{Time: now, Actor: actor, CorrelationID: projector.CorrelationID, Action: "identity.group_role_feature.disable", Resource: audit.ResourceRef{Type: "identity_group_role_feature", ID: "all"}, AfterRedacted: map[string]any{"changed_mappings": p.ChangedMappings, "removed_sources": p.RemovedSources, "plan_id": p.PlanID}, Result: "success"}); e != nil {
		return result, e
	}
	if e = tx.Commit(); e != nil {
		return result, fmt.Errorf("recovery commit outcome requires inspection: %w", e)
	}
	result.Changed = true
	return result, nil
}

// begin sets recovery-local utility policy and acquires all four locks BEFORE
// any SELECT, including schema checks/current_user. It never certifies host trust.
// Complexity: fixed statements plus delegated locks Q/S: O(Q), Omega(1) time,
// O(S+1), Omega(1) space; no uniform tight bound under lock/error latency.
func (s GroupRecoveryService) begin(ctx context.Context, apply bool) (*sql.Tx, error) {
	if s.DB == nil {
		return nil, errors.New("recovery database is unavailable")
	}
	opt := &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	if apply {
		opt = &sql.TxOptions{Isolation: sql.LevelSerializable}
	}
	tx, e := s.DB.BeginTx(ctx, opt)
	if e != nil {
		return nil, e
	}
	statements := []string{"SET LOCAL search_path = pg_catalog,public,pg_temp", "SET LOCAL row_security = off"}
	if apply {
		statements = append(statements, "LOCK TABLE public.schema_migrations IN SHARE MODE NOWAIT", "LOCK TABLE public.identity_group_role_mappings IN SHARE ROW EXCLUSIVE MODE NOWAIT", "LOCK TABLE public.role_bindings IN SHARE ROW EXCLUSIVE MODE NOWAIT", "LOCK TABLE public.role_binding_group_sources IN SHARE ROW EXCLUSIVE MODE NOWAIT")
	}
	for _, q := range statements {
		if _, e = tx.ExecContext(ctx, q); e != nil {
			tx.Rollback()
			return nil, e
		}
	}
	return tx, nil
}

// readRecovery retains only canonical metadata, never User documents/subjects.
// Complexity: N returned bytes plus Q/S SQL; O(N+Q) time/O(N+S) space, Omega(N)
// each on success; no tight delegated bound. LEFT JOINs expose dangling endpoints.
func readRecovery(ctx context.Context, tx *sql.Tx) (recoveryState, error) {
	st := recoveryState{Mappings: []recoveryMapping{}, Bindings: []recoveryBinding{}, Sources: []recoverySource{}, Ledger: []recoveryLedger{}}
	if e := store.ValidateCurrentSQL(ctx, tx); e != nil {
		return st, e
	}
	if e := tx.QueryRowContext(ctx, "SELECT pg_catalog.current_database(), CURRENT_USER").Scan(&st.Database, &st.User); e != nil {
		return st, e
	}
	e := recoveryRows(ctx, tx, "SELECT m.id::text,m.issuer,m.scope,m.group_id,m.role,m.domain_id::text,m.revision,m.enabled,m.group_deleted,m.created_at,m.updated_at,(m.domain_id IS NULL OR d.id IS NOT NULL) FROM public.identity_group_role_mappings m LEFT JOIN public.domains d ON d.id=m.domain_id ORDER BY m.id", func(rows *sql.Rows) error {
		var m recoveryMapping
		var endpoint bool
		if e := rows.Scan(&m.ID, &m.Issuer, &m.Scope, &m.GroupID, &m.Role, &m.Domain, &m.Revision, &m.Enabled, &m.Deleted, &m.Created, &m.Updated, &endpoint); e != nil {
			return e
		}
		domain := ""
		if m.Domain != nil {
			domain = *m.Domain
		}
		if !endpoint || !validIssuer(m.Issuer) || !validText(m.Issuer, 1, 2048) || !validText(m.Scope, 1, 1024) || !validText(m.GroupID, 1, 1024) || !roleprojection.ValidRoleDomain(m.Role, domain) || m.Revision < 1 || m.Deleted && m.Enabled {
			return errors.New("recovery mapping invariant violated")
		}
		st.Mappings = append(st.Mappings, m)
		return nil
	})
	if e != nil {
		return st, e
	}
	e = recoveryRows(ctx, tx, "SELECT b.id::text,b.identity_ref_id::text,b.role,b.domain_id::text,b.operator_owned,b.authority_revision,b.created_at,b.updated_at,(i.id IS NOT NULL AND (b.domain_id IS NULL OR d.id IS NOT NULL)) FROM public.role_bindings b LEFT JOIN public.identity_refs i ON i.id=b.identity_ref_id LEFT JOIN public.domains d ON d.id=b.domain_id ORDER BY b.id", func(rows *sql.Rows) error {
		var b recoveryBinding
		var endpoint bool
		if e := rows.Scan(&b.ID, &b.IdentityID, &b.Role, &b.Domain, &b.Operator, &b.Revision, &b.Created, &b.Updated, &endpoint); e != nil {
			return e
		}
		domain := ""
		if b.Domain != nil {
			domain = *b.Domain
		}
		if !endpoint || !roleprojection.ValidRoleDomain(b.Role, domain) || b.Revision < 1 {
			return errors.New("recovery binding invariant violated")
		}
		st.Bindings = append(st.Bindings, b)
		return nil
	})
	if e != nil {
		return st, e
	}
	e = recoveryRows(ctx, tx, "SELECT binding_id::text,mapping_id::text FROM public.role_binding_group_sources ORDER BY binding_id,mapping_id", func(rows *sql.Rows) error {
		var src recoverySource
		if e := rows.Scan(&src.BindingID, &src.MappingID); e != nil {
			return e
		}
		st.Sources = append(st.Sources, src)
		return nil
	})
	if e != nil {
		return st, e
	}
	e = recoveryRows(ctx, tx, "SELECT version,checksum,dirty,applied_at FROM public.schema_migrations ORDER BY version", func(rows *sql.Rows) error {
		var l recoveryLedger
		if e := rows.Scan(&l.Version, &l.Checksum, &l.Dirty, &l.Applied); e != nil {
			return e
		}
		st.Ledger = append(st.Ledger, l)
		return nil
	})
	return st, e
}

// recoveryRows drains/closes one fixed query before another query on the tx.
// Complexity: N rows and delegated query/scan Q/S, O(N+Q)/O(S+1), Omega(N)/Omega(1)
// on success; callbacks retain their documented state, not hidden buffers here.
func recoveryRows(ctx context.Context, tx *sql.Tx, q string, consume func(*sql.Rows) error) error {
	rows, e := tx.QueryContext(ctx, q)
	if e != nil {
		return e
	}
	defer rows.Close()
	for rows.Next() {
		if e = consume(rows); e != nil {
			return e
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	return rows.Close()
}

// planRecovery validates every edge (including orphans hidden by inner joins) and
// derives the exact global withdrawal. No eligibility or projection-add work.
// Complexity: N metadata bytes; expected O(N) time/space, Omega(N); map lookup
// costs expected constant, JSON hashing/copying explicit; no SQL or side effects.
func planRecovery(st recoveryState) (RecoveryPlan, error) {
	p := RecoveryPlan{Schema: recoverySchema, Mappings: []RecoveryMapping{}, Bindings: []RecoveryBinding{}, RemovedSources: len(st.Sources)}
	mm := map[string]recoveryMapping{}
	bb := map[string]recoveryBinding{}
	mc := map[string]int{}
	bc := map[string]int{}
	for _, m := range st.Mappings {
		if _, ok := mm[m.ID]; ok {
			return p, errors.New("recovery duplicate mapping")
		}
		mm[m.ID] = m
	}
	for _, b := range st.Bindings {
		if _, ok := bb[b.ID]; ok {
			return p, errors.New("recovery duplicate binding")
		}
		bb[b.ID] = b
	}
	seen := map[recoverySource]bool{}
	for _, edge := range st.Sources {
		if seen[edge] {
			return p, errors.New("recovery duplicate source")
		}
		seen[edge] = true
		m, mok := mm[edge.MappingID]
		b, bok := bb[edge.BindingID]
		if !mok || !bok || m.Role != b.Role || !reflect.DeepEqual(m.Domain, b.Domain) {
			return p, errors.New("recovery source invariant violated")
		}
		mc[m.ID]++
		bc[b.ID]++
	}
	for _, m := range st.Mappings {
		changed := m.Enabled || mc[m.ID] > 0
		if changed {
			p.ChangedMappings++
		}
		p.Mappings = append(p.Mappings, RecoveryMapping{m.ID, m.Role, m.Domain, m.Revision, m.Enabled, mc[m.ID], changed})
	}
	for _, b := range st.Bindings {
		if !b.Operator && bc[b.ID] == 0 {
			return p, errors.New("recovery found preexisting nonoperator orphan")
		}
		p.Bindings = append(p.Bindings, RecoveryBinding{b.ID, b.Role, b.Domain, b.Revision, b.Operator, bc[b.ID], b.Operator})
	}
	payload, e := json.Marshal(struct {
		Schema string
		State  recoveryState
	}{recoverySchema, st})
	if e != nil {
		return p, e
	}
	digest := sha256.Sum256(payload)
	p.PlanID = hex.EncodeToString(digest[:])
	return p, nil
}

// verifyRecovery checks exact preserved operator tuples, intended revisions and
// mapping metadata/ledger history, not just final row counts.
// Complexity: N state bytes; expected O(N) time/space, Omega(N); no delegated SQL.
func verifyRecovery(before, after recoveryState, p RecoveryPlan) error {
	bad := errors.New("recovery postcondition failed")
	if before.Database != after.Database || before.User != after.User || !reflect.DeepEqual(before.Ledger, after.Ledger) || len(after.Sources) != 0 || len(before.Mappings) != len(after.Mappings) {
		return bad
	}
	for i, m := range before.Mappings {
		a := after.Mappings[i]
		if p.Mappings[i].Changed {
			m.Enabled = false
			m.Revision++
			m.Updated = a.Updated
		}
		if !reflect.DeepEqual(m, a) || a.Enabled {
			return bad
		}
	}
	j := 0
	for i, b := range before.Bindings {
		if !b.Operator {
			continue
		}
		if j >= len(after.Bindings) {
			return bad
		}
		a := after.Bindings[j]
		b.Revision += int64(p.Bindings[i].RemovedSources)
		if p.Bindings[i].RemovedSources > 0 {
			b.Updated = a.Updated
		}
		if !reflect.DeepEqual(b, a) {
			return bad
		}
		j++
	}
	if j != len(after.Bindings) {
		return bad
	}
	return nil
}
