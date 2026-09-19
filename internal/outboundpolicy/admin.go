package outboundpolicy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
)

type Impact struct {
	Aliases          int `json:"aliases"`
	ExternalTargets  int `json:"external_targets"`
	QueuedRecipients int `json:"queued_recipients"`
}

type ChangePlan struct {
	Digest         string `json:"digest"`
	DomainID       string `json:"domain_id"`
	Domain         string `json:"domain"`
	CurrentScope   Scope  `json:"current_scope"`
	RequestedScope Scope  `json:"requested_scope"`
	Revision       uint64 `json:"revision"`
	Impact         Impact `json:"impact"`
}

type ChangeResult struct {
	Plan    ChangePlan `json:"plan"`
	Changed bool       `json:"changed"`
}

type AdminService struct {
	DB  *sql.DB
	Now func() time.Time
}

const (
	maxPolicyAliases        = 100_000
	maxAliasTargetJSONBytes = 1 << 20
	maxAliasTargets         = 10_000
	maxPolicyTargetBytes    = 64 << 20
)

type policyQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Preview computes a confirmation digest from the current locked-state inputs
// without mutating policy. Apply recomputes the same plan transactionally.
// Complexity: process time O(b), Omega(1), tight worst-case Theta(b); database
// time adds O(q*s+r); auxiliary space O(j), Omega(1), where b is bounded alias
// target bytes, j is one target document, q is queue messages, s their bounded
// sources, and r their recipients.
func (s AdminService) Preview(ctx context.Context, domain string, requested Scope) (ChangePlan, error) {
	if s.DB == nil {
		return ChangePlan{}, errors.New("outbound policy database is unavailable")
	}
	return loadChangePlan(ctx, s.DB, domain, requested, false)
}

// Apply serializes one revision-bound scope change and its redacted audit
// event. Audit failure rolls back; commit failure is returned without claiming
// success.
// Complexity: process time O(b), Omega(1), tight worst-case Theta(b); database
// time adds O(q*s+r); auxiliary space O(j), Omega(1), with Preview variables;
// database locking, audit, and commit are additive.
func (s AdminService) Apply(ctx context.Context, actor audit.ActorRef, correlationID, domain string, requested Scope, confirmation string) (ChangeResult, error) {
	if s.DB == nil {
		return ChangeResult{}, errors.New("outbound policy database is unavailable")
	}
	if actor.Type == "" || actor.ID == "" || correlationID == "" {
		return ChangeResult{}, errors.New("actor and correlation ID are required")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return ChangeResult{}, err
	}
	defer tx.Rollback()
	plan, err := loadChangePlan(ctx, tx, domain, requested, true)
	if err != nil {
		return ChangeResult{}, err
	}
	if !equalPlanDigest(plan.Digest, confirmation) {
		return ChangeResult{}, errors.New("confirmation digest does not match current outbound policy state")
	}
	if plan.CurrentScope == plan.RequestedScope {
		return ChangeResult{Plan: plan, Changed: false}, nil
	}
	now := s.now()
	result, err := tx.ExecContext(ctx, `UPDATE domains SET outbound_scope=$1,outbound_policy_revision=outbound_policy_revision+1,updated_at=$2 WHERE id=$3 AND outbound_policy_revision=$4`, string(plan.RequestedScope), now, plan.DomainID, plan.Revision)
	if err != nil {
		return ChangeResult{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ChangeResult{}, err
	}
	if affected != 1 {
		return ChangeResult{}, errors.New("outbound policy revision changed")
	}
	if err := audit.WriteSQL(ctx, tx, audit.Event{
		Time:   now,
		Actor:  actor,
		Action: "domain.outbound_scope.update",
		Resource: audit.ResourceRef{
			Type: "domain", ID: plan.DomainID,
		},
		BeforeRedacted: map[string]any{"scope": plan.CurrentScope, "revision": plan.Revision},
		AfterRedacted: map[string]any{
			"scope": plan.RequestedScope, "revision": plan.Revision + 1,
			"confirmation_digest": plan.Digest, "impact": plan.Impact,
		},
		CorrelationID: correlationID,
		Result:        "success",
	}); err != nil {
		return ChangeResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ChangeResult{}, err
	}
	return ChangeResult{Plan: plan, Changed: true}, nil
}

// now supplies one UTC audit/update timestamp source.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func (s AdminService) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// loadChangePlan reads the authoritative domain revision and the current alias
// impact; lock requests a row lock for transactional confirmation.
// Complexity: process time O(b), Omega(1), tight worst-case Theta(b); database
// time adds O(q*s+r); auxiliary space O(j), Omega(1), with Preview variables.
func loadChangePlan(ctx context.Context, queryer policyQueryer, rawDomain string, requested Scope, lock bool) (ChangePlan, error) {
	if !validScope(requested) {
		return ChangePlan{}, errors.New("invalid outbound scope")
	}
	domain, err := NormalizeDomain(rawDomain)
	if err != nil {
		return ChangePlan{}, err
	}
	query := `SELECT id,name,outbound_scope,outbound_policy_revision FROM domains WHERE name=$1 AND enabled=true`
	if lock {
		query += ` FOR UPDATE`
	}
	var plan ChangePlan
	var current string
	if err := queryer.QueryRowContext(ctx, query, domain).Scan(&plan.DomainID, &plan.Domain, &current, &plan.Revision); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ChangePlan{}, errors.New("enabled domain not found")
		}
		return ChangePlan{}, err
	}
	plan.CurrentScope = Scope(current)
	plan.RequestedScope = requested
	if !validScope(plan.CurrentScope) || plan.Revision == 0 {
		return ChangePlan{}, errors.New("stored outbound policy state is invalid")
	}
	plan.Impact, err = loadAliasImpact(ctx, queryer, plan.DomainID, plan.Domain)
	if err != nil {
		return ChangePlan{}, err
	}
	plan.Impact.QueuedRecipients, err = loadQueuedRecipientImpact(ctx, queryer, plan.DomainID, plan.Domain)
	if err != nil {
		return ChangePlan{}, err
	}
	plan.Digest, err = planDigest(plan)
	if err != nil {
		return ChangePlan{}, err
	}
	return plan, nil
}

// loadQueuedRecipientImpact counts active queued recipients outside the exact
// domain when any immutable mailbox or expansion-source object belongs to that
// domain. Any unresolved source fails the preview closed.
// Complexity: database time O(q*s+r), Omega(1), tight worst-case Theta(q*s+r);
// auxiliary process space O(1), Omega(1), where q is active queue messages, s
// is bounded sources per message, and r is their recipient rows.
func loadQueuedRecipientImpact(ctx context.Context, queryer policyQueryer, domainID, domain string) (int, error) {
	var unresolved int64
	if err := queryer.QueryRowContext(ctx, `SELECT count(*)
FROM outbound_queue_sources s
JOIN outbound_queue_messages q ON q.queue_id=s.queue_id
LEFT JOIN mailboxes m ON s.source_kind IN ('authenticated_mailbox','envelope_sender') AND m.id::text=s.object_id
LEFT JOIN aliases a ON s.source_kind IN ('alias','forward','list','catch_all') AND a.id::text=s.object_id
LEFT JOIN outbound_system_senders y ON s.source_kind='system_sender' AND y.id=s.object_id
WHERE q.hold_state <> 'released' AND m.id IS NULL AND a.id IS NULL AND y.id IS NULL`).Scan(&unresolved); err != nil {
		return 0, err
	}
	if unresolved != 0 {
		return 0, errors.New("active outbound queue contains unresolved policy sources")
	}
	var count int64
	if err := queryer.QueryRowContext(ctx, `SELECT count(*)
FROM outbound_queue_recipients r
JOIN outbound_queue_messages q ON q.queue_id=r.queue_id
WHERE q.hold_state <> 'released'
  AND r.recipient_domain <> $2
  AND EXISTS (
      SELECT 1
      FROM outbound_queue_sources s
      LEFT JOIN mailboxes m ON s.source_kind IN ('authenticated_mailbox','envelope_sender') AND m.id::text=s.object_id
      LEFT JOIN aliases a ON s.source_kind IN ('alias','forward','list','catch_all') AND a.id::text=s.object_id
      LEFT JOIN outbound_system_senders y ON s.source_kind='system_sender' AND y.id=s.object_id
      WHERE s.queue_id=q.queue_id AND (m.domain_id=$1 OR a.domain_id=$1 OR y.domain_id=$1)
  )`, domainID, domain).Scan(&count); err != nil {
		return 0, err
	}
	if count < 0 || uint64(count) > uint64(^uint(0)>>1) {
		return 0, errors.New("outbound queue recipient impact exceeds process integer range")
	}
	return int(count), nil
}

// loadAliasImpact counts only enabled source aliases that currently expand to
// at least one recipient outside the exact canonical source domain.
// Complexity: worst-case time O(b), Omega(1), tight Theta(b); auxiliary space
// O(j), Omega(1), where b is at most maxPolicyTargetBytes and j is at most
// maxAliasTargetJSONBytes. The query caps rows at maxPolicyAliases+1.
func loadAliasImpact(ctx context.Context, queryer policyQueryer, domainID, domain string) (Impact, error) {
	rows, err := queryer.QueryContext(ctx, `SELECT octet_length(targets_json), CASE WHEN octet_length(targets_json) <= $3 THEN targets_json ELSE NULL END FROM aliases WHERE domain_id=$1 AND enabled=true LIMIT $2`, domainID, maxPolicyAliases+1, maxAliasTargetJSONBytes)
	if err != nil {
		return Impact{}, err
	}
	defer rows.Close()
	var impact Impact
	aliases := 0
	totalBytes := 0
	for rows.Next() {
		aliases++
		if aliases > maxPolicyAliases {
			return Impact{}, errors.New("outbound policy alias limit exceeded")
		}
		var encodedBytes int
		var encoded sql.NullString
		if err := rows.Scan(&encodedBytes, &encoded); err != nil {
			return Impact{}, err
		}
		if encodedBytes < 0 || encodedBytes > maxAliasTargetJSONBytes || !encoded.Valid || totalBytes > maxPolicyTargetBytes-encodedBytes {
			return Impact{}, errors.New("outbound policy alias target data limit exceeded")
		}
		totalBytes += encodedBytes
		var targets []string
		if err := json.Unmarshal([]byte(encoded.String), &targets); err != nil || len(targets) == 0 || len(targets) > maxAliasTargets {
			return Impact{}, errors.New("stored alias targets are invalid")
		}
		external := 0
		for _, target := range targets {
			targetDomain, err := recipientDomain(target)
			if err != nil {
				return Impact{}, errors.New("stored alias target is invalid")
			}
			if targetDomain != domain {
				external++
			}
		}
		if external > 0 {
			impact.Aliases++
			impact.ExternalTargets += external
		}
	}
	if err := rows.Err(); err != nil {
		return Impact{}, err
	}
	return impact, nil
}

// planDigest binds confirmation to all current policy and bounded impact data.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1), because the encoded plan contains only fixed-size
// scalar fields and bounded domain identifiers.
func planDigest(plan ChangePlan) (string, error) {
	payload := struct {
		Contract       string `json:"contract"`
		DomainID       string `json:"domain_id"`
		Domain         string `json:"domain"`
		CurrentScope   Scope  `json:"current_scope"`
		RequestedScope Scope  `json:"requested_scope"`
		Revision       uint64 `json:"revision"`
		Impact         Impact `json:"impact"`
	}{"gotth-mail/outbound-policy-plan/v1", plan.DomainID, plan.Domain, plan.CurrentScope, plan.RequestedScope, plan.Revision, plan.Impact}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

// validScope recognizes the complete closed outbound-policy enum.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func validScope(scope Scope) bool {
	return scope == ScopeUnrestricted || scope == ScopeSameDomainOnly
}

// equalPlanDigest compares canonical SHA-256 hex confirmations without leaking
// a useful prefix oracle.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1), because both inputs must be canonical SHA-256 hex.
func equalPlanDigest(expected, actual string) bool {
	if len(expected) != sha256.Size*2 || len(actual) != sha256.Size*2 {
		return false
	}
	left, leftErr := hex.DecodeString(expected)
	right, rightErr := hex.DecodeString(actual)
	return leftErr == nil && rightErr == nil && len(left) == sha256.Size && len(right) == sha256.Size && subtle.ConstantTimeCompare(left, right) == 1
}
