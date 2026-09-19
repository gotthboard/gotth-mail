package outboundpolicy

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"github.com/lib/pq"
)

type EnforcementRequest struct {
	Stage                Stage         `json:"stage"`
	QueueID              string        `json:"queue_id,omitempty"`
	AuthenticatedMailbox string        `json:"authenticated_mailbox,omitempty"`
	SystemSenderID       string        `json:"system_sender_id,omitempty"`
	EnvelopeSender       string        `json:"envelope_sender,omitempty"`
	Recipient            string        `json:"recipient"`
	ExpansionSources     []QueueSource `json:"expansion_sources,omitempty"`
}

type EnforcementService struct {
	DB        *sql.DB
	Queue     QueueStore
	HoldActor audit.ActorRef
}

type SystemSenderBinding struct {
	ID       string `json:"id"`
	DomainID string `json:"domain_id"`
	Address  string `json:"address"`
	Enabled  bool   `json:"enabled"`
	Revision uint64 `json:"revision"`
}

type SystemSenderStore struct {
	DB  *sql.DB
	Now func() time.Time
}

// Decide resolves every governing domain from authoritative object state. A
// caller supplies identities and opaque source IDs, never policy domains.
// Transport loads immutable provenance by queue ID and records a required hold
// before returning the defer decision.
// Complexity: process time O(s*m+r log r+b), Omega(s); database time adds
// O(s log N), auxiliary space O(s*m+r+b), where bounded s is sources, m domain
// length, r recipients, b their bytes, and N is authoritative object rows.
func (s EnforcementService) Decide(ctx context.Context, correlationID string, req EnforcementRequest) (Decision, error) {
	if s.DB == nil || strings.TrimSpace(correlationID) == "" {
		return unavailableDecision(errors.New("outbound enforcement service is unavailable"))
	}
	if req.Stage == StageSubmission {
		sources, err := s.submissionSources(ctx, req)
		if err != nil {
			return unavailableDecision(err)
		}
		governing, err := resolvePolicySources(ctx, s.DB, sources)
		if err != nil {
			return unavailableDecision(err)
		}
		decision := Evaluate(Request{Stage: StageSubmission, Recipient: req.Recipient, Governing: governing})
		return decision, nil
	}
	if req.Stage != StageTransport || req.AuthenticatedMailbox != "" || req.SystemSenderID != "" || req.EnvelopeSender != "" || len(req.ExpansionSources) != 0 {
		return unavailableDecision(errors.New("invalid outbound enforcement stage request"))
	}
	queue := s.Queue
	if queue.DB == nil {
		queue.DB = s.DB
	}
	record, err := queue.Load(ctx, req.QueueID)
	if err != nil {
		return unavailableDecision(err)
	}
	recipient, _, err := normalizeQueueRecipient(req.Recipient)
	if err != nil || !sortedStringContains(record.Recipients, recipient) {
		return unavailableDecision(errors.New("transport recipient is absent from immutable queue provenance"))
	}
	governing, err := resolvePolicySources(ctx, s.DB, record.Sources)
	if err != nil {
		return unavailableDecision(err)
	}
	decision := Evaluate(Request{Stage: StageTransport, QueueID: record.QueueID, Recipient: recipient, Governing: governing})
	if decision.Action == ActionDefer && decision.Reason == ReasonPolicyHold {
		actor := s.HoldActor
		if actor.Type == "" || actor.ID == "" {
			actor = audit.ActorRef{Type: "service", ID: "outbound-policy"}
		}
		if err := queue.RequireHold(ctx, actor, correlationID, record.QueueID, decision); err != nil {
			return unavailableDecision(err)
		}
	}
	return decision, nil
}

// submissionSources authenticates one mailbox or durable system sender,
// verifies the envelope binding, and admits only expansion-object source kinds.
// Complexity: process time O(s*b), Omega(s); database time O(log N);
// auxiliary space O(s*b), where s is bounded sources and b identifier bytes.
func (s EnforcementService) submissionSources(ctx context.Context, req EnforcementRequest) ([]QueueSource, error) {
	if req.QueueID != "" || (req.AuthenticatedMailbox == "") == (req.SystemSenderID == "") || len(req.ExpansionSources) > maxQueueSources-2 {
		return nil, errors.New("invalid submission authority")
	}
	envelope, _, err := normalizeQueueRecipient(req.EnvelopeSender)
	if err != nil {
		return nil, errors.New("invalid admitted envelope sender")
	}
	sources := make([]QueueSource, 0, 2+len(req.ExpansionSources))
	if req.AuthenticatedMailbox != "" {
		mailbox, id, err := mailboxObjectByAddress(ctx, s.DB, req.AuthenticatedMailbox)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(mailbox, envelope) {
			return nil, errors.New("envelope sender is not bound to authenticated mailbox")
		}
		sources = append(sources,
			QueueSource{Kind: SourceAuthenticatedMailbox, ObjectID: id},
			QueueSource{Kind: SourceEnvelopeSender, ObjectID: id},
		)
	} else {
		boundAddress, err := systemSenderAddress(ctx, s.DB, req.SystemSenderID)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(boundAddress, envelope) {
			return nil, errors.New("envelope sender is not bound to system sender")
		}
		sources = append(sources, QueueSource{Kind: SourceSystemSender, ObjectID: req.SystemSenderID})
	}
	for _, source := range req.ExpansionSources {
		if source.Kind != SourceAlias && source.Kind != SourceForward && source.Kind != SourceList && source.Kind != SourceCatchAll || !validQueueObjectID(source.ObjectID) {
			return nil, errors.New("invalid expansion source")
		}
		sources = append(sources, source)
	}
	return sources, nil
}

// resolvePolicySources batch-resolves bounded immutable object references to
// current source/domain enablement, scope, and revision in one SQL query.
// Complexity: process time O(s*m), Omega(s), tight Theta(s*m); database time
// O(s log N); auxiliary space O(s*m), Omega(s), with Decide variables.
func resolvePolicySources(ctx context.Context, db *sql.DB, sources []QueueSource) ([]GoverningDomain, error) {
	if db == nil || len(sources) == 0 || len(sources) > maxQueueSources {
		return nil, errors.New("invalid outbound policy sources")
	}
	kinds := make([]string, len(sources))
	ids := make([]string, len(sources))
	for i, source := range sources {
		if !validSourceKind(source.Kind) || !validQueueObjectID(source.ObjectID) {
			return nil, errors.New("invalid outbound policy source")
		}
		kinds[i] = string(source.Kind)
		ids[i] = source.ObjectID
	}
	rows, err := db.QueryContext(ctx, `WITH input AS (
    SELECT source_kind,object_id,ord
    FROM unnest($1::text[],$2::text[]) WITH ORDINALITY AS u(source_kind,object_id,ord)
)
SELECT i.source_kind,i.object_id,
       CASE
         WHEN i.source_kind IN ('authenticated_mailbox','envelope_sender') THEN COALESCE(m.enabled,false)
         WHEN i.source_kind IN ('alias','forward','list','catch_all') THEN COALESCE(a.enabled,false)
         WHEN i.source_kind='system_sender' THEN COALESCE(y.enabled,false)
         ELSE false
       END AS source_enabled,
       d.name,d.enabled,d.outbound_scope,d.outbound_policy_revision
FROM input i
LEFT JOIN mailboxes m ON i.source_kind IN ('authenticated_mailbox','envelope_sender') AND m.id::text=i.object_id
LEFT JOIN aliases a ON i.source_kind IN ('alias','forward','list','catch_all') AND a.id::text=i.object_id
LEFT JOIN outbound_system_senders y ON i.source_kind='system_sender' AND y.id=i.object_id
LEFT JOIN domains d ON d.id=COALESCE(m.domain_id,a.domain_id,y.domain_id)
ORDER BY i.ord`, pq.Array(kinds), pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	governing := make([]GoverningDomain, 0, len(sources))
	for rows.Next() {
		var kind, id string
		var sourceEnabled bool
		var domain, scope sql.NullString
		var domainEnabled sql.NullBool
		var revision sql.NullInt64
		if err := rows.Scan(&kind, &id, &sourceEnabled, &domain, &domainEnabled, &scope, &revision); err != nil {
			return nil, err
		}
		if !sourceEnabled || !domain.Valid || !domainEnabled.Valid || !domainEnabled.Bool || !scope.Valid || !revision.Valid || revision.Int64 <= 0 {
			return nil, errors.New("outbound policy source is missing or disabled")
		}
		canonical, err := NormalizeDomain(domain.String)
		if err != nil || canonical != domain.String || !validScope(Scope(scope.String)) {
			return nil, errors.New("outbound policy source state is invalid")
		}
		governing = append(governing, GoverningDomain{Domain: canonical, Scope: Scope(scope.String), Revision: uint64(revision.Int64)})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(governing) != len(sources) {
		return nil, errors.New("outbound policy source resolution was incomplete")
	}
	return governing, nil
}

// mailboxObjectByAddress resolves one enabled product mailbox and returns its
// canonical address plus immutable object ID.
// Complexity: process time O(n), Omega(1), tight Theta(n); database time
// O(log N); auxiliary space O(n), where n is bounded address length.
func mailboxObjectByAddress(ctx context.Context, db *sql.DB, rawAddress string) (string, string, error) {
	address, domain, err := normalizeQueueRecipient(rawAddress)
	if err != nil {
		return "", "", errors.New("invalid authenticated mailbox")
	}
	local := address[:strings.LastIndexByte(address, '@')]
	rows, err := db.QueryContext(ctx, `SELECT m.id::text,m.local_part,d.name FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE lower(m.local_part)=lower($1) AND d.name=$2 AND m.enabled=true AND d.enabled=true ORDER BY m.id LIMIT 2`, local, domain)
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	var id, storedLocal, storedDomain string
	count := 0
	for rows.Next() {
		count++
		if err := rows.Scan(&id, &storedLocal, &storedDomain); err != nil {
			return "", "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	if count != 1 {
		return "", "", errors.New("authenticated mailbox is missing or ambiguous")
	}
	return strings.ToLower(storedLocal) + "@" + storedDomain, id, nil
}

// systemSenderAddress resolves one enabled durable system-sender binding.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is bounded address length; one indexed query is additive.
func systemSenderAddress(ctx context.Context, db *sql.DB, id string) (string, error) {
	if !validQueueObjectID(id) {
		return "", errors.New("invalid system sender identity")
	}
	var address string
	if err := db.QueryRowContext(ctx, `SELECT y.address FROM outbound_system_senders y JOIN domains d ON d.id=y.domain_id WHERE y.id=$1 AND y.enabled=true AND d.enabled=true`, id).Scan(&address); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", errors.New("system sender identity not found")
		}
		return "", err
	}
	canonical, _, err := normalizeQueueRecipient(address)
	if err != nil || canonical != address {
		return "", errors.New("stored system sender identity is invalid")
	}
	return address, nil
}

// Bind creates one immutable ID-to-address system-sender binding for a current
// hosted domain. Repeating the exact binding is a no-op; rebinding is rejected.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is bounded address/ID bytes; one serializable transaction
// and indexed domain/binding queries are additive.
func (s SystemSenderStore) Bind(ctx context.Context, actor audit.ActorRef, correlationID, id, rawAddress string) (SystemSenderBinding, error) {
	if s.DB == nil || actor.Type == "" || actor.ID == "" || correlationID == "" || !validQueueObjectID(id) {
		return SystemSenderBinding{}, errors.New("invalid system sender binding request")
	}
	address, domain, err := normalizeQueueRecipient(rawAddress)
	if err != nil {
		return SystemSenderBinding{}, errors.New("invalid system sender address")
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return SystemSenderBinding{}, err
	}
	defer tx.Rollback()
	var domainID string
	if err := tx.QueryRowContext(ctx, `SELECT id::text FROM domains WHERE name=$1 AND enabled=true`, domain).Scan(&domainID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SystemSenderBinding{}, errors.New("enabled system sender domain not found")
		}
		return SystemSenderBinding{}, err
	}
	now := s.now()
	result, err := tx.ExecContext(ctx, `INSERT INTO outbound_system_senders(id,domain_id,address,enabled,revision,created_at,updated_at) VALUES ($1,$2,$3,true,1,$4,$4) ON CONFLICT (id) DO NOTHING`, id, domainID, address, now)
	if err != nil {
		return SystemSenderBinding{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return SystemSenderBinding{}, err
	}
	var binding SystemSenderBinding
	var revision int64
	if err := tx.QueryRowContext(ctx, `SELECT id,domain_id::text,address,enabled,revision FROM outbound_system_senders WHERE id=$1 FOR UPDATE`, id).Scan(&binding.ID, &binding.DomainID, &binding.Address, &binding.Enabled, &revision); err != nil {
		return SystemSenderBinding{}, err
	}
	if binding.DomainID != domainID || binding.Address != address || !binding.Enabled || revision <= 0 {
		return SystemSenderBinding{}, errors.New("system sender ID is already bound to different state")
	}
	binding.Revision = uint64(revision)
	if affected == 1 {
		if err := audit.WriteSQL(ctx, tx, audit.Event{
			Time:   now,
			Actor:  actor,
			Action: "system_sender.bind",
			Resource: audit.ResourceRef{
				Type: "system_sender", ID: id,
			},
			AfterRedacted: map[string]any{"domain_id": domainID, "revision": 1},
			CorrelationID: correlationID,
			Result:        "success",
		}); err != nil {
			return SystemSenderBinding{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return SystemSenderBinding{}, err
	}
	return binding, nil
}

// now supplies one UTC system-sender persistence timestamp source.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func (s SystemSenderStore) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// sortedStringContains performs exact membership on canonical sorted queue
// recipients.
// Complexity: time O(log n), Omega(1), tight Theta(log n); auxiliary space
// O(1), Omega(1), where n is bounded recipients.
func sortedStringContains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

// unavailableDecision preserves the fail-closed wire decision while returning
// the internal error for observability.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func unavailableDecision(err error) (Decision, error) {
	return Decision{Action: ActionDefer, Reason: ReasonUnavailable}, err
}
