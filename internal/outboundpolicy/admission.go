package outboundpolicy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/lib/pq"
)

const maxExpansionAliases = maxQueueSources

type QueueDelivery struct {
	OriginalRecipient string `json:"original_recipient"`
	Recipient         string `json:"recipient"`
}

type QueueAdmissionRequest struct {
	Metadata             QueueMetadata   `json:"metadata"`
	AuthenticatedMailbox string          `json:"authenticated_mailbox,omitempty"`
	SystemSenderID       string          `json:"system_sender_id,omitempty"`
	Deliveries           []QueueDelivery `json:"deliveries"`
}

type QueueAdmissionService struct {
	DB    *sql.DB
	Queue QueueStore
}

// Admit resolves transport provenance from database objects and registers one
// immutable Postfix queue observation. The privileged caller supplies queue
// facts and original/final addresses, never governing domains or object IDs.
// Complexity: process time O(a*t+r log r+b), Omega(r); database time O(a+log N);
// auxiliary space O(a*t+r+b), where bounded a is aliases, t targets, r queue
// recipients, b bytes, and N authoritative rows.
func (s QueueAdmissionService) Admit(ctx context.Context, req QueueAdmissionRequest) (QueueRecord, bool, error) {
	if s.DB == nil || req.Metadata.Held || len(req.Deliveries) == 0 || len(req.Deliveries) > maxQueueRecipients {
		return QueueRecord{}, false, errors.New("invalid outbound queue admission request")
	}
	if err := validateQueueDeliveries(req.Metadata.Recipients, req.Deliveries); err != nil {
		return QueueRecord{}, false, err
	}
	sources := make([]QueueSource, 0, 2+len(req.Deliveries))
	if req.AuthenticatedMailbox != "" || req.SystemSenderID != "" {
		service := EnforcementService{DB: s.DB}
		authority, err := service.submissionSources(ctx, EnforcementRequest{
			Stage:                StageSubmission,
			AuthenticatedMailbox: req.AuthenticatedMailbox,
			SystemSenderID:       req.SystemSenderID,
			EnvelopeSender:       req.Metadata.EnvelopeSender,
			Recipient:            req.Deliveries[0].Recipient,
		})
		if err != nil {
			return QueueRecord{}, false, err
		}
		sources = append(sources, authority...)
	} else if req.Metadata.EnvelopeSender != "<>" {
		_, id, err := mailboxObjectByAddress(ctx, s.DB, req.Metadata.EnvelopeSender)
		if err == nil {
			sources = append(sources, QueueSource{Kind: SourceEnvelopeSender, ObjectID: id})
		}
	}
	expansion, err := resolveExpansionDeliveries(ctx, s.DB, req.Deliveries)
	if err != nil {
		return QueueRecord{}, false, err
	}
	sources = append(sources, expansion...)
	if len(sources) == 0 {
		return QueueRecord{}, false, errors.New("outbound queue has no authoritative local source")
	}
	queue := s.Queue
	if queue.DB == nil {
		queue.DB = s.DB
	}
	return queue.Register(ctx, QueueRegistration{
		QueueID:            req.Metadata.QueueID,
		ArrivalFingerprint: req.Metadata.ArrivalFingerprint,
		EnvelopeSender:     req.Metadata.EnvelopeSender,
		Recipients:         req.Metadata.Recipients,
		Sources:            sources,
	})
}

// validateQueueDeliveries requires the pipe(8) delivery request to cover the
// exact inspected final-recipient set. Multiple originals may legitimately
// collapse onto one final recipient, so only the final set is compared.
// Complexity: time O((r+d) log(r+d)+b), Omega(r+d); auxiliary space O(r+d+b),
// where r is queue recipients, d delivery pairs, and b their bounded bytes.
func validateQueueDeliveries(recipients []string, deliveries []QueueDelivery) error {
	want, err := canonicalQueueRecipients(recipients)
	if err != nil {
		return errors.New("invalid inspected queue recipients")
	}
	finals := make([]string, len(deliveries))
	for i, delivery := range deliveries {
		finals[i] = delivery.Recipient
	}
	got, err := canonicalQueueRecipients(finals)
	if err != nil || len(got) != len(want) {
		return errors.New("Postfix delivery recipients do not match inspected queue")
	}
	for i := range want {
		if got[i] != want[i] {
			return errors.New("Postfix delivery recipients do not match inspected queue")
		}
	}
	return nil
}

type expansionAlias struct {
	ID      string
	Address string
	Targets []string
	Kind    SourceKind
}

// resolveExpansionDeliveries proves every original-to-final pair against the
// complete reachable alias subgraph. Cycles, excessive fan-out, and omitted
// alternate branches fail closed.
// Complexity: process time O(a*t+d*(a+t)), Omega(d); database time O(h*a log N);
// auxiliary space O(a*t+f), where a is aliases, t targets, d delivery pairs,
// h graph depth, f fan-out, and N authoritative rows.
func resolveExpansionDeliveries(ctx context.Context, db *sql.DB, deliveries []QueueDelivery) ([]QueueSource, error) {
	originals := make([]string, 0, len(deliveries))
	canonical := make([]QueueDelivery, len(deliveries))
	for i, delivery := range deliveries {
		original, _, err := normalizeQueueRecipient(delivery.OriginalRecipient)
		if err != nil {
			return nil, errors.New("invalid original recipient")
		}
		final, _, err := normalizeQueueRecipient(delivery.Recipient)
		if err != nil {
			return nil, errors.New("invalid expanded recipient")
		}
		canonical[i] = QueueDelivery{OriginalRecipient: original, Recipient: final}
		originals = append(originals, original)
	}
	aliases, err := loadExpansionAliases(ctx, db, originals)
	if err != nil {
		return nil, err
	}
	sourceSet := map[string]QueueSource{}
	for _, delivery := range canonical {
		if delivery.OriginalRecipient == delivery.Recipient {
			continue
		}
		leaves := map[string]bool{}
		reachedSources := map[string]QueueSource{}
		if err := walkExpansionGraph(aliases, delivery.OriginalRecipient, nil, leaves, reachedSources, 0); err != nil {
			return nil, err
		}
		if !leaves[delivery.Recipient] {
			return nil, errors.New("expanded recipient is not derived from authoritative aliases")
		}
		for key, source := range reachedSources {
			sourceSet[key] = source
			if len(sourceSet) > maxQueueSources {
				return nil, errors.New("outbound alias source limit exceeded")
			}
		}
	}
	result := make([]QueueSource, 0, len(sourceSet))
	for _, source := range sourceSet {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ObjectID < result[j].ObjectID })
	return result, nil
}

// expandOriginal resolves one SMTP recipient into every leaf and every local
// alias source before RCPT admission.
// Complexity: process time O(a*t+f), Omega(1); database time O(h*a log N);
// auxiliary space O(a*t+f), with resolveExpansionDeliveries bounds.
func expandOriginal(ctx context.Context, db *sql.DB, rawOriginal string) ([]string, []QueueSource, error) {
	original, _, err := normalizeQueueRecipient(rawOriginal)
	if err != nil {
		return nil, nil, errors.New("invalid original recipient")
	}
	aliases, err := loadExpansionAliases(ctx, db, []string{original})
	if err != nil {
		return nil, nil, err
	}
	leaves := map[string]bool{}
	sourceSet := map[string]QueueSource{}
	if err := walkExpansionGraph(aliases, original, nil, leaves, sourceSet, 0); err != nil {
		return nil, nil, err
	}
	recipients := make([]string, 0, len(leaves))
	for recipient := range leaves {
		recipients = append(recipients, recipient)
	}
	sort.Strings(recipients)
	sources := make([]QueueSource, 0, len(sourceSet))
	for _, source := range sourceSet {
		sources = append(sources, source)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].ObjectID < sources[j].ObjectID })
	return recipients, sources, nil
}

// loadExpansionAliases fetches only the bounded subgraph reachable from the
// supplied originals, one breadth layer per SQL query.
// Complexity: process time O(a*t+f), Omega(1); database time O(h*a log N);
// auxiliary space O(a*t+f), with resolveExpansionDeliveries bounds.
func loadExpansionAliases(ctx context.Context, db *sql.DB, originals []string) (map[string]expansionAlias, error) {
	aliases := make(map[string]expansionAlias)
	seen := make(map[string]bool)
	frontier := append([]string(nil), originals...)
	for depth := 0; len(frontier) > 0; depth++ {
		if depth >= maxQueueSources {
			return nil, errors.New("outbound alias expansion depth exceeded")
		}
		batchSet := map[string]bool{}
		for _, address := range frontier {
			if !seen[address] {
				seen[address] = true
				batchSet[address] = true
			}
		}
		if len(batchSet) == 0 {
			break
		}
		if len(seen) > maxQueueRecipients {
			return nil, errors.New("outbound alias expansion fan-out exceeded")
		}
		batch := make([]string, 0, len(batchSet))
		for address := range batchSet {
			batch = append(batch, address)
		}
		rows, err := db.QueryContext(ctx, `WITH input(address) AS (SELECT unnest($1::text[]))
SELECT a.id::text,i.address,a.local_part,d.name,a.targets_json
FROM input i
JOIN domains d ON d.name=split_part(i.address,'@',2)
JOIN aliases a ON a.domain_id=d.id
 AND (
   lower(a.local_part)=lower(split_part(i.address,'@',1))
   OR (
     a.local_part='*'
     AND NOT EXISTS (
       SELECT 1 FROM aliases exact
       WHERE exact.domain_id=d.id
         AND exact.enabled=true
         AND lower(exact.local_part)=lower(split_part(i.address,'@',1))
     )
     AND NOT EXISTS (
       SELECT 1 FROM mailboxes mailbox
       WHERE mailbox.domain_id=d.id
         AND mailbox.enabled=true
         AND lower(mailbox.local_part)=lower(split_part(i.address,'@',1))
     )
   )
 )
WHERE a.enabled=true AND d.enabled=true
ORDER BY i.address,a.id`, pq.Array(batch))
		if err != nil {
			return nil, err
		}
		next := make([]string, 0)
		for rows.Next() {
			if len(aliases) >= maxExpansionAliases {
				rows.Close()
				return nil, errors.New("outbound alias graph limit exceeded")
			}
			alias, err := scanExpansionAlias(rows)
			if err != nil {
				rows.Close()
				return nil, err
			}
			if _, duplicate := aliases[alias.Address]; duplicate {
				rows.Close()
				return nil, errors.New("ambiguous outbound alias state")
			}
			aliases[alias.Address] = alias
			next = append(next, alias.Targets...)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
		frontier = next
	}
	return aliases, nil
}

type expansionAliasScanner interface {
	Scan(...any) error
}

// scanExpansionAlias validates one authoritative alias row and target set.
// Complexity: time and space O(t+b), Omega(1), where t is bounded targets and
// b their bytes.
func scanExpansionAlias(row expansionAliasScanner) (expansionAlias, error) {
	var alias expansionAlias
	var inputAddress, local, domain, encoded string
	if err := row.Scan(&alias.ID, &inputAddress, &local, &domain, &encoded); err != nil {
		return expansionAlias{}, err
	}
	address, _, err := normalizeQueueRecipient(inputAddress)
	if err != nil || address != inputAddress || !validQueueObjectID(alias.ID) || (local != "*" && address != strings.ToLower(local)+"@"+domain) {
		return expansionAlias{}, errors.New("stored outbound alias is invalid")
	}
	var targets []string
	if err := json.Unmarshal([]byte(encoded), &targets); err != nil || len(targets) == 0 || len(targets) > maxQueueRecipients {
		return expansionAlias{}, errors.New("stored outbound alias targets are invalid")
	}
	alias.Address = address
	alias.Targets = make([]string, 0, len(targets))
	for _, target := range targets {
		canonical, _, err := normalizeQueueRecipient(target)
		if err != nil {
			return expansionAlias{}, errors.New("stored outbound alias target is invalid")
		}
		alias.Targets = append(alias.Targets, canonical)
	}
	alias.Kind = classifyExpansionSource(local, domain, alias.Targets)
	return alias, nil
}

// classifyExpansionSource derives the policy provenance class from the
// existing alias mechanism: wildcard catch-all, one-to-many list, external
// forward, or ordinary local alias. The classification changes no delivery
// behavior; it preserves the authoritative object kind in queue provenance.
// Complexity: time O(t*n), Omega(1); auxiliary space O(1), where t is the
// bounded target count and n is a bounded address length.
func classifyExpansionSource(local, domain string, targets []string) SourceKind {
	if local == "*" {
		return SourceCatchAll
	}
	if len(targets) > 1 {
		return SourceList
	}
	if len(targets) == 1 {
		_, targetDomain, err := normalizeQueueRecipient(targets[0])
		if err == nil && targetDomain != domain {
			return SourceForward
		}
	}
	return SourceAlias
}

// walkExpansionGraph collects every reachable leaf and alias source. Any
// reachable cycle invalidates the whole expansion.
// Complexity: time O(a*t), Omega(1); auxiliary space O(a+f), where a is
// aliases, t targets, and f leaves.
func walkExpansionGraph(aliases map[string]expansionAlias, current string, active map[string]bool, leaves map[string]bool, sources map[string]QueueSource, depth int) error {
	alias, ok := aliases[current]
	if !ok {
		leaves[current] = true
		if len(leaves) > maxQueueRecipients {
			return errors.New("outbound alias expansion fan-out exceeded")
		}
		return nil
	}
	if depth >= maxQueueSources {
		return errors.New("outbound alias expansion depth exceeded")
	}
	if active == nil {
		active = make(map[string]bool)
	}
	if active[current] {
		return errors.New("outbound alias expansion cycle")
	}
	active[current] = true
	defer delete(active, current)
	source := QueueSource{Kind: alias.Kind, ObjectID: alias.ID}
	sources[string(source.Kind)+"\x00"+source.ObjectID] = source
	if len(sources) > maxQueueSources {
		return errors.New("outbound alias source limit exceeded")
	}
	for _, target := range alias.Targets {
		if err := walkExpansionGraph(aliases, target, active, leaves, sources, depth+1); err != nil {
			return err
		}
	}
	return nil
}
