package outboundpolicy

import (
	"errors"
	"net/mail"
	"strings"

	"golang.org/x/net/idna"
)

type Scope string

const (
	ScopeUnrestricted   Scope = "unrestricted"
	ScopeSameDomainOnly Scope = "same_domain_only"
)

type Stage string

const (
	StageSubmission Stage = "submission"
	StageTransport  Stage = "transport"
)

type Action string

const (
	ActionOK     Action = "ok"
	ActionReject Action = "reject"
	ActionDefer  Action = "defer"
)

type Reason string

const (
	ReasonUnrestricted        Reason = "outbound_scope_unrestricted"
	ReasonSameDomain          Reason = "same_domain"
	ReasonRecipientForbidden  Reason = "recipient_domain_forbidden"
	ReasonCrossDomainConflict Reason = "cross_domain_policy_conflict"
	ReasonPolicyHold          Reason = "recipient_domain_policy_hold"
	ReasonUnavailable         Reason = "outbound_policy_unavailable"
)

type GoverningDomain struct {
	Domain   string `json:"domain"`
	Scope    Scope  `json:"scope"`
	Revision uint64 `json:"revision"`
}

type Request struct {
	Stage     Stage             `json:"stage"`
	QueueID   string            `json:"queue_id,omitempty"`
	Recipient string            `json:"recipient"`
	Governing []GoverningDomain `json:"governing"`
}

type Decision struct {
	Action    Action            `json:"action"`
	Reason    Reason            `json:"reason"`
	Revisions map[string]uint64 `json:"revisions,omitempty"`
}

var lookupProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.VerifyDNSLength(true),
	idna.Transitional(false),
)

const (
	maxEnvelopeRecipientBytes = 254
	maxGoverningDomains       = 64
	maxPostfixQueueIDBytes    = 100
)

// NormalizeDomain returns the exact lowercase DNS A-label used by outbound
// policy comparisons. Errors are terminal: idna returns a sanitized partial
// result on some failures, and this function deliberately discards it.
// Complexity: time O(n), Omega(n), tight Theta(n); auxiliary space O(n),
// Omega(n), tight Theta(n); n is the UTF-8 input length and delegated IDNA
// mapping/validation is linear in that input under the pinned x/net profile.
func NormalizeDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("domain required")
	}
	ascii, err := lookupProfile.ToASCII(raw)
	if err != nil {
		return "", errors.New("invalid domain")
	}
	ascii = strings.ToLower(ascii)
	if strings.HasSuffix(ascii, ".") {
		ascii = strings.TrimSuffix(ascii, ".")
	}
	if ascii == "" || strings.HasPrefix(ascii, ".") || strings.HasSuffix(ascii, ".") || strings.Contains(ascii, "..") {
		return "", errors.New("invalid domain")
	}
	return ascii, nil
}

// recipientDomain extracts a strict SMTP envelope domain and normalizes it.
// Display-name syntax is rejected because policy input is an envelope address,
// not a message header.
// Complexity: time O(n), Omega(n), tight Theta(n); auxiliary space O(n),
// Omega(n), tight Theta(n); n is the address length and includes parser and
// IDNA work.
func recipientDomain(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > maxEnvelopeRecipientBytes {
		return "", errors.New("invalid envelope recipient")
	}
	parsed, err := mail.ParseAddress(trimmed)
	if err != nil || parsed.Name != "" || parsed.Address != trimmed {
		return "", errors.New("invalid envelope recipient")
	}
	at := strings.LastIndexByte(parsed.Address, '@')
	if at <= 0 || at == len(parsed.Address)-1 {
		return "", errors.New("invalid envelope recipient")
	}
	return NormalizeDomain(parsed.Address[at+1:])
}

// validLongQueueID admits only the documented Postfix long-ID alphabet and
// shape. The separator follows at least six seconds digits and four
// microseconds digits, and at least one inode character follows it.
// Complexity: time O(n), Omega(1), tight Theta(n) for valid input; auxiliary
// space O(1), Omega(1), tight Theta(1), where n is the bounded ID length.
func validLongQueueID(queueID string) bool {
	if len(queueID) < 12 || len(queueID) > maxPostfixQueueIDBytes {
		return false
	}
	separator := false
	for i := 0; i < len(queueID); i++ {
		c := queueID[i]
		if !strings.ContainsRune("0123456789BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz", rune(c)) {
			return false
		}
		if c == 'z' && i >= 10 && i < len(queueID)-1 {
			separator = true
		}
	}
	return separator
}

// Evaluate applies the current governing-domain snapshot to one resolved
// envelope recipient. Invalid, missing, or contradictory authority defers;
// it never falls back to unrestricted delivery.
// Complexity: worst-case time O(n*m), Omega(1), tight Theta(n*m); auxiliary
// space O(n*m), Omega(1), where bounded n is governing domains and m is their
// maximum DNS length.
func Evaluate(req Request) Decision {
	if req.Stage != StageSubmission && req.Stage != StageTransport {
		return Decision{Action: ActionDefer, Reason: ReasonUnavailable}
	}
	if req.Stage == StageTransport && !validLongQueueID(req.QueueID) {
		return Decision{Action: ActionDefer, Reason: ReasonUnavailable}
	}
	if len(req.Governing) == 0 || len(req.Governing) > maxGoverningDomains {
		return Decision{Action: ActionDefer, Reason: ReasonUnavailable}
	}
	recipient, err := recipientDomain(req.Recipient)
	if err != nil {
		return Decision{Action: ActionDefer, Reason: ReasonUnavailable}
	}

	type policyState struct {
		scope    Scope
		revision uint64
	}
	authoritative := make(map[string]policyState, len(req.Governing))
	restricted := make(map[string]uint64, len(req.Governing))
	for _, governing := range req.Governing {
		domain, err := NormalizeDomain(governing.Domain)
		if err != nil || governing.Revision == 0 || !validScope(governing.Scope) {
			return Decision{Action: ActionDefer, Reason: ReasonUnavailable}
		}
		state := policyState{scope: governing.Scope, revision: governing.Revision}
		if prior, exists := authoritative[domain]; exists {
			if prior != state {
				return Decision{Action: ActionDefer, Reason: ReasonUnavailable}
			}
			continue
		}
		authoritative[domain] = state
		if governing.Scope == ScopeSameDomainOnly {
			restricted[domain] = governing.Revision
		}
	}
	if len(restricted) == 0 {
		return Decision{Action: ActionOK, Reason: ReasonUnrestricted}
	}
	if len(restricted) > 1 {
		return Decision{Action: ActionReject, Reason: ReasonCrossDomainConflict, Revisions: restricted}
	}
	for domain := range restricted {
		if recipient == domain {
			return Decision{Action: ActionOK, Reason: ReasonSameDomain, Revisions: restricted}
		}
	}
	if req.Stage == StageTransport {
		return Decision{Action: ActionDefer, Reason: ReasonPolicyHold, Revisions: restricted}
	}
	return Decision{Action: ActionReject, Reason: ReasonRecipientForbidden, Revisions: restricted}
}
