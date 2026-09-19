package notifyruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

const maxPolicyResponseBytes = 64 << 10

type HTTPPolicyClient struct {
	endpoint string
	client   *http.Client
}

type policyWireResponse struct {
	CorrelationID   string            `json:"correlation_id"`
	Decision        string            `json:"decision"`
	Reason          string            `json:"reason"`
	PolicyRevisions map[string]uint64 `json:"policy_revisions,omitempty"`
}

// NewHTTPPolicyClient admits one explicit HTTP(S) internal endpoint without
// credentials, query parameters, or fragments.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded endpoint length.
func NewHTTPPolicyClient(raw string) (*HTTPPolicyClient, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > 2048 {
		return nil, errors.New("outbound policy URL required")
	}
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid outbound policy URL")
	}
	return &HTTPPolicyClient{endpoint: parsed.String(), client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// Decide sends one bounded JSON request and validates the closed decision,
// reason, revision, and correlation contract before returning it.
// Complexity: time O(n+m), Omega(n), tight Theta(n+m); auxiliary space O(n+m),
// Omega(n), where n is bounded request bytes and m is response bytes capped at
// 64 KiB; one HTTP round trip is additive.
func (c *HTTPPolicyClient) Decide(ctx context.Context, correlationID string, request outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
	if c == nil || c.client == nil || c.endpoint == "" || strings.TrimSpace(correlationID) == "" {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("outbound policy client unavailable")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-Correlation-ID", correlationID)
	response, err := c.client.Do(httpRequest)
	if err != nil {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("outbound policy request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("outbound policy returned non-success status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPolicyResponseBytes+1))
	if err != nil || len(body) > maxPolicyResponseBytes {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("outbound policy response exceeded limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	var wire policyWireResponse
	if err := decoder.Decode(&wire); err != nil {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("invalid outbound policy response")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("invalid outbound policy response")
	}
	decision := outboundpolicy.Decision{Action: outboundpolicy.Action(wire.Decision), Reason: outboundpolicy.Reason(wire.Reason), Revisions: wire.PolicyRevisions}
	if wire.CorrelationID != correlationID || !validWireDecision(decision) || !validWireRevisions(decision.Revisions) {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("invalid outbound policy response contract")
	}
	return decision, nil
}

// validWireDecision recognizes the complete action/reason combinations.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1),
// Omega(1), tight Theta(1).
func validWireDecision(decision outboundpolicy.Decision) bool {
	switch decision.Action {
	case outboundpolicy.ActionOK:
		return decision.Reason == outboundpolicy.ReasonUnrestricted || decision.Reason == outboundpolicy.ReasonSameDomain
	case outboundpolicy.ActionReject:
		return decision.Reason == outboundpolicy.ReasonRecipientForbidden || decision.Reason == outboundpolicy.ReasonCrossDomainConflict
	case outboundpolicy.ActionDefer:
		return decision.Reason == outboundpolicy.ReasonPolicyHold || decision.Reason == outboundpolicy.ReasonUnavailable
	default:
		return false
	}
}

// validWireRevisions validates the bounded normalized domain/revision map.
// Complexity: time O(n*m), Omega(1), tight Theta(n*m) for non-empty input;
// auxiliary space O(m), Omega(1), where n is at most 64 and m domain length.
func validWireRevisions(revisions map[string]uint64) bool {
	if len(revisions) > 64 {
		return false
	}
	for domain, revision := range revisions {
		canonical, err := outboundpolicy.NormalizeDomain(domain)
		if err != nil || canonical != domain || revision == 0 {
			return false
		}
	}
	return true
}
