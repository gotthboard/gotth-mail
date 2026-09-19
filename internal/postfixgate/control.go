package postfixgate

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

	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

const maxControlResponseBytes = 64 << 10

type HTTPController struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

// NewHTTPController validates one fixed core origin and privileged bearer.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is bounded configuration text.
func NewHTTPController(rawURL, token string) (*HTTPController, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid GOTTH Mail core URL")
	}
	if len(token) < 32 || len(token) > 4096 || strings.TrimSpace(token) != token {
		return nil, errors.New("invalid Postfix helper token")
	}
	return &HTTPController{BaseURL: strings.TrimRight(parsed.String(), "/"), Token: token, Client: &http.Client{Timeout: 15 * time.Second}}, nil
}

// Register persists authoritative queue provenance before a transport policy
// decision is requested.
// Complexity: time and space O(n), Omega(1), with bounded JSON and one round
// trip.
func (c *HTTPController) Register(ctx context.Context, request outboundpolicy.QueueAdmissionRequest) error {
	response, err := c.call(ctx, "/internal/v1/postfix/queue/register", request, true)
	if err != nil {
		return err
	}
	if response.Decision != daemon.OK || (response.Reason != "outbound_queue_registered" && response.Reason != "outbound_queue_already_registered") {
		return errors.New("GOTTH Mail rejected queue registration")
	}
	return nil
}

// Decide requests the current transport-stage policy for one immutable queue
// recipient.
// Complexity: time and space O(n), Omega(1), with bounded JSON and one round
// trip.
func (c *HTTPController) Decide(ctx context.Context, queueID, recipient string) (outboundpolicy.Decision, error) {
	response, err := c.call(ctx, "/internal/v1/postfix/outbound-policy", outboundpolicy.EnforcementRequest{Stage: outboundpolicy.StageTransport, QueueID: queueID, Recipient: recipient}, false)
	if err != nil {
		return outboundpolicy.Decision{}, err
	}
	action := outboundpolicy.Action(response.Decision)
	reason := outboundpolicy.Reason(response.Reason)
	if action != outboundpolicy.ActionOK && action != outboundpolicy.ActionReject && action != outboundpolicy.ActionDefer {
		return outboundpolicy.Decision{}, errors.New("GOTTH Mail returned invalid policy action")
	}
	if reason != outboundpolicy.ReasonUnrestricted && reason != outboundpolicy.ReasonSameDomain && reason != outboundpolicy.ReasonRecipientForbidden && reason != outboundpolicy.ReasonCrossDomainConflict && reason != outboundpolicy.ReasonPolicyHold && reason != outboundpolicy.ReasonUnavailable {
		return outboundpolicy.Decision{}, errors.New("GOTTH Mail returned invalid policy reason")
	}
	return outboundpolicy.Decision{Action: action, Reason: reason, Revisions: response.PolicyRevisions}, nil
}

// Reconcile requests one idempotent whole-message hold after policy state has
// durably marked the queue record.
// Complexity: time and space O(n), Omega(1), with bounded JSON and one round
// trip.
func (c *HTTPController) Reconcile(ctx context.Context, queueID string) error {
	response, err := c.call(ctx, "/internal/v1/postfix/queue/reconcile", map[string]string{"queue_id": queueID}, true)
	if err != nil {
		return err
	}
	if response.Decision != daemon.OK || (response.Reason != "outbound_queue_hold_applied" && response.Reason != "outbound_queue_hold_already_applied") {
		return errors.New("GOTTH Mail did not reconcile queue hold")
	}
	return nil
}

// call performs one strict bounded request. Privileged queue mutation routes
// receive the helper bearer; the read-only policy route remains token-free.
// Complexity: time and space O(n), Omega(1), with 1 MiB request and 64 KiB
// response ceilings.
func (c *HTTPController) call(ctx context.Context, path string, input any, privileged bool) (daemon.Response, error) {
	if c == nil || c.Client == nil {
		return daemon.Response{}, errors.New("GOTTH Mail controller unavailable")
	}
	payload, err := json.Marshal(input)
	if err != nil || len(payload) > 1<<20 {
		return daemon.Response{}, errors.New("GOTTH Mail control request invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return daemon.Response{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Correlation-ID", "postfix-gate:"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if privileged {
		request.Header.Set("Authorization", "Bearer "+c.Token)
	}
	response, err := c.Client.Do(request)
	if err != nil {
		return daemon.Response{}, errors.New("GOTTH Mail control plane unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxControlResponseBytes+1))
	if err != nil || len(body) > maxControlResponseBytes || response.StatusCode != http.StatusOK {
		return daemon.Response{}, errors.New("GOTTH Mail control response invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result daemon.Response
	if err := decoder.Decode(&result); err != nil {
		return daemon.Response{}, errors.New("GOTTH Mail control response invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return daemon.Response{}, errors.New("GOTTH Mail control response invalid")
	}
	return result, nil
}
