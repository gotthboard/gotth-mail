package outboundpolicy

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
)

const maxPostfixHelperResponseBytes = 64 << 10

type RemotePostfixBoundary struct {
	BaseURL      string
	Token        string
	ReleaseToken string
	Client       *http.Client
}

// NewRemotePostfixBoundary validates the fixed helper origin and a nontrivial
// bearer secret before constructing the narrow inspect/hold client.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is bounded configuration text.
func NewRemotePostfixBoundary(rawURL, token string) (*RemotePostfixBoundary, error) {
	return newRemotePostfixBoundary(rawURL, token, "")
}

// NewRemotePostfixBoundaryWithRelease adds a distinct release credential that
// must not be exported into Postfix pipe(8) service environments.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n), where
// n is bounded configuration text.
func NewRemotePostfixBoundaryWithRelease(rawURL, token, releaseToken string) (*RemotePostfixBoundary, error) {
	if !validPostfixHelperToken(releaseToken) || releaseToken == token {
		return nil, errors.New("invalid Postfix release token")
	}
	return newRemotePostfixBoundary(rawURL, token, releaseToken)
}

// newRemotePostfixBoundary validates shared helper configuration.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n).
func newRemotePostfixBoundary(rawURL, token, releaseToken string) (*RemotePostfixBoundary, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return nil, errors.New("invalid Postfix helper URL")
	}
	if !validPostfixHelperToken(token) {
		return nil, errors.New("invalid Postfix helper token")
	}
	return &RemotePostfixBoundary{BaseURL: strings.TrimRight(parsed.String(), "/"), Token: token, ReleaseToken: releaseToken, Client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// validPostfixHelperToken enforces the shared secret bound.
// Complexity: time O(n), Omega(1); auxiliary space O(1).
func validPostfixHelperToken(token string) bool {
	return len(token) >= 32 && len(token) <= 4096 && strings.TrimSpace(token) == token
}

// Inspect retrieves one canonical queue observation from the privileged
// Postfix-side helper.
// Complexity: time and space O(r+b), Omega(r), where r is bounded recipients
// and b is the bounded response body; one network round trip is additive.
func (b *RemotePostfixBoundary) Inspect(ctx context.Context, queueID string) (QueueMetadata, error) {
	var metadata QueueMetadata
	if err := b.call(ctx, "/v1/queue/inspect", queueID, &metadata); err != nil {
		return QueueMetadata{}, err
	}
	normalized, err := normalizeQueueRegistration(QueueRegistration{
		QueueID:            metadata.QueueID,
		ArrivalFingerprint: metadata.ArrivalFingerprint,
		EnvelopeSender:     metadata.EnvelopeSender,
		Recipients:         metadata.Recipients,
		Sources:            []QueueSource{{Kind: SourceSystemSender, ObjectID: "validation-only"}},
	})
	if err != nil || normalized.QueueID != queueID || normalized.ArrivalFingerprint != metadata.ArrivalFingerprint || normalized.EnvelopeSender != metadata.EnvelopeSender || !equalCanonicalStrings(normalized.Recipients, metadata.Recipients) {
		return QueueMetadata{}, errors.New("Postfix helper returned invalid queue metadata")
	}
	return metadata, nil
}

// Hold asks the helper to execute its single documented whole-message hold
// operation for one validated long queue ID.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded response body; one round trip is additive.
func (b *RemotePostfixBoundary) Hold(ctx context.Context, queueID string) error {
	return b.call(ctx, "/v1/queue/hold", queueID, nil)
}

// Release asks the helper to execute its single documented whole-message
// release operation for one validated long queue ID.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(n),
// Omega(1), where n is the bounded response body; one round trip is additive.
func (b *RemotePostfixBoundary) Release(ctx context.Context, queueID string) error {
	return b.call(ctx, "/v1/queue/release", queueID, nil)
}

// call performs one bounded authenticated JSON request to a fixed endpoint.
// Complexity: time and space O(n), Omega(1), with a 64 KiB response ceiling.
func (b *RemotePostfixBoundary) call(ctx context.Context, path, queueID string, out any) error {
	if b == nil || b.Client == nil || !validLongQueueID(queueID) || (path != "/v1/queue/inspect" && path != "/v1/queue/hold" && path != "/v1/queue/release") {
		return errors.New("invalid Postfix helper request")
	}
	payload, _ := json.Marshal(map[string]string{"queue_id": queueID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.BaseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	token := b.Token
	if path == "/v1/queue/release" {
		token = b.ReleaseToken
		if !validPostfixHelperToken(token) {
			return errors.New("Postfix release credential unavailable")
		}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := b.Client.Do(req)
	if err != nil {
		return errors.New("Postfix helper unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPostfixHelperResponseBytes+1))
	if err != nil || len(body) > maxPostfixHelperResponseBytes {
		return errors.New("Postfix helper response invalid")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("Postfix helper rejected request")
	}
	if out == nil {
		if len(bytes.TrimSpace(body)) != 0 {
			return errors.New("Postfix helper mutation response was not empty")
		}
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return errors.New("Postfix helper response invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("Postfix helper response invalid")
	}
	return nil
}

// equalStrings compares two canonical bounded sequences.
// Complexity: time O(n*b), Omega(1); auxiliary space O(1), where n is count
// and b item length.
func equalCanonicalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
