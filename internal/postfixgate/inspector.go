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

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

type HTTPQueueInspector struct {
	BaseURL string
	Token   string
	Client  *http.Client
}

func NewHTTPQueueInspector(rawURL, token string) (*HTTPQueueInspector, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() != "127.0.0.1" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid Postfix helper URL")
	}
	if len(token) < 32 || len(token) > 4096 || strings.TrimSpace(token) != token {
		return nil, errors.New("invalid Postfix helper token")
	}
	return &HTTPQueueInspector{BaseURL: strings.TrimRight(parsed.String(), "/"), Token: token, Client: &http.Client{Timeout: 15 * time.Second}}, nil
}

func (c *HTTPQueueInspector) Inspect(ctx context.Context, queueID string) (outboundpolicy.QueueMetadata, error) {
	if c == nil || c.Client == nil {
		return outboundpolicy.QueueMetadata{}, errors.New("Postfix helper unavailable")
	}
	payload, err := json.Marshal(map[string]string{"queue_id": queueID})
	if err != nil {
		return outboundpolicy.QueueMetadata{}, errors.New("Postfix queue inspection request invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/queue/inspect", bytes.NewReader(payload))
	if err != nil {
		return outboundpolicy.QueueMetadata{}, errors.New("Postfix queue inspection request invalid")
	}
	request.Header.Set("Authorization", "Bearer "+c.Token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.Client.Do(request)
	if err != nil {
		return outboundpolicy.QueueMetadata{}, errors.New("Postfix helper unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxControlResponseBytes+1))
	if err != nil || len(body) > maxControlResponseBytes || response.StatusCode != http.StatusOK {
		return outboundpolicy.QueueMetadata{}, errors.New("Postfix queue inspection failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var metadata outboundpolicy.QueueMetadata
	if err := decoder.Decode(&metadata); err != nil {
		return outboundpolicy.QueueMetadata{}, errors.New("Postfix queue inspection response invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return outboundpolicy.QueueMetadata{}, errors.New("Postfix queue inspection response invalid")
	}
	return metadata, nil
}
