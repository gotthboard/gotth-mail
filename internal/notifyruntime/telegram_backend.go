package notifyruntime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/plugin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const telegramAPIBase = "https://api.telegram.org"

type TelegramConfig struct {
	BotToken       string
	AlertChatID    string
	AllowedChatIDs []string
	APIBaseURL     string
	HTTPClient     *http.Client
}

type TelegramBackend struct {
	endpoint    string
	alertChatID string
	allowed     map[string]struct{}
	client      *http.Client
}

func NewTelegramBackend(cfg TelegramConfig) (TelegramBackend, error) {
	token := strings.TrimSpace(cfg.BotToken)
	if len(token) < 16 || len(token) > 256 || strings.ContainsAny(token, " \t\r\n/") {
		return TelegramBackend{}, errors.New("valid Telegram bot token required")
	}
	alertChatID, err := cleanTelegramChatID(cfg.AlertChatID)
	if err != nil {
		return TelegramBackend{}, fmt.Errorf("alert chat: %w", err)
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedChatIDs)+1)
	for _, raw := range cfg.AllowedChatIDs {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		chatID, err := cleanTelegramChatID(raw)
		if err != nil {
			return TelegramBackend{}, fmt.Errorf("allowed chat: %w", err)
		}
		allowed[chatID] = struct{}{}
	}
	allowed[alertChatID] = struct{}{}
	base := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if base == "" {
		base = telegramAPIBase
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return TelegramBackend{}, errors.New("valid Telegram API base URL required")
	}
	if !allowedTelegramAPIBase(parsed) {
		return TelegramBackend{}, errors.New("Telegram API base URL must be the official API or loopback")
	}
	client := http.Client{Timeout: 10 * time.Second}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
		if client.Timeout == 0 {
			client.Timeout = 10 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return TelegramBackend{endpoint: base + "/bot" + url.PathEscape(token) + "/sendMessage", alertChatID: alertChatID, allowed: allowed, client: &client}, nil
}

func allowedTelegramAPIBase(u *url.URL) bool {
	if u.Scheme == "https" && u.Host == "api.telegram.org" {
		return true
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return (u.Scheme == "http" || u.Scheme == "https") && ip != nil && ip.IsLoopback()
}

func cleanTelegramChatID(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 20 {
		return "", errors.New("numeric chat id required")
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id == 0 {
		return "", errors.New("numeric chat id required")
	}
	return strconv.FormatInt(id, 10), nil
}

func (b TelegramBackend) SendAlert(ctx context.Context, in notification.Alert) (notification.DeliveryResult, error) {
	alert, err := notification.SanitizeAlert(in)
	if err != nil {
		return notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "telegram_invalid_alert"}, status.Error(codes.InvalidArgument, "invalid notification alert")
	}
	lines := []string{"[" + strings.ToUpper(string(alert.Severity)) + "] " + alert.Title, alert.Summary, "class=" + alert.Class}
	if alert.Resource.Type != "" || alert.Resource.ID != "" {
		lines = append(lines, "resource="+alert.Resource.Type+":"+alert.Resource.ID)
	}
	keys := make([]string, 0, len(alert.Details))
	for key := range alert.Details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		lines = append(lines, key+"="+alert.Details[key])
	}
	messageID, result, err := b.send(ctx, telegramSendMessage{ChatID: b.alertChatID, Text: boundTelegramText(strings.Join(lines, "\n"))})
	if err != nil {
		return result, err
	}
	result.Evidence = notification.DeliveryEvidence{Transport: "telegram", MessageID: "telegram:" + b.alertChatID + ":" + messageID, GeneratedAt: time.Now().UTC(), Workflow: "alert"}
	return result, nil
}

func (b TelegramBackend) SendPrompt(ctx context.Context, p plugin.NotificationPrompt) (plugin.PromptResult, error) {
	if p.Transport != "telegram" || p.ID == "" || len(p.ID) > 36 || p.CorrelationID == "" || p.ActorType == "" || p.ActorID == "" || p.Action == "" || p.ResourceType == "" || p.ResourceID == "" || p.RequestHash == "" || p.ExpiresAt == "" || !validTelegramBindingToken(p.ConfirmationToken) {
		return plugin.PromptResult{}, status.Error(codes.InvalidArgument, "complete prompt binding required")
	}
	expiresAt, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil || !expiresAt.After(time.Now()) {
		return plugin.PromptResult{}, status.Error(codes.InvalidArgument, "valid prompt expiry required")
	}
	chatID, err := telegramActorChatID(p.ExternalActorID)
	if err != nil {
		return plugin.PromptResult{}, status.Error(codes.InvalidArgument, "invalid Telegram actor")
	}
	if _, ok := b.allowed[chatID]; !ok {
		return plugin.PromptResult{}, status.Error(codes.PermissionDenied, "Telegram chat is not allowed")
	}
	callback := "gm:a:" + p.ID + ":" + p.ConfirmationToken
	if len(callback) > 64 || strings.ContainsAny(callback, " \t\r\n/") {
		return plugin.PromptResult{}, status.Error(codes.InvalidArgument, "invalid confirmation binding")
	}
	clean, err := notification.SanitizeAlert(notification.Alert{ID: p.ID, Class: "approval.prompt", Title: p.Title, Summary: p.Summary, CorrelationID: p.CorrelationID, Resource: notification.ResourceRef{Type: p.ResourceType, ID: p.ResourceID}})
	if err != nil || clean.Title == "[REDACTED]" || clean.Summary == "[REDACTED]" || clean.Resource.ID == "[REDACTED]" {
		return plugin.PromptResult{}, status.Error(codes.InvalidArgument, "invalid notification prompt")
	}
	text := boundTelegramText(strings.Join([]string{clean.Title, clean.Summary, "action=" + p.Action, "resource=" + clean.Resource.Type + ":" + clean.Resource.ID, "expires=" + p.ExpiresAt}, "\n"))
	_, result, err := b.send(ctx, telegramSendMessage{ChatID: chatID, Text: text, ReplyMarkup: &telegramReplyMarkup{InlineKeyboard: [][]telegramButton{{{Text: "Approve", CallbackData: callback}}}}})
	if err != nil {
		return plugin.PromptResult{}, telegramPromptError(result, err)
	}
	return plugin.PromptResult{Accepted: true, Message: "telegram_prompt_delivered"}, nil
}

func telegramActorChatID(externalID string) (string, error) {
	parts := strings.Split(externalID, ":")
	if len(parts) != 4 || parts[0] != "chat" || parts[2] != "user" {
		return "", errors.New("invalid Telegram actor")
	}
	if _, err := strconv.ParseInt(parts[3], 10, 64); err != nil {
		return "", errors.New("invalid Telegram actor")
	}
	return cleanTelegramChatID(parts[1])
}

type telegramSendMessage struct {
	ChatID      string               `json:"chat_id"`
	Text        string               `json:"text"`
	ReplyMarkup *telegramReplyMarkup `json:"reply_markup,omitempty"`
}

type telegramReplyMarkup struct {
	InlineKeyboard [][]telegramButton `json:"inline_keyboard"`
}

type telegramButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type telegramAPIResponse struct {
	OK     bool `json:"ok"`
	Result struct {
		MessageID int64 `json:"message_id"`
	} `json:"result"`
}

func (b TelegramBackend) send(ctx context.Context, payload telegramSendMessage) (string, notification.DeliveryResult, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "telegram_invalid_payload"}, status.Error(codes.InvalidArgument, "invalid notification payload")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "telegram_invalid_request"}, status.Error(codes.InvalidArgument, "invalid notification request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return "", notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "telegram_unavailable"}, status.Error(codes.Unavailable, "Telegram delivery unavailable")
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(responseBody) > 64<<10 {
		return "", notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "telegram_invalid_response"}, status.Error(codes.Unavailable, "Telegram delivery unavailable")
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	var decoded telegramAPIResponse
	if err := decoder.Decode(&decoded); err != nil {
		return "", notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "telegram_invalid_response"}, status.Error(codes.Unavailable, "Telegram delivery unavailable")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "telegram_invalid_response"}, status.Error(codes.Unavailable, "Telegram delivery unavailable")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || !decoded.OK || decoded.Result.MessageID == 0 {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return "", notification.DeliveryResult{Status: notification.StatusFailedRetryable, Reason: "telegram_api_retry"}, status.Error(codes.Unavailable, "Telegram delivery unavailable")
		}
		return "", notification.DeliveryResult{Status: notification.StatusFailedPermanent, Reason: "telegram_api_rejected"}, status.Error(codes.InvalidArgument, "Telegram delivery rejected")
	}
	return strconv.FormatInt(decoded.Result.MessageID, 10), notification.DeliveryResult{Status: notification.StatusDelivered, Reason: "telegram_delivered"}, nil
}

func telegramPromptError(result notification.DeliveryResult, err error) error {
	if result.Status == notification.StatusFailedRetryable {
		return status.Error(codes.Unavailable, "Telegram delivery unavailable")
	}
	return err
}

func boundTelegramText(text string) string {
	text = strings.TrimSpace(text)
	const max = 4000
	if len(text) <= max {
		return text
	}
	cut := max - 1
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut] + "…"
}

func validTelegramBindingToken(token string) bool {
	if len(token) != 22 || strings.TrimSpace(token) != token {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 16
}
