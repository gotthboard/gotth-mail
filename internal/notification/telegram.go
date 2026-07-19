package notification

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ApprovalConfirmer interface {
	Get(context.Context, string) (ApprovalRequest, bool, error)
	Confirm(context.Context, ApprovalConfirmation) (ApprovalRequest, error)
}

type TelegramReceiver struct {
	Commands  CommandService
	Mapper    ActorMapper
	Approvals ApprovalConfirmer
	Now       func() time.Time
}

type TelegramReply struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

func (r TelegramReceiver) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer req.Body.Close()
		var update telegramUpdate
		if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 64<<10)).Decode(&update); err != nil {
			http.Error(w, "invalid telegram update", http.StatusBadRequest)
			return
		}
		reply, err := r.Process(req.Context(), update)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(reply)
	})
}

func (r TelegramReceiver) Process(ctx context.Context, update telegramUpdate) (TelegramReply, error) {
	if update.Message != nil {
		return r.processMessage(ctx, *update.Message)
	}
	if update.CallbackQuery != nil {
		return r.processCallback(ctx, *update.CallbackQuery)
	}
	return TelegramReply{}, errors.New("unsupported telegram update")
}

func (r TelegramReceiver) processMessage(ctx context.Context, msg telegramMessage) (TelegramReply, error) {
	cmd, ok := parseTelegramCommand(msg.Text)
	if !ok {
		return TelegramReply{ChatID: msg.ChatID(), Text: "unsupported command"}, nil
	}
	resp, err := r.Commands.Run(ctx, CommandRequest{TransportActor: msg.Actor(), Command: cmd, CorrelationID: msg.CorrelationID()})
	if err != nil {
		return TelegramReply{ChatID: msg.ChatID(), Text: "denied: " + boundLine(err.Error(), 120)}, err
	}
	return TelegramReply{ChatID: msg.ChatID(), Text: resp.Summary}, nil
}

func (r TelegramReceiver) processCallback(ctx context.Context, cb telegramCallbackQuery) (TelegramReply, error) {
	id, ok := parseApprovalCallback(cb.Data)
	if !ok {
		return TelegramReply{ChatID: cb.ChatID(), Text: "unsupported callback"}, nil
	}
	if r.Mapper == nil || r.Approvals == nil {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval service unavailable"}, errors.New("approval service unavailable")
	}
	transportActor := cb.Actor()
	actor, mapped, err := r.Mapper.Map(ctx, transportActor)
	if err != nil {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval mapping failed"}, err
	}
	if !mapped {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval actor unmapped"}, errors.New("notification actor mapping required")
	}
	req, found, err := r.Approvals.Get(ctx, id)
	if err != nil {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval lookup failed"}, err
	}
	if !found {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval not found"}, errors.New("approval request not found")
	}
	_, err = r.Approvals.Confirm(ctx, ApprovalConfirmation{ID: id, TransportActor: transportActor, Actor: actor, Action: req.Action, Resource: req.Resource, RequestHash: req.RequestHash, Now: r.now()})
	if err != nil {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval rejected: " + boundLine(err.Error(), 120)}, err
	}
	return TelegramReply{ChatID: cb.ChatID(), Text: "approval accepted"}, nil
}

func (r TelegramReceiver) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func parseTelegramCommand(text string) (ReadOnlyCommand, bool) {
	cmd := strings.Fields(strings.TrimSpace(text))
	if len(cmd) == 0 || !strings.HasPrefix(cmd[0], "/") {
		return "", false
	}
	name := strings.TrimPrefix(cmd[0], "/")
	if i := strings.IndexByte(name, '@'); i >= 0 {
		name = name[:i]
	}
	switch strings.ToLower(name) {
	case "doctor":
		return CommandDoctorSummary, true
	case "queue":
		return CommandQueueSummary, true
	case "domains":
		return CommandDomainHealth, true
	case "backup":
		return CommandBackupStatus, true
	case "deploy", "deployment":
		return CommandDeploymentStatus, true
	case "plugins":
		return CommandPluginHealth, true
	default:
		return "", false
	}
}

func parseApprovalCallback(data string) (string, bool) {
	data = strings.TrimSpace(data)
	if !strings.HasPrefix(data, "gmf:approve:") {
		return "", false
	}
	id := strings.TrimSpace(strings.TrimPrefix(data, "gmf:approve:"))
	if id == "" || strings.ContainsAny(id, " \t\r\n/") || len(id) > 128 {
		return "", false
	}
	return id, true
}

type telegramUpdate struct {
	UpdateID      int                    `json:"update_id"`
	Message       *telegramMessage       `json:"message,omitempty"`
	CallbackQuery *telegramCallbackQuery `json:"callback_query,omitempty"`
}

type telegramUser struct {
	ID       int64  `json:"id"`
	Username string `json:"username,omitempty"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}

type telegramMessage struct {
	MessageID int64        `json:"message_id"`
	From      telegramUser `json:"from"`
	Chat      telegramChat `json:"chat"`
	Text      string       `json:"text"`
}

func (m telegramMessage) ChatID() string { return strconv.FormatInt(m.Chat.ID, 10) }
func (m telegramMessage) Actor() TransportActor {
	return TransportActor{Transport: "telegram", ExternalID: "chat:" + strconv.FormatInt(m.Chat.ID, 10) + ":user:" + strconv.FormatInt(m.From.ID, 10)}
}
func (m telegramMessage) CorrelationID() string {
	return "telegram:" + strconv.FormatInt(m.Chat.ID, 10) + ":" + strconv.FormatInt(m.MessageID, 10)
}

type telegramCallbackQuery struct {
	ID      string           `json:"id"`
	From    telegramUser     `json:"from"`
	Message *telegramMessage `json:"message,omitempty"`
	Data    string           `json:"data"`
}

func (c telegramCallbackQuery) ChatID() string {
	if c.Message != nil {
		return c.Message.ChatID()
	}
	return ""
}
func (c telegramCallbackQuery) Actor() TransportActor {
	chatID := int64(0)
	if c.Message != nil {
		chatID = c.Message.Chat.ID
	}
	return TransportActor{Transport: "telegram", ExternalID: "chat:" + strconv.FormatInt(chatID, 10) + ":user:" + strconv.FormatInt(c.From.ID, 10)}
}
