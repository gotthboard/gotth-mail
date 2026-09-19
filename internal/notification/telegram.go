package notification

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type TelegramReceiver struct {
	Commands        CommandService
	ExecuteApproval func(context.Context, string, string, TransportActor) error
	Now             func() time.Time
	Updates         TelegramUpdateStore
}

type TelegramReply struct {
	Method string `json:"method,omitempty"`
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

func (r TelegramReceiver) Handler() http.Handler {
	return r.handler("")
}

func (r TelegramReceiver) HandlerWithSecret(secret string) http.Handler {
	if strings.TrimSpace(secret) == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "telegram receiver unavailable", http.StatusServiceUnavailable)
		})
	}
	return r.handler(secret)
}

func (r TelegramReceiver) handler(secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if secret != "" && subtle.ConstantTimeCompare([]byte(req.Header.Get("X-Telegram-Bot-Api-Secret-Token")), []byte(secret)) != 1 {
			http.Error(w, "telegram update unauthorized", http.StatusUnauthorized)
			return
		}
		defer req.Body.Close()
		var update telegramUpdate
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 64<<10))
		if err := decoder.Decode(&update); err != nil {
			http.Error(w, "invalid telegram update", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			http.Error(w, "invalid telegram update", http.StatusBadRequest)
			return
		}
		process := func() (TelegramReply, error) { return r.Process(req.Context(), update) }
		var reply TelegramReply
		var err error
		if r.Updates != nil {
			reply, err = r.Updates.Process(req.Context(), update.UpdateID, process)
		} else {
			reply, err = process()
		}
		if reply.ChatID != "" {
			reply.Method = "sendMessage"
		}
		w.Header().Set("Content-Type", "application/json")
		if reply.ChatID == "" {
			_, _ = w.Write([]byte("{}\n"))
			return
		}
		_ = json.NewEncoder(w).Encode(reply)
		_ = err
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
		return TelegramReply{ChatID: msg.ChatID(), Text: "command denied"}, err
	}
	return TelegramReply{ChatID: msg.ChatID(), Text: resp.Summary}, nil
}

func (r TelegramReceiver) processCallback(ctx context.Context, cb telegramCallbackQuery) (TelegramReply, error) {
	id, bindingToken, ok := parseApprovalCallback(cb.Data)
	if !ok {
		return TelegramReply{ChatID: cb.ChatID(), Text: "unsupported callback"}, nil
	}
	if r.ExecuteApproval == nil {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval service unavailable"}, errors.New("approval service unavailable")
	}
	transportActor := cb.Actor()
	if err := r.ExecuteApproval(ctx, id, bindingToken, transportActor); err != nil {
		return TelegramReply{ChatID: cb.ChatID(), Text: "approval rejected"}, err
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

func parseApprovalCallback(data string) (string, string, bool) {
	data = strings.TrimSpace(data)
	if !strings.HasPrefix(data, "gm:a:") || len(data) > 64 {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(data, "gm:a:"), ":")
	if len(parts) != 2 {
		return "", "", false
	}
	id, token := parts[0], parts[1]
	if id == "" || strings.ContainsAny(id, " \t\r\n/") || len(id) > 36 || !validBindingToken(token) {
		return "", "", false
	}
	return id, token, true
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
