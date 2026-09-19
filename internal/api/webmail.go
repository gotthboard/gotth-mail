package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
)

func (s Server) registerWebmail(mux *http.ServeMux, ids *identity.Service) {
	mux.HandleFunc("/webmail", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		webmailSecurityHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(webmailAppHTML))
	})
	mux.HandleFunc("/webmail/assets/app.css", func(w http.ResponseWriter, r *http.Request) {
		serveWebmailAsset(w, r, "text/css; charset=utf-8", webmailAppCSS)
	})
	mux.HandleFunc("/webmail/assets/app.js", func(w http.ResponseWriter, r *http.Request) {
		serveWebmailAsset(w, r, "text/javascript; charset=utf-8", webmailAppJS)
	})
	require := func(w http.ResponseWriter, r *http.Request, mutation bool) (authz.Actor, string, bool) {
		var a authz.Actor
		var mailbox string
		if r.Header.Get("Authorization") != "" {
			var err error
			a, err = ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
			if err != nil {
				http.Error(w, "webmail authentication required", http.StatusUnauthorized)
				return authz.Actor{}, "", false
			}
			mailbox = webmailMailboxScope(a)
			if mailbox == "" {
				http.Error(w, "mailbox-scoped webmail token required", http.StatusForbidden)
				return authz.Actor{}, "", false
			}
		} else {
			actor, session, authenticated := s.identityRequestActor(w, r, ids)
			if !authenticated {
				return authz.Actor{}, "", false
			}
			a = actor
			mailbox = strings.ToLower(strings.TrimSpace(a.Mailbox))
			if mailbox == "" {
				http.Error(w, "bound mailbox session required", http.StatusForbidden)
				return authz.Actor{}, "", false
			}
			if mutation {
				if session == nil || !validSessionCSRF(r, *session) {
					http.Error(w, "CSRF validation failed", http.StatusForbidden)
					return authz.Actor{}, "", false
				}
			}
		}
		d, err := s.authorizer().Decide(r.Context(), a, "webmail:use", authz.Resource{Type: "webmail", ID: mailbox})
		if err != nil || !d.Allow {
			http.Error(w, "webmail authorization required", http.StatusForbidden)
			return authz.Actor{}, "", false
		}
		return a, mailbox, true
	}
	client := s.WebmailClient
	sender := s.WebmailSender
	if sender != nil && sender.Store == nil && s.AuditDB != nil {
		sender.Store = webmail.SQLDraftStore{DB: s.AuditDB}
	}
	mux.HandleFunc("/api/v1/webmail/identity", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r, false)
		if !ok {
			return
		}
		if sender == nil {
			http.Error(w, "webmail sender unavailable", http.StatusServiceUnavailable)
			return
		}
		identity, err := sender.DefaultIdentity(r.Context(), mailbox)
		if err != nil {
			http.Error(w, "webmail signing identity unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]string{"mailbox": mailbox, "signing_fingerprint": identity.Fingerprint})
	})
	mux.HandleFunc("/api/v1/webmail/folders", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r, false)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", 503)
			return
		}
		details, err := client.FolderListDetailed(r.Context(), mailbox)
		if err != nil {
			http.Error(w, "mail folders unavailable", http.StatusBadGateway)
			return
		}
		folders := make([]string, 0, len(details))
		for _, folder := range details {
			folders = append(folders, folder.Name)
		}
		writeJSON(w, map[string]any{"folders": folders, "folder_details": details})
	})
	mux.HandleFunc("/api/v1/webmail/quota", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r, false)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", http.StatusServiceUnavailable)
			return
		}
		used, limit, err := client.Quota(r.Context(), mailbox)
		if err != nil {
			http.Error(w, "mailbox quota unavailable", http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]int64{"used_bytes": used, "limit_bytes": limit})
	})
	mux.HandleFunc("/api/v1/webmail/messages/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r, false)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", 503)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/webmail/messages/")
		parts := strings.Split(rest, "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		msg, err := client.Read(r.Context(), mailbox, parts[0], parts[1])
		if err != nil {
			http.Error(w, "message unavailable", http.StatusNotFound)
			return
		}
		writeJSON(w, msg)
	})
	mux.HandleFunc("/api/v1/webmail/message", func(w http.ResponseWriter, r *http.Request) {
		mutation := r.Method == http.MethodPost
		if r.Method != http.MethodGet && !mutation {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, mailbox, ok := require(w, r, mutation)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", http.StatusServiceUnavailable)
			return
		}
		folder, id := r.URL.Query().Get("folder"), r.URL.Query().Get("id")
		if folder == "" || id == "" {
			http.Error(w, "folder and message id required", http.StatusBadRequest)
			return
		}
		if !mutation {
			msg, err := client.Read(r.Context(), mailbox, folder, id)
			if err != nil {
				http.Error(w, "message unavailable", http.StatusNotFound)
				return
			}
			writeJSON(w, msg)
			return
		}
		var in struct {
			Action      string `json:"action"`
			Destination string `json:"destination"`
		}
		if err := decodeWebmailJSON(w, r, 4<<10, &in); err != nil {
			http.Error(w, "bad message action", http.StatusBadRequest)
			return
		}
		var err error
		switch in.Action {
		case "mark_read":
			err = client.SetFlag(r.Context(), mailbox, folder, id, "seen", true)
		case "mark_unread":
			err = client.SetFlag(r.Context(), mailbox, folder, id, "seen", false)
		case "flag":
			err = client.SetFlag(r.Context(), mailbox, folder, id, "flagged", true)
		case "unflag":
			err = client.SetFlag(r.Context(), mailbox, folder, id, "flagged", false)
		case "move":
			err = client.Move(r.Context(), mailbox, folder, id, in.Destination)
		case "delete":
			err = client.Delete(r.Context(), mailbox, folder, id)
		default:
			http.Error(w, "unsupported message action", http.StatusBadRequest)
			return
		}
		if err != nil {
			http.Error(w, "message action failed", http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/v1/webmail/attachment", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r, false)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", http.StatusServiceUnavailable)
			return
		}
		index, err := strconv.Atoi(r.URL.Query().Get("index"))
		if err != nil || index < 0 {
			http.Error(w, "valid attachment index required", http.StatusBadRequest)
			return
		}
		msg, err := client.Read(r.Context(), mailbox, r.URL.Query().Get("folder"), r.URL.Query().Get("id"))
		if err != nil || index >= len(msg.Attachments) {
			http.NotFound(w, r)
			return
		}
		attachment := msg.Attachments[index]
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": attachment.Filename}))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "private, no-store")
		_, _ = w.Write(attachment.Content)
	})
	mux.HandleFunc("/api/v1/webmail/messages", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r, false)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", 503)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		folder := r.URL.Query().Get("folder")
		if folder == "" {
			folder = "INBOX"
		}
		var (
			res webmail.ListResult
			err error
		)
		if q := r.URL.Query().Get("q"); q != "" {
			res, err = client.Search(r.Context(), mailbox, folder, q, r.URL.Query().Get("cursor"), limit)
		} else {
			res, err = client.List(r.Context(), mailbox, folder, r.URL.Query().Get("cursor"), limit)
		}
		if err != nil {
			http.Error(w, "message list unavailable", http.StatusBadGateway)
			return
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("/api/v1/webmail/drafts", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, mailbox, ok := require(w, r, r.Method == http.MethodPost)
		if !ok {
			return
		}
		if sender == nil {
			http.Error(w, "webmail sender unavailable", 503)
			return
		}
		if r.Method == http.MethodGet {
			drafts, err := sender.ListDrafts(r.Context(), mailbox, 100)
			if err != nil {
				http.Error(w, "draft list unavailable", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"drafts": drafts})
			return
		}
		var d webmail.Draft
		if err := decodeWebmailJSON(w, r, 1<<20, &d); err != nil {
			http.Error(w, "bad draft", 400)
			return
		}
		if d.From == "" {
			d.From = mailbox
		} else if d.From != mailbox {
			http.Error(w, "draft sender must match authenticated actor", http.StatusForbidden)
			return
		}
		if d.SigningFingerprint == "" {
			identity, err := sender.DefaultIdentity(r.Context(), mailbox)
			if err != nil {
				http.Error(w, "webmail signing identity unavailable", http.StatusServiceUnavailable)
				return
			}
			d.SigningFingerprint = identity.Fingerprint
		}
		d.ID = ""
		saved, err := sender.SaveDraftContext(r.Context(), d)
		if err != nil {
			http.Error(w, "draft could not be saved", http.StatusInternalServerError)
			return
		}
		writeJSON(w, saved)
	})
	mux.HandleFunc("/api/v1/webmail/drafts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_, mailbox, ok := require(w, r, r.Method != http.MethodGet)
		if !ok {
			return
		}
		if sender == nil {
			http.Error(w, "webmail sender unavailable", 503)
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/webmail/drafts/")
		submitting := r.Method == http.MethodPost && strings.HasSuffix(rest, "/submit")
		id := strings.TrimSuffix(rest, "/submit")
		if id == "" || strings.Contains(id, "/") || (r.Method == http.MethodPost && !submitting) || (r.Method != http.MethodPost && submitting) {
			http.NotFound(w, r)
			return
		}
		draft, ok, err := sender.DraftContext(r.Context(), id)
		if err != nil {
			http.Error(w, "draft unavailable", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if draft.From != mailbox {
			http.Error(w, "draft does not belong to authenticated mailbox", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodGet {
			writeJSON(w, draft)
			return
		}
		if r.Method == http.MethodPut {
			if draft.State != "" && draft.State != "draft" && draft.State != "failed" {
				http.Error(w, "draft is no longer editable", http.StatusConflict)
				return
			}
			var updated webmail.Draft
			if err := decodeWebmailJSON(w, r, 1<<20, &updated); err != nil {
				http.Error(w, "bad draft", http.StatusBadRequest)
				return
			}
			updated.ID = id
			updated.From = mailbox
			if updated.SigningFingerprint == "" {
				identity, err := sender.DefaultIdentity(r.Context(), mailbox)
				if err != nil {
					http.Error(w, "webmail signing identity unavailable", http.StatusServiceUnavailable)
					return
				}
				updated.SigningFingerprint = identity.Fingerprint
			}
			saved, updatedOK, err := sender.UpdateDraft(r.Context(), updated)
			if err != nil {
				http.Error(w, "draft could not be saved", http.StatusInternalServerError)
				return
			}
			if !updatedOK {
				http.Error(w, "draft is no longer editable", http.StatusConflict)
				return
			}
			writeJSON(w, saved)
			return
		}
		d, err := sender.Submit(r.Context(), id)
		if err != nil {
			http.Error(w, webmailSubmitError(err), http.StatusBadRequest)
			return
		}
		writeJSON(w, d)
	})
}

func decodeWebmailJSON(w http.ResponseWriter, r *http.Request, limit int64, out any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func webmailSubmitError(err error) string {
	var deliveryErr *webmail.SMTPDeliveryError
	if errors.As(err, &deliveryErr) {
		if deliveryErr.Class == webmail.SMTPFailureAmbiguous {
			return "delivery status is uncertain; do not retry automatically"
		}
		return "SMTP submission failed before acceptance"
	}
	message := err.Error()
	for _, safe := range []string{
		"draft not found or no longer submittable", "invalid recipient",
		"outbound policy rejected submission", "OpenPGP signing identity required",
		"exact sender identity binding failed", "OpenPGP signing identity invalid",
		"OpenPGP exact sender verification failed",
	} {
		if message == safe {
			return safe
		}
	}
	return "message submission failed"
}

func webmailMailboxScope(a authz.Actor) string {
	for _, scope := range a.Scopes {
		if !strings.HasPrefix(scope, "mailbox:") || !strings.HasSuffix(scope, ":webmail:use") {
			continue
		}
		mailbox := strings.TrimSuffix(strings.TrimPrefix(scope, "mailbox:"), ":webmail:use")
		if mailbox != "" && strings.Contains(mailbox, "@") && !strings.ContainsAny(mailbox, " \r\n") {
			return strings.ToLower(mailbox)
		}
	}
	return ""
}
