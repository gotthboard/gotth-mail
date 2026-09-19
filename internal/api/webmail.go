package api

import (
	"encoding/json"
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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(webmailShellHTML))
	})
	require := func(w http.ResponseWriter, r *http.Request) (authz.Actor, string, bool) {
		a, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "webmail bearer token required", http.StatusUnauthorized)
			return authz.Actor{}, "", false
		}
		mailbox := webmailMailboxScope(a)
		if mailbox == "" {
			http.Error(w, "mailbox-scoped webmail token required", http.StatusForbidden)
			return authz.Actor{}, "", false
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
	mux.HandleFunc("/api/v1/webmail/folders", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", 503)
			return
		}
		folders, err := client.FolderList(r.Context(), mailbox)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]any{"folders": folders})
	})
	mux.HandleFunc("/api/v1/webmail/quota", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r)
		if !ok {
			return
		}
		if client == nil {
			http.Error(w, "webmail client unavailable", http.StatusServiceUnavailable)
			return
		}
		used, limit, err := client.Quota(r.Context(), mailbox)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]int64{"used_bytes": used, "limit_bytes": limit})
	})
	mux.HandleFunc("/api/v1/webmail/messages/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r)
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
			http.Error(w, err.Error(), 404)
			return
		}
		writeJSON(w, msg)
	})
	mux.HandleFunc("/api/v1/webmail/messages", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		_, mailbox, ok := require(w, r)
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
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, res)
	})
	mux.HandleFunc("/api/v1/webmail/drafts", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		_, mailbox, ok := require(w, r)
		if !ok {
			return
		}
		if sender == nil {
			http.Error(w, "webmail sender unavailable", 503)
			return
		}
		var d webmail.Draft
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&d); err != nil {
			http.Error(w, "bad draft", 400)
			return
		}
		if d.From == "" {
			d.From = mailbox
		} else if d.From != mailbox {
			http.Error(w, "draft sender must match authenticated actor", http.StatusForbidden)
			return
		}
		d.ID = ""
		saved, err := sender.SaveDraftContext(r.Context(), d)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, saved)
	})
	mux.HandleFunc("/api/v1/webmail/drafts/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		_, mailbox, ok := require(w, r)
		if !ok {
			return
		}
		if sender == nil {
			http.Error(w, "webmail sender unavailable", 503)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/webmail/drafts/"), "/submit")
		if !strings.HasSuffix(r.URL.Path, "/submit") || id == "" {
			http.NotFound(w, r)
			return
		}
		draft, ok, err := sender.DraftContext(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), 500)
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
		d, err := sender.Submit(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, d)
	})
}

const webmailShellHTML = `<!doctype html><html><head><meta charset="utf-8"><title>GOTTH Mail Webmail</title></head><body><main id="gotth-mail-webmail"><h1>GOTTH Mail Webmail</h1><p id="transport-note">Custom webmail shell backed by the GOTTH Mail webmail API, Dovecot IMAP, SMTP submission, durable drafts, and conservative text-only message rendering.</p><section id="folders"><h2>Folders</h2><p>Loads from <code>/api/v1/webmail/folders</code> with a mailbox-scoped bearer token.</p></section><section id="messages"><h2>Messages</h2><p>Lists, searches, and reads via <code>/api/v1/webmail/messages</code>. HTML message bodies are treated as data unless a real sanitizer/browser proof is admitted.</p></section><section id="drafts"><h2>Drafts</h2><p>Saves mailbox-owned drafts through <code>/api/v1/webmail/drafts</code>; submit requires exact sender signing and SMTP submission.</p></section></main></body></html>`

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
