package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/identity"
	"forgejo/linus/gophermailforge/internal/webmail"
)

func (s Server) registerWebmail(mux *http.ServeMux, ids *identity.Service) {
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
		writeJSON(w, sender.SaveDraft(d))
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
		draft, ok := sender.Draft(id)
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
