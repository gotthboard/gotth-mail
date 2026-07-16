package httpui

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"forgejo/linus/gophermailforge/internal/admin"
)

func TestMailAdminCRUDScreensRenderAndMutate(t *testing.T) {
	s := admin.NewStore()
	h := HandlerWithAdmin(s)
	form := url.Values{"name": {"Example.Test"}, "enabled": {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/domains", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("domain status=%d", w.Code)
	}
	form = url.Values{"address": {"Smoke@Example.Test"}, "enabled": {"on"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	form = url.Values{"address": {"Alias@Example.Test"}, "targets": {"Smoke@Example.Test"}, "enabled": {"on"}}
	req = httptest.NewRequest(http.MethodPost, "/admin/aliases", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body, _ := io.ReadAll(w.Result().Body)
	text := string(body)
	for _, want := range []string{"Domain CRUD", "User CRUD", "Alias CRUD", "example.test", "smoke@example.test", "alias@example.test", "Doctor screens", "DNS/DKIM screens", "Plugin status/config screens", "Lookup debugger UI"} {
		if !strings.Contains(text, want) {
			t.Fatalf("admin UI missing %q in %s", want, text)
		}
	}
}
