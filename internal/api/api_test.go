package api

import (
	"forgejo/linus/gophermailforge/internal/authz"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthAndStatus(t *testing.T) {
	h := Server{Authz: authz.StaticAuthorizer{}}.Handler()
	for _, path := range []string{"/healthz", "/readyz", "/api/v1/status"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != 200 {
			t.Fatalf("%s status %d", path, rr.Code)
		}
	}
}
