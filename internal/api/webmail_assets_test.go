package api

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebmailSharedAssetServedIdentity(t *testing.T) {
	h := webmailServer(t, &apiFakeSMTP{})
	for _, tc := range []struct {
		path, mime, hash string
		size             int
	}{
		{"/webmail/assets/app.css", "text/css; charset=utf-8", "6645ad2c766970bd568e4d3d1db75f060e2e0669ec0f375b6b4cddc077822c28", 11102},
		{"/webmail/assets/htmx-2.0.10.min.js", "text/javascript; charset=utf-8", "71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de", 0},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != 200 || fmt.Sprintf("%x", sha256.Sum256(w.Body.Bytes())) != tc.hash || (tc.size > 0 && w.Body.Len() != tc.size) {
				t.Fatal("served asset changed", w.Code, w.Body.Len())
			}
			for key, want := range map[string]string{"Content-Type": tc.mime, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; trusted-types default; require-trusted-types-for 'script'"} {
				if w.Header().Get(key) != want {
					t.Errorf("%s changed", key)
				}
			}
		})
	}
}
