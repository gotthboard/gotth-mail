package httpui

import (
	"bytes"
	_ "embed"
	"errors"
	"io"
	"net/http"

	"github.com/a-h/templ"
)

var errExtensionDetailRender = errors.New("extension detail render failed")
var errExtensionDetailWrite = errors.New("extension detail transport failed")

// Complexity: time O(R+B+W), Omega(1) across failures, Omega(B) on complete
// rendering; auxiliary space O(S+B), Omega(1), Omega(B) for buffered output.
// B rendered bytes; R/S delegated component time/space; W transport work.
// Tight Theta bounds are not established for arbitrary components/writers.
// One outer buffer prevents render failure from committing partial success.
// This is a display boundary after mutation, not rollback or a resource cap.
func writeExtensionDetailComponent(w http.ResponseWriter, r *http.Request, c templ.Component) error {
	h := w.Header()
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
	var buf bytes.Buffer
	err := r.Context().Err()
	if err == nil {
		err = c.Render(r.Context(), &buf)
	}
	if err == nil {
		err = r.Context().Err()
	}
	if err != nil {
		http.Error(w, "extension display unavailable; verify current state before retrying", http.StatusInternalServerError)
		return errExtensionDetailRender
	}
	h.Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err = buf.WriteTo(w); err != nil {
		return errExtensionDetailWrite
	}
	return nil
}

//go:embed assets/detail.css
var extensionDetailCSS string

// Complexity: registration time O(R), Omega(1), space O(S), Omega(1),
// with R/S delegated mux costs; no general tight bound. Each response costs
// O(B+W) time, Omega(1) across errors, Omega(B) for full GET; auxiliary O(B),
// Omega(1), no tight bound across writers. B fixed asset bytes, W transport.
func registerExtensionDetailAsset(mux *http.ServeMux) {
	mux.HandleFunc("/admin/extensions/assets/detail.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		_, _ = io.WriteString(w, extensionDetailCSS)
	})
}
