package httpui

import (
	"bytes"
	_ "embed"
	"io"
	"net/http"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/presentation"
	"github.com/a-h/templ"
)

const inventoryMarker = "<!-- gotth-mail-extension-inventory-v1 -->"
const inventoryHTMXConfig = "{\"allowEval\":false,\"allowScriptTags\":false,\"selfRequestsOnly\":true,\"includeIndicatorStyles\":false,\"historyEnabled\":false,\"historyCacheSize\":0,\"historyRestoreAsHxRequest\":false,\"allowNestedOobSwaps\":false,\"timeout\":10000}"
const inventoryTokensCSS = ":root{" + presentation.LightColors + "color-scheme:light}\n@media(prefers-color-scheme:dark){:root[data-theme=system]{" + presentation.DarkColors + "color-scheme:dark}}\n:root[data-theme=dark]{" + presentation.DarkColors + "color-scheme:dark}\n"

//go:embed assets/inventory.css
var inventoryCSS string

//go:embed assets/inventory.js
var inventoryJS string

type inventoryView struct {
	Items         []extensionsadmin.Instance
	BlockedReason string
	Theme         string
}

// Complexity: fixed scalar normalization time/space O(1), Omega(1), Theta(1).
// String equality rejects other lengths before comparing bounded literal bytes.
func inventoryTheme(value string) string {
	switch value {
	case "light", "dark":
		return value
	default:
		return "system"
	}
}

// Complexity: time and auxiliary space O(1), Omega(1), Theta(1): only a
// fixed-length UUID is inspected and the resulting fixed-length path allocated.
func inventoryDetailURL(id string) string {
	if len(id) != 36 {
		return "/admin/extensions"
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "/admin/extensions"
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "/admin/extensions"
		}
	}
	return "/admin/extensions/" + id
}

// Complexity: under a bounded existing response-header set, time/space
// O(1), Omega(1), Theta(1). Fixed headers do not scale with inventory size.
func inventoryHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Add("Vary", "HX-Request, HX-History-Restore-Request")
	h.Set("Cache-Control", "private, no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
}

// Complexity: successful buffered rendering time O(R+B+W), Omega(B); auxiliary
// O(S+B), Omega(B), tight Theta not established for arbitrary components/writers.
// B rendered bytes, R/S delegated templ render time/memory, W transport cost.
// Exactly one outer buffer prevents a component failure committing partial200.
// This is NOT a fixed response-byte bound; List and templ internal storage remain.
func writeInventoryComponent(w http.ResponseWriter, r *http.Request, c templ.Component, fragment bool) error {
	var buf bytes.Buffer
	if fragment {
		buf.WriteString(inventoryMarker)
	}
	if err := c.Render(r.Context(), &buf); err != nil {
		http.Error(w, "extension inventory rendering unavailable", http.StatusInternalServerError)
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := buf.WriteTo(w)
	return err // Post-commit transport failure cannot be changed into a500.
}

// Complexity: registration O(R), Omega(1) time, O(S), Omega(1) auxiliary
// space for delegated mux registration R/S; tight bounds depend on mux state.
// Each fixed-asset response costs O(B+W), Omega(B) time; O(B), Omega(1) space,
// no tight allocation bound across writers. B asset bytes, W transport work.
func registerInventoryAssets(mux *http.ServeMux) {
	for _, asset := range []struct{ name, mime, body string }{
		{"inventory.css", "text/css; charset=utf-8", inventoryCSS},
		{"tokens.css", "text/css; charset=utf-8", inventoryTokensCSS},
		{"htmx-2.0.10.min.js", "text/javascript; charset=utf-8", presentation.HTMX()},
		{"inventory.js", "text/javascript; charset=utf-8", inventoryJS},
	} {
		mux.HandleFunc("/admin/extensions/assets/"+asset.name, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", asset.mime)
			_, _ = io.WriteString(w, asset.body)
		})
	}
}
