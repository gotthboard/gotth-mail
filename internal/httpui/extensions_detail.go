package httpui

import (
	"bytes"
	_ "embed"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/a-h/templ"

	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
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
	extensionDetailHeaders(w)
	h := w.Header()
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

// extensionOperationErrorMessage projects operation errors, never their diagnostics.
// Errors can follow committed changes; no message promises rollback or no effects.
// Complexity: time O(1+T), Omega(1); auxiliary space O(1+S), Omega(1).
// T is the total cost of at most six errors.Is traversals, including custom
// Is/Unwrap methods; S is their peak auxiliary storage (including tree recursion).
// Tight Theta is not established for arbitrary delegates. Local nil handling and
// literal selection are Theta(1) time/space; no error text is read or copied.
func extensionOperationErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, extensionsadmin.ErrUnavailable):
		return "extension administrator unavailable. Check current state before retrying."
	case errors.Is(err, extensionsadmin.ErrNotFound):
		return "extension instance not found. Check current state before retrying."
	case errors.Is(err, extensionsadmin.ErrConflict):
		return "extension state conflict. Check current state before retrying."
	case errors.Is(err, extensionsadmin.ErrConfirmation):
		return "extension confirmation rejected. Check the confirmation required for this operation. Check current state before retrying."
	case errors.Is(err, extensionsadmin.ErrUnauthenticated):
		return "extension runtime unauthenticated. Check current state before retrying."
	case errors.Is(err, extensionsadmin.ErrUnhealthy):
		return "extension runtime unhealthy. Check current state before retrying."
	default:
		return "Extension operation could not be confirmed. Check current state before retrying."
	}
}

// extensionDetailActionURL receives the already-authorized route spelling, not
// Item.InstanceID: PostgreSQL aliases and raw-ID token scopes are distinct.
// Complexity: time and auxiliary space O(1+P), Omega(1+P), Theta(1+P), where
// P is route-ID bytes escaped/copied. Theme selection compares fixed literals.
// No request Host, RawQuery, fragment, credential or action enters this URL.
func extensionDetailActionURL(authorizedRouteID, theme string) string {
	return "/admin/extensions/" + url.PathEscape(authorizedRouteID) + "?theme=" + inventoryTheme(theme)
}

// Complexity: O(1+H) time/space, Omega(1); H delegated Header/Set work.
// Fixed key/value bytes, no request input; no tight bound for custom writers.
func extensionDetailHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "private, no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'")
}

// UI classification of a decoded snapshot, not raw decoding or an atomic service
// precondition. In particular it cannot recover unknown/duplicate raw JSON keys.
// Complexity: time O(F+V), Omega(1), auxiliary O(M), Omega(1); F fields, V/M
// delegated ValidateMetadata maps, value checks and JSON marshal storage/work.
// No tight Theta across early failures. The float scan itself uses O(1) space.
func extensionMetadataDisplayValid(metadata extensionsadmin.Metadata) bool {
	for _, field := range metadata.Fields {
		if field.Kind == extensionsadmin.FieldInteger {
			if value, ok := field.Default.(float64); ok && (math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < -0x1p63 || value >= 0x1p63) {
				return false
			}
		}
	}
	return extensionsadmin.ValidateMetadata(metadata) == nil
}

// This DTO intentionally has no Instance, Metadata, Configuration, Fields, diff,
// secret/status lists, or raw diagnostic. Strings are fixed notices or admitted
// scalars; CSRF retains every authenticated length and is escaped by templ.
type extensionRecoveryView struct {
	InstanceID, ExtensionID, Pin, PreviousPin string
	Revision                                  int64
	Enabled, Routed, Blocked, OperationError  bool
	PreviewID, Confirmation, Operation        string
	CSRF, RouteID, Theme, ActionURL, Message  string
}

var recoveryUUID = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
var recoveryPin = regexp.MustCompile("^sha256:[0-9a-f]{64}$")
var recoveryTokenPart = regexp.MustCompile("^[a-z][a-z0-9-]*[a-z0-9]$|^[a-z]$")
var recoveryPreviewID = regexp.MustCompile("^extp_[0-9a-f]{24}$")
var recoveryConfirmation = regexp.MustCompile("^confirm-[0-9a-f]{32}$")

// Scalar grammar mirrors existing service Install/createPreview and SQL0017
// contracts; invalid nonmetadata authority fails display, never truncates it.
// No raw lifecycle is inspected. Route spelling already passed auth/Get.
// Complexity: O(1+I+P) time/space, Omega(1); I bounded identity bytes, P route
// escape/copy bytes. Regex/delegates preclude a universal tight Theta on failure.
// Struct copying is constant; no metadata/config/secrets are copied or marshaled.
func extensionRecoveryProjection(view extensionPageView, route, theme string) (extensionRecoveryView, error) {
	item := view.Item
	if !recoveryUUID.MatchString(item.InstanceID) || len(item.ExtensionID) < 3 || len(item.ExtensionID) > 128 || !recoveryPin.MatchString(item.ArtifactPin) || item.PreviousArtifact != "" && !recoveryPin.MatchString(item.PreviousArtifact) || item.ConfigurationRev < 1 || len(route) > 41 {
		return extensionRecoveryView{}, errExtensionDetailRender
	}
	parts := strings.Split(item.ExtensionID, ".")
	if len(parts) < 2 {
		return extensionRecoveryView{}, errExtensionDetailRender
	}
	for _, part := range parts {
		if len(part) > 63 || !recoveryTokenPart.MatchString(part) {
			return extensionRecoveryView{}, errExtensionDetailRender
		}
	}
	preview := view.Preview
	if preview.Operation != "" {
		if (preview.Operation != "delete_secrets" && preview.Operation != "uninstall") || !recoveryPreviewID.MatchString(preview.ID) || !recoveryConfirmation.MatchString(preview.Confirmation) {
			return extensionRecoveryView{}, errExtensionDetailRender
		}
	}
	return extensionRecoveryView{InstanceID: item.InstanceID, ExtensionID: item.ExtensionID, Pin: item.ArtifactPin, PreviousPin: item.PreviousArtifact, Revision: item.ConfigurationRev, Enabled: item.Enabled, Routed: item.Routed, Blocked: view.BlockedReason != "", OperationError: view.OperationError, PreviewID: preview.ID, Confirmation: preview.Confirmation, Operation: preview.Operation, CSRF: view.CSRF, RouteID: route, Theme: inventoryTheme(theme), ActionURL: extensionDetailActionURL(route, theme), Message: view.Message}, nil
}
