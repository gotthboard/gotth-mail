package httpui

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
)

type extensionFieldView struct {
	Name, Label, Kind, Value string
	Required, Checked        bool
	Options                  []string
}

type extensionPageView struct {
	PermissionsPage uint64
	Item            extensionsadmin.Instance
	Fields          []extensionFieldView
	Preview         extensionsadmin.Preview
	UpdateTarget    extensionsadmin.UpdateInput
	Message         string
	OperationError  bool
	ActionURL       string
	BlockedReason   string
	CSRF            string
}

// Complexity: registration time O(1+R), Omega(1); auxiliary space
// O(1+S), Omega(1). No tight Theta bound for arbitrary supplied mux state.
// Local fixed-pattern/closure setup is constant; R/S include delegated ServeMux
// parsing, conflict scans, synchronization waits and tree/index allocation/growth.
// Inventory request: time O(A+U+Q+N+B), Omega(N+B) on successful reads;
// auxiliary O(U+L+B), Omega(B). A auth time, U bounded query parsing/URL bytes,
// Q SQL/service time (including selected status queries), N<=50 selected rows,
// B escaped output bytes, L selected payload/grant storage. Tight Theta bounds
// are not established across delegated auth/SQL/rendering. No per-row byte/grant,
// database-work or fixed response-byte bound; query count excludes auth work.
// Detail rendering adds O(U+P+Rd+Bd+Wd) time and O(U+P+Sd+Bd) space,
// Omega(Bd) on complete output. U query bytes, P escaped raw route bytes,
// Rd/Sd delegated components, Bd output, Wd transport. No tight bounds.
// Normal metadata-valid GET parsing caps U at4096 before ParseQuery; recovery/POST
// keep existing query semantics. Page admission and template selection each inspect
// three lengths/sub-slices, Theta(1) local work/space, without copying grant arrays.
// No additional service read; submitted configure-preview Fields are retained.
// Loaded and result metadata classification adds O(F+V) time/O(M) space,
// Omega(1), with V/M delegated validation (maps/marshal/copies). No tight Theta
// across invalid paths; this is snapshot UI policy, not atomic backend validation.
// Terminal response adds O(U+Rt+Bt+Wt) time, Omega(Bt) on complete rendering,
// and O(U+St+Bt) auxiliary space, Omega(Bt) for complete buffered output.
// U raw-query parsing bytes, Rt/St delegated templ costs, Bt receipt bytes,
// Wt transport. No general tight bound or new SQL query.
// POST error projection adds O(1+E) time / O(1+Es) auxiliary space,
// Omega(1); E/Es are delegated errors.Is traversal/custom-method costs.
// No uniform tight Theta bound; literal presentation-role selection is Theta(1).
// Audit request costs are specified by registerExtensionAuditUI. Quarantine uses
// O(P+F+W) time, Omega(1), and O(P) space, Omega(1), tight Theta not established
// across errors: P tracked runtime dirs, F filesystem work, W lock wait.
func registerExtensionUI(mux *http.ServeMux, ids *identity.Service, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time, service *extensionsadmin.Service) {
	registerInventoryAssets(mux)
	registerExtensionDetailAsset(mux)
	registerExtensionAuditUI(mux, ids, az, sessions, now, service)
	mux.HandleFunc("/admin/extensions", func(w http.ResponseWriter, r *http.Request) {
		inventoryHeaders(w)
		if r.URL.Path != "/admin/extensions" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		_, _, ok := requireExtensionUIActor(w, r, ids, az, sessions, now, false, authz.Resource{Type: "extensions", ID: extensionsadmin.Product})
		if !ok {
			return
		}
		if service == nil {
			http.Error(w, "extension administrator unavailable", http.StatusServiceUnavailable)
			return
		}
		query, err := parseInventoryPageQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid extension inventory query", http.StatusBadRequest)
			return
		}
		page, err := service.ListInventoryPage(r.Context(), query.AfterKey)
		if err != nil {
			http.Error(w, "extension inventory unavailable", http.StatusInternalServerError)
			return
		}
		view := inventoryView{Items: page.Items, Theme: query.Theme, AfterCursor: query.AfterCursor}
		if page.HasMore {
			view.NextCursor = inventoryPageCursor(page.Items[len(page.Items)-1].ExtensionID)
		}
		if service.RuntimeBlockReason != nil {
			view.BlockedReason = service.RuntimeBlockReason()
		}
		fragment := r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
		component := inventoryDocument(view)
		if fragment {
			component = inventoryRows(view)
		}
		if err := writeInventoryComponent(w, r, component, fragment); err != nil {
			log.Print("extension inventory render/transport failure")
		}
	})

	mux.HandleFunc("/admin/extensions/", func(w http.ResponseWriter, r *http.Request) {
		extensionDetailHeaders(w)
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/extensions/"), "/")
		if id == "" || strings.Contains(id, "/") || (r.Method != http.MethodGet && r.Method != http.MethodPost) {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid extension form", http.StatusBadRequest)
				return
			}
		}
		actor, csrf, ok := requireExtensionUIActor(w, r, ids, az, sessions, now, r.Method == http.MethodPost, authz.Resource{Type: "extension", ID: id})
		if !ok {
			return
		}
		if service == nil {
			http.Error(w, "extension administrator unavailable", http.StatusServiceUnavailable)
			return
		}
		item, err := service.Get(r.Context(), id)
		if err != nil {
			writeExtensionUIError(w, err)
			return
		}
		metadataValid := extensionMetadataDisplayValid(item.Metadata)
		view := extensionPageView{Item: item, CSRF: csrf}
		if r.Method == http.MethodPost {
			view, err = applyExtensionUIAction(r, service, actor, item, metadataValid)
			view.CSRF = csrf
			if err != nil {
				view.Item = item
				view.Message = extensionOperationErrorMessage(err)
				view.OperationError = true
			}
		}
		if service.RuntimeBlockReason != nil {
			view.BlockedReason = service.RuntimeBlockReason()
		}
		if r.Method == http.MethodPost && r.Form.Get("action") == "uninstall-apply" && err == nil && view.Item.InstanceID == "" {
			if err := writeExtensionDetailComponent(w, r, extensionTerminalDocument(inventoryTheme(r.URL.Query().Get("theme")), view.BlockedReason)); err != nil {
				log.Print("extension terminal render/transport failure")
			}
			return
		}
		// GET and errors retain the originally classified snapshot. Only a
		// successful POST can supply a replacement requiring classification.
		if r.Method == http.MethodPost && err == nil {
			metadataValid = extensionMetadataDisplayValid(view.Item.Metadata)
		}
		theme := "system"
		if r.Method == http.MethodGet && metadataValid {
			query, queryErr := parsePermissionsPageQuery(r.URL.RawQuery)
			if queryErr != nil {
				http.Error(w, "invalid permissions page query", http.StatusBadRequest)
				return
			}
			theme = query.Theme
			if _, pageErr := permissionsWindow(view.Item.Capabilities, view.Item.Interfaces, view.Item.SecretSlots, query.Page); pageErr != nil {
				if pageErr == errPermissionsPageRange {
					http.Error(w, "permissions page not found", http.StatusNotFound)
				} else {
					http.Error(w, "extension display unavailable; verify current state before retrying", http.StatusInternalServerError)
				}
				return
			}
			view.PermissionsPage = query.Page
		} else {
			theme = inventoryTheme(r.URL.Query().Get("theme"))
		}
		if !metadataValid {
			recovery, projectionErr := extensionRecoveryProjection(view, id, theme)
			if projectionErr != nil {
				http.Error(w, "extension display unavailable; verify current state before retrying", http.StatusInternalServerError)
				return
			}
			if err := writeExtensionDetailComponent(w, r, extensionMetadataRecoveryDocument(recovery)); err != nil {
				log.Print("extension recovery render/transport failure")
			}
			return
		}
		if r.Method != http.MethodPost || err != nil || r.Form.Get("action") != "configure-preview" {
			view.Fields = extensionFields(view.Item, nil)
		}
		view.ActionURL = extensionDetailActionURL(id, theme)
		if err := writeExtensionDetailComponent(w, r, extensionDetailDocument(view, id, theme)); err != nil {
			log.Print("extension detail render/transport failure")
		}
	})
}

func requireExtensionUIActor(w http.ResponseWriter, r *http.Request, ids *identity.Service, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time, mutation bool, resource authz.Resource) (audit.ActorRef, string, bool) {
	if r.Header.Get("Authorization") != "" {
		actor, ok := requireUIAuditActor(w, r, ids, az, "ops:admin", resource)
		return actor, "", ok
	}
	if sessions == nil {
		http.Error(w, "admin identity session required", http.StatusUnauthorized)
		return audit.ActorRef{}, "", false
	}
	bound, actor, csrf, ok := boundUIIdentity(w, r, sessions, now)
	if !ok {
		return audit.ActorRef{}, "", false
	}
	if az == nil {
		az = authz.StaticAuthorizer{}
	}
	decision, err := az.Decide(r.Context(), actor, "ops:admin", resource)
	if err != nil || !decision.Allow {
		http.Error(w, "admin authorization required", http.StatusForbidden)
		return audit.ActorRef{}, "", false
	}
	if mutation && !validUIFormCSRF(r.Form.Get("csrf_token"), csrf, bound.Session) {
		http.Error(w, "CSRF validation failed", http.StatusForbidden)
		return audit.ActorRef{}, "", false
	}
	return audit.ActorRef{Type: actor.Type, ID: actor.ID}, csrf, true
}

// Complexity: time O(B+P+D), Omega(1); auxiliary space O(B+A+M),
// Omega(1) across action/error paths. Configure-preview projection is
// Omega(F+O) time/space. No general tight Theta across delegated calls.
// B form/configuration bytes, P/A time/space of the configure-preview
// extensionFields projection/copies; F fields, O option entries. D/M
// delegated service time/memory include validation, hashing, serialization,
// SQL/audit, filesystem/runtime work and lock waits. Target-bound Apply adds
// one parameterized SQL query inside the existing service call, not a preflight Get; actual driver/protocol cost is delegated.
// Recovery dispatch adds Theta(1) time/space for fixed action selection.
// No eager field projection; caller classifies results before projecting.
// No extra service calls;
// successful configure preview retains its input projection, never stored values.
func applyExtensionUIAction(r *http.Request, service *extensionsadmin.Service, actor audit.ActorRef, item extensionsadmin.Instance, metadataValid bool) (extensionPageView, error) {
	view := extensionPageView{Item: item}
	action := r.Form.Get("action")
	if !metadataValid {
		switch action {
		case "disable", "secrets-delete-preview", "secrets-delete-apply", "uninstall-preview", "uninstall-apply", "rollback", "update-apply":
		default:
			view.Message = "Operation unavailable while configuration metadata is invalid"
			view.OperationError = true
			return view, nil
		}
	}
	var err error
	switch action {
	case "configure-preview":
		input, inputErr := extensionConfigurationInput(item, r)
		if inputErr != nil {
			return view, inputErr
		}
		view.Preview, err = service.PreviewConfigure(r.Context(), actor, item.InstanceID, input)
		view.Fields = extensionFields(item, input.Configuration)
	case "configure-apply":
		input, inputErr := extensionConfigurationInput(item, r)
		if inputErr != nil {
			return view, inputErr
		}
		view.Item, err = service.ApplyConfigure(r.Context(), actor, item.InstanceID, r.Form.Get("preview_id"), r.Form.Get("confirmation"), input)
	case "test":
		view.Item, err = service.Test(r.Context(), actor, item.InstanceID)
	case "enable":
		view.Item, err = service.Enable(r.Context(), actor, item.InstanceID)
	case "disable":
		view.Item, err = service.Disable(r.Context(), actor, item.InstanceID)
	case "update-preview":
		input := extensionsadmin.UpdateInput{ArtifactPin: r.Form.Get("artifact_pin"), ManifestDigest: r.Form.Get("manifest_sha256"), GrantDigest: r.Form.Get("grant_sha256"), SessionDigest: r.Form.Get("session_sha256"), Capabilities: commaTokens(r.Form.Get("capabilities")), Interfaces: commaTokens(r.Form.Get("interfaces")), SecretSlots: commaTokens(r.Form.Get("secret_slots")), Metadata: item.Metadata}
		view.Preview, err = service.PreviewUpdate(r.Context(), actor, item.InstanceID, input)
		if err == nil {
			view.UpdateTarget = input
		}
	case "update-apply":
		view.Item, err = service.ApplyUpdate(r.Context(), actor, item.InstanceID, r.Form.Get("preview_id"), r.Form.Get("confirmation"))
	case "rollback":
		view.Item, err = service.Rollback(r.Context(), actor, item.InstanceID, r.Form.Get("confirmation"))
	case "secrets-delete-preview":
		view.Preview, err = service.PreviewDeleteSecrets(r.Context(), actor, item.InstanceID)
	case "secrets-delete-apply":
		view.Item, err = service.ApplyDeleteSecrets(r.Context(), actor, item.InstanceID, r.Form.Get("preview_id"), r.Form.Get("confirmation"))
	case "uninstall-preview":
		view.Preview, err = service.PreviewUninstall(r.Context(), actor, item.InstanceID)
	case "uninstall-apply":
		err = service.ApplyUninstall(r.Context(), actor, item.InstanceID, r.Form.Get("preview_id"), r.Form.Get("confirmation"))
		if err == nil {
			return extensionPageView{Message: "extension uninstalled"}, nil
		}
	default:
		err = errors.New("invalid extension action")
	}
	if err != nil {
		return view, err
	}
	view.Message = "extension operation accepted"
	return view, nil
}

func extensionConfigurationInput(item extensionsadmin.Instance, r *http.Request) (extensionsadmin.ConfigureInput, error) {
	input := extensionsadmin.ConfigureInput{Configuration: map[string]any{}, Secrets: map[string]string{}}
	for _, field := range item.Metadata.Fields {
		name := "field." + field.Name
		value := r.Form.Get(name)
		switch field.Kind {
		case extensionsadmin.FieldSecret:
			if value != "" {
				input.Secrets[field.Name] = value
			}
		case extensionsadmin.FieldBoolean:
			input.Configuration[field.Name] = r.Form.Has(name)
		case extensionsadmin.FieldInteger:
			if value == "" {
				continue
			}
			integer, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return extensionsadmin.ConfigureInput{}, errors.New("invalid integer extension field")
			}
			input.Configuration[field.Name] = integer
		default:
			if value != "" {
				input.Configuration[field.Name] = value
			}
		}
	}
	return input, nil
}

// Complexity: time O(F+K*S+O+B), Omega(F+O); auxiliary space O(F+O+B),
// Omega(F+O). Tight Theta is not established across status hits and value types.
// F fields, K required secret fields, S statuses, O copied option entries,
// B total name/value bytes inspected or formatted (including repeated comparisons).
// toUIString/TrimSpace delegate scalar formatting/scanning; option slices copy
// string headers, not backing bytes. Assumes expected constant-time configuration
// map lookup with hashing/comparison bytes included in B. No I/O; field names are slot IDs.
// Defaults permit omission per ValidateConfiguration; projection does not insert them.
func extensionFields(item extensionsadmin.Instance, override map[string]any) []extensionFieldView {
	configuration := item.Configuration
	if override != nil {
		configuration = override
	}
	result := make([]extensionFieldView, 0, len(item.Metadata.Fields))
	for _, field := range item.Metadata.Fields {
		view := extensionFieldView{Name: field.Name, Label: field.Label, Kind: string(field.Kind), Required: field.Required && field.Default == nil, Options: append([]string(nil), field.Options...)}
		if field.Kind == extensionsadmin.FieldSecret && view.Required {
			for _, status := range item.Secrets {
				if status.Slot == field.Name && status.Configured {
					view.Required = false // Blank retains; previewed rotations still bind re-entry in the service.
					break
				}
			}
		}
		if field.Kind != extensionsadmin.FieldSecret {
			if value, ok := configuration[field.Name]; ok {
				if boolean, ok := value.(bool); ok {
					view.Checked = boolean
				} else {
					view.Value = strings.TrimSpace(toUIString(value))
				}
			}
		}
		result = append(result, view)
	}
	return result
}

func toUIString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return ""
	}
}

func commaTokens(value string) []string {
	var result []string
	for _, token := range strings.Split(value, ",") {
		if token = strings.TrimSpace(token); token != "" {
			result = append(result, token)
		}
	}
	return result
}

func writeExtensionUIError(w http.ResponseWriter, err error) {
	if errors.Is(err, extensionsadmin.ErrNotFound) {
		http.NotFound(w, nil)
		return
	}
	http.Error(w, "extension operation failed", http.StatusBadRequest)
}
