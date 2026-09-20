package httpui

import (
	"errors"
	"html/template"
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
	Items   []extensionsadmin.Instance
	Item    extensionsadmin.Instance
	Fields  []extensionFieldView
	Preview extensionsadmin.Preview
	Message string
	CSRF    string
}

func registerExtensionUI(mux *http.ServeMux, ids *identity.Service, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time, service *extensionsadmin.Service) {
	mux.HandleFunc("/admin/extensions", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/extensions" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		_, csrf, ok := requireExtensionUIActor(w, r, ids, az, sessions, now, false, authz.Resource{Type: "extensions", ID: extensionsadmin.Product})
		if !ok {
			return
		}
		if service == nil {
			http.Error(w, "extension administrator unavailable", http.StatusServiceUnavailable)
			return
		}
		items, err := service.List(r.Context())
		if err != nil {
			http.Error(w, "extension inventory unavailable", http.StatusInternalServerError)
			return
		}
		renderExtensionPage(w, extensionPageView{Items: items, CSRF: csrf})
	})

	mux.HandleFunc("/admin/extensions/", func(w http.ResponseWriter, r *http.Request) {
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
		view := extensionPageView{Item: item, Fields: extensionFields(item, nil), CSRF: csrf}
		if r.Method == http.MethodPost {
			view, err = applyExtensionUIAction(r, service, actor, item)
			view.CSRF = csrf
			if err != nil {
				view.Item = item
				view.Fields = extensionFields(item, nil)
				view.Message = err.Error()
			}
		}
		renderExtensionPage(w, view)
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

func applyExtensionUIAction(r *http.Request, service *extensionsadmin.Service, actor audit.ActorRef, item extensionsadmin.Instance) (extensionPageView, error) {
	view := extensionPageView{Item: item, Fields: extensionFields(item, nil)}
	action := r.Form.Get("action")
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
		view.Item, err = service.ApplyConfigure(r.Context(), actor, r.Form.Get("preview_id"), r.Form.Get("confirmation"), input)
	case "test":
		view.Item, err = service.Test(r.Context(), actor, item.InstanceID)
	case "enable":
		view.Item, err = service.Enable(r.Context(), actor, item.InstanceID)
	case "disable":
		view.Item, err = service.Disable(r.Context(), actor, item.InstanceID)
	case "update-preview":
		input := extensionsadmin.UpdateInput{ArtifactPin: r.Form.Get("artifact_pin"), ManifestDigest: r.Form.Get("manifest_sha256"), GrantDigest: r.Form.Get("grant_sha256"), SessionDigest: r.Form.Get("session_sha256"), Capabilities: commaTokens(r.Form.Get("capabilities")), Interfaces: commaTokens(r.Form.Get("interfaces")), SecretSlots: commaTokens(r.Form.Get("secret_slots")), Metadata: item.Metadata}
		view.Preview, err = service.PreviewUpdate(r.Context(), actor, item.InstanceID, input)
	case "update-apply":
		view.Item, err = service.ApplyUpdate(r.Context(), actor, r.Form.Get("preview_id"), r.Form.Get("confirmation"))
	case "rollback":
		view.Item, err = service.Rollback(r.Context(), actor, item.InstanceID, r.Form.Get("confirmation"))
	case "secrets-delete-preview":
		view.Preview, err = service.PreviewDeleteSecrets(r.Context(), actor, item.InstanceID)
	case "secrets-delete-apply":
		view.Item, err = service.ApplyDeleteSecrets(r.Context(), actor, r.Form.Get("preview_id"), r.Form.Get("confirmation"))
	case "uninstall-preview":
		view.Preview, err = service.PreviewUninstall(r.Context(), actor, item.InstanceID)
	case "uninstall-apply":
		err = service.ApplyUninstall(r.Context(), actor, r.Form.Get("preview_id"), r.Form.Get("confirmation"))
		if err == nil {
			return extensionPageView{Message: "extension uninstalled"}, nil
		}
	default:
		err = errors.New("invalid extension action")
	}
	if err != nil {
		return view, err
	}
	if view.Item.InstanceID != "" {
		view.Fields = extensionFields(view.Item, nil)
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

func extensionFields(item extensionsadmin.Instance, override map[string]any) []extensionFieldView {
	configuration := item.Configuration
	if override != nil {
		configuration = override
	}
	result := make([]extensionFieldView, 0, len(item.Metadata.Fields))
	for _, field := range item.Metadata.Fields {
		view := extensionFieldView{Name: field.Name, Label: field.Label, Kind: string(field.Kind), Required: field.Required, Options: append([]string(nil), field.Options...)}
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

func renderExtensionPage(w http.ResponseWriter, view extensionPageView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = extensionPage.Execute(w, view)
}

var extensionPage = template.Must(template.New("extensions").Funcs(template.FuncMap{"join": strings.Join}).Parse(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>GOTTH Mail Extensions</title><style>body{font:1rem system-ui;max-width:72rem;margin:auto;padding:1rem}nav,section{margin-block:1rem}label{display:block;margin:.5rem 0}input,select,button{font:inherit;max-width:100%}input:focus,select:focus,button:focus,a:focus{outline:3px solid Highlight;outline-offset:2px}@media(max-width:40rem){form{display:grid;gap:.5rem}button{min-height:2.75rem}}</style></head><body><main>
<p><a href="/">GOTTH Mail</a> / <a href="/admin/extensions">Extensions</a></p>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}
{{if .Item.InstanceID}}
<h1>{{.Item.ExtensionID}}</h1>
<nav><a href="#overview">Overview</a> <a href="#configuration">Configuration</a> <a href="#secrets">Secrets</a> <a href="#permissions">Permissions</a> <a href="#health">Health</a> <a href="#audit">Audit</a> <a href="#versions">Versions</a> <a href="#rollback">Rollback</a></nav>
<section id="overview"><h2>Overview</h2><dl><dt>Repository</dt><dd>{{.Item.Repository}}</dd><dt>Artifact</dt><dd><code>{{.Item.ArtifactPin}}</code></dd><dt>Manifest</dt><dd><code>{{.Item.ManifestDigest}}</code></dd><dt>Lifecycle</dt><dd>{{.Item.Lifecycle}}</dd><dt>Enabled / routed</dt><dd>{{.Item.Enabled}} / {{.Item.Routed}}</dd></dl><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="action" value="test">Test</button>{{if .Item.Enabled}}<button name="action" value="disable">Disable</button>{{else}}<button name="action" value="enable">Enable</button>{{end}}</form></section>
<section id="configuration"><h2>Configuration</h2><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}">{{range .Fields}}<label>{{.Label}} {{if eq .Kind "boolean"}}<input type="checkbox" name="field.{{.Name}}" {{if .Checked}}checked{{end}}>{{else if eq .Kind "enum"}}<select name="field.{{.Name}}" {{if .Required}}required{{end}}>{{range .Options}}<option>{{.}}</option>{{end}}</select>{{else}}<input name="field.{{.Name}}" value="{{.Value}}" {{if eq .Kind "secret"}}type="password" autocomplete="new-password"{{else if eq .Kind "integer"}}type="number"{{end}} {{if .Required}}required{{end}}>{{end}}</label>{{end}}<button name="action" value="configure-preview">Preview configuration</button>{{if eq .Preview.Operation "configure"}}<input type="hidden" name="preview_id" value="{{.Preview.ID}}"><p>Re-enter all changed secrets, then type <code>{{.Preview.Confirmation}}</code>.</p><input name="confirmation" autocomplete="off" required><button name="action" value="configure-apply">Apply configuration</button>{{end}}</form></section>
<section id="secrets"><h2>Secrets</h2><ul>{{range .Item.Secrets}}<li>{{.Slot}}: {{if .Configured}}configured (value hidden){{else}}not configured{{end}}</li>{{end}}</ul><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="action" value="secrets-delete-preview">Preview deletion of all secrets</button>{{if eq .Preview.Operation "delete_secrets"}}<input type="hidden" name="preview_id" value="{{.Preview.ID}}"><p>Type <code>{{.Preview.Confirmation}}</code>.</p><input name="confirmation" required><button name="action" value="secrets-delete-apply">Delete secrets</button>{{end}}</form></section>
<section id="permissions"><h2>Permissions</h2><p>Capabilities: <code>{{join .Item.Capabilities ", "}}</code></p><p>Interfaces: <code>{{join .Item.Interfaces ", "}}</code></p><p>Granted secret slots: <code>{{join .Item.SecretSlots ", "}}</code></p></section>
<section id="health"><h2>Health</h2><p>{{.Item.HealthCode}}; tested revision {{.Item.TestedRevision}}; configuration revision {{.Item.ConfigurationRev}}</p></section>
<section id="audit"><h2>Audit</h2><a href="/api/v1/audit/export?format=jsonl&resource_type=extension&resource_id={{.Item.InstanceID}}">Export redacted extension audit</a></section>
<section id="versions"><h2>Versions / update</h2><p>Previous pin: <code>{{.Item.PreviousArtifact}}</code>; available pin: <code>{{.Item.AvailableUpdate}}</code></p><form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input name="artifact_pin" placeholder="sha256:…" required><input name="manifest_sha256" placeholder="manifest SHA-256" required><input name="grant_sha256" placeholder="grant SHA-256" required><input name="session_sha256" placeholder="session SHA-256" required><input name="capabilities" value="{{join .Item.Capabilities ","}}"><input name="interfaces" value="{{join .Item.Interfaces ","}}"><input name="secret_slots" value="{{join .Item.SecretSlots ","}}"><button name="action" value="update-preview">Preview update</button>{{if eq .Preview.Operation "update"}}<p>Privilege diff: <code>{{join .Preview.PrivilegeDiff ", "}}</code></p><p>Configuration-schema diff: <code>{{join .Preview.ConfigurationDiff ", "}}</code></p><p>Secret-slot diff: <code>{{join .Preview.SecretSlotDiff ", "}}</code></p><p>Type <code>{{.Preview.Confirmation}}</code>.</p><input type="hidden" name="preview_id" value="{{.Preview.ID}}"><input name="confirmation" required><button name="action" value="update-apply">Apply update</button>{{end}}</form></section>
<section id="rollback"><h2>Rollback / uninstall</h2>{{if .Item.PreviousArtifact}}<form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><p>Type <code>rollback {{.Item.ExtensionID}} to {{.Item.PreviousArtifact}}</code>.</p><input name="confirmation" required><button name="action" value="rollback">Rollback</button></form>{{end}}<form method="post"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><button name="action" value="uninstall-preview">Preview uninstall</button>{{if eq .Preview.Operation "uninstall"}}<input type="hidden" name="preview_id" value="{{.Preview.ID}}"><p>Type <code>{{.Preview.Confirmation}}</code>. Secrets must be deleted separately first.</p><input name="confirmation" required><button name="action" value="uninstall-apply">Uninstall</button>{{end}}</form></section>
{{else}}
<h1>Extensions</h1><p>Mail owns this presentation. Extension metadata supplies bounded scalar field descriptions only.</p><ul>{{range .Items}}<li><a href="/admin/extensions/{{.InstanceID}}">{{.ExtensionID}}</a> — {{.Lifecycle}} — {{if .Enabled}}enabled{{else}}disabled{{end}} — {{.HealthCode}}</li>{{else}}<li>No extensions installed.</li>{{end}}</ul>
{{end}}</main></body></html>`))
