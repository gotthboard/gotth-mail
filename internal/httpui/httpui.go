package httpui

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"forgejo/linus/gophermailforge/internal/admin"
	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/authz"
	"forgejo/linus/gophermailforge/internal/identity"
)

func Handler() http.Handler { return HandlerWithAdmin(admin.NewStore()) }

func HandlerWithAdmin(store *admin.Store) http.Handler {
	return HandlerWithAdminAndIdentity(store, identity.NewService("example.test"), authz.StaticAuthorizer{})
}

func HandlerWithAdminAndIdentity(store *admin.Store, ids *identity.Service, az authz.Authorizer) http.Handler {
	if store == nil {
		store = admin.NewStore()
	}
	if ids == nil {
		ids = identity.NewService("example.test")
	}
	if ids.Authorizer == nil {
		ids.Authorizer = az
	}
	if ids.Audit == nil {
		ids.Audit = &audit.MemoryWriter{}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		renderPage(w, store, ids, "", "")
	})
	mux.HandleFunc("/admin/domains", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			err := r.ParseForm()
			if err == nil {
				err = store.UpsertDomain(admin.Domain{Name: r.Form.Get("name"), Enabled: r.Form.Get("enabled") == "on", MailHost: r.Form.Get("mail_host"), DKIMSelector: r.Form.Get("dkim_selector")})
			}
			renderPage(w, store, ids, message(err, "domain saved"), "")
		case http.MethodGet:
			renderPage(w, store, ids, "", "")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/admin/domains/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		_ = store.DeleteDomain(r.Form.Get("name"))
		renderPage(w, store, ids, "domain deleted", "")
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = r.ParseForm()
			q, _ := strconv.Atoi(r.Form.Get("quota_mb"))
			err := store.UpsertUser(admin.User{Address: r.Form.Get("address"), Enabled: r.Form.Get("enabled") == "on", QuotaMB: q})
			renderPage(w, store, ids, message(err, "user saved"), "")
		case http.MethodGet:
			renderPage(w, store, ids, "", "")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/admin/users/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		_ = store.DeleteUser(r.Form.Get("address"))
		renderPage(w, store, ids, "user deleted", "")
	})
	mux.HandleFunc("/admin/aliases", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = r.ParseForm()
			targets := splitTargets(r.Form.Get("targets"))
			err := store.UpsertAlias(admin.Alias{Address: r.Form.Get("address"), Enabled: r.Form.Get("enabled") == "on", Targets: targets})
			renderPage(w, store, ids, message(err, "alias saved"), "")
		case http.MethodGet:
			renderPage(w, store, ids, "", "")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/admin/aliases/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		_ = store.DeleteAlias(r.Form.Get("address"))
		renderPage(w, store, ids, "alias deleted", "")
	})

	mux.HandleFunc("/identity/scim-test", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		m, err := ids.CreateOrReplaceUser(r.Context(), authz.Actor{Type: "local_admin", ID: "ui"}, identity.Mailbox{Email: r.Form.Get("userName"), DisplayName: r.Form.Get("displayName"), Active: true}, r.Form.Get("password"))
		renderPage(w, store, ids, message(err, "SCIM test user provisioned: "+m.Email), "")
	})
	mux.HandleFunc("/identity/app-passwords", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = r.ParseForm()
			created, err := ids.CreateAppPassword(r.Context(), authz.Actor{Type: "local_admin", ID: "ui"}, r.Form.Get("mailbox"), r.Form.Get("label"))
			msg := message(err, "app password created; secret_once="+created.SecretOnce)
			renderPage(w, store, ids, msg, "")
		case http.MethodGet:
			renderPage(w, store, ids, "", "")
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/identity/app-passwords/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		err := ids.RevokeAppPassword(r.Context(), authz.Actor{Type: "local_admin", ID: "ui"}, r.Form.Get("mailbox"), r.Form.Get("token_id"))
		renderPage(w, store, ids, message(err, "app password revoked"), "")
	})
	mux.HandleFunc("/identity/simulator", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		ex, _ := az.Explain(r.Context(), authz.Actor{Type: r.Form.Get("actor_type"), ID: r.Form.Get("actor_id")}, authz.Action(r.Form.Get("action")), authz.Resource{Type: r.Form.Get("resource_type"), ID: r.Form.Get("resource_id")})
		renderPage(w, store, ids, "permission simulated", ex.Decision.Reason)
	})
	return mux
}

func message(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}
func splitTargets(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func renderPage(w http.ResponseWriter, store *admin.Store, ids *identity.Service, msg, simulation string) {
	domains, users, aliases := store.Lists()
	mailboxes := ids.ListUsers()
	apps := map[string][]identity.AppPassword{}
	for _, m := range mailboxes {
		apps[m.ID] = ids.ListAppPasswords(m.ID)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, map[string]any{"Message": msg, "Simulation": simulation, "Domains": domains, "Users": users, "Aliases": aliases, "Mailboxes": mailboxes, "AppPasswords": apps})
}

var page = template.Must(template.New("page").Parse(`<!doctype html><html><body><main id="app">
<h1>GopherMailForge</h1>
<nav>Dashboard Config Audit Authentik Identity SCIM App Passwords Permission Simulator Plugins Doctor DNS DKIM Lookup Queue Mail Admin</nav>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}

<section id="identity-status"><h3>OIDC/Auth status</h3><p>OIDC login uses browser-bound authorization-code state, nonce, redirect URI, issuer, audience, azp, and token-signature validation.</p></section>
<section id="authentik-role-mapping"><h3>Authentik role/group mapping</h3><p>Mappings assign global admin, domain manager, and scoped domain access through Authentik groups. Local manual role edits are not the expected path.</p></section>
<section id="scim-status"><h3>SCIM status/test</h3><form method="post" action="/identity/scim-test"><input name="userName" placeholder="user@example.test"><input name="displayName" placeholder="User"><input name="password" placeholder="mail password"><button>Provision SCIM test user</button></form><p>Provisioned users visible to identity service:</p><ul>{{range .Mailboxes}}<li>{{.Email}} active={{.Active}} display={{.DisplayName}}</li>{{else}}<li>No SCIM users provisioned.</li>{{end}}</ul></section>
<section id="app-passwords"><h3>App-password list/create/revoke</h3><form method="post" action="/identity/app-passwords"><input name="mailbox" placeholder="user@example.test"><input name="label" placeholder="phone"><button>Create app password</button></form>{{range .Mailboxes}}{{$mb := .}}<h4>{{.Email}}</h4><ul>{{range index $.AppPasswords .ID}}<li>{{.ID}} {{.Label}} revoked={{if .RevokedAt}}yes{{else}}no{{end}} <form method="post" action="/identity/app-passwords/revoke"><input type="hidden" name="mailbox" value="{{$mb.Email}}"><input type="hidden" name="token_id" value="{{.ID}}"><button>Revoke</button></form></li>{{else}}<li>No app passwords.</li>{{end}}</ul>{{end}}</section>
<section id="permission-simulator"><h3>Permission simulator UI</h3><form method="post" action="/identity/simulator"><input name="actor_type" value="local_admin"><input name="actor_id" value="ui"><input name="action" value="status:read"><input name="resource_type" value="system"><input name="resource_id" value="self"><button>Explain permission</button></form>{{if .Simulation}}<pre>{{.Simulation}}</pre>{{end}}</section>
<section id="mail-admin"><h2>Mail admin UI</h2>
<section id="domain-crud"><h3>Domain CRUD</h3><form method="post" action="/admin/domains"><input name="name" placeholder="example.test"><input name="mail_host" placeholder="mail.example.test"><input name="dkim_selector" placeholder="mail"><label><input type="checkbox" name="enabled" checked> enabled</label><button>Save domain</button></form><ul>{{range .Domains}}<li>{{.Name}} {{.MailHost}} {{.DKIMSelector}} <form method="post" action="/admin/domains/delete"><input type="hidden" name="name" value="{{.Name}}"><button>Delete</button></form></li>{{end}}</ul></section>
<section id="user-crud"><h3>User CRUD</h3><form method="post" action="/admin/users"><input name="address" placeholder="user@example.test"><input name="quota_mb" placeholder="1024"><label><input type="checkbox" name="enabled" checked> enabled</label><button>Save user</button></form><ul>{{range .Users}}<li>{{.Address}} quota={{.QuotaMB}}MB <form method="post" action="/admin/users/delete"><input type="hidden" name="address" value="{{.Address}}"><button>Delete</button></form></li>{{end}}</ul></section>
<section id="alias-crud"><h3>Alias CRUD</h3><form method="post" action="/admin/aliases"><input name="address" placeholder="alias@example.test"><input name="targets" placeholder="user@example.test, other@example.test"><label><input type="checkbox" name="enabled" checked> enabled</label><button>Save alias</button></form><ul>{{range .Aliases}}<li>{{.Address}} → {{range .Targets}}{{.}} {{end}}<form method="post" action="/admin/aliases/delete"><input type="hidden" name="address" value="{{.Address}}"><button>Delete</button></form></li>{{end}}</ul></section>
<section id="doctor-screens"><h3>Doctor screens</h3><a href="/api/v1/doctor">Machine-readable doctor</a></section>
<section id="dns-dkim-screens"><h3>DNS/DKIM screens</h3><p>DNS readiness, DKIM material, MTA-STS, and TLS-RPT are surfaced through doctor/config routes.</p></section>
<section id="plugin-status-config"><h3>Plugin status/config screens</h3><a href="/api/v1/plugins">Plugin status</a></section>
<section id="lookup-debugger"><h3>Lookup debugger UI</h3><form method="get" action="/api/v1/debug/lookup"><input name="kind" value="recipient"><input name="value" placeholder="user@example.test"><button>Debug lookup</button></form></section>
</section>
</main></body></html>`))
