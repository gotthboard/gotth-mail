package httpui

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"forgejo/linus/gophermailforge/internal/admin"
)

func Handler() http.Handler { return HandlerWithAdmin(admin.NewStore()) }

func HandlerWithAdmin(store *admin.Store) http.Handler {
	if store == nil {
		store = admin.NewStore()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		renderPage(w, store, "")
	})
	mux.HandleFunc("/admin/domains", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			err := r.ParseForm()
			if err == nil {
				err = store.UpsertDomain(admin.Domain{Name: r.Form.Get("name"), Enabled: r.Form.Get("enabled") == "on", MailHost: r.Form.Get("mail_host"), DKIMSelector: r.Form.Get("dkim_selector")})
			}
			renderPage(w, store, message(err, "domain saved"))
		case http.MethodGet:
			renderPage(w, store, "")
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
		renderPage(w, store, "domain deleted")
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = r.ParseForm()
			q, _ := strconv.Atoi(r.Form.Get("quota_mb"))
			err := store.UpsertUser(admin.User{Address: r.Form.Get("address"), Enabled: r.Form.Get("enabled") == "on", QuotaMB: q})
			renderPage(w, store, message(err, "user saved"))
		case http.MethodGet:
			renderPage(w, store, "")
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
		renderPage(w, store, "user deleted")
	})
	mux.HandleFunc("/admin/aliases", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = r.ParseForm()
			targets := splitTargets(r.Form.Get("targets"))
			err := store.UpsertAlias(admin.Alias{Address: r.Form.Get("address"), Enabled: r.Form.Get("enabled") == "on", Targets: targets})
			renderPage(w, store, message(err, "alias saved"))
		case http.MethodGet:
			renderPage(w, store, "")
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
		renderPage(w, store, "alias deleted")
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

func renderPage(w http.ResponseWriter, store *admin.Store, msg string) {
	domains, users, aliases := store.Lists()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, map[string]any{"Message": msg, "Domains": domains, "Users": users, "Aliases": aliases})
}

var page = template.Must(template.New("page").Parse(`<!doctype html><html><body><main id="app">
<h1>GopherMailForge</h1>
<nav>Dashboard Config Audit Authentik Plugins Doctor DNS DKIM Lookup Queue Mail Admin</nav>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}
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
