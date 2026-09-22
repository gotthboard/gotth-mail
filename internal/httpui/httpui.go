package httpui

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/admin"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authn"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/diag"
	"forgejo/gotthboard/gotth-mail/internal/extensionsadmin"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/ops"
	"forgejo/gotthboard/gotth-mail/internal/version"
)

type DNSAdmin struct {
	Plans    map[string]diag.DomainDNSPlan
	Resolver diag.DNSResolver
}

func Handler() http.Handler { return HandlerWithAdmin(admin.NewStore()) }

func HandlerWithAdmin(store *admin.Store) http.Handler {
	return HandlerWithAdminAndIdentity(store, identity.NewService("example.test"), authz.StaticAuthorizer{})
}

func requireUIActor(w http.ResponseWriter, r *http.Request, ids *identity.Service, az authz.Authorizer, action string, resource authz.Resource) (authz.Actor, bool) {
	actor, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
	if err != nil {
		http.Error(w, "admin bearer token required", http.StatusUnauthorized)
		return authz.Actor{}, false
	}
	if az == nil {
		az = authz.StaticAuthorizer{}
	}
	d, err := az.Decide(r.Context(), actor, authz.Action(action), resource)
	if err != nil || !d.Allow {
		http.Error(w, "admin authorization required", http.StatusForbidden)
		return authz.Actor{}, false
	}
	return actor, true
}

func requireUIAuditActor(w http.ResponseWriter, r *http.Request, ids *identity.Service, az authz.Authorizer, action string, resource authz.Resource) (audit.ActorRef, bool) {
	actor, ok := requireUIActor(w, r, ids, az, action, resource)
	if !ok {
		return audit.ActorRef{}, false
	}
	return audit.ActorRef{Type: actor.Type, ID: actor.ID}, true
}
func HandlerWithAdminAndIdentity(store *admin.Store, ids *identity.Service, az authz.Authorizer) http.Handler {
	return HandlerWithAdminIdentityAndSessions(store, ids, az, nil, nil)
}

func HandlerWithAdminIdentityAndSessions(store *admin.Store, ids *identity.Service, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time) http.Handler {
	return HandlerWithAdminIdentitySessionsAndExtensions(store, ids, az, sessions, now, nil)
}

func HandlerWithAdminIdentitySessionsAndExtensions(store *admin.Store, ids *identity.Service, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time, extensions *extensionsadmin.Service) http.Handler {
	return HandlerWithAdminIdentitySessionsExtensionsAndDNS(store, ids, az, sessions, now, extensions, DNSAdmin{})
}

func HandlerWithAdminIdentitySessionsExtensionsAndDNS(store *admin.Store, ids *identity.Service, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time, extensions *extensionsadmin.Service, dns DNSAdmin) http.Handler {
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
	importStore := ops.NewImportStore()
	bulkStore := ops.NewBulkStore()
	mux := http.NewServeMux()
	registerExtensionUI(mux, ids, az, sessions, now, extensions)
	registerDNSAdminUI(mux, az, sessions, now, dns)
	render := func(w http.ResponseWriter, msg, simulation string) {
		renderPage(w, store, ids, sessions != nil, msg, simulation)
	}
	if sessions != nil {
		mux.HandleFunc("/identity/app-passwords", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			bound, actor, csrf, ok := boundUIIdentity(w, r, sessions, now)
			if !ok {
				return
			}
			created := identity.AppPasswordCreated{}
			message := ""
			if r.Method == http.MethodPost {
				r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
				if err := r.ParseForm(); err != nil || !validUIFormCSRF(r.Form.Get("csrf_token"), csrf, bound.Session) {
					http.Error(w, "CSRF validation failed", http.StatusForbidden)
					return
				}
				var err error
				switch r.Form.Get("action") {
				case "create":
					created, err = ids.CreateAppPassword(r.Context(), actor, bound.Mailbox, r.Form.Get("label"))
				case "revoke":
					err = ids.RevokeAppPassword(r.Context(), actor, bound.Mailbox, r.Form.Get("credential_id"))
				default:
					err = fmt.Errorf("invalid app-password action")
				}
				message = messageForIdentityMutation(err, r.Form.Get("action"))
			}
			apps, err := ids.ListAppPasswordsForActor(r.Context(), actor, bound.Mailbox)
			if err != nil {
				http.Error(w, "app-password authorization required", http.StatusForbidden)
				return
			}
			renderAppPasswords(w, bound.Mailbox, csrf, apps, created, message)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		render(w, "", "")
	})
	mux.HandleFunc("/admin/domains", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if _, ok := requireUIActor(w, r, ids, az, "domain:admin", authz.Resource{Type: "domain", ID: r.FormValue("name")}); !ok {
				return
			}
			err := r.ParseForm()
			if err == nil {
				err = store.UpsertDomain(admin.Domain{Name: r.Form.Get("name"), Enabled: r.Form.Get("enabled") == "on", MailHost: r.Form.Get("mail_host"), DKIMSelector: r.Form.Get("dkim_selector")})
			}
			render(w, message(err, "domain saved"), "")
		case http.MethodGet:
			render(w, "", "")
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
		if _, ok := requireUIActor(w, r, ids, az, "domain:admin", authz.Resource{Type: "domain", ID: r.Form.Get("name")}); !ok {
			return
		}
		_ = store.DeleteDomain(r.Form.Get("name"))
		render(w, "domain deleted", "")
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = r.ParseForm()
			if _, ok := requireUIActor(w, r, ids, az, "mailbox:admin", authz.Resource{Type: "mailbox", ID: r.Form.Get("address")}); !ok {
				return
			}
			q, _ := strconv.Atoi(r.Form.Get("quota_mb"))
			err := store.UpsertUser(admin.User{Address: r.Form.Get("address"), Enabled: r.Form.Get("enabled") == "on", QuotaMB: q})
			render(w, message(err, "user saved"), "")
		case http.MethodGet:
			render(w, "", "")
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
		if _, ok := requireUIActor(w, r, ids, az, "mailbox:admin", authz.Resource{Type: "mailbox", ID: r.Form.Get("address")}); !ok {
			return
		}
		_ = store.DeleteUser(r.Form.Get("address"))
		render(w, "user deleted", "")
	})
	mux.HandleFunc("/admin/aliases", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = r.ParseForm()
			if _, ok := requireUIActor(w, r, ids, az, "alias:admin", authz.Resource{Type: "alias", ID: r.Form.Get("address")}); !ok {
				return
			}
			targets := splitTargets(r.Form.Get("targets"))
			err := store.UpsertAlias(admin.Alias{Address: r.Form.Get("address"), Enabled: r.Form.Get("enabled") == "on", Targets: targets})
			render(w, message(err, "alias saved"), "")
		case http.MethodGet:
			render(w, "", "")
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
		if _, ok := requireUIActor(w, r, ids, az, "alias:admin", authz.Resource{Type: "alias", ID: r.Form.Get("address")}); !ok {
			return
		}
		_ = store.DeleteAlias(r.Form.Get("address"))
		render(w, "alias deleted", "")
	})

	mux.HandleFunc("/ops/backup-verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		if _, ok := requireUIAuditActor(w, r, ids, az, "ops:admin", authz.Resource{Type: "ops", ID: "backup"}); !ok {
			return
		}
		render(w, "backup verification unavailable: no configured backup storage", "")
	})
	mux.HandleFunc("/ops/mailu-preview", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		actor, ok := requireUIAuditActor(w, r, ids, az, "ops:admin", authz.Resource{Type: "ops", ID: "mailu-import"})
		if !ok {
			return
		}
		p := importStore.Preview(r.Form.Get("source"), actor, time.Now())
		render(w, "mailu preview created: "+p.ID+" hash="+p.Hash+" source_fingerprint="+p.SourceFingerprint, "")
	})
	mux.HandleFunc("/ops/bulk-preview", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		actor, ok := requireUIAuditActor(w, r, ids, az, "ops:admin", authz.Resource{Type: "ops", ID: "bulk"})
		if !ok {
			return
		}
		p, err := bulkStore.Preview(r.Form.Get("operation"), splitTargets(r.Form.Get("items")), actor, time.Now())
		render(w, message(err, "bulk preview created: "+p.ID+" hash="+p.Hash), "")
	})

	mux.HandleFunc("/ops/mailu-apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		actor, ok := requireUIAuditActor(w, r, ids, az, "ops:admin", authz.Resource{Type: "ops", ID: "mailu-import"})
		if !ok {
			return
		}
		verify := daemon.Service{Domains: map[string]daemon.Domain{"example.test": {Name: "example.test", Enabled: true}}, Mailboxes: map[string]daemon.Mailbox{"postmaster@example.test": {Address: "postmaster@example.test", Enabled: true}}}
		err := importStore.Apply(r.Context(), ids.Audit, actor, r.Form.Get("id"), r.Form.Get("hash"), r.Form.Get("source_fingerprint"), time.Now(), verify)
		render(w, message(err, "mailu import applied"), "")
	})
	mux.HandleFunc("/ops/bulk-apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		actor, ok := requireUIAuditActor(w, r, ids, az, "ops:admin", authz.Resource{Type: "ops", ID: "bulk"})
		if !ok {
			return
		}
		_, err := bulkStore.Apply(r.Context(), ids.Audit, actor, r.Form.Get("operation"), r.Form.Get("id"), r.Form.Get("confirm"), r.Form.Get("hash"), time.Now())
		render(w, message(err, "bulk operation applied"), "")
	})
	mux.HandleFunc("/identity/simulator", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		ex, _ := az.Explain(r.Context(), authz.Actor{Type: r.Form.Get("actor_type"), ID: r.Form.Get("actor_id")}, authz.Action(r.Form.Get("action")), authz.Resource{Type: r.Form.Get("resource_type"), ID: r.Form.Get("resource_id")})
		render(w, "permission simulated", ex.Decision.Reason)
	})
	return mux
}

func registerDNSAdminUI(mux *http.ServeMux, az authz.Authorizer, sessions authn.IdentitySessionStore, now func() time.Time, dns DNSAdmin) {
	if sessions == nil || dns.Resolver == nil || len(dns.Plans) == 0 {
		return
	}
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, "/admin/dns", http.StatusSeeOther)
	})
	mux.HandleFunc("/admin/dns", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/dns" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if cookie, err := r.Cookie("gotth_mail_session"); err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/api/v1/oidc/login?mode=redirect&redirect=/admin/dns", http.StatusSeeOther)
			return
		}
		pageStarted := time.Now()
		bound, actor, _, ok := boundUIIdentity(w, r, sessions, now)
		if !ok {
			return
		}
		at := strings.LastIndexByte(bound.Mailbox, '@')
		if at < 1 || at == len(bound.Mailbox)-1 {
			http.Error(w, "bound mailbox domain is invalid", http.StatusForbidden)
			return
		}
		domain := strings.ToLower(bound.Mailbox[at+1:])
		plan, ok := dns.Plans[domain]
		if !ok {
			http.Error(w, "DNS plan is not configured for this domain", http.StatusServiceUnavailable)
			return
		}
		if az == nil {
			az = authz.StaticAuthorizer{}
		}
		decision, err := az.Decide(r.Context(), actor, authz.Action("domain:admin"), authz.Resource{Type: "domain", ID: domain})
		if err != nil || !decision.Allow {
			http.Error(w, "domain administrator authorization required", http.StatusForbidden)
			return
		}
		renderDNSAdmin(w, pageStarted, bound.Mailbox, plan, diag.DNSReadiness(plan, dns.Resolver))
	})
}

func renderDNSAdmin(w http.ResponseWriter, pageStarted time.Time, mailbox string, plan diag.DomainDNSPlan, checks []diag.DNSRecordCheck) {
	templateStarted := time.Now()
	var body strings.Builder
	if err := dnsAdminPage.Execute(&body, map[string]any{"Mailbox": mailbox, "Plan": plan, "Checks": checks}); err != nil {
		http.Error(w, "DNS administrator rendering failed", http.StatusInternalServerError)
		return
	}
	templateMilliseconds := time.Since(templateStarted).Milliseconds()
	pageMilliseconds := time.Since(pageStarted).Milliseconds()
	body.WriteString(`<footer class="gotth-footer" aria-label="Application information"><span>Powered by <strong class="product">GOTTH Mail</strong></span><span>Version: <strong>`)
	body.WriteString(template.HTMLEscapeString(version.Version))
	body.WriteString(`</strong></span><span>Page: <strong>`)
	body.WriteString(strconv.FormatInt(pageMilliseconds, 10))
	body.WriteString(`ms</strong></span><span>Template: <strong>`)
	body.WriteString(strconv.FormatInt(templateMilliseconds, 10))
	body.WriteString(`ms</strong></span></footer></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	_, _ = w.Write([]byte(body.String()))
}

var dnsAdminPage = template.Must(template.New("dns-admin").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>DNS Administration · GOTTH Mail</title><style>
:root{font-family:Inter,ui-sans-serif,system-ui,sans-serif;color:#e8ecf4;background:#0b1020}*{box-sizing:border-box}body{margin:0;background:#0b1020;color:#e8ecf4}header,main{width:min(1180px,calc(100% - 2rem));margin:auto}header{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;padding:1.25rem 0;border-bottom:1px solid #252d42}header a{color:#f28b8f;text-decoration:none}main{min-height:calc(100vh - 198px);padding:2rem 0}h1{margin:0 0 .5rem}p{color:#aeb8cc;overflow-wrap:anywhere}.summary{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}.card{flex:1 1 12rem;min-width:0;padding:1rem 1.25rem;border:1px solid #29324a;background:#12192b;border-radius:8px}.card strong{display:block;margin-top:.3rem;color:#fff;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse;background:#12192b;border:1px solid #29324a}th,td{text-align:left;vertical-align:top;padding:.8rem;border-bottom:1px solid #29324a}th{color:#aeb8cc;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}code{display:inline-block;max-width:100%;overflow-wrap:anywhere;color:#e8ecf4}.status{font-weight:700}.status.present{color:#75d69c}.status.missing,.status.mismatch{color:#ff9d91}.status.not_checked,.status.unsupported{color:#f0c674}.note{margin-top:1.2rem;padding:1rem;border-left:3px solid #f0c674;background:#171b2a;overflow-wrap:anywhere}.gotth-footer{min-height:104px;display:flex;align-items:center;gap:.5rem 1.25rem;flex-wrap:wrap;padding:1.4rem clamp(1rem,10vw,7.5rem);background:#050817;border-top:1px solid #262b3b;color:#9da8bd}.gotth-footer strong{color:#f4f6fb}.gotth-footer .product{color:#f28b8f}@media(max-width:900px){header,main{width:calc(100% - 1rem)}header{align-items:flex-start;padding:1rem 0}main{padding:1rem 0}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,12rem),1fr));gap:.75rem;margin:1rem 0}table,thead,tbody,tr,th,td{display:block}table{border:0;background:transparent}thead{display:none}tbody{display:grid;gap:.75rem}tr{border:1px solid #29324a;border-radius:8px;background:#12192b;overflow:hidden}td{border:0;padding:.5rem .8rem}td::before{content:attr(data-label);display:block;margin-bottom:.1rem;color:#7f8ba3;font-size:.72rem;text-transform:uppercase}.note{margin-top:1rem}.gotth-footer{min-height:72px;padding:.75rem 1rem;font-size:12px}}
</style></head><body><header><strong>GOTTH Mail · DNS Administration</strong><a href="/webmail">Back to Web Mail</a></header><main><h1>{{.Plan.Domain}}</h1><p>Signed in as {{.Mailbox}}. Copy missing or mismatched records to the authoritative DNS provider, then refresh this page.</p><div class="summary"><div class="card">Mail host<strong>{{.Plan.MailHost}}</strong></div>{{if .Plan.MailIP}}<div class="card">IPv4 address<strong>{{.Plan.MailIP}}</strong></div>{{end}}<div class="card">DKIM selector<strong>{{.Plan.DKIMSelector}}</strong></div></div><table><thead><tr><th>Status</th><th>Type</th><th>Name</th><th>Expected</th><th>Observed</th><th>Action</th></tr></thead><tbody>{{range .Checks}}<tr><td data-label="Status"><span class="status {{.Status}}">{{.Status}}</span></td><td data-label="Type">{{.Type}}</td><td data-label="Name"><code>{{.Name}}</code></td><td data-label="Expected">{{range .Expected}}<code>{{.}}</code><br>{{else}}—{{end}}</td><td data-label="Observed">{{range .Observed}}<code>{{.}}</code><br>{{else}}—{{end}}</td><td data-label="Action">{{if .Remediation}}{{.Remediation}}{{else}}No change required{{end}}</td></tr>{{end}}</tbody></table><div class="note"><strong>Provider boundary:</strong> this page checks and explains DNS. It does not hold registrar credentials or silently modify external DNS. PTR/reverse DNS must be changed at the server provider, not at the domain registrar.</div></main>`))

func message(err error, ok string) string {
	if err != nil {
		return err.Error()
	}
	return ok
}

func boundUIIdentity(w http.ResponseWriter, r *http.Request, sessions authn.IdentitySessionStore, now func() time.Time) (authn.BoundSession, authz.Actor, string, bool) {
	sessionCookie, err := r.Cookie("gotth_mail_session")
	if err != nil || sessionCookie.Value == "" {
		http.Error(w, "identity session required", http.StatusUnauthorized)
		return authn.BoundSession{}, authz.Actor{}, "", false
	}
	current := time.Now().UTC()
	if now != nil {
		current = now().UTC()
	}
	bound, ok := sessions.BoundSession(r.Context(), sessionCookie.Value, current)
	if !ok {
		http.Error(w, "identity session is invalid", http.StatusUnauthorized)
		return authn.BoundSession{}, authz.Actor{}, "", false
	}
	csrfCookie, err := r.Cookie("gotth_mail_csrf")
	if err != nil || !authn.ValidCSRF(bound.Session, csrfCookie.Value) {
		http.Error(w, "identity CSRF binding is invalid", http.StatusUnauthorized)
		return authn.BoundSession{}, authz.Actor{}, "", false
	}
	actor := authz.Actor{Type: "oidc_subject", ID: bound.IdentityRefID, Mailbox: bound.Mailbox, Roles: append([]authz.RoleAssignment(nil), bound.Roles...)}
	return bound, actor, csrfCookie.Value, true
}

func validUIFormCSRF(form, cookie string, session authn.Session) bool {
	return form != "" && len(form) == len(cookie) && subtle.ConstantTimeCompare([]byte(form), []byte(cookie)) == 1 && authn.ValidCSRF(session, form)
}

func messageForIdentityMutation(err error, action string) string {
	if err != nil {
		return err.Error()
	}
	if action == "create" {
		return "app password created; copy the secret now"
	}
	return "app password revoked"
}

func renderAppPasswords(w http.ResponseWriter, mailbox, csrf string, apps []identity.AppPassword, created identity.AppPasswordCreated, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	_ = appPasswordsPage.Execute(w, map[string]any{"Mailbox": mailbox, "CSRF": csrf, "AppPasswords": apps, "Created": created, "Message": message})
}

var appPasswordsPage = template.Must(template.New("app-passwords").Parse(`<!doctype html><html><body><main>
<h1>App passwords</h1><p>Signed in mailbox: {{.Mailbox}}</p>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}
{{if .Created.SecretOnce}}<section><h2>New secret</h2><p>This value is shown once.</p><code id="created-secret">{{.Created.SecretOnce}}</code></section>{{end}}
<section><h2>Create</h2><form method="post" action="/identity/app-passwords"><input type="hidden" name="csrf_token" value="{{.CSRF}}"><input type="hidden" name="action" value="create"><label>Label <input name="label" maxlength="128" required></label><button type="submit">Create app password</button></form></section>
<section><h2>Existing credentials</h2>{{range .AppPasswords}}<article><span>{{.Label}}</span> <code>{{.ID}}</code>{{if .RevokedAt}} <span>revoked</span>{{else}}<form method="post" action="/identity/app-passwords"><input type="hidden" name="csrf_token" value="{{$.CSRF}}"><input type="hidden" name="action" value="revoke"><input type="hidden" name="credential_id" value="{{.ID}}"><button type="submit">Revoke</button></form>{{end}}</article>{{else}}<p>No app passwords.</p>{{end}}</section>
</main></body></html>`))

func splitTargets(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func renderPage(w http.ResponseWriter, store *admin.Store, ids *identity.Service, appPasswordSelfService bool, msg, simulation string) {
	domains, users, aliases := store.Lists()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, map[string]any{"Message": msg, "Simulation": simulation, "Domains": domains, "Users": users, "Aliases": aliases, "AppPasswordSelfService": appPasswordSelfService})
}

var page = template.Must(template.New("page").Parse(`<!doctype html><html><body><main id="app">
<h1>GOTTH Mail</h1>
<nav>Dashboard Config Audit Authentik Identity SCIM App Passwords Permission Simulator Backups Snapshots Import Abuse Bulk <a href="/admin/extensions">Extensions</a> Plugins Doctor DNS DKIM Lookup Queue Mail Admin</nav>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}

<section id="identity-status"><h3>OIDC/Auth status</h3><p>OIDC login uses browser-bound authorization-code state, nonce, redirect URI, issuer, audience, azp, and token-signature validation.</p></section>
<section id="authentik-role-mapping"><h3>Authentik role/group mapping</h3><p>Mappings assign global admin, domain manager, and scoped domain access through Authentik groups. Local manual role edits are not the expected path.</p></section>
<section id="scim-status"><h3>SCIM capability/status</h3><p>Provisioning uses the authenticated <a href="/scim/v2/ServiceProviderConfig">gotth-scim service endpoint</a>. Browser test provisioning is unavailable because it would bypass the canonical SCIM protocol and transaction.</p></section>
<section id="app-passwords"><h3>App passwords</h3>{{if .AppPasswordSelfService}}<p>Browser self-service uses the verified gotth-oidc session durably bound to active gotth-scim mailbox state. Manage the signed-in mailbox at <a href="/identity/app-passwords">/identity/app-passwords</a>.</p>{{else}}<p>Browser self-service is unavailable until the runtime has durable gotth-oidc and gotth-scim identity binding.</p>{{end}}<p>Authorized automation may use the scoped <code>/api/v1/mailboxes/{id}/app-passwords</code> API.</p></section>
<section id="permission-simulator"><h3>Permission simulator UI</h3><form method="post" action="/identity/simulator"><input name="actor_type" value="local_admin"><input name="actor_id" value="ui"><input name="action" value="status:read"><input name="resource_type" value="system"><input name="resource_id" value="self"><button>Explain permission</button></form>{{if .Simulation}}<pre>{{.Simulation}}</pre>{{end}}</section>

<section id="audit-ui"><h3>Audit UI/search/export</h3><p>Audit viewer supports actor/action/resource/result filtering and redacted export through API routes.</p><a href="/api/v1/audit/export?format=jsonl">Export audit JSONL</a></section>
<section id="backup-restore"><h3>Backup/restore verification</h3><p>Backups are verified only after isolated restore, schema check, and daemon contract validation.</p><form method="post" action="/ops/backup-verify"><input name="artifact_ref" value="ui-backup"><button>Verify backup</button></form></section>
<section id="snapshot-rollback"><h3>Snapshot/rollback guidance</h3><p>Rollback guidance refuses fake safety unless verified restore status is present.</p><a href="/api/v1/snapshots">Snapshot browser</a></section>
<section id="mailu-import"><h3>Mailu import preview/apply</h3><p>Mailu import uses preview hash, source fingerprint, actor binding, expiry, validation, and audit before admission.</p><form method="post" action="/ops/mailu-preview"><textarea name="source">[{"Type":"domain","ID":"example.test"}]</textarea><button>Preview Mailu import</button></form><form method="post" action="/ops/mailu-apply"><input name="id" placeholder="preview id"><input name="hash" placeholder="preview hash"><input name="source_fingerprint" placeholder="source fingerprint"><button>Apply Mailu import</button></form></section>
<section id="abuse-dashboard"><h3>Abuse/rate-limit dashboard</h3><p>Surfaces auth failures, sender limits, rejected recipients, spam decisions, suspicious outbound volume, and deferred queue correlation.</p><a href="/api/v1/ops/abuse-summary">Abuse summary</a></section>
<section id="bulk-admin"><h3>Bulk admin workflows</h3><p>Bulk operations require preview, explicit confirmation, per-item result reporting, and audit events.</p><form method="post" action="/ops/bulk-preview"><input name="operation" value="disable-users"><input name="items" value="user@example.test"><button>Preview bulk operation</button></form><form method="post" action="/ops/bulk-apply"><input name="operation" value="disable-users"><input name="id" placeholder="preview id"><input name="confirm" placeholder="preview id"><input name="hash" placeholder="preview hash"><button>Apply bulk operation</button></form></section>
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
