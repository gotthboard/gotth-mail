package httpui

import "net/http"

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><body><main id="app"><h1>GopherMailForge</h1><nav>Dashboard Config Audit Authentik Plugins</nav><p>v0 GOTTH shell: HTMX-ready server-rendered shell; mutations use API/service paths.</p></main></body></html>`))
	})
	return mux
}
