package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/ops"
)

func (s Server) v3Runtime() *ops.V3Runtime {
	if s.V3 != nil {
		return s.V3
	}
	rt := ops.NewV3Runtime()
	if len(s.Daemon.Domains) > 0 || len(s.Daemon.Mailboxes) > 0 {
		rt.BackupStore.Artifacts["current"] = ops.BackupArtifact{Domains: s.Daemon.Domains, Mailboxes: s.Daemon.Mailboxes, Aliases: s.Daemon.Aliases, SchemaVersion: "schema_migrations", ConfigSetID: "current"}
	}
	return rt
}

func (s Server) registerV3(mux *http.ServeMux, auditLog *audit.MemoryWriter, ids *identity.Service) {
	rt := s.v3Runtime()
	requireAdmin := func(w http.ResponseWriter, r *http.Request) (audit.ActorRef, bool) {
		a, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			http.Error(w, "admin bearer token required", http.StatusUnauthorized)
			return audit.ActorRef{}, false
		}
		d, err := s.authorizer().Decide(r.Context(), a, "ops:admin", authz.Resource{Type: "ops", ID: "v3"})
		if err != nil || !d.Allow {
			http.Error(w, "admin authorization required", http.StatusForbidden)
			return audit.ActorRef{}, false
		}
		return audit.ActorRef{Type: a.Type, ID: a.ID}, true
	}
	mux.HandleFunc("/api/v1/audit/export", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		ev := ops.FilterAudit(auditLog.Events, auditFilter(r))
		if s.AuditDB != nil {
			var err error
			ev, err = (ops.SQLAuditStore{DB: s.AuditDB}).Query(r.Context(), auditFilter(r), 1000)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		if r.URL.Query().Get("format") == "csv" {
			writeText(w, ops.ExportAuditCSV(ev))
			return
		}
		writeText(w, ops.ExportAuditJSONL(ev))
	})
	mux.HandleFunc("/api/v1/audit/events/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/events/")
		if s.AuditDB != nil {
			e, ok, err := (ops.SQLAuditStore{DB: s.AuditDB}).Get(r.Context(), id)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if ok {
				writeJSON(w, e)
				return
			}
			http.NotFound(w, r)
			return
		}
		for _, e := range auditLog.Events {
			if e.ID == id {
				writeJSON(w, audit.Redact(e))
				return
			}
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/audit/retention/preview", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		var p ops.RetentionPreview
		var err error
		if s.AuditDB != nil {
			p, err = (ops.SQLAuditStore{DB: s.AuditDB}).PreviewRetention(r.Context(), r.URL.Query().Get("policy"), time.Now())
			if err == nil {
				rt.RetentionStore.Remember(p)
			}
		} else {
			p, err = rt.RetentionStore.Preview(auditLog.Events, r.URL.Query().Get("policy"), time.Now())
		}
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, p)
	})
	mux.HandleFunc("/api/v1/audit/retention/apply", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		reqActor, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		var in struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad retention preview", 400)
			return
		}
		if s.AuditDB != nil {
			p, ok := rt.RetentionStore.Get(in.ID)
			if !ok {
				http.Error(w, "retention preview not found", 400)
				return
			}
			if err := (ops.SQLAuditStore{DB: s.AuditDB}).ApplyRetention(r.Context(), reqActor, p, r.URL.Query().Get("confirm"), time.Now()); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		} else if err := rt.RetentionStore.Apply(r.Context(), auditLog, reqActor, in.ID, r.URL.Query().Get("confirm")); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"applied": true})
	})
	mux.HandleFunc("/api/v1/backups/verify", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		ref := r.URL.Query().Get("artifact_ref")
		if ref == "" {
			var in struct {
				ArtifactRef string `json:"artifact_ref"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			ref = in.ArtifactRef
		}
		if s.AuditDB != nil {
			b, err := (ops.SQLBackupVerificationStore{DB: s.AuditDB}).VerifyAndRecordWithRestore(r.Context(), rt.BackupStore, ref, "configured-backup", "", rt.RestoreEngine, time.Now())
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			writeJSON(w, b)
			return
		}
		writeJSON(w, ops.VerifyBackupFromStorage(r.Context(), rt.BackupStore, ref))
	})
	mux.HandleFunc("/api/v1/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		if s.AuditDB != nil {
			out, err := (ops.SQLSnapshotStore{DB: s.AuditDB}).List(r.Context())
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			writeJSON(w, out)
			return
		}
		out := []ops.SnapshotView{}
		for _, v := range rt.Snapshots {
			out = append(out, v)
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("/api/v1/snapshots/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/snapshots/")
		if strings.HasSuffix(rest, "/diff") {
			id := strings.TrimSuffix(rest, "/diff")
			var a, b ops.SnapshotView
			var ok bool
			if s.AuditDB != nil {
				var err error
				a, ok, err = (ops.SQLSnapshotStore{DB: s.AuditDB}).Get(r.Context(), id)
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, ok, err = (ops.SQLSnapshotStore{DB: s.AuditDB}).Get(r.Context(), r.URL.Query().Get("against"))
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
			} else {
				a, ok = rt.Snapshots[id]
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, ok = rt.Snapshots[r.URL.Query().Get("against")]
			}
			if !ok {
				http.NotFound(w, r)
				return
			}
			writeJSON(w, map[string]any{"changed": ops.SnapshotDiff(a, b)})
			return
		}
		var snap ops.SnapshotView
		var ok bool
		if s.AuditDB != nil {
			var err error
			snap, ok, err = (ops.SQLSnapshotStore{DB: s.AuditDB}).Get(r.Context(), rest)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		} else {
			snap, ok = rt.Snapshots[rest]
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, map[string]any{"snapshot": snap, "rollback_guidance": ops.RollbackGuidance(snap)})
	})
	mux.HandleFunc("/api/v1/imports/mailu/preview", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		reqActor, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		var in struct {
			Source string `json:"source"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		writeJSON(w, safeImportPreview(rt.ImportStore.Preview(in.Source, reqActor, time.Now())))
	})
	mux.HandleFunc("/api/v1/imports/mailu/apply", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		reqActor, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		var in struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		var err error
		if s.AuditDB != nil {
			err = (ops.SQLImportStore{DB: s.AuditDB}).Apply(r.Context(), audit.SQLWriter{DB: s.AuditDB}, rt.ImportStore, reqActor, in.ID, r.URL.Query().Get("hash"), r.URL.Query().Get("source_fingerprint"), time.Now())
		} else {
			err = rt.ImportStore.Apply(r.Context(), auditLog, reqActor, in.ID, r.URL.Query().Get("hash"), r.URL.Query().Get("source_fingerprint"), time.Now(), s.Daemon)
		}
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"applied": true})
	})
	mux.HandleFunc("/api/v1/imports/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/imports/")
		p, ok := rt.ImportStore.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, safeImportPreview(p))
	})
	mux.HandleFunc("/api/v1/ops/abuse-summary", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		q := s.Queue
		if q == nil {
			q = &ops.Queue{}
		}
		summary := ops.BuildAbuseSummary(auditLog.Events, q.Summary)
		writeJSON(w, summary)
	})
	mux.HandleFunc("/api/v1/ops/rate-limits", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		writeJSON(w, ops.RateLimitViews(s.Daemon.RateLimits))
	})
	mux.HandleFunc("/api/v1/ops/deferred-correlation", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		q := s.Queue
		if q == nil {
			q = &ops.Queue{}
		}
		writeJSON(w, ops.DeferredCorrelations(q.Summary))
	})
	mux.HandleFunc("/api/v1/bulk/jobs/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		if _, ok := requireAdmin(w, r); !ok {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/bulk/jobs/")
		j, ok := rt.BulkStore.Job(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, j)
	})
	mux.HandleFunc("/api/v1/bulk/", func(w http.ResponseWriter, r *http.Request) {
		reqActor, ok := requireAdmin(w, r)
		if !ok {
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/bulk/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		op, action := parts[0], parts[1]
		switch action {
		case "preview":
			if !method(w, r, http.MethodPost) {
				return
			}
			var in struct {
				Items []string `json:"items"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			p, err := rt.BulkStore.Preview(op, in.Items, reqActor, time.Now())
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			writeJSON(w, p)
		case "apply":
			if !method(w, r, http.MethodPost) {
				return
			}
			var in struct {
				ID string `json:"id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&in)
			var res []ops.BulkResult
			var err error
			if s.AuditDB != nil {
				res, err = (ops.SQLBulkStore{DB: s.AuditDB}).Apply(r.Context(), audit.SQLWriter{DB: s.AuditDB}, rt.BulkStore, reqActor, op, in.ID, r.URL.Query().Get("confirm"), r.URL.Query().Get("hash"), time.Now())
			} else {
				res, err = rt.BulkStore.Apply(r.Context(), auditLog, reqActor, op, in.ID, r.URL.Query().Get("confirm"), r.URL.Query().Get("hash"), time.Now())
			}
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			writeJSON(w, res)
		default:
			http.NotFound(w, r)
		}
	})
}
func auditFilter(r *http.Request) ops.AuditFilter {
	q := r.URL.Query()
	f := ops.AuditFilter{ActorType: q.Get("actor_type"), ActorID: q.Get("actor_id"), Action: q.Get("action"), ResourceType: q.Get("resource_type"), ResourceID: q.Get("resource_id"), Result: q.Get("result"), CorrelationID: q.Get("correlation_id"), ErrorCode: q.Get("error_code")}
	if v := q.Get("from"); v != "" {
		f.From, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("to"); v != "" {
		f.To, _ = time.Parse(time.RFC3339, v)
	}
	return f
}

type safeImportPreviewView struct {
	ID, Hash, SourceFingerprint, ActorType, ActorID string
	ExpiresAt                                       time.Time
	Items                                           []ops.ImportItem
}

func safeImportPreview(p ops.ImportPreview) safeImportPreviewView {
	return safeImportPreviewView{ID: p.ID, Hash: p.Hash, SourceFingerprint: p.SourceFingerprint, ActorType: p.ActorType, ActorID: p.ActorID, ExpiresAt: p.ExpiresAt, Items: p.Items}
}
