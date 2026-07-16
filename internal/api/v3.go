package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/daemon"
	"forgejo/linus/gophermailforge/internal/ops"
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

func (s Server) registerV3(mux *http.ServeMux, auditLog *audit.MemoryWriter) {
	rt := s.v3Runtime()
	mux.HandleFunc("/api/v1/audit/export", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		ev := ops.FilterAudit(auditLog.Events, auditFilter(r))
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
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/audit/events/")
		for _, e := range auditLog.Events {
			if e.ID == id {
				writeJSON(w, e)
				return
			}
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("/api/v1/audit/retention/preview", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		p, err := rt.RetentionStore.Preview(auditLog.Events, r.URL.Query().Get("policy"), time.Now())
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
		var in struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad retention preview", 400)
			return
		}
		if err := rt.RetentionStore.Apply(r.Context(), auditLog, actor(r), in.ID, r.URL.Query().Get("confirm")); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"applied": true})
	})
	mux.HandleFunc("/api/v1/backups/verify", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
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
		writeJSON(w, ops.VerifyBackupFromStorage(r.Context(), rt.BackupStore, ref))
	})
	mux.HandleFunc("/api/v1/snapshots", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
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
		rest := strings.TrimPrefix(r.URL.Path, "/api/v1/snapshots/")
		if strings.HasSuffix(rest, "/diff") {
			id := strings.TrimSuffix(rest, "/diff")
			a := rt.Snapshots[id]
			b := rt.Snapshots[r.URL.Query().Get("against")]
			writeJSON(w, map[string]any{"changed": ops.SnapshotDiff(a, b)})
			return
		}
		snap, ok := rt.Snapshots[rest]
		if !ok {
			snap = ops.SnapshotView{ID: rest, VerifiedRestoreStatus: r.URL.Query().Get("verified_restore_status")}
		}
		writeJSON(w, map[string]any{"snapshot": snap, "rollback_guidance": ops.RollbackGuidance(snap)})
	})
	mux.HandleFunc("/api/v1/imports/mailu/preview", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var in struct {
			Source string `json:"source"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		writeJSON(w, safeImportPreview(rt.ImportStore.Preview(in.Source, actor(r), time.Now())))
	})
	mux.HandleFunc("/api/v1/imports/mailu/apply", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodPost) {
			return
		}
		var in struct {
			ID string `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		if err := rt.ImportStore.Apply(r.Context(), auditLog, actor(r), in.ID, r.URL.Query().Get("hash"), r.URL.Query().Get("source_fingerprint"), time.Now(), s.Daemon); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"applied": true})
	})
	mux.HandleFunc("/api/v1/imports/", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
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
		q := s.Queue
		if q == nil {
			q = &ops.Queue{}
		}
		writeJSON(w, ops.BuildAbuseSummary(auditLog.Events, q.Summary))
	})
	mux.HandleFunc("/api/v1/ops/rate-limits", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
			return
		}
		writeJSON(w, ops.RateLimitViews(s.Daemon.RateLimits))
	})
	mux.HandleFunc("/api/v1/ops/deferred-correlation", func(w http.ResponseWriter, r *http.Request) {
		if !method(w, r, http.MethodGet) {
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
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/bulk/jobs/")
		j, ok := rt.BulkStore.Job(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, j)
	})
	mux.HandleFunc("/api/v1/bulk/", func(w http.ResponseWriter, r *http.Request) {
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
			p, err := rt.BulkStore.Preview(op, in.Items, actor(r), time.Now())
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
			res, err := rt.BulkStore.Apply(r.Context(), auditLog, actor(r), op, in.ID, r.URL.Query().Get("confirm"), r.URL.Query().Get("hash"), time.Now())
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			writeJSON(w, res)
		default:
			http.NotFound(w, r)
		}
	})
	_ = daemon.OK
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
