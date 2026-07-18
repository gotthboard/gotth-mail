package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"forgejo/linus/gophermailforge/internal/audit"
	"forgejo/linus/gophermailforge/internal/identity"
)

func writeAPIAudit(w audit.Writer, r *http.Request, action, resource, result, code string) {
	if w == nil {
		return
	}
	_ = w.Write(r.Context(), audit.Event{Actor: audit.ActorRef{Type: "api", ID: r.RemoteAddr}, Action: action, Resource: audit.ResourceRef{Type: "identity", ID: resource}, Result: result, ErrorCode: code, CorrelationID: r.Header.Get("X-Correlation-ID")})
}

func (s Server) identityService(auditLog *audit.MemoryWriter) *identity.Service {
	ids := s.Identity
	if ids == nil {
		var domains []string
		for name := range s.Daemon.Domains {
			domains = append(domains, name)
		}
		ids = identity.NewService(domains...)
	}
	if ids.Daemon == nil {
		ids.Daemon = &s.Daemon
	}
	if ids.Authorizer == nil {
		ids.Authorizer = s.authorizer()
	}
	if ids.Audit == nil {
		ids.Audit = auditLog
	}
	return ids
}

func (s Server) registerIdentityAPI(mux *http.ServeMux, auditLog *audit.MemoryWriter, ids *identity.Service) {
	mux.HandleFunc("/api/v1/mailboxes/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/mailboxes/")
		parts := strings.Split(path, "/")
		if len(parts) < 2 || parts[1] != "app-passwords" {
			http.NotFound(w, r)
			return
		}
		mailboxID := parts[0]
		actor, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "api_token")
		if err != nil {
			writeAPIAudit(auditLog, r, "app_password.auth", mailboxID, "denied", err.Error())
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		switch {
		case len(parts) == 2 && r.Method == http.MethodGet:
			apps, err := ids.ListAppPasswordsForActor(r.Context(), actor, mailboxID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			writeJSON(w, apps)
		case len(parts) == 2 && r.Method == http.MethodPost:
			var in struct {
				Label string `json:"label"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
				writeAPIAudit(auditLog, r, "app_password.create", mailboxID, "failure", "bad_request")
				http.Error(w, "bad app password request", http.StatusBadRequest)
				return
			}
			created, err := ids.CreateAppPassword(r.Context(), actor, mailboxID, in.Label)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, created)
		case len(parts) == 3 && r.Method == http.MethodDelete:
			if err := ids.RevokeAppPassword(r.Context(), actor, mailboxID, parts[2]); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			writeJSON(w, map[string]bool{"revoked": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

var scimSchemas = []string{"urn:ietf:params:scim:schemas:core:2.0:User"}

func (s Server) registerSCIM(mux *http.ServeMux, auditLog *audit.MemoryWriter, ids *identity.Service) {
	mux.HandleFunc("/scim/v2/ServiceProviderConfig", func(w http.ResponseWriter, r *http.Request) {
		if method(w, r, "GET") {
			writeJSON(w, map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"}, "patch": map[string]bool{"supported": true}, "filter": map[string]bool{"supported": false}, "bulk": map[string]bool{"supported": false}})
		}
	})
	mux.HandleFunc("/scim/v2/ResourceTypes", func(w http.ResponseWriter, r *http.Request) {
		if method(w, r, "GET") {
			writeJSON(w, []map[string]any{{"id": "User", "name": "User", "endpoint": "/Users", "schema": scimSchemas[0]}, {"id": "Group", "name": "Group", "endpoint": "/Groups", "schema": "urn:ietf:params:scim:schemas:core:2.0:Group"}})
		}
	})
	mux.HandleFunc("/scim/v2/Schemas", func(w http.ResponseWriter, r *http.Request) {
		if method(w, r, "GET") {
			writeJSON(w, []map[string]any{{"id": scimSchemas[0], "name": "User"}})
		}
	})
	mux.HandleFunc("/scim/v2/Groups", func(w http.ResponseWriter, r *http.Request) {
		scimError(w, http.StatusNotImplemented, "unsupported", "SCIM groups are explicitly unsupported")
	})
	mux.HandleFunc("/scim/v2/Users", func(w http.ResponseWriter, r *http.Request) {
		actor, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "scim_client")
		if err != nil {
			writeAPIAudit(auditLog, r, "scim.auth", "Users", "denied", err.Error())
			scimError(w, http.StatusUnauthorized, "invalidValue", err.Error())
			return
		}
		switch r.Method {
		case http.MethodGet:
			users := ids.ListUsers()
			resources := make([]any, 0, len(users))
			for _, u := range users {
				resources = append(resources, scimUser(u))
			}
			writeJSON(w, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"}, "totalResults": len(resources), "Resources": resources})
		case http.MethodPost:
			u, password, err := decodeSCIMUser(r)
			if err != nil {
				writeAPIAudit(auditLog, r, "scim.user.write", "Users", "failure", err.Error())
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			out, err := ids.CreateOrReplaceUser(r.Context(), actor, u, password)
			if err != nil {
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(scimUser(out))
		default:
			method(w, r, http.MethodGet)
		}
	})
	mux.HandleFunc("/scim/v2/Users/", func(w http.ResponseWriter, r *http.Request) {
		actor, err := ids.AuthenticateBearer(r.Header.Get("Authorization"), "scim_client")
		if err != nil {
			writeAPIAudit(auditLog, r, "scim.auth", "Users", "denied", err.Error())
			scimError(w, http.StatusUnauthorized, "invalidValue", err.Error())
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			u, ok := ids.GetUser(id)
			if !ok {
				scimError(w, http.StatusNotFound, "notFound", "user not found")
				return
			}
			writeJSON(w, scimUser(u))
		case http.MethodPut:
			u, password, err := decodeSCIMUser(r)
			if err != nil {
				writeAPIAudit(auditLog, r, "scim.user.write", id, "failure", err.Error())
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			if strings.ToLower(id) != strings.ToLower(u.Email) {
				writeAPIAudit(auditLog, r, "scim.user.write", id, "failure", "id_userName_mismatch")
				scimError(w, http.StatusBadRequest, "invalidValue", "id must match userName mailbox email")
				return
			}
			u.ID = strings.ToLower(u.Email)
			out, err := ids.CreateOrReplaceUser(r.Context(), actor, u, password)
			if err != nil {
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			writeJSON(w, scimUser(out))
		case http.MethodPatch:
			ops, err := decodeSCIMPatch(r)
			if err != nil {
				writeAPIAudit(auditLog, r, "scim.user.patch", id, "failure", err.Error())
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			out, err := ids.PatchUser(r.Context(), actor, id, ops)
			if err != nil {
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			writeJSON(w, scimUser(out))
		case http.MethodDelete:
			out, err := ids.DisableUser(r.Context(), actor, id)
			if err != nil {
				scimError(w, http.StatusBadRequest, "invalidValue", err.Error())
				return
			}
			writeJSON(w, scimUser(out))
		default:
			method(w, r, http.MethodGet)
		}
	})
}

func decodeSCIMUser(r *http.Request) (identity.Mailbox, string, error) {
	var raw map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&raw); err != nil {
		return identity.Mailbox{}, "", err
	}
	userName, ok := raw["userName"].(string)
	if !ok || userName == "" {
		return identity.Mailbox{}, "", errString("userName must be string")
	}
	active := true
	if v, ok := raw["active"]; ok {
		b, ok := v.(bool)
		if !ok {
			return identity.Mailbox{}, "", errString("active must be boolean")
		}
		active = b
	}
	display := ""
	if v, ok := raw["displayName"]; ok {
		display, ok = v.(string)
		if !ok {
			return identity.Mailbox{}, "", errString("displayName must be string")
		}
	}
	if name, ok := raw["name"].(map[string]any); ok && display == "" {
		if v, exists := name["formatted"]; exists {
			display, ok = v.(string)
			if !ok {
				return identity.Mailbox{}, "", errString("name.formatted must be string")
			}
		}
	} else if raw["name"] != nil && !ok {
		return identity.Mailbox{}, "", errString("name must be object")
	}
	password := ""
	if v, ok := raw["password"]; ok {
		password, ok = v.(string)
		if !ok {
			return identity.Mailbox{}, "", errString("password must be string")
		}
	}
	return identity.Mailbox{Email: userName, Active: active, DisplayName: display}, password, nil
}
func decodeSCIMPatch(r *http.Request) ([]identity.PatchOperation, error) {
	var raw struct {
		Operations []struct {
			Op    string `json:"op"`
			Path  string `json:"path"`
			Value any    `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&raw); err != nil {
		return nil, err
	}
	if len(raw.Operations) == 0 {
		return nil, errString("Operations required")
	}
	out := make([]identity.PatchOperation, 0, len(raw.Operations))
	for _, op := range raw.Operations {
		out = append(out, identity.PatchOperation{Op: op.Op, Path: op.Path, Value: op.Value})
	}
	return out, nil
}
func scimUser(u identity.Mailbox) map[string]any {
	return map[string]any{"schemas": scimSchemas, "id": u.ID, "userName": u.Email, "displayName": u.DisplayName, "active": u.Active, "name": map[string]any{"formatted": u.DisplayName}}
}
func scimError(w http.ResponseWriter, code int, typ, detail string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": fmt.Sprintf("%d", code), "scimType": typ, "detail": detail})
}

type errString string

func (e errString) Error() string { return string(e) }
