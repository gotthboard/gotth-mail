package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/scimstore"
	gotthscim "github.com/gotthboard/gotth-scim/pkg/scim"
)

type scimScopeKey struct{}

func NewSCIMHandler(externalURL string, db *sql.DB, ids *identity.Service, authorizer authz.Authorizer, auditWriter audit.Writer) (http.Handler, error) {
	if db == nil || ids == nil || authorizer == nil || auditWriter == nil {
		return nil, errors.New("SCIM database, identity service, authorizer, and audit writer are required")
	}
	ids.Authorizer = authorizer
	definitions := gotthscim.DefaultDefinitions()
	registry, err := gotthscim.NewRegistry(definitions)
	if err != nil {
		return nil, err
	}
	store := &scimstore.SQLStore{DB: db, Identity: ids}
	server, err := gotthscim.NewServer(gotthscim.ServerConfig{
		Store: store, Registry: registry, ExternalURL: externalURL,
		ResolveScope: func(request *http.Request) (string, error) {
			scope, ok := request.Context().Value(scimScopeKey{}).(string)
			if !ok || scope == "" {
				return "", errors.New("SCIM scope is unavailable")
			}
			return scope, nil
		},
		MaximumPageSize: 100, MaximumPatchOperations: 100, MaximumSearchCandidates: 1000,
		AuthenticationSchemes: []gotthscim.AuthenticationScheme{{Type: "oauthbearertoken", Name: "Bearer token", Description: "Verifier-backed GOTTH Mail SCIM client token"}},
		PublicDiscovery:       false, ChangePasswordSupported: true,
	})
	if err != nil {
		return nil, err
	}
	return &authenticatedSCIMHandler{next: server, identities: ids, audit: auditWriter}, nil
}

type authenticatedSCIMHandler struct {
	next       http.Handler
	identities *identity.Service
	audit      audit.Writer
}

func (handler *authenticatedSCIMHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	actor, err := handler.identities.AuthenticateBearer(request.Header.Get("Authorization"), "scim_client")
	if err != nil {
		handler.writeFailure(request, authz.Actor{Type: "scim_client", ID: "unknown"}, "denied", "authentication_failed")
		writeSCIMError(writer, http.StatusUnauthorized, "", "authentication is required")
		return
	}
	scope := provisioningScope(actor.ID)
	sourceIP, _, _ := net.SplitHostPort(request.RemoteAddr)
	ctx := context.WithValue(request.Context(), scimScopeKey{}, scope)
	ctx = scimstore.WithRequestMetadata(ctx, actor, request.Header.Get("X-Correlation-ID"), sourceIP, request.UserAgent())
	request = request.WithContext(ctx)
	status := &statusWriter{ResponseWriter: writer}
	handler.next.ServeHTTP(status, request)
	if isMutation(request.Method) && status.status >= 400 {
		handler.writeFailure(request, actor, "failure", "request_rejected")
	}
}

func (handler *authenticatedSCIMHandler) writeFailure(request *http.Request, actor authz.Actor, result, code string) {
	if handler.audit == nil {
		return
	}
	_ = handler.audit.Write(request.Context(), audit.Event{
		Actor: actorRef(actor), Action: "scim.request", Resource: audit.ResourceRef{Type: "identity", ID: "SCIM"},
		CorrelationID: request.Header.Get("X-Correlation-ID"), Result: result, ErrorCode: code,
	})
}

func actorRef(actor authz.Actor) audit.ActorRef {
	return audit.ActorRef{Type: actor.Type, ID: actor.ID}
}

func provisioningScope(actorID string) string {
	digest := sha256.Sum256([]byte("gotth-mail/scim-scope/v1\x00" + actorID))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func isMutation(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(body)
}

func writeSCIMError(writer http.ResponseWriter, status int, scimType, detail string) {
	response, err := gotthscim.NewError(status, scimType, detail)
	if err != nil {
		http.Error(writer, "SCIM request failed", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/scim+json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(response)
}
