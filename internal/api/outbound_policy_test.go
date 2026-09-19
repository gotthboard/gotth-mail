package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/identity"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestOutboundPolicyAdminAPIRequiresScopedPreviewAndConfirmation(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000a01','example.test',true,'unrestricted',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("domain-admin", "api_token", "domain-admin-secret", "domain:admin:example.test"); err != nil {
		t.Fatal(err)
	}
	handler := (Server{AuditDB: db, Identity: ids, Authz: authz.StaticAuthorizer{}}).Handler()
	body := `{"domain":"example.test","scope":"same_domain_only"}`
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/api/v1/domains/outbound-policy/preview", strings.NewReader(body)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}

	previewResponse := httptest.NewRecorder()
	previewRequest := httptest.NewRequest(http.MethodPost, "/api/v1/domains/outbound-policy/preview", strings.NewReader(body))
	previewRequest.Header.Set("Authorization", "Bearer domain-admin-secret")
	handler.ServeHTTP(previewResponse, previewRequest)
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", previewResponse.Code, previewResponse.Body.String())
	}
	var plan outboundpolicy.ChangePlan
	if err := json.Unmarshal(previewResponse.Body.Bytes(), &plan); err != nil || plan.Digest == "" || plan.RequestedScope != outboundpolicy.ScopeSameDomainOnly {
		t.Fatalf("plan=%#v err=%v", plan, err)
	}

	applyBody := `{"domain":"example.test","scope":"same_domain_only","confirmation":"` + plan.Digest + `"}`
	applyResponse := httptest.NewRecorder()
	applyRequest := httptest.NewRequest(http.MethodPost, "/api/v1/domains/outbound-policy/apply", strings.NewReader(applyBody))
	applyRequest.Header.Set("Authorization", "Bearer domain-admin-secret")
	applyRequest.Header.Set("X-Correlation-ID", "outbound-policy-api-test")
	handler.ServeHTTP(applyResponse, applyRequest)
	if applyResponse.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applyResponse.Code, applyResponse.Body.String())
	}
	var scope string
	var revision uint64
	if err := db.QueryRowContext(context.Background(), `SELECT outbound_scope,outbound_policy_revision FROM domains WHERE name='example.test'`).Scan(&scope, &revision); err != nil {
		t.Fatal(err)
	}
	if scope != string(outboundpolicy.ScopeSameDomainOnly) || revision != 2 {
		t.Fatalf("scope=%q revision=%d", scope, revision)
	}
}
