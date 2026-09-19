package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/authz"
	"forgejo/gotthboard/gotth-mail/internal/daemon"
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
	const mailboxID = "00000000-0000-4000-8000-000000000a02"
	if _, err := db.Exec(`INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ($1,'00000000-0000-4000-8000-000000000a01','sender',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, mailboxID); err != nil {
		t.Fatal(err)
	}
	queue := outboundpolicy.QueueStore{DB: db}
	registration := outboundpolicy.QueueRegistration{
		QueueID: "3Pt2mN2VXxznjll", ArrivalFingerprint: strings.Repeat("a", 64), EnvelopeSender: "sender@example.test",
		Recipients: []string{"outside@example.net"}, Sources: []outboundpolicy.QueueSource{{Kind: outboundpolicy.SourceAuthenticatedMailbox, ObjectID: mailboxID}},
	}
	if _, _, err := queue.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	boundary := &apiActivationBoundary{metadata: outboundpolicy.QueueMetadata{QueueID: registration.QueueID, ArrivalFingerprint: registration.ArrivalFingerprint, EnvelopeSender: registration.EnvelopeSender, Recipients: registration.Recipients}}
	policy := &outboundpolicy.EnforcementService{DB: db, Queue: queue, HoldActor: audit.ActorRef{Type: "service", ID: "outbound-policy"}}
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("domain-admin", "api_token", "domain-admin-secret", "domain:admin:example.test"); err != nil {
		t.Fatal(err)
	}
	handler := (Server{AuditDB: db, Identity: ids, Authz: authz.StaticAuthorizer{}, Daemon: daemon.Service{
		OutboundPolicy: policy, OutboundReconciler: &outboundpolicy.QueueReconciler{Store: queue, Inspector: boundary, Holder: boundary},
	}}).Handler()
	body := `{"domain":"Example.TEST.","scope":"same_domain_only"}`
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
	var applied outboundpolicy.ChangeResult
	if err := json.Unmarshal(applyResponse.Body.Bytes(), &applied); err != nil || applied.Reconciliation == nil || applied.Reconciliation.Held != 1 || boundary.holds != 1 {
		t.Fatalf("applied=%#v holds=%d err=%v", applied, boundary.holds, err)
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

func TestOutboundPolicyAdminAPIReportsCommittedPendingReconciliation(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	if _, err := db.Exec(`INSERT INTO domains(id,name,enabled,outbound_scope,outbound_policy_revision,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000a11','example.test',true,'unrestricted',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP); INSERT INTO mailboxes(id,domain_id,local_part,enabled,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000a12','00000000-0000-4000-8000-000000000a11','sender',true,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	queue := outboundpolicy.QueueStore{DB: db}
	if _, _, err := queue.Register(context.Background(), outboundpolicy.QueueRegistration{
		QueueID: "BCDFGHJKLMNPz2345", ArrivalFingerprint: strings.Repeat("b", 64), EnvelopeSender: "sender@example.test",
		Recipients: []string{"outside@example.net"}, Sources: []outboundpolicy.QueueSource{{Kind: outboundpolicy.SourceAuthenticatedMailbox, ObjectID: "00000000-0000-4000-8000-000000000a12"}},
	}); err != nil {
		t.Fatal(err)
	}
	ids := identity.NewService("example.test")
	if err := ids.AddTokenWithScopes("domain-admin", "api_token", "domain-admin-secret", "domain:admin:example.test"); err != nil {
		t.Fatal(err)
	}
	handler := (Server{AuditDB: db, Identity: ids, Authz: authz.StaticAuthorizer{}}).Handler()
	request := func(path, body string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer domain-admin-secret")
		r.Header.Set("X-Correlation-ID", "outbound-policy-pending-test")
		handler.ServeHTTP(response, r)
		return response
	}
	preview := request("/api/v1/domains/outbound-policy/preview", `{"domain":"example.test","scope":"same_domain_only"}`)
	var plan outboundpolicy.ChangePlan
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &plan) != nil {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	applied := request("/api/v1/domains/outbound-policy/apply", `{"domain":"example.test","scope":"same_domain_only","confirmation":"`+plan.Digest+`"}`)
	var result outboundpolicy.ChangeResult
	if err := json.Unmarshal(applied.Body.Bytes(), &result); applied.Code != http.StatusAccepted || applied.Header().Get("Content-Type") != "application/json" || err != nil || !result.Changed || result.Reconciliation == nil || result.Reconciliation.Failed != 1 {
		t.Fatalf("status=%d content-type=%q result=%#v err=%v", applied.Code, applied.Header().Get("Content-Type"), result, err)
	}
}

type apiActivationBoundary struct {
	metadata outboundpolicy.QueueMetadata
	holds    int
}

func (b *apiActivationBoundary) Inspect(context.Context, string) (outboundpolicy.QueueMetadata, error) {
	return b.metadata, nil
}

func (b *apiActivationBoundary) Hold(context.Context, string) error {
	b.holds++
	b.metadata.Held = true
	return nil
}
