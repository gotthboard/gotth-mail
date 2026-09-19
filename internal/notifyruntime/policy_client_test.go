package notifyruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

func TestHTTPPolicyClientUsesStrictInternalDecisionContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Correlation-ID") != "corr-policy" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request method=%s correlation=%q content-type=%q", r.Method, r.Header.Get("X-Correlation-ID"), r.Header.Get("Content-Type"))
		}
		var request outboundpolicy.EnforcementRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.SystemSenderID != "system:alerts@example.test" || request.Recipient != "outside@example.net" {
			t.Fatalf("request=%+v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"correlation_id": "corr-policy", "decision": "reject", "reason": "recipient_domain_forbidden", "policy_revisions": map[string]uint64{"example.test": 2},
		})
	}))
	defer server.Close()
	client, err := NewHTTPPolicyClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.Decide(context.Background(), "corr-policy", outboundpolicy.EnforcementRequest{
		Stage: outboundpolicy.StageSubmission, SystemSenderID: "system:alerts@example.test", EnvelopeSender: "alerts@example.test", Recipient: "outside@example.net",
	})
	if err != nil || decision.Action != outboundpolicy.ActionReject || decision.Reason != outboundpolicy.ReasonRecipientForbidden || decision.Revisions["example.test"] != 2 {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
}

func TestHTTPPolicyClientRejectsUnsafeConfigAndMalformedResponses(t *testing.T) {
	for _, raw := range []string{"", "ftp://mail/policy", "http://user:pass@mail/policy", "http://mail/policy?x=1"} {
		if _, err := NewHTTPPolicyClient(raw); err == nil {
			t.Fatalf("unsafe URL %q accepted", raw)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"decision":"ok","reason":"same_domain"} trailing`))
	}))
	defer server.Close()
	client, err := NewHTTPPolicyClient(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(context.Background(), "corr", outboundpolicy.EnforcementRequest{Stage: outboundpolicy.StageSubmission}); err == nil {
		t.Fatal("malformed response accepted")
	}
}
