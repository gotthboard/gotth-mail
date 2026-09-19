package postfixgate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/daemon"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

func TestHTTPControllerUsesPrivilegedAndPolicyRoutes(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	privileged := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := daemon.Response{CorrelationID: "test"}
		switch r.URL.Path {
		case "/internal/v1/postfix/queue/register":
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Fatalf("register auth=%q", r.Header.Get("Authorization"))
			}
			privileged++
			response.Decision, response.Reason = daemon.OK, "outbound_queue_registered"
		case "/internal/v1/postfix/outbound-policy":
			if r.Header.Get("Authorization") != "" {
				t.Fatal("policy request leaked privileged bearer")
			}
			response.Decision, response.Reason = daemon.Defer, string(outboundpolicy.ReasonPolicyHold)
		case "/internal/v1/postfix/queue/reconcile":
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Fatalf("reconcile auth=%q", r.Header.Get("Authorization"))
			}
			privileged++
			response.Decision, response.Reason = daemon.OK, "outbound_queue_hold_applied"
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	controller, err := NewHTTPController(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Register(context.Background(), outboundpolicy.QueueAdmissionRequest{}); err != nil {
		t.Fatal(err)
	}
	decision, err := controller.Decide(context.Background(), "BCDFGHJKLMNPz6789", "outside@example.net")
	if err != nil || decision.Reason != outboundpolicy.ReasonPolicyHold {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	if err := controller.Reconcile(context.Background(), "BCDFGHJKLMNPz6789"); err != nil {
		t.Fatal(err)
	}
	if privileged != 2 {
		t.Fatalf("privileged=%d", privileged)
	}
}

func TestHTTPControllerRejectsInvalidConfigurationAndUnknownDecision(t *testing.T) {
	if _, err := NewHTTPController("http://core:8080/path", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("accepted URL path")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(daemon.Response{Decision: daemon.OK, Reason: "invented"})
	}))
	defer server.Close()
	controller, err := NewHTTPController(server.URL, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Decide(context.Background(), "BCDFGHJKLMNPz6789", "outside@example.net"); err == nil {
		t.Fatal("accepted unknown policy reason")
	}
}
