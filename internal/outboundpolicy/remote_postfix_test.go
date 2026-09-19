package outboundpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemotePostfixBoundaryUsesFixedAuthenticatedEndpoints(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	const releaseToken = "abcdef0123456789abcdef0123456789"
	queueID := "BCDFGHJKLMNPz6789"
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		wantToken := token
		if r.URL.Path == "/v1/queue/release" {
			wantToken = releaseToken
		}
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+wantToken {
			t.Fatalf("request=%s auth=%q", r.Method, r.Header.Get("Authorization"))
		}
		var in map[string]string
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in["queue_id"] != queueID {
			t.Fatalf("body=%#v err=%v", in, err)
		}
		switch r.URL.Path {
		case "/v1/queue/inspect":
			_ = json.NewEncoder(w).Encode(QueueMetadata{
				QueueID:            queueID,
				ArrivalFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				EnvelopeSender:     "user@example.test",
				Recipients:         []string{"outside@example.net"},
			})
		case "/v1/queue/hold", "/v1/queue/release":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	boundary, err := NewRemotePostfixBoundary(server.URL, token)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := boundary.Inspect(context.Background(), queueID)
	if err != nil || metadata.QueueID != queueID {
		t.Fatalf("metadata=%#v err=%v", metadata, err)
	}
	if err := boundary.Hold(context.Background(), queueID); err != nil {
		t.Fatal(err)
	}
	if err := boundary.Release(context.Background(), queueID); err == nil {
		t.Fatal("ordinary helper client obtained release authority")
	}
	boundary, err = NewRemotePostfixBoundaryWithRelease(server.URL, token, releaseToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := boundary.Release(context.Background(), queueID); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatalf("requests=%d", requests)
	}
}

func TestRemotePostfixBoundaryRejectsBadConfigurationAndResponses(t *testing.T) {
	if _, err := NewRemotePostfixBoundary("ftp://helper.example.test", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("accepted an unsupported transport scheme")
	}
	if _, err := NewRemotePostfixBoundary("http://helper:10026/path", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("accepted a helper URL path")
	}
	if _, err := NewRemotePostfixBoundary("http://helper:10026", "short"); err == nil {
		t.Fatal("accepted a weak helper token")
	}
	if _, err := NewRemotePostfixBoundaryWithRelease("http://helper:10026", "0123456789abcdef0123456789abcdef", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("accepted identical helper and release credentials")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"queue_id":"wrong"}`))
	}))
	defer server.Close()
	boundary, err := NewRemotePostfixBoundary(server.URL, "0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.Inspect(context.Background(), "BCDFGHJKLMNPz6789"); err == nil {
		t.Fatal("accepted invalid helper metadata")
	}
}
