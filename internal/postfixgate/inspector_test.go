package postfixgate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPQueueInspectorUsesAuthenticatedHelper(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	metadata := gateMetadata()
	helper, err := NewHelper(fakeInspector{metadata: metadata}, &fakeHolder{}, &fakeHolder{}, &fakeHolder{}, token, "abcdef0123456789abcdef0123456789")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(helper.Handler())
	defer server.Close()
	inspector := &HTTPQueueInspector{BaseURL: server.URL, Token: token, Client: server.Client()}
	got, err := inspector.Inspect(context.Background(), metadata.QueueID)
	if err != nil || got.QueueID != metadata.QueueID || got.ArrivalFingerprint != metadata.ArrivalFingerprint {
		t.Fatalf("metadata=%#v err=%v", got, err)
	}
}

func TestHTTPQueueInspectorFailsClosed(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", http.StatusUnauthorized, `{}`},
		{"oversized", http.StatusOK, `{"queue_id":"BCDFGHJKLMNPz6789","extra":true}`},
		{"trailing", http.StatusOK, `{} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			inspector := &HTTPQueueInspector{BaseURL: server.URL, Token: token, Client: server.Client()}
			if _, err := inspector.Inspect(context.Background(), "BCDFGHJKLMNPz6789"); err == nil {
				t.Fatal("accepted invalid helper response")
			}
		})
	}
}

func TestNewHTTPQueueInspectorRejectsNonLoopbackAndWeakToken(t *testing.T) {
	if _, err := NewHTTPQueueInspector("http://postfix:10026", "0123456789abcdef0123456789abcdef"); err == nil {
		t.Fatal("accepted non-loopback helper")
	}
	if _, err := NewHTTPQueueInspector("http://127.0.0.1:10026", "weak"); err == nil {
		t.Fatal("accepted weak helper token")
	}
}
