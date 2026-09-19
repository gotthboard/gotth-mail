package postfixgate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakeHolder struct{ calls int }

func (f *fakeHolder) Hold(context.Context, string) error {
	f.calls++
	return nil
}

func TestHelperAuthenticatesAndExposesOnlyInspectAndHold(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	metadata := gateMetadata()
	holder := &fakeHolder{}
	helper, err := NewHelper(fakeInspector{metadata: metadata}, holder, token)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/queue/inspect", "/v1/queue/hold"} {
		body, _ := json.Marshal(map[string]string{"queue_id": metadata.QueueID})
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		helper.Handler().ServeHTTP(response, request)
		if response.Code < 200 || response.Code >= 300 {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	if holder.calls != 1 {
		t.Fatalf("hold calls=%d", holder.calls)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/queue/hold", bytes.NewBufferString(`{"queue_id":"BCDFGHJKLMNPz6789"}`))
	request.Header.Set("Authorization", "Bearer wrong-wrong-wrong-wrong-wrong-wrong")
	response := httptest.NewRecorder()
	helper.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || holder.calls != 1 {
		t.Fatalf("status=%d hold calls=%d", response.Code, holder.calls)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/queue/delete", bytes.NewBufferString(`{}`))
	request.Header.Set("Authorization", "Bearer "+token)
	response = httptest.NewRecorder()
	helper.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unexpected helper surface status=%d", response.Code)
	}
}

var _ QueueInspector = fakeInspector{}
