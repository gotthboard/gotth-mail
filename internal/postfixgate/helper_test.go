package postfixgate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

type fakeHolder struct {
	holdCalls    int
	releaseCalls int
	snapshotErr  error
}

func (f *fakeHolder) Hold(context.Context, string) error {
	f.holdCalls++
	return nil
}

func (f *fakeHolder) Release(context.Context, string) error {
	f.releaseCalls++
	return nil
}

func (f *fakeHolder) Snapshot(context.Context, string) (outboundpolicy.QueueSnapshot, error) {
	return outboundpolicy.QueueSnapshot{Digest: strings.Repeat("a", 64)}, f.snapshotErr
}

func TestHelperClassifiesMissingQueueSnapshot(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	const releaseToken = "abcdef0123456789abcdef0123456789"
	holder := &fakeHolder{snapshotErr: outboundpolicy.ErrQueueIDNotFound}
	helper, err := NewHelper(fakeInspector{metadata: gateMetadata()}, holder, holder, holder, token, releaseToken)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"queue_id": gateMetadata().QueueID})
	request := httptest.NewRequest(http.MethodPost, "/v1/queue/summary", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	helper.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing queue snapshot status=%d body=%q", response.Code, response.Body.String())
	}
}
func (f *fakeHolder) Flush(context.Context) error         { return nil }
func (f *fakeHolder) Retry(context.Context, string) error { return nil }

func TestHelperAuthenticatesAndExposesOnlyInspectHoldAndRelease(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	const releaseToken = "abcdef0123456789abcdef0123456789"
	metadata := gateMetadata()
	holder := &fakeHolder{}
	helper, err := NewHelper(fakeInspector{metadata: metadata}, holder, holder, holder, token, releaseToken)
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
	body, _ := json.Marshal(map[string]string{"queue_id": metadata.QueueID})
	request := httptest.NewRequest(http.MethodPost, "/v1/queue/release", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	helper.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || holder.releaseCalls != 0 {
		t.Fatalf("ordinary helper token released queue: status=%d calls=%d", response.Code, holder.releaseCalls)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/queue/release", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+releaseToken)
	response = httptest.NewRecorder()
	helper.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || holder.releaseCalls != 1 {
		t.Fatalf("release token status=%d calls=%d", response.Code, holder.releaseCalls)
	}
	if holder.holdCalls != 1 || holder.releaseCalls != 1 {
		t.Fatalf("hold calls=%d release calls=%d", holder.holdCalls, holder.releaseCalls)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/queue/hold", bytes.NewBufferString(`{"queue_id":"BCDFGHJKLMNPz6789"}`))
	request.Header.Set("Authorization", "Bearer wrong-wrong-wrong-wrong-wrong-wrong")
	response = httptest.NewRecorder()
	helper.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || holder.holdCalls != 1 || holder.releaseCalls != 1 {
		t.Fatalf("status=%d hold calls=%d release calls=%d", response.Code, holder.holdCalls, holder.releaseCalls)
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
