package audit

import (
	"context"
	"testing"
)

func TestRedaction(t *testing.T) {
	w := &MemoryWriter{}
	err := w.Write(context.Background(), Event{Actor: ActorRef{Type: "local_admin", ID: "x"}, Action: "test", Resource: ResourceRef{Type: "r", ID: "1"}, BeforeRedacted: map[string]any{"password": "secret", "nested": map[string]any{"client_secret": "abc"}}, AfterRedacted: map[string]any{"ok": "visible"}, Result: "success"})
	if err != nil {
		t.Fatal(err)
	}
	if ContainsSecretJSON(w.Events[0].BeforeRedacted, "secret", "abc") {
		t.Fatalf("secret leaked: %#v", w.Events[0].BeforeRedacted)
	}
}
