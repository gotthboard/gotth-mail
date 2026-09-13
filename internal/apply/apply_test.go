package apply

import (
	"context"
	"forgejo/gotthboard/gotth-mail/internal/audit"
	"forgejo/gotthboard/gotth-mail/internal/render"
	"testing"
)

func TestApplyRequiresConfirmAndAudits(t *testing.T) {
	w := &audit.MemoryWriter{}
	g := Gate{Audit: w}
	staged := render.Set{ID: "abc"}
	if err := g.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "test"}, staged, "wrong"); err == nil {
		t.Fatal("expected confirmation failure")
	}
	if err := g.Apply(context.Background(), audit.ActorRef{Type: "local_admin", ID: "test"}, staged, "abc"); err != nil {
		t.Fatal(err)
	}
	if len(w.Events) != 1 {
		t.Fatalf("audit events=%d", len(w.Events))
	}
	if w.Events[0].Action != "config.apply" {
		t.Fatalf("bad audit action %s", w.Events[0].Action)
	}
}
