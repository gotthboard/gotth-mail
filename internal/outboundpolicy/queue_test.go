package outboundpolicy

import (
	"context"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestQueueStoreRegisterIsDurableIdempotentAndCanonical(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	now := time.Date(2026, 9, 19, 13, 0, 0, 0, time.UTC)
	queue := QueueStore{DB: db, Now: func() time.Time { return now }}
	in := QueueRegistration{
		QueueID:            "3Pt2mN2VXxznjll",
		ArrivalFingerprint: strings.Repeat("a", 64),
		EnvelopeSender:     "Sender@BÜCHER.example",
		Recipients:         []string{"local@BÜCHER.example", "outside@Example.NET.", "local@xn--bcher-kva.example"},
		Sources: []QueueSource{
			{Kind: SourceAuthenticatedMailbox, ObjectID: "00000000-0000-4000-8000-000000000901"},
			{Kind: SourceEnvelopeSender, ObjectID: "00000000-0000-4000-8000-000000000901"},
		},
	}
	record, created, err := queue.Register(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !created || record.HoldState != HoldPending || !record.FirstSeenAt.Equal(now) || !record.UpdatedAt.Equal(now) {
		t.Fatalf("record=%+v created=%v", record, created)
	}
	if record.EnvelopeSender != "Sender@xn--bcher-kva.example" {
		t.Fatalf("envelope sender=%q", record.EnvelopeSender)
	}
	if got, want := record.Recipients, []string{"local@xn--bcher-kva.example", "outside@example.net"}; !equalStrings(got, want) {
		t.Fatalf("recipients=%q want=%q", got, want)
	}
	if len(record.RecipientSetDigest) != 64 || len(record.SourceSetDigest) != 64 {
		t.Fatalf("digests=%q/%q", record.RecipientSetDigest, record.SourceSetDigest)
	}

	again, created, err := queue.Register(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if created || again.RecipientSetDigest != record.RecipientSetDigest || again.SourceSetDigest != record.SourceSetDigest {
		t.Fatalf("idempotent register=%+v created=%v", again, created)
	}
	reloaded, err := queue.Load(context.Background(), in.QueueID)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ArrivalFingerprint != in.ArrivalFingerprint || !equalStrings(reloaded.Recipients, record.Recipients) || len(reloaded.Sources) != 2 {
		t.Fatalf("reloaded=%+v", reloaded)
	}
}

func TestQueueStoreRejectsQueueIDReuseAndCorruption(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	queue := QueueStore{DB: db}
	base := QueueRegistration{
		QueueID:            "3Pt2mN2VXxznjll",
		ArrivalFingerprint: strings.Repeat("b", 64),
		EnvelopeSender:     "sender@example.test",
		Recipients:         []string{"recipient@example.test"},
		Sources:            []QueueSource{{Kind: SourceAuthenticatedMailbox, ObjectID: "mailbox-1"}},
	}
	if _, _, err := queue.Register(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	changed := base
	changed.ArrivalFingerprint = strings.Repeat("c", 64)
	if _, _, err := queue.Register(context.Background(), changed); err == nil {
		t.Fatal("queue ID reuse with changed arrival identity accepted")
	}
	if _, err := db.Exec(`UPDATE outbound_queue_recipients SET recipient='tampered@example.net',recipient_domain='example.net' WHERE queue_id=$1`, base.QueueID); err != nil {
		t.Fatal(err)
	}
	if _, err := queue.Load(context.Background(), base.QueueID); err == nil {
		t.Fatal("tampered recipient set accepted")
	}
}

func TestQueueStoreRejectsMalformedOrUnboundedRegistration(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	queue := QueueStore{DB: db}
	valid := QueueRegistration{
		QueueID:            "3Pt2mN2VXxznjll",
		ArrivalFingerprint: strings.Repeat("d", 64),
		EnvelopeSender:     "sender@example.test",
		Recipients:         []string{"recipient@example.test"},
		Sources:            []QueueSource{{Kind: SourceAuthenticatedMailbox, ObjectID: "mailbox-1"}},
	}
	tests := []struct {
		name   string
		mutate func(*QueueRegistration)
	}{
		{name: "queue ID", mutate: func(v *QueueRegistration) { v.QueueID = "ALL" }},
		{name: "arrival fingerprint", mutate: func(v *QueueRegistration) { v.ArrivalFingerprint = "bad" }},
		{name: "envelope sender", mutate: func(v *QueueRegistration) { v.EnvelopeSender = "bad sender" }},
		{name: "recipients absent", mutate: func(v *QueueRegistration) { v.Recipients = nil }},
		{name: "recipient malformed", mutate: func(v *QueueRegistration) { v.Recipients = []string{"bad"} }},
		{name: "sources absent", mutate: func(v *QueueRegistration) { v.Sources = nil }},
		{name: "source kind", mutate: func(v *QueueRegistration) { v.Sources[0].Kind = "header_from" }},
		{name: "source ID", mutate: func(v *QueueRegistration) { v.Sources[0].ObjectID = " bad " }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := valid
			candidate.Recipients = append([]string(nil), valid.Recipients...)
			candidate.Sources = append([]QueueSource(nil), valid.Sources...)
			tc.mutate(&candidate)
			if _, _, err := queue.Register(context.Background(), candidate); err == nil {
				t.Fatal("malformed registration accepted")
			}
		})
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
