package webmail

import (
	"context"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
)

func TestSQLDraftStorePersistsDraftAcrossReload(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	st := SQLDraftStore{DB: db}
	ctx := context.Background()
	d := Draft{ID: "draft-sql", From: "user@example.test", To: "to@example.test", Subject: "subject", Body: "body", SigningFingerprint: "fp", State: "draft"}
	if err := st.PutDraft(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, ok, err := (SQLDraftStore{DB: db}).Draft(ctx, "draft-sql")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got.From != d.From || got.To != d.To || got.Subject != d.Subject || got.Body != d.Body || got.SigningFingerprint != d.SigningFingerprint || got.State != "draft" {
		t.Fatalf("got=%#v", got)
	}
}

func TestSQLDraftStorePersistsReplyForwardAndAttachmentsAcrossReload(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	st := SQLDraftStore{DB: db}
	ctx := context.Background()
	d := Draft{
		ID:                 "draft-rich",
		From:               "user@example.test",
		To:                 "to@example.test",
		Subject:            "subject",
		Body:               "body",
		ReplyTo:            "imap-42",
		ForwardOf:          "imap-17",
		SigningFingerprint: "fp",
		State:              "draft",
		Attachments: []Attachment{{
			Filename:    "report.txt",
			ContentType: "text/plain",
			Size:        12,
			Content:     []byte("hello world!"),
		}},
	}
	if err := st.PutDraft(ctx, d); err != nil {
		t.Fatal(err)
	}
	got, ok, err := (SQLDraftStore{DB: db}).Draft(ctx, "draft-rich")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got.ReplyTo != d.ReplyTo || got.ForwardOf != d.ForwardOf {
		t.Fatalf("linkage lost: %#v", got)
	}
	if len(got.Attachments) != 1 || got.Attachments[0].Filename != "report.txt" || got.Attachments[0].ContentType != "text/plain" || string(got.Attachments[0].Content) != "hello world!" || got.Attachments[0].Size != 12 {
		t.Fatalf("attachments lost: %#v", got.Attachments)
	}
}

func TestSQLDraftStoreRejectsCrossMailboxOverwrite(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	st := SQLDraftStore{DB: db}
	ctx := context.Background()
	if err := st.PutDraft(ctx, Draft{ID: "draft-owned", From: "a@example.test", To: "to@example.test", Subject: "s", Body: "a", State: "draft"}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutDraft(ctx, Draft{ID: "draft-owned", From: "b@example.test", To: "to@example.test", Subject: "s", Body: "b", State: "draft"}); err == nil {
		t.Fatal("cross-mailbox overwrite accepted")
	}
	got, ok, err := st.Draft(ctx, "draft-owned")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got.From != "a@example.test" || got.Body != "a" {
		t.Fatalf("draft overwritten: %#v", got)
	}
}

func TestSenderSubmitPersistsSQLDraftState(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	smtp := &fakeSMTP{}
	s := &Sender{Store: SQLDraftStore{DB: db}, SMTP: smtp, Signer: fakeSigner{}, Resolver: fakeResolver{}}
	d, err := s.SaveDraftContext(context.Background(), Draft{From: "u@example.test", To: "r@example.test", Subject: "s", Body: "body", SigningFingerprint: "fp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Submit(context.Background(), d.ID); err != nil {
		t.Fatal(err)
	}
	got, ok, err := (SQLDraftStore{DB: db}).Draft(context.Background(), d.ID)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got.State != "sent" {
		t.Fatalf("state=%q draft=%#v", got.State, got)
	}
}
