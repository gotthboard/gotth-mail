package webmail

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestRuntimeRegistryLoadsExactMailboxAndReloadsSigningMaterial(t *testing.T) {
	dir := t.TempDir()
	entity := runtimeTestEntity(t, "user@example.test")
	fingerprint := strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))
	keyPath := filepath.Join(dir, "key.asc")
	writeRuntimePrivateKey(t, keyPath, entity, 0o600)
	imapSecret := writeRuntimeFile(t, dir, "imap.secret", []byte("imap-password\n"), 0o600)
	smtpSecret := writeRuntimeFile(t, dir, "smtp.secret", []byte("smtp-password\n"), 0o600)
	configPath := writeRuntimeConfig(t, dir, RuntimeConfig{
		IMAPAddr: "127.0.0.1:1143", SMTPAddr: "front:1587", SMTPAuthMechanism: "plain",
		SMTPStartTLS: true, SMTPTLSServerName: "mail.example.test",
		Mailboxes: []RuntimeMailbox{{
			Address: "User@Example.Test", IMAPPasswordFile: imapSecret,
			SMTPPasswordFile: smtpSecret, SigningFingerprint: strings.ToLower(fingerprint),
			PrivateKeyFile: keyPath,
		}},
	})

	runtime, err := NewRuntimeRegistryFromFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := runtime.ResolveSender(context.Background(), fingerprint, "user@example.test", "")
	if err != nil || identity.Address != "user@example.test" || identity.Fingerprint != fingerprint {
		t.Fatalf("identity = %#v, %v", identity, err)
	}
	msg, err := BuildMIME(Draft{
		From: identity.Address, To: "dest@example.test", Subject: "runtime", Body: "body",
		MessageID: "<runtime@example.test>", Date: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, status, err := runtime.SignMIME(context.Background(), identity, msg)
	if err != nil || !status.Signed {
		t.Fatalf("sign = %#v, %v", status, err)
	}
	verified, err := runtime.VerifyExactSender(context.Background(), signed, identity)
	if err != nil || !verified.Signed || verified.Identity != identity.Address || verified.Fingerprint != identity.Fingerprint {
		t.Fatalf("verify = %#v, %v", verified, err)
	}
	if _, err := runtime.ResolveSender(context.Background(), strings.Repeat("0", len(fingerprint)), identity.Address, ""); err == nil {
		t.Fatal("mismatched fingerprint accepted")
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runtime.SignMIME(context.Background(), identity, msg); err == nil {
		t.Fatal("signing material permission drift accepted")
	}
}

func TestRuntimeRegistryRejectsUnsafeOrAmbiguousConfiguration(t *testing.T) {
	dir := t.TempDir()
	entity := runtimeTestEntity(t, "user@example.test")
	fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	keyPath := filepath.Join(dir, "key.asc")
	writeRuntimePrivateKey(t, keyPath, entity, 0o600)
	secret := writeRuntimeFile(t, dir, "mail.secret", []byte("secret"), 0o600)
	mailbox := RuntimeMailbox{Address: "user@example.test", IMAPPasswordFile: secret, SMTPPasswordFile: secret, SigningFingerprint: fingerprint, PrivateKeyFile: keyPath}

	tests := []struct {
		name string
		cfg  RuntimeConfig
	}{
		{"public endpoint", RuntimeConfig{IMAPAddr: "203.0.113.4:143", SMTPAddr: "postfix:25", Mailboxes: []RuntimeMailbox{mailbox}}},
		{"duplicate mailbox", RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "postfix:25", Mailboxes: []RuntimeMailbox{mailbox, mailbox}}},
		{"missing mailbox", RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "postfix:25"}},
		{"missing auth mechanism", RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "postfix:25", Mailboxes: []RuntimeMailbox{mailbox}}},
		{"unknown auth mechanism", RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "postfix:25", SMTPAuthMechanism: "login", Mailboxes: []RuntimeMailbox{mailbox}}},
		{"plain without STARTTLS", RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "front:1587", SMTPAuthMechanism: "plain", Mailboxes: []RuntimeMailbox{mailbox}}},
		{"STARTTLS without server name", RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "front:1587", SMTPAuthMechanism: "plain", SMTPStartTLS: true, Mailboxes: []RuntimeMailbox{mailbox}}},
		{"TLS name without STARTTLS", RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "front:1587", SMTPAuthMechanism: "cram-md5", SMTPTLSServerName: "mail.example.test", Mailboxes: []RuntimeMailbox{mailbox}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewRuntimeRegistry(tt.cfg); err == nil {
				t.Fatal("unsafe configuration accepted")
			}
		})
	}

	if err := os.Chmod(secret, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRuntimeRegistry(RuntimeConfig{IMAPAddr: "dovecot:143", SMTPAddr: "postfix:25", SMTPAuthMechanism: "cram-md5", Mailboxes: []RuntimeMailbox{mailbox}}); err == nil {
		t.Fatal("world-readable credential accepted")
	}
}

func TestRuntimeRegistryConfigRejectsUnknownAndTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown":  `{"imap_addr":"dovecot:143","smtp_addr":"postfix:25","mailboxes":[],"surprise":true}`,
		"trailing": `{"imap_addr":"dovecot:143","smtp_addr":"postfix:25","mailboxes":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeRuntimeFile(t, dir, name+".json", []byte(body), 0o600)
			if _, err := NewRuntimeRegistryFromFile(path); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}

func TestRuntimeRegistryLiveComposeFlow(t *testing.T) {
	path := os.Getenv("GOTTH_MAIL_LIVE_WEBMAIL_RUNTIME_FILE")
	if path == "" {
		t.Skip("GOTTH_MAIL_LIVE_WEBMAIL_RUNTIME_FILE not set")
	}
	from := os.Getenv("GOTTH_MAIL_LIVE_WEBMAIL_FROM")
	fingerprint := os.Getenv("GOTTH_MAIL_LIVE_WEBMAIL_FINGERPRINT")
	subject := os.Getenv("GOTTH_MAIL_LIVE_WEBMAIL_SUBJECT")
	if from == "" || fingerprint == "" || subject == "" {
		t.Fatal("live webmail sender, fingerprint, and subject are required")
	}
	runtime, err := NewRuntimeRegistryFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sender := &Sender{SMTP: runtime, Signer: runtime, Verifier: runtime, Resolver: runtime, Policy: fakeOutboundPolicy{}, Drafts: map[string]Draft{}}
	draft := sender.SaveDraft(Draft{From: from, To: from, Subject: subject, Body: "containerized production webmail runtime", SigningFingerprint: fingerprint})
	sent, err := sender.Submit(context.Background(), draft.ID)
	if err != nil || sent.State != "sent" {
		t.Fatalf("submit state=%q err=%v", sent.State, err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var delivered Message
	for {
		messages, searchErr := runtime.Search(context.Background(), from, "INBOX", subject, "", 10)
		if searchErr == nil && len(messages) > 0 && messages[0].Subject == subject {
			delivered = messages[0]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("signed SMTP message not visible over IMAP: %v", searchErr)
		}
		time.Sleep(250 * time.Millisecond)
	}
	used, limit, err := runtime.Quota(context.Background(), from)
	if err != nil || used <= 0 || limit != 1<<30 {
		t.Fatalf("live quota used=%d limit=%d err=%v", used, limit, err)
	}
	folders, err := runtime.ListFoldersDetailed(context.Background(), from)
	if err != nil || len(folders) < 2 {
		t.Fatalf("live folder details=%#v err=%v", folders, err)
	}
	foundInbox := false
	for _, folder := range folders {
		if folder.Name == "INBOX" {
			foundInbox = true
			if folder.Unread < 1 {
				t.Fatalf("live INBOX unread count=%d", folder.Unread)
			}
		}
	}
	if !foundInbox {
		t.Fatalf("live INBOX missing from folder details: %#v", folders)
	}
	if err := runtime.SetFlag(context.Background(), from, "INBOX", delivered.ID, "flagged", true); err != nil {
		t.Fatal(err)
	}
	flagged, err := runtime.ReadMessage(context.Background(), from, "INBOX", delivered.ID)
	if err != nil || !containsString(flagged.Flags, `\Flagged`) {
		t.Fatalf("live flag state=%#v err=%v", flagged.Flags, err)
	}
	if err := runtime.Move(context.Background(), from, "INBOX", delivered.ID, "Archive"); err != nil {
		t.Fatal(err)
	}
	archived, err := runtime.Search(context.Background(), from, "Archive", subject, "", 10)
	if err != nil || len(archived) != 1 {
		t.Fatalf("live move search=%#v err=%v", archived, err)
	}
	if err := runtime.Delete(context.Background(), from, "Archive", archived[0].ID); err != nil {
		t.Fatal(err)
	}
	remaining, err := runtime.Search(context.Background(), from, "Archive", subject, "", 10)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("live delete search=%#v err=%v", remaining, err)
	}
}

func writeRuntimeConfig(t *testing.T, dir string, cfg RuntimeConfig) string {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return writeRuntimeFile(t, dir, "runtime.json", raw, 0o600)
}

func writeRuntimeFile(t *testing.T, dir, name string, raw []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func runtimeTestEntity(t *testing.T, address string) *protonpgp.Entity {
	t.Helper()
	entity, err := protonpgp.NewEntity("Runtime User", "", address, &packet.Config{
		DefaultHash: crypto.SHA256, Time: func() time.Time { return time.Now().UTC().Add(-time.Hour) }, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

func writeRuntimePrivateKey(t *testing.T, path string, entity *protonpgp.Entity, mode os.FileMode) {
	t.Helper()
	var raw bytes.Buffer
	armored, err := armor.Encode(&raw, protonpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, nil); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw.Bytes(), mode); err != nil {
		t.Fatal(err)
	}
}
