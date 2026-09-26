package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/api"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestConfigureWebmailFromEnvRequiresDurabilityAndWiresProductionRuntime(t *testing.T) {
	dir := t.TempDir()
	entity, err := protonpgp.NewEntity("Webmail User", "", "user@example.test", &packet.Config{
		DefaultHash: crypto.SHA256, Time: func() time.Time { return time.Now().UTC().Add(-time.Hour) }, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint)
	keyPath := filepath.Join(dir, "signing-key.asc")
	var key bytes.Buffer
	armored, err := armor.Encode(&key, protonpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, nil); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	writeWebmailTestFile(t, keyPath, key.Bytes())
	imapSecret := filepath.Join(dir, "imap-password")
	smtpSecret := filepath.Join(dir, "smtp-password")
	writeWebmailTestFile(t, imapSecret, []byte("imap-secret\n"))
	writeWebmailTestFile(t, smtpSecret, []byte("smtp-secret\n"))
	configPath := filepath.Join(dir, "runtime.json")
	raw, err := json.Marshal(webmail.RuntimeConfig{
		IMAPAddr: "dovecot:143", SMTPAddr: "postfix:25", SMTPAuthMechanism: "cram-md5",
		Mailboxes: []webmail.RuntimeMailbox{{
			Address: "user@example.test", IMAPPasswordFile: imapSecret, SMTPPasswordFile: smtpSecret,
			SigningFingerprint: fingerprint, PrivateKeyFile: keyPath,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	writeWebmailTestFile(t, configPath, raw)
	t.Setenv("GOTTH_MAIL_WEBMAIL_RUNTIME_FILE", configPath)
	if err := configureWebmailFromEnv(&api.Server{}); err == nil {
		t.Fatal("production webmail accepted missing durable database and policy")
	}

	db := testpg.DB(t, store.MigrateSQL)
	server := api.Server{AuditDB: db}
	server.Daemon.OutboundPolicy = &outboundpolicy.EnforcementService{DB: db, Queue: outboundpolicy.QueueStore{DB: db}}
	if err := configureWebmailFromEnv(&server); err != nil {
		t.Fatal(err)
	}
	if server.WebmailClient == nil || server.WebmailSender == nil || server.WebmailSender.Store == nil || server.WebmailSender.SMTP == nil || server.WebmailSender.Signer == nil || server.WebmailSender.Verifier == nil || server.WebmailSender.Resolver == nil || server.WebmailSender.Policy == nil {
		t.Fatalf("production webmail was not completely wired: %#v", server.WebmailSender)
	}
}

func TestConfigureWebmailFromEnvAbsentIsNoop(t *testing.T) {
	server := api.Server{}
	if err := configureWebmailFromEnv(&server); err != nil || server.WebmailClient != nil || server.WebmailSender != nil {
		t.Fatalf("absent webmail runtime = %#v, %v", server, err)
	}
}

func writeWebmailTestFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
