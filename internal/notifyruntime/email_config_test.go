package notifyruntime

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var emailConfigTestTime = time.Unix(1700000000, 0).UTC()

func TestNewSignedEmailBackendComposesRealAdapters(t *testing.T) {
	entity := newEmailConfigEntity(t, emailConfigTestTime)
	path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	backend, err := NewSignedEmailBackend(validEmailConfig(path, emailConfigFingerprint(entity)))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := backend.SMTP.(webmail.NetSMTPSubmitter); !ok {
		t.Fatalf("SMTP adapter = %T, want webmail.NetSMTPSubmitter", backend.SMTP)
	}
	material, ok := backend.Signer.(*runtimeEmailMaterial)
	if !ok {
		t.Fatalf("signer = %T, want *runtimeEmailMaterial", backend.Signer)
	}
	if backend.Verifier != material || backend.Resolver != material {
		t.Fatalf("signer/verifier/resolver do not share runtime key source: signer=%T verifier=%T resolver=%T", backend.Signer, backend.Verifier, backend.Resolver)
	}
	if backend.Now == nil || !backend.Now().Equal(emailConfigTestTime.Add(2*time.Hour)) {
		t.Fatal("backend clock was not wired from email configuration")
	}
	identity, err := backend.Resolver.ResolveSender(context.Background(), backend.SigningFingerprint, backend.From, "")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Address != "alerts@example.test" || identity.Fingerprint != emailConfigFingerprint(entity) {
		t.Fatalf("bad static identity: %#v", identity)
	}
}

func TestNewSignedEmailBackendUsesRuntimeClockAndExplicitSMTPOptions(t *testing.T) {
	entity := newEmailConfigEntity(t, emailConfigTestTime)
	path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	config := validEmailConfig(path, emailConfigFingerprint(entity))
	config.Now = nil
	config.SMTPHelloName = "notify.example.test"
	config.SMTPTimeout = 7 * time.Second
	before := time.Now().UTC()
	backend, err := NewSignedEmailBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().UTC()
	if backend.Now == nil {
		t.Fatal("runtime clock missing")
	}
	gotNow := backend.Now()
	if gotNow.Before(before) || gotNow.After(after.Add(time.Second)) {
		t.Fatalf("runtime clock = %s, expected current time", gotNow)
	}
	smtp, ok := backend.SMTP.(webmail.NetSMTPSubmitter)
	if !ok || smtp.HelloName != config.SMTPHelloName || smtp.Timeout != config.SMTPTimeout || smtp.Auth == nil {
		t.Fatalf("bad SMTP options: %#v", backend.SMTP)
	}
}

func TestNewSignedEmailBackendRejectsIncompleteConfig(t *testing.T) {
	entity := newEmailConfigEntity(t, emailConfigTestTime)
	path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	valid := validEmailConfig(path, emailConfigFingerprint(entity))
	tests := map[string]func(*EmailConfig){
		"missing from":        func(c *EmailConfig) { c.From = "" },
		"invalid from":        func(c *EmailConfig) { c.From = "not an address" },
		"SMTPUTF8 from":       func(c *EmailConfig) { c.From = "tést@example.test" },
		"missing recipient":   func(c *EmailConfig) { c.To = "" },
		"invalid recipient":   func(c *EmailConfig) { c.To = "not an address" },
		"SMTPUTF8 recipient":  func(c *EmailConfig) { c.To = "tést@example.test" },
		"missing fingerprint": func(c *EmailConfig) { c.SigningFingerprint = "" },
		"invalid fingerprint": func(c *EmailConfig) { c.SigningFingerprint = strings.Repeat("z", 40) },
		"missing key file":    func(c *EmailConfig) { c.PrivateKeyFile = "" },
		"missing smtp":        func(c *EmailConfig) { c.SMTPAddr = "" },
		"smtp without port":   func(c *EmailConfig) { c.SMTPAddr = "mail.example.test" },
		"smtp invalid port":   func(c *EmailConfig) { c.SMTPAddr = "mail.example.test:70000" },
		"missing smtp user":   func(c *EmailConfig) { c.SMTPUsername = "" },
		"wrong smtp user":     func(c *EmailConfig) { c.SMTPUsername = "system:other@example.test" },
		"missing smtp secret": func(c *EmailConfig) { c.SMTPPassword = "" },
		"oversized smtp secret": func(c *EmailConfig) {
			c.SMTPPassword = strings.Repeat("x", maxNotificationSMTPSecretBytes+1)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := NewSignedEmailBackend(config); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestNewSignedEmailBackendRestrictsSMTPToTrustedLocalRelay(t *testing.T) {
	entity := newEmailConfigEntity(t, emailConfigTestTime)
	path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	valid := validEmailConfig(path, emailConfigFingerprint(entity))
	for _, addr := range []string{
		"postfix:25",
		"mail-relay:2525",
		"localhost:25",
		"127.0.0.1:25",
		"[::1]:25",
		"10.0.0.2:25",
		"172.16.0.2:25",
		"192.168.0.2:25",
		"[fd00::2]:25",
	} {
		t.Run("accept_"+strings.NewReplacer(":", "_", "[", "", "]", "").Replace(addr), func(t *testing.T) {
			config := valid
			config.SMTPAddr = addr
			if _, err := NewSignedEmailBackend(config); err != nil {
				t.Fatalf("trusted local relay %q rejected: %v", addr, err)
			}
		})
	}
	for _, addr := range []string{
		"8.8.8.8:25",
		"[2001:4860:4860::8888]:25",
		"169.254.1.2:25",
		"0.0.0.0:25",
		"[::]:25",
		"mail.example.test:25",
		"postfix.local:25",
		"-postfix:25",
		"postfix-:25",
		"post_fix:25",
		"123:25",
	} {
		t.Run("reject_"+strings.NewReplacer(":", "_", "[", "", "]", "", ".", "_").Replace(addr), func(t *testing.T) {
			config := valid
			config.SMTPAddr = addr
			if _, err := NewSignedEmailBackend(config); err == nil || !strings.Contains(err.Error(), "trusted local relay") {
				t.Fatalf("untrusted SMTP target %q returned %v", addr, err)
			}
		})
	}
}

func TestNewSignedEmailBackendRejectsMissingAmbiguousAndMismatchedIdentity(t *testing.T) {
	entity := newEmailConfigEntity(t, emailConfigTestTime)
	fingerprint := emailConfigFingerprint(entity)
	path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	tests := []struct {
		name   string
		config EmailConfig
		want   error
	}{
		{name: "missing fingerprint", config: validEmailConfig(path, strings.Repeat("0", len(fingerprint))), want: ErrSigningKeyMissing},
		{name: "unmapped from", config: func() EmailConfig {
			c := validEmailConfig(path, fingerprint)
			c.From = "other@example.test"
			c.SMTPUsername = "system:other@example.test"
			return c
		}(), want: ErrSigningIdentityMismatch},
		{name: "ambiguous entity", config: validEmailConfig(writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity, entity), fingerprint), want: ErrAmbiguousSigner},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewSignedEmailBackend(tt.config); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewSignedEmailBackendRejectsRevokedExpiredDisabledEncryptedAndPublicOnlyKeys(t *testing.T) {
	revoked := newEmailConfigEntity(t, emailConfigTestTime)
	if err := revoked.RevokeKey(packet.KeyRetired, "retired", &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return emailConfigTestTime.Add(time.Minute) }}); err != nil {
		t.Fatal(err)
	}

	expired, err := protonpgp.NewEntity("Alert Sender", "", "alerts@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, DefaultHash: crypto.SHA256, KeyLifetimeSecs: 1, Time: func() time.Time { return emailConfigTestTime }})
	if err != nil {
		t.Fatal(err)
	}

	disabled := newEmailConfigEntity(t, emailConfigTestTime)
	for _, identity := range disabled.Identities {
		identity.SelfSignature.FlagsValid = true
		identity.SelfSignature.FlagSign = false
	}

	encrypted := newEmailConfigEntity(t, emailConfigTestTime)
	if err := encrypted.EncryptPrivateKeys([]byte("not-loaded-at-runtime"), nil); err != nil {
		t.Fatal(err)
	}

	publicOnly := newEmailConfigEntity(t, emailConfigTestTime)
	tests := []struct {
		name      string
		entity    *protonpgp.Entity
		armorType string
		resign    bool
		want      error
	}{
		{name: "revoked", entity: revoked, armorType: protonpgp.PrivateKeyType, want: ErrSigningKeyRevoked},
		{name: "expired", entity: expired, armorType: protonpgp.PrivateKeyType, want: ErrSigningKeyExpired},
		{name: "disabled", entity: disabled, armorType: protonpgp.PrivateKeyType, resign: true, want: ErrSigningIdentityDisabled},
		{name: "encrypted", entity: encrypted, armorType: protonpgp.PrivateKeyType, want: ErrSigningKeyEncrypted},
		{name: "public only", entity: publicOnly, armorType: protonpgp.PublicKeyType, want: ErrSigningKeyMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeEmailConfigKeyFile(t, tt.armorType, tt.resign, tt.entity)
			config := validEmailConfig(path, emailConfigFingerprint(tt.entity))
			if _, err := NewSignedEmailBackend(config); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestNewSignedEmailBackendRejectsSigningKeyThatCannotEmitSHA256(t *testing.T) {
	entity, err := protonpgp.NewEntity("Alert Sender", "", "alerts@example.test", &packet.Config{
		Algorithm:   packet.PubKeyAlgoECDSA,
		Curve:       packet.CurveNistP384,
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return emailConfigTestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	_, err = NewSignedEmailBackend(validEmailConfig(path, emailConfigFingerprint(entity)))
	if !errors.Is(err, ErrSigningHashUnsupported) {
		t.Fatalf("P-384 signing configuration error = %v, want %v", err, ErrSigningHashUnsupported)
	}
}

func TestNewSignedEmailBackendRejectsUnusablePrivateKeyFiles(t *testing.T) {
	entity := newEmailConfigEntity(t, emailConfigTestTime)
	fingerprint := emailConfigFingerprint(entity)
	empty := t.TempDir() + "/empty.asc"
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	malformed := t.TempDir() + "/malformed.asc"
	if err := os.WriteFile(malformed, []byte("not an OpenPGP private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	oversized := t.TempDir() + "/oversized.asc"
	if err := os.WriteFile(oversized, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(oversized, maxNotificationPrivateKeyBytes+1); err != nil {
		t.Fatal(err)
	}
	worldReadable := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	if err := os.Chmod(worldReadable, 0o644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"empty": empty, "malformed": malformed, "directory": t.TempDir(), "oversized": oversized, "world readable": worldReadable,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSignedEmailBackend(validEmailConfig(path, fingerprint)); !errors.Is(err, ErrSigningKeyUnusable) {
				t.Fatalf("error = %v, want %v", err, ErrSigningKeyUnusable)
			}
		})
	}
	missing := t.TempDir() + "/password=secret.asc"
	if _, err := NewSignedEmailBackend(validEmailConfig(missing, fingerprint)); !errors.Is(err, ErrSigningKeyMissing) || strings.Contains(err.Error(), "password=") || strings.Contains(err.Error(), missing) {
		t.Fatalf("missing key error = %v, want sanitized %v", err, ErrSigningKeyMissing)
	}
}

func TestRuntimeEmailMaterialRejectsWrongOrCancelledBinding(t *testing.T) {
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: strings.Repeat("A", 40)}
	resolver := runtimeEmailMaterial{from: identity.Address, fingerprint: identity.Fingerprint, clock: time.Now}
	for _, request := range []struct{ fingerprint, from, sender string }{
		{strings.Repeat("B", 40), identity.Address, ""},
		{identity.Fingerprint, "other@example.test", ""},
		{identity.Fingerprint, identity.Address, "sender@example.test"},
	} {
		_, err := resolver.ResolveSender(context.Background(), request.fingerprint, request.from, request.sender)
		var resolution *IdentityResolutionError
		if !errors.Is(err, ErrSigningIdentityMismatch) || !errors.As(err, &resolution) || resolution.Code != ReasonSigningIdentityMismatch {
			t.Fatalf("binding %#v returned %v", request, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.ResolveSender(ctx, identity.Fingerprint, identity.Address, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolver error = %v", err)
	}
}

type emailConfigCaptureSMTP struct {
	bodies [][]byte
}

func (c *emailConfigCaptureSMTP) Submit(_ context.Context, _ webmail.Envelope, body []byte) error {
	c.bodies = append(c.bodies, append([]byte(nil), body...))
	return nil
}

func TestSignedEmailBackendRevalidatesReplacedKeyMaterialPerAlert(t *testing.T) {
	now := emailConfigTestTime.Add(2 * time.Hour)
	entity := newEmailConfigEntity(t, emailConfigTestTime)
	path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
	config := validEmailConfig(path, emailConfigFingerprint(entity))
	config.Now = func() time.Time { return now }
	backend, err := NewSignedEmailBackend(config)
	if err != nil {
		t.Fatal(err)
	}
	smtp := &emailConfigCaptureSMTP{}
	backend.SMTP = smtp
	if _, err := backend.SendAlert(context.Background(), runtimeEmailAlert("before-replacement")); err != nil {
		t.Fatal(err)
	}
	replaceEmailConfigKeyFile(t, path, protonpgp.PrivateKeyType, false, entity)
	if _, err := backend.SendAlert(context.Background(), runtimeEmailAlert("same-key-replacement")); err != nil {
		t.Fatal(err)
	}
	if len(smtp.bodies) != 2 {
		t.Fatalf("same-key replacement submissions = %d, want 2", len(smtp.bodies))
	}
	rotated := newEmailConfigEntity(t, emailConfigTestTime.Add(time.Minute))
	replaceEmailConfigKeyFile(t, path, protonpgp.PrivateKeyType, false, rotated)
	result, err := backend.SendAlert(context.Background(), runtimeEmailAlert("unconfigured-rotation"))
	assertRuntimeEmailFailure(t, result, err, ReasonSigningKeyMissing, smtp, 2)
}

func TestSignedEmailBackendRevalidatesLifecycleTransitionsPerAlert(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(*testing.T) (*protonpgp.Entity, time.Time)
		transition func(*testing.T, string, *protonpgp.Entity, *time.Time)
		want       string
	}{
		{
			name: "revoked",
			prepare: func(t *testing.T) (*protonpgp.Entity, time.Time) {
				entity := newEmailConfigEntity(t, emailConfigTestTime)
				if err := entity.RevokeKey(packet.KeyRetired, "retired", &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return emailConfigTestTime.Add(time.Hour) }}); err != nil {
					t.Fatal(err)
				}
				return entity, emailConfigTestTime.Add(30 * time.Minute)
			},
			transition: func(_ *testing.T, _ string, _ *protonpgp.Entity, now *time.Time) {
				*now = emailConfigTestTime.Add(2 * time.Hour)
			},
			want: ReasonSigningKeyRevoked,
		},
		{
			name: "expired",
			prepare: func(t *testing.T) (*protonpgp.Entity, time.Time) {
				entity, err := protonpgp.NewEntity("Alert Sender", "", "alerts@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, DefaultHash: crypto.SHA256, KeyLifetimeSecs: 3600, Time: func() time.Time { return emailConfigTestTime }})
				if err != nil {
					t.Fatal(err)
				}
				return entity, emailConfigTestTime.Add(30 * time.Minute)
			},
			transition: func(_ *testing.T, _ string, _ *protonpgp.Entity, now *time.Time) {
				*now = emailConfigTestTime.Add(2 * time.Hour)
			},
			want: ReasonSigningKeyExpired,
		},
		{
			name: "disabled",
			prepare: func(t *testing.T) (*protonpgp.Entity, time.Time) {
				return newEmailConfigEntity(t, emailConfigTestTime), emailConfigTestTime.Add(30 * time.Minute)
			},
			transition: func(t *testing.T, path string, entity *protonpgp.Entity, _ *time.Time) {
				for _, identity := range entity.Identities {
					identity.SelfSignature.FlagsValid = true
					identity.SelfSignature.FlagSign = false
				}
				replaceEmailConfigKeyFile(t, path, protonpgp.PrivateKeyType, true, entity)
			},
			want: ReasonSigningIdentityDisabled,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entity, now := tt.prepare(t)
			path := writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity)
			config := validEmailConfig(path, emailConfigFingerprint(entity))
			config.Now = func() time.Time { return now }
			backend, err := NewSignedEmailBackend(config)
			if err != nil {
				t.Fatal(err)
			}
			smtp := &emailConfigCaptureSMTP{}
			backend.SMTP = smtp
			if _, err := backend.SendAlert(context.Background(), runtimeEmailAlert("before-"+tt.name)); err != nil {
				t.Fatal(err)
			}
			tt.transition(t, path, entity, &now)
			result, err := backend.SendAlert(context.Background(), runtimeEmailAlert("after-"+tt.name))
			assertRuntimeEmailFailure(t, result, err, tt.want, smtp, 1)
		})
	}
}

func TestRuntimeIdentityResolutionErrorsDoNotExposeRawKeyFailures(t *testing.T) {
	tests := []struct {
		failure error
		code    string
	}{
		{ErrSigningKeyMissing, ReasonSigningKeyMissing},
		{ErrAmbiguousSigner, ReasonSigningIdentityAmbig},
		{ErrSigningIdentityMismatch, ReasonSigningIdentityMismatch},
		{ErrSigningKeyRevoked, ReasonSigningKeyRevoked},
		{ErrSigningKeyExpired, ReasonSigningKeyExpired},
		{ErrSigningIdentityDisabled, ReasonSigningIdentityDisabled},
		{ErrSigningKeyEncrypted, ReasonSigningKeyMissing},
		{ErrSigningKeyUnusable, ReasonSigningKeyMissing},
		{ErrSigningHashUnsupported, ReasonSigningHashUnsupported},
	}
	for _, tt := range tests {
		raw := fmt.Errorf("private path and password=secret: %w", tt.failure)
		err := runtimeIdentityResolutionError(raw)
		var resolution *IdentityResolutionError
		if !errors.As(err, &resolution) || resolution.Code != tt.code || err.Error() != tt.code || strings.Contains(err.Error(), "secret") {
			t.Fatalf("raw lifecycle error escaped for %v: %v", tt.failure, err)
		}
	}
}

func TestRuntimeEmailMaterialHidesReloadFailuresAndHonorsCancellation(t *testing.T) {
	material := &runtimeEmailMaterial{path: t.TempDir() + "/password=secret.asc", fingerprint: strings.Repeat("A", 40), from: "alerts@example.test", clock: time.Now}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := material.load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled load error = %v", err)
	}
	identity := webmail.Identity{Address: material.from, Fingerprint: material.fingerprint}
	if _, _, err := material.SignMIME(context.Background(), identity, []byte("message")); err == nil || err.Error() != ReasonOpenPGPSignFailed || strings.Contains(err.Error(), "secret") {
		t.Fatalf("sign reload error escaped: %v", err)
	}
	if _, err := material.VerifyExactSender(context.Background(), []byte("message"), identity); err == nil || err.Error() != ReasonOpenPGPVerifyFailed || strings.Contains(err.Error(), "secret") {
		t.Fatalf("verify reload error escaped: %v", err)
	}
}

func TestRuntimeEmailMaterialPreservesUnsupportedSigningHashClassification(t *testing.T) {
	entity, err := protonpgp.NewEntity("Alert Sender", "", "alerts@example.test", &packet.Config{
		Algorithm:   packet.PubKeyAlgoECDSA,
		Curve:       packet.CurveNistP384,
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return emailConfigTestTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	material := &runtimeEmailMaterial{
		path:        writeEmailConfigKeyFile(t, protonpgp.PrivateKeyType, false, entity),
		fingerprint: emailConfigFingerprint(entity),
		from:        "alerts@example.test",
		clock:       func() time.Time { return emailConfigTestTime.Add(2 * time.Hour) },
	}
	identity := webmail.Identity{Address: material.from, Fingerprint: material.fingerprint}
	if _, _, err := material.SignMIME(context.Background(), identity, []byte("not reached")); !errors.Is(err, ErrSigningHashUnsupported) {
		t.Fatalf("runtime signer reload error = %v, want %v", err, ErrSigningHashUnsupported)
	}
}

func runtimeEmailAlert(id string) notification.Alert {
	return notification.Alert{ID: id, Class: "backup.failure", Severity: notification.SeverityCritical, Title: "Backup failed", Summary: "verification failed", CorrelationID: "corr-" + id}
}

func assertRuntimeEmailFailure(t *testing.T, result notification.DeliveryResult, err error, reason string, smtp *emailConfigCaptureSMTP, calls int) {
	t.Helper()
	if err == nil || err.Error() != reason || result.Status != notification.StatusFailedPermanent || result.Reason != reason || len(smtp.bodies) != calls {
		t.Fatalf("failure result=%#v err=%v SMTP calls=%d, want reason=%s calls=%d", result, err, len(smtp.bodies), reason, calls)
	}
}

func validEmailConfig(path, fingerprint string) EmailConfig {
	return EmailConfig{
		From:               "Alert Sender <alerts@example.test>",
		To:                 "Ops <ops@example.test>",
		SigningFingerprint: strings.ToLower(fingerprint),
		PrivateKeyFile:     path,
		SMTPAddr:           "127.0.0.1:2525",
		SMTPUsername:       "system:alerts@example.test",
		SMTPPassword:       "smtp-secret",
		Policy:             notificationPolicyFunc(allowNotificationPolicy),
		Now:                func() time.Time { return emailConfigTestTime.Add(2 * time.Hour) },
	}
}

func newEmailConfigEntity(t *testing.T, created time.Time) *protonpgp.Entity {
	t.Helper()
	entity, err := protonpgp.NewEntity("Alert Sender", "", "alerts@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, DefaultHash: crypto.SHA256, Time: func() time.Time { return created }})
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

func emailConfigFingerprint(entity *protonpgp.Entity) string {
	return strings.ToUpper(fmt.Sprintf("%X", entity.PrimaryKey.Fingerprint))
}

func writeEmailConfigKeyFile(t *testing.T, armorType string, resign bool, entities ...*protonpgp.Entity) string {
	t.Helper()
	path := t.TempDir() + "/signing-key.asc"
	writeEmailConfigKeyAt(t, path, armorType, resign, entities...)
	return path
}

func replaceEmailConfigKeyFile(t *testing.T, path, armorType string, resign bool, entities ...*protonpgp.Entity) {
	t.Helper()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".signing-key-replacement-*")
	if err != nil {
		t.Fatal(err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		t.Fatal(err)
	}
	writeEmailConfigKeyAt(t, tmpPath, armorType, resign, entities...)
	if err := os.Rename(tmpPath, path); err != nil {
		t.Fatal(err)
	}
}

func writeEmailConfigKeyAt(t *testing.T, path, armorType string, resign bool, entities ...*protonpgp.Entity) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	block, err := armor.Encode(f, armorType, nil)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	for _, entity := range entities {
		if armorType == protonpgp.PublicKeyType {
			err = entity.Serialize(block)
		} else if resign {
			err = entity.SerializePrivate(block, &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return emailConfigTestTime }})
		} else {
			err = entity.SerializePrivateWithoutSigning(block, nil)
		}
		if err != nil {
			_ = block.Close()
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := block.Close(); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
