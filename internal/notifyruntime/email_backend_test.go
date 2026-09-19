package notifyruntime

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"testing"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
	"forgejo/gotthboard/gotth-mail/internal/store"
	"forgejo/gotthboard/gotth-mail/internal/testpg"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type captureSMTP struct {
	envelopes []webmail.Envelope
	bodies    [][]byte
	err       error
}

func (c *captureSMTP) Submit(ctx context.Context, e webmail.Envelope, b []byte) error {
	c.envelopes = append(c.envelopes, e)
	c.bodies = append(c.bodies, append([]byte(nil), b...))
	return c.err
}

type resolverFunc func(context.Context, string, string, string) (webmail.Identity, error)

func (f resolverFunc) ResolveSender(ctx context.Context, fp, from, sender string) (webmail.Identity, error) {
	return f(ctx, fp, from, sender)
}

type signerFunc func(context.Context, webmail.Identity, []byte) ([]byte, webmail.SignatureStatus, error)

func (f signerFunc) SignMIME(ctx context.Context, identity webmail.Identity, msg []byte) ([]byte, webmail.SignatureStatus, error) {
	return f(ctx, identity, msg)
}

type verifierFunc func(context.Context, []byte, webmail.Identity) (webmail.SignatureStatus, error)

type notificationPolicyFunc func(context.Context, string, outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error)

func (f notificationPolicyFunc) Decide(ctx context.Context, correlationID string, request outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
	return f(ctx, correlationID, request)
}

func allowNotificationPolicy(context.Context, string, outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
	return outboundpolicy.Decision{Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted}, nil
}

func (f verifierFunc) VerifyExactSender(ctx context.Context, msg []byte, identity webmail.Identity) (webmail.SignatureStatus, error) {
	return f(ctx, msg, identity)
}

func TestSignedEmailBackendSendsOnlyOpenPGPMIMESignedAlert(t *testing.T) {
	entity := notifyTestOpenPGPEntity(t, "Notifier", "alerts@example.test")
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: notifyEntityFingerprint(entity)}
	smtp := &captureSMTP{}
	backend := signedEmailTestBackend(entity, identity, smtp)
	alert := notification.Alert{
		ID: "alert-1", Class: "backup.failure", Severity: notification.SeverityCritical,
		Title: "Backup failed", Summary: "password=hunter2 failed",
		Resource:      notification.ResourceRef{Type: "backup", ID: "artifact-1"},
		CorrelationID: "corr-1", Details: map[string]string{"zeta": "last", "alpha": "first"},
	}
	result, err := backend.SendAlert(context.Background(), alert)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != ReasonSignedEmailDelivered {
		t.Fatalf("unexpected delivery reason %q", result.Reason)
	}
	evidence := result.Evidence
	if evidence.Transport != "email" || evidence.From != identity.Address || evidence.SigningFingerprint != identity.Fingerprint || evidence.SenderIdentityID != "system:"+identity.Address || evidence.SenderIdentityClass != "system" || evidence.PolicyVersion != SignedEmailPolicyVersion || evidence.IdentityStateRef != "openpgp:"+identity.Fingerprint || evidence.VerificationResult != VerificationValidExactSender || evidence.Workflow != SignedEmailWorkflow || evidence.MessageID == "" || evidence.GeneratedAt.IsZero() {
		t.Fatalf("incomplete structured delivery evidence: %#v", evidence)
	}
	if result.Status != notification.StatusDelivered || len(smtp.bodies) != 1 {
		t.Fatalf("bad delivery result=%#v smtp calls=%d", result, len(smtp.bodies))
	}
	if smtp.envelopes[0].From != identity.Address || len(smtp.envelopes[0].To) != 1 || smtp.envelopes[0].To[0] != "ops@example.test" {
		t.Fatalf("bad envelope: %#v", smtp.envelopes[0])
	}
	if !strings.Contains(string(smtp.bodies[0]), "multipart/signed") || strings.Contains(string(smtp.bodies[0]), "hunter2") || !strings.Contains(string(smtp.bodies[0]), "[REDACTED]") {
		t.Fatalf("bad signed body: %s", smtp.bodies[0])
	}
	if bytes.Index(smtp.bodies[0], []byte("alpha: first")) > bytes.Index(smtp.bodies[0], []byte("zeta: last")) {
		t.Fatal("notification details were not serialized deterministically")
	}
	verified, err := (webmail.OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedNotifyPGPTime}).VerifyExactSender(context.Background(), smtp.bodies[0], identity)
	if err != nil || !verified.Signed || verified.Fingerprint != identity.Fingerprint {
		t.Fatalf("submitted MIME was not exact-sender verified: status=%#v err=%v", verified, err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(smtp.bodies[0]))
	if err != nil {
		t.Fatal(err)
	}
	if got := message.Header.Get("Message-ID"); got == "" || result.Evidence.MessageID != got {
		t.Fatalf("message id not present in delivery evidence: header=%q evidence=%#v", got, result.Evidence)
	}
}

func TestSignedEmailBackendTreatsUnsupportedSigningHashAsPermanentWithoutSMTP(t *testing.T) {
	entity, err := protonpgp.NewEntity("P-384 Notifier", "", "alerts@example.test", &packet.Config{
		Algorithm:   packet.PubKeyAlgoECDSA,
		Curve:       packet.CurveNistP384,
		DefaultHash: crypto.SHA256,
		Time:        fixedNotifyPGPTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: notifyEntityFingerprint(entity)}
	smtp := &captureSMTP{}
	backend := signedEmailTestBackend(entity, identity, smtp)
	result, err := backend.SendAlert(context.Background(), notification.Alert{
		ID: "unsupported-signing-hash", Class: "backup.failure", Title: "Backup failed", Summary: "failed",
	})
	assertFailedWithoutSMTP(t, result, err, ReasonSigningHashUnsupported, smtp)
	if result.Evidence.VerificationResult != "unsupported_signing_hash" {
		t.Fatalf("unsupported hash evidence = %#v", result.Evidence)
	}
}

func TestSignedEmailBackendSuppressesPolicyBlockedAutomaticMail(t *testing.T) {
	entity := notifyTestOpenPGPEntity(t, "Notifier", "alerts@example.test")
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: notifyEntityFingerprint(entity)}
	smtp := &captureSMTP{}
	backend := signedEmailTestBackend(entity, identity, smtp)
	backend.Policy = notificationPolicyFunc(func(_ context.Context, _ string, request outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
		if request.SystemSenderID != "system:alerts@example.test" || request.EnvelopeSender != identity.Address || request.Recipient != "ops@example.test" {
			t.Fatalf("policy request=%+v", request)
		}
		return outboundpolicy.Decision{Action: outboundpolicy.ActionReject, Reason: outboundpolicy.ReasonRecipientForbidden}, nil
	})
	result, err := backend.SendAlert(context.Background(), notification.Alert{ID: "policy-block", Class: "backup.failure", Title: "Backup failed", Summary: "failed"})
	assertFailedWithoutSMTP(t, result, err, ReasonOutboundPolicyBlocked, smtp)
	if result.Evidence.VerificationResult != "policy_blocked" {
		t.Fatalf("evidence=%+v", result.Evidence)
	}
}

func TestSignedEmailBackendDefersWhenPolicyIsUnavailable(t *testing.T) {
	entity := notifyTestOpenPGPEntity(t, "Notifier", "alerts@example.test")
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: notifyEntityFingerprint(entity)}
	smtp := &captureSMTP{}
	backend := signedEmailTestBackend(entity, identity, smtp)
	backend.Policy = notificationPolicyFunc(func(context.Context, string, outboundpolicy.EnforcementRequest) (outboundpolicy.Decision, error) {
		return outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonUnavailable}, errors.New("policy database unavailable")
	})
	result, err := backend.SendAlert(context.Background(), notification.Alert{ID: "policy-down", Class: "backup.failure", Title: "Backup failed", Summary: "failed"})
	if err == nil || result.Status != notification.StatusFailedRetryable || result.Reason != ReasonOutboundPolicyDown || len(smtp.bodies) != 0 {
		t.Fatalf("result=%+v err=%v smtp=%d", result, err, len(smtp.bodies))
	}
}

func TestSignedEmailDeliveryEvidencePersistsThroughSQLRecorder(t *testing.T) {
	db := testpg.DB(t, store.MigrateSQL)
	entity := notifyTestOpenPGPEntity(t, "Notifier", "alerts@example.test")
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: notifyEntityFingerprint(entity)}
	backend := signedEmailTestBackend(entity, identity, &captureSMTP{})
	service := notification.Service{Backend: backend, Recorder: notification.SQLRecorder{DB: db}, Now: fixedNotifyPGPTime}
	record, err := service.SendAlert(context.Background(), notification.Alert{ID: "audit-alert", Class: "backup.failure", Severity: notification.SeverityCritical, Title: "Backup failed", Summary: "failed"})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, ok, err := (notification.SQLRecorder{DB: db}).Get(context.Background(), "audit-alert")
	if err != nil || !ok {
		t.Fatalf("reload ok=%v err=%v", ok, err)
	}
	for name, got := range map[string]notification.DeliveryEvidence{"service": record.Evidence, "sql": reloaded.Evidence} {
		if got.VerificationResult != VerificationValidExactSender || got.SigningFingerprint != identity.Fingerprint || got.From != identity.Address || got.SenderIdentityID != "system:"+identity.Address || got.SenderIdentityClass != "system" || got.MessageID == "" || got.PolicyVersion != SignedEmailPolicyVersion || got.IdentityStateRef == "" || got.Workflow != SignedEmailWorkflow || got.GeneratedAt.IsZero() {
			t.Fatalf("%s evidence incomplete after persistence: %#v", name, got)
		}
	}
}

func TestSignedEmailBackendFailsClosedWithoutSignerOrMatchingIdentity(t *testing.T) {
	entity := notifyTestOpenPGPEntity(t, "Notifier", "alerts@example.test")
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: notifyEntityFingerprint(entity)}
	validAlert := notification.Alert{ID: "alert-1", Class: "backup.failure", Title: "Backup failed", Summary: "failed"}

	t.Run("invalid payload", func(t *testing.T) {
		smtp := &captureSMTP{}
		backend := signedEmailTestBackend(entity, identity, smtp)
		result, err := backend.SendAlert(context.Background(), notification.Alert{})
		assertFailedWithoutSMTP(t, result, err, ReasonPayloadInvalid, smtp)
	})

	t.Run("configuration", func(t *testing.T) {
		base := signedEmailTestBackend(entity, identity, &captureSMTP{})
		cases := []struct {
			name   string
			mutate func(*SignedEmailBackend)
		}{
			{"missing smtp", func(b *SignedEmailBackend) { b.SMTP = nil }},
			{"missing signer", func(b *SignedEmailBackend) { b.Signer = nil }},
			{"missing verifier", func(b *SignedEmailBackend) { b.Verifier = nil }},
			{"missing resolver", func(b *SignedEmailBackend) { b.Resolver = nil }},
			{"invalid from", func(b *SignedEmailBackend) { b.From = "bad from" }},
			{"SMTPUTF8 from", func(b *SignedEmailBackend) { b.From = "tést@example.test" }},
			{"multiple from", func(b *SignedEmailBackend) { b.From = "a@example.test, b@example.test" }},
			{"invalid to", func(b *SignedEmailBackend) { b.To = "bad to" }},
			{"SMTPUTF8 to", func(b *SignedEmailBackend) { b.To = "tést@example.test" }},
			{"invalid fingerprint", func(b *SignedEmailBackend) { b.SigningFingerprint = "XYZ" }},
			{"non hex fingerprint", func(b *SignedEmailBackend) { b.SigningFingerprint = strings.Repeat("Z", 40) }},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				backend := base
				tc.mutate(&backend)
				result, err := backend.SendAlert(context.Background(), validAlert)
				assertFailedWithoutSMTP(t, result, err, ReasonConfigInvalid, backend.SMTP)
			})
		}
	})

	t.Run("identity lifecycle and ambiguity", func(t *testing.T) {
		for _, code := range []string{
			ReasonSigningKeyMissing, ReasonSigningKeyRevoked, ReasonSigningKeyExpired,
			ReasonSigningIdentityDisabled, ReasonSigningIdentityAmbig, ReasonSigningIdentityUnmapped, ReasonSigningIdentityMismatch,
			ReasonSigningHashUnsupported,
		} {
			t.Run(code, func(t *testing.T) {
				smtp := &captureSMTP{}
				backend := signedEmailTestBackend(entity, identity, smtp)
				backend.Resolver = resolverFunc(func(context.Context, string, string, string) (webmail.Identity, error) {
					return webmail.Identity{}, &IdentityResolutionError{Code: code}
				})
				result, err := backend.SendAlert(context.Background(), validAlert)
				assertFailedWithoutSMTP(t, result, err, code, smtp)
			})
		}
	})

	t.Run("resolver outage is retryable and sanitized", func(t *testing.T) {
		smtp := &captureSMTP{}
		backend := signedEmailTestBackend(entity, identity, smtp)
		backend.Resolver = resolverFunc(func(context.Context, string, string, string) (webmail.Identity, error) {
			return webmail.Identity{}, errors.New("database password=resolver-secret")
		})
		result, err := backend.SendAlert(context.Background(), validAlert)
		if err == nil || result.Status != notification.StatusFailedRetryable || result.Reason != ReasonSigningIdentityDown || strings.Contains(err.Error(), "resolver-secret") || len(smtp.bodies) != 0 {
			t.Fatalf("bad resolver outage result=%#v err=%v calls=%d", result, err, len(smtp.bodies))
		}
	})

	t.Run("identity mismatch", func(t *testing.T) {
		smtp := &captureSMTP{}
		backend := signedEmailTestBackend(entity, identity, smtp)
		backend.Resolver = resolverFunc(func(context.Context, string, string, string) (webmail.Identity, error) {
			return webmail.Identity{Address: "other@example.test", Fingerprint: identity.Fingerprint}, nil
		})
		result, err := backend.SendAlert(context.Background(), validAlert)
		assertFailedWithoutSMTP(t, result, err, ReasonSigningIdentityMismatch, smtp)
	})

	t.Run("signer failures", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			signer webmail.OpenPGPSigner
			status notification.DeliveryStatus
		}{
			{"error", signerFunc(func(context.Context, webmail.Identity, []byte) ([]byte, webmail.SignatureStatus, error) {
				return nil, webmail.SignatureStatus{}, errors.New("hsm secret")
			}), notification.StatusFailedRetryable},
			{"lying status", signerFunc(func(context.Context, webmail.Identity, []byte) ([]byte, webmail.SignatureStatus, error) {
				return []byte("x"), webmail.SignatureStatus{Signed: true, Identity: "other@example.test", Fingerprint: identity.Fingerprint}, nil
			}), notification.StatusFailedPermanent},
		} {
			t.Run(tc.name, func(t *testing.T) {
				smtp := &captureSMTP{}
				backend := signedEmailTestBackend(entity, identity, smtp)
				backend.Signer = tc.signer
				result, err := backend.SendAlert(context.Background(), validAlert)
				if err == nil || result.Status != tc.status || result.Reason != ReasonOpenPGPSignFailed || strings.Contains(err.Error(), "hsm secret") || len(smtp.bodies) != 0 {
					t.Fatalf("bad signer failure result=%#v err=%v calls=%d", result, err, len(smtp.bodies))
				}
			})
		}
	})

	t.Run("cryptographic verifier gates SMTP", func(t *testing.T) {
		smtp := &captureSMTP{}
		backend := signedEmailTestBackend(entity, identity, smtp)
		realSigner := backend.Signer
		backend.Signer = signerFunc(func(ctx context.Context, id webmail.Identity, msg []byte) ([]byte, webmail.SignatureStatus, error) {
			signed, status, err := realSigner.SignMIME(ctx, id, msg)
			if err == nil {
				signed = bytes.Replace(signed, []byte("Backup failed"), []byte("Backup forged"), 1)
			}
			return signed, status, err
		})
		result, err := backend.SendAlert(context.Background(), validAlert)
		assertFailedWithoutSMTP(t, result, err, ReasonOpenPGPVerifyFailed, smtp)
	})

	t.Run("verifier status mismatch", func(t *testing.T) {
		smtp := &captureSMTP{}
		backend := signedEmailTestBackend(entity, identity, smtp)
		backend.Verifier = verifierFunc(func(context.Context, []byte, webmail.Identity) (webmail.SignatureStatus, error) {
			return webmail.SignatureStatus{Signed: true, Identity: identity.Address, Fingerprint: strings.Repeat("0", len(identity.Fingerprint))}, nil
		})
		result, err := backend.SendAlert(context.Background(), validAlert)
		assertFailedWithoutSMTP(t, result, err, ReasonOpenPGPVerifyFailed, smtp)
	})

	t.Run("smtp classification", func(t *testing.T) {
		cases := []struct {
			class  webmail.SMTPFailureClass
			status notification.DeliveryStatus
			reason string
		}{
			{webmail.SMTPFailurePermanent, notification.StatusFailedPermanent, ReasonSMTPRejected},
			{webmail.SMTPFailureRetryable, notification.StatusFailedRetryable, ReasonSMTPUnavailable},
			{webmail.SMTPFailureAmbiguous, notification.StatusFailedPermanent, ReasonSMTPAmbiguous},
		}
		for _, tc := range cases {
			t.Run(string(tc.class), func(t *testing.T) {
				smtp := &captureSMTP{err: &webmail.SMTPDeliveryError{Class: tc.class, Phase: "test", Err: errors.New("smtp password=secret")}}
				backend := signedEmailTestBackend(entity, identity, smtp)
				result, err := backend.SendAlert(context.Background(), validAlert)
				if err == nil || result.Status != tc.status || result.Reason != tc.reason || strings.Contains(err.Error(), "secret") || len(smtp.bodies) != 1 {
					t.Fatalf("bad smtp result=%#v err=%v calls=%d", result, err, len(smtp.bodies))
				}
			})
		}
	})

	t.Run("untyped smtp failure", func(t *testing.T) {
		smtp := &captureSMTP{err: errors.New("smtp token=secret")}
		backend := signedEmailTestBackend(entity, identity, smtp)
		result, err := backend.SendAlert(context.Background(), validAlert)
		if err == nil || result.Status != notification.StatusFailedRetryable || result.Reason != ReasonSMTPUnavailable || strings.Contains(err.Error(), "secret") || len(smtp.bodies) != 1 {
			t.Fatalf("bad untyped SMTP result=%#v err=%v calls=%d", result, err, len(smtp.bodies))
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		smtp := &captureSMTP{}
		backend := signedEmailTestBackend(entity, identity, smtp)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := backend.SendAlert(ctx, validAlert)
		if err == nil || result.Status != notification.StatusFailedRetryable || result.Reason != ReasonCancelled || len(smtp.bodies) != 0 {
			t.Fatalf("bad cancellation result=%#v err=%v calls=%d", result, err, len(smtp.bodies))
		}
	})

	t.Run("cancellation during dependencies", func(t *testing.T) {
		for _, stage := range []string{"resolver", "signer", "verifier"} {
			t.Run(stage, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				smtp := &captureSMTP{}
				backend := signedEmailTestBackend(entity, identity, smtp)
				switch stage {
				case "resolver":
					backend.Resolver = resolverFunc(func(context.Context, string, string, string) (webmail.Identity, error) {
						cancel()
						return webmail.Identity{}, context.Canceled
					})
				case "signer":
					backend.Signer = signerFunc(func(context.Context, webmail.Identity, []byte) ([]byte, webmail.SignatureStatus, error) {
						cancel()
						return nil, webmail.SignatureStatus{}, context.Canceled
					})
				case "verifier":
					backend.Verifier = verifierFunc(func(context.Context, []byte, webmail.Identity) (webmail.SignatureStatus, error) {
						cancel()
						return webmail.SignatureStatus{}, context.Canceled
					})
				}
				result, err := backend.SendAlert(ctx, validAlert)
				if err == nil || result.Status != notification.StatusFailedRetryable || result.Reason != ReasonCancelled || len(smtp.bodies) != 0 {
					t.Fatalf("bad %s cancellation result=%#v err=%v calls=%d", stage, result, err, len(smtp.bodies))
				}
			})
		}
	})
}

func TestSignedEmailBackendUsesStableMessageIDAcrossRetries(t *testing.T) {
	entity := notifyTestOpenPGPEntity(t, "Notifier", "alerts@example.test")
	identity := webmail.Identity{Address: "alerts@example.test", Fingerprint: notifyEntityFingerprint(entity)}
	smtp := &captureSMTP{}
	backend := signedEmailTestBackend(entity, identity, smtp)
	backend.Now = nil
	alert := notification.Alert{ID: "stable-alert", Class: "backup.failure", Title: "Backup failed", Summary: "failed", Details: map[string]string{"b": "2", "a": "1"}}
	if _, err := backend.SendAlert(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	backend.Now = func() time.Time { return time.Unix(1700001000, 0) }
	if _, err := backend.SendAlert(context.Background(), alert); err != nil {
		t.Fatal(err)
	}
	if len(smtp.bodies) != 2 {
		t.Fatalf("expected two submissions, got %d", len(smtp.bodies))
	}
	var ids []string
	for _, body := range smtp.bodies {
		msg, err := mail.ReadMessage(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, msg.Header.Get("Message-ID"))
	}
	if ids[0] == "" || ids[0] != ids[1] {
		t.Fatalf("message id changed across retries: %#v", ids)
	}
}

func TestSignedEmailBackendIdentityErrorAndHelperTaxonomy(t *testing.T) {
	root := errors.New("resolver failed")
	err := &IdentityResolutionError{Code: ReasonSigningKeyMissing, Err: root}
	if err.Error() != ReasonSigningKeyMissing || !errors.Is(err, root) {
		t.Fatalf("bad identity error: %v", err)
	}
	var nilErr *IdentityResolutionError
	if nilErr.Error() != ReasonSigningIdentityDown || nilErr.Unwrap() != nil {
		t.Fatalf("bad nil identity error behavior: %v", nilErr)
	}
	if permanentIdentityFailure("unknown") {
		t.Fatal("unknown identity failure was classified permanent")
	}
	if got := notificationMessageID("alert", "localhost", "ops@example.test"); !strings.HasSuffix(got, "@localhost>") {
		t.Fatalf("bad fallback message id %q", got)
	}
}

func signedEmailTestBackend(entity *protonpgp.Entity, identity webmail.Identity, smtp webmail.SMTPSubmitter) SignedEmailBackend {
	return SignedEmailBackend{
		From: identity.Address, To: "ops@example.test", SigningFingerprint: identity.Fingerprint,
		SMTP:     smtp,
		Signer:   webmail.OpenPGPMIMESigner{Entity: entity, Now: fixedNotifyPGPTime},
		Verifier: webmail.OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedNotifyPGPTime},
		Resolver: resolverFunc(func(context.Context, string, string, string) (webmail.Identity, error) {
			return identity, nil
		}),
		Policy: notificationPolicyFunc(allowNotificationPolicy),
		Now:    fixedNotifyPGPTime,
	}
}

func assertFailedWithoutSMTP(t *testing.T, result notification.DeliveryResult, err error, reason string, submitter webmail.SMTPSubmitter) {
	t.Helper()
	if err == nil || result.Status != notification.StatusFailedPermanent || result.Reason != reason {
		t.Fatalf("expected permanent %s failure, result=%#v err=%v", reason, result, err)
	}
	if smtp, ok := submitter.(*captureSMTP); ok && len(smtp.bodies) != 0 {
		t.Fatalf("SMTP called %d times after %s", len(smtp.bodies), reason)
	}
}

func notifyTestOpenPGPEntity(t *testing.T, name, email string) *protonpgp.Entity {
	t.Helper()
	entity, err := protonpgp.NewEntity(name, "", email, &packet.Config{DefaultHash: crypto.SHA256, Time: fixedNotifyPGPTime, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

func notifyEntityFingerprint(e *protonpgp.Entity) string {
	return strings.ToUpper(fmt.Sprintf("%X", e.PrimaryKey.Fingerprint))
}

func fixedNotifyPGPTime() time.Time { return time.Unix(1700000000, 0).UTC() }
