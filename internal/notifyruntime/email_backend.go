package notifyruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"sort"
	"strings"
	"time"

	"forgejo/gotthboard/gotth-mail/internal/notification"
	"forgejo/gotthboard/gotth-mail/internal/webmail"
)

const (
	ReasonSigningKeyMissing       = "signing_key_missing"
	ReasonSigningKeyRevoked       = "signing_key_revoked"
	ReasonSigningKeyExpired       = "signing_key_expired"
	ReasonSigningIdentityDisabled = "signing_identity_disabled"
	ReasonSigningIdentityAmbig    = "signing_identity_ambiguous"
	ReasonSigningIdentityUnmapped = "signing_identity_unmapped"
	ReasonSigningIdentityMismatch = "signing_identity_mismatch"
	ReasonSigningIdentityDown     = "signing_identity_unavailable"
	ReasonSigningHashUnsupported  = "signing_hash_unsupported"
	ReasonOpenPGPSignFailed       = "openpgp_sign_failed"
	ReasonOpenPGPVerifyFailed     = "openpgp_verification_failed"
	ReasonSMTPRejected            = "smtp_rejected"
	ReasonSMTPUnavailable         = "smtp_unavailable"
	ReasonSMTPAmbiguous           = "smtp_delivery_ambiguous"
	ReasonConfigInvalid           = "notification_email_config_invalid"
	ReasonPayloadInvalid          = "notification_payload_invalid"
	ReasonCancelled               = "notification_cancelled"
	ReasonSignedEmailDelivered    = "signed_email_delivered"
	VerificationValidExactSender  = "valid_exact_sender"
	SignedEmailPolicyVersion      = "gotth-mail-exact-sender-v1"
	SignedEmailWorkflow           = "notification"
)

type IdentityResolutionError struct {
	Code string
	Err  error
}

func (e *IdentityResolutionError) Error() string {
	if e == nil || e.Code == "" {
		return ReasonSigningIdentityDown
	}
	return e.Code
}

func (e *IdentityResolutionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type SignedEmailBackend struct {
	From, To           string
	SigningFingerprint string
	SMTP               webmail.SMTPSubmitter
	Signer             webmail.OpenPGPSigner
	Verifier           webmail.ExactSenderVerifier
	Resolver           webmail.SenderIdentityResolver
	Now                func() time.Time
}

func (b SignedEmailBackend) SendAlert(ctx context.Context, alert notification.Alert) (notification.DeliveryResult, error) {
	if err := ctx.Err(); err != nil {
		return deliveryFailure(notification.StatusFailedRetryable, ReasonCancelled)
	}
	clean, err := notification.SanitizeAlert(alert)
	if err != nil {
		return deliveryFailure(notification.StatusFailedPermanent, ReasonPayloadInvalid)
	}
	if b.SMTP == nil || b.Signer == nil || b.Verifier == nil || b.Resolver == nil {
		return deliveryFailure(notification.StatusFailedPermanent, ReasonConfigInvalid)
	}
	from, err := oneAddress(b.From)
	if err != nil {
		return deliveryFailure(notification.StatusFailedPermanent, ReasonConfigInvalid)
	}
	to, err := oneAddress(b.To)
	if err != nil {
		return deliveryFailure(notification.StatusFailedPermanent, ReasonConfigInvalid)
	}
	fingerprint, err := normalizeFingerprint(b.SigningFingerprint)
	if err != nil {
		return deliveryFailure(notification.StatusFailedPermanent, ReasonConfigInvalid)
	}

	now := time.Now().UTC()
	if b.Now != nil {
		now = b.Now().UTC()
	}
	evidence := notification.DeliveryEvidence{
		Transport:           "email",
		GeneratedAt:         now,
		From:                from,
		SigningFingerprint:  fingerprint,
		SenderIdentityID:    "system:" + from,
		SenderIdentityClass: "system",
		PolicyVersion:       SignedEmailPolicyVersion,
		IdentityStateRef:    "openpgp:" + fingerprint,
		VerificationResult:  "verification_error",
		Workflow:            SignedEmailWorkflow,
	}

	identity, err := b.Resolver.ResolveSender(ctx, fingerprint, from, "")
	if err != nil {
		if ctx.Err() != nil {
			return deliveryFailure(notification.StatusFailedRetryable, ReasonCancelled, evidence)
		}
		var resolution *IdentityResolutionError
		if errors.As(err, &resolution) && permanentIdentityFailure(resolution.Code) {
			evidence.VerificationResult = verificationResultForReason(resolution.Code)
			return deliveryFailure(notification.StatusFailedPermanent, resolution.Code, evidence)
		}
		return deliveryFailure(notification.StatusFailedRetryable, ReasonSigningIdentityDown, evidence)
	}
	identityFingerprint, err := normalizeFingerprint(identity.Fingerprint)
	if err != nil || !strings.EqualFold(identity.Address, from) || identityFingerprint != fingerprint {
		evidence.VerificationResult = verificationResultForReason(ReasonSigningIdentityMismatch)
		return deliveryFailure(notification.StatusFailedPermanent, ReasonSigningIdentityMismatch, evidence)
	}
	identity.Address = from
	identity.Fingerprint = fingerprint

	messageID := notificationMessageID(clean.ID, from, to)
	evidence.MessageID = messageID
	msg, err := webmail.BuildMIME(webmail.Draft{
		From:      from,
		To:        to,
		Subject:   "GOTTH Mail alert: " + clean.Title,
		Body:      alertBody(clean),
		MessageID: messageID,
		Date:      now,
	})
	if err != nil {
		return deliveryFailure(notification.StatusFailedPermanent, ReasonPayloadInvalid, evidence)
	}
	signed, signStatus, err := b.Signer.SignMIME(ctx, identity, msg)
	if err != nil {
		if ctx.Err() != nil {
			return deliveryFailure(notification.StatusFailedRetryable, ReasonCancelled, evidence)
		}
		if errors.Is(err, webmail.ErrOpenPGPMIMEUnsupportedHash) || errors.Is(err, ErrSigningHashUnsupported) {
			evidence.VerificationResult = verificationResultForReason(ReasonSigningHashUnsupported)
			return deliveryFailure(notification.StatusFailedPermanent, ReasonSigningHashUnsupported, evidence)
		}
		return deliveryFailure(notification.StatusFailedRetryable, ReasonOpenPGPSignFailed, evidence)
	}
	if !exactSignatureStatus(signStatus, identity) {
		return deliveryFailure(notification.StatusFailedPermanent, ReasonOpenPGPSignFailed, evidence)
	}
	verified, err := b.Verifier.VerifyExactSender(ctx, signed, identity)
	if err != nil || !exactSignatureStatus(verified, identity) {
		if ctx.Err() != nil {
			return deliveryFailure(notification.StatusFailedRetryable, ReasonCancelled, evidence)
		}
		return deliveryFailure(notification.StatusFailedPermanent, ReasonOpenPGPVerifyFailed, evidence)
	}
	evidence.VerificationResult = VerificationValidExactSender
	if err := b.SMTP.Submit(ctx, webmail.Envelope{From: from, To: []string{to}}, signed); err != nil {
		return smtpDeliveryFailure(err, evidence)
	}
	return notification.DeliveryResult{Status: notification.StatusDelivered, Reason: ReasonSignedEmailDelivered, Evidence: evidence}, nil
}

func deliveryFailure(status notification.DeliveryStatus, reason string, evidence ...notification.DeliveryEvidence) (notification.DeliveryResult, error) {
	result := notification.DeliveryResult{Status: status, Reason: reason}
	if len(evidence) != 0 {
		result.Evidence = evidence[0]
	}
	return result, errors.New(reason)
}

func smtpDeliveryFailure(err error, evidence notification.DeliveryEvidence) (notification.DeliveryResult, error) {
	var smtpErr *webmail.SMTPDeliveryError
	if !errors.As(err, &smtpErr) {
		return deliveryFailure(notification.StatusFailedRetryable, ReasonSMTPUnavailable, evidence)
	}
	switch smtpErr.Class {
	case webmail.SMTPFailurePermanent:
		return deliveryFailure(notification.StatusFailedPermanent, ReasonSMTPRejected, evidence)
	case webmail.SMTPFailureAmbiguous:
		// Do not blindly retry after an uncertain DATA acceptance boundary.
		return deliveryFailure(notification.StatusFailedPermanent, ReasonSMTPAmbiguous, evidence)
	default:
		return deliveryFailure(notification.StatusFailedRetryable, ReasonSMTPUnavailable, evidence)
	}
}

func verificationResultForReason(reason string) string {
	switch reason {
	case ReasonSigningKeyMissing, ReasonSigningIdentityUnmapped:
		return "unknown_signer"
	case ReasonSigningKeyRevoked:
		return "revoked_signer"
	case ReasonSigningKeyExpired:
		return "expired_signer"
	case ReasonSigningIdentityDisabled:
		return "disabled_sender_identity"
	case ReasonSigningIdentityAmbig:
		return "ambiguous_signer"
	case ReasonSigningIdentityMismatch:
		return "mismatched_from"
	case ReasonSigningHashUnsupported:
		return "unsupported_signing_hash"
	default:
		return "verification_error"
	}
}

func permanentIdentityFailure(code string) bool {
	switch code {
	case ReasonSigningKeyMissing, ReasonSigningKeyRevoked, ReasonSigningKeyExpired,
		ReasonSigningIdentityDisabled, ReasonSigningIdentityAmbig,
		ReasonSigningIdentityUnmapped, ReasonSigningIdentityMismatch,
		ReasonSigningHashUnsupported:
		return true
	default:
		return false
	}
}

func exactSignatureStatus(status webmail.SignatureStatus, identity webmail.Identity) bool {
	return status.Signed && strings.EqualFold(status.Identity, identity.Address) && strings.EqualFold(status.Fingerprint, identity.Fingerprint)
}

func oneAddress(raw string) (string, error) {
	addresses, err := mail.ParseAddressList(strings.TrimSpace(raw))
	if err != nil || len(addresses) != 1 || !asciiEmailAddress(addresses[0].Address) {
		return "", errors.New("one valid address required")
	}
	return strings.ToLower(addresses[0].Address), nil
}

func asciiEmailAddress(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] > 0x7f {
			return false
		}
	}
	return true
}

func normalizeFingerprint(raw string) (string, error) {
	fingerprint := strings.ToUpper(strings.TrimSpace(raw))
	if len(fingerprint) != 40 && len(fingerprint) != 64 {
		return "", errors.New("invalid OpenPGP fingerprint")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return "", errors.New("invalid OpenPGP fingerprint")
	}
	return fingerprint, nil
}

func notificationMessageID(alertID, from, to string) string {
	digest := sha256.Sum256([]byte(alertID + "\x00" + strings.ToLower(from) + "\x00" + strings.ToLower(to)))
	domain := "localhost"
	if _, d, ok := strings.Cut(from, "@"); ok && d != "" {
		domain = strings.ToLower(d)
	}
	return "<gotth-mail-notify-" + hex.EncodeToString(digest[:16]) + "@" + domain + ">"
}

func alertBody(a notification.Alert) string {
	var b strings.Builder
	b.WriteString(a.Title)
	b.WriteString("\n\n")
	b.WriteString(a.Summary)
	b.WriteString("\n\n")
	b.WriteString("severity: ")
	b.WriteString(string(a.Severity))
	b.WriteString("\nclass: ")
	b.WriteString(a.Class)
	if a.Resource.Type != "" || a.Resource.ID != "" {
		b.WriteString("\nresource: ")
		b.WriteString(a.Resource.Type)
		b.WriteString(":")
		b.WriteString(a.Resource.ID)
	}
	if a.CorrelationID != "" {
		b.WriteString("\ncorrelation: ")
		b.WriteString(a.CorrelationID)
	}
	keys := make([]string, 0, len(a.Details))
	for key := range a.Details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b.WriteString("\n")
		b.WriteString(key)
		b.WriteString(": ")
		b.WriteString(a.Details[key])
	}
	return b.String()
}
