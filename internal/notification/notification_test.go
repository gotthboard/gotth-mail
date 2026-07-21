package notification

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type fakeBackend struct {
	got    Alert
	res    DeliveryResult
	err    error
	called bool
}

func (f *fakeBackend) SendAlert(ctx context.Context, a Alert) (DeliveryResult, error) {
	f.called = true
	f.got = a
	return f.res, f.err
}

func baseAlert() Alert {
	return Alert{ID: "alert-1", Class: "auth.failure", Severity: SeverityWarning, Title: "Auth failure", Summary: "login failed", CorrelationID: "corr-1", Resource: ResourceRef{Type: "session", ID: "sess-1"}, Details: map[string]string{"ip": "127.0.0.1"}}
}

func TestSendAlertRecordsDeliveredStatus(t *testing.T) {
	rec := NewMemoryRecorder()
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	svc := Service{Backend: backend, Recorder: rec, Now: func() time.Time { return time.Unix(1, 0) }}
	got, err := svc.SendAlert(context.Background(), baseAlert())
	if err != nil {
		t.Fatal(err)
	}
	if !backend.called || got.Status != StatusDelivered || got.Alert.ID != "alert-1" {
		t.Fatalf("called=%v got=%#v", backend.called, got)
	}
	listed, err := rec.List(context.Background())
	if err != nil || len(listed) != 1 || listed[0].Status != StatusDelivered {
		t.Fatalf("listed=%#v err=%v", listed, err)
	}
}

func TestSendAlertRecordsRetryableFailureVisibleInStatus(t *testing.T) {
	rec := NewMemoryRecorder()
	backend := &fakeBackend{res: DeliveryResult{Status: StatusFailedRetryable, Reason: "telegram_unavailable"}, err: errors.New("send failed")}
	svc := Service{Backend: backend, Recorder: rec}
	got, err := svc.SendAlert(context.Background(), baseAlert())
	if err == nil || got.Status != StatusFailedRetryable || got.Reason != "telegram_unavailable" {
		t.Fatalf("got=%#v err=%v", got, err)
	}
	stored, ok, err := rec.Get(context.Background(), "alert-1")
	if err != nil || !ok || stored.Status != StatusFailedRetryable || stored.Reason == "" {
		t.Fatalf("stored=%#v ok=%v err=%v", stored, ok, err)
	}
}

func TestSendAlertRedactsSecretsBeforeBackend(t *testing.T) {
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	a := baseAlert()
	a.Summary = "password=hunter2 token=abcdef"
	a.Details = map[string]string{"token": "abcdef", "log": "secret=value"}
	if _, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	joined := backend.got.Summary + " " + backend.got.Details["token"] + " " + backend.got.Details["log"]
	if strings.Contains(joined, "hunter2") || strings.Contains(joined, "abcdef") || strings.Contains(joined, "secret=value") || !strings.Contains(joined, "[REDACTED]") {
		t.Fatalf("secrets leaked to backend: %#v", backend.got)
	}
}

func TestSanitizeAlertRedactsBearerAPIKeysAndPrivateKeyBlocks(t *testing.T) {
	entity, err := protonpgp.NewEntity("Alert Sender", "", "alerts@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, DefaultHash: crypto.SHA256, Time: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	var armored bytes.Buffer
	block, err := armor.Encode(&armored, protonpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivateWithoutSigning(block, nil); err != nil {
		t.Fatal(err)
	}
	if err := block.Close(); err != nil {
		t.Fatal(err)
	}
	a := baseAlert()
	a.Summary = "Authorization: Bearer eyJhbGci.secret api_key=api-value " + armored.String()
	a.Details = map[string]string{
		"trace": "Bearer loose-token access_token=access-value",
	}
	clean, err := SanitizeAlert(a)
	if err != nil {
		t.Fatal(err)
	}
	if clean.Summary != "[REDACTED]" || clean.Details["trace"] != "[REDACTED]" {
		t.Fatalf("secret-bearing fields were only partially redacted: %#v", clean)
	}
	joined := clean.Summary + " " + clean.Details["trace"]
	for _, secret := range []string{"eyJhbGci", "api-value", "loose-token", "access-value", "BEGIN PGP PRIVATE KEY BLOCK", "END PGP PRIVATE KEY BLOCK"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("secret %q leaked after sanitization: %q", secret, joined)
		}
	}
}

func TestSanitizeAlertRedactsWholeSecretMarkedFields(t *testing.T) {
	tests := []string{
		`{"password":"correct horse battery staple","safe":"must not survive beside a secret"}`,
		`token="quoted multi word value" trailing prose must not survive`,
		`secret: arbitrary prose, punctuation; and multiple words must not survive`,
		`{"client_secret":"alpha beta gamma"}`,
		`API key: quoted or unquoted multiword material must not survive`,
		`{"private key":"line one\nline two"}`,
		"API\nkey: newline-separated label must not survive",
		"private\u00a0key: unicode-space-separated label must not survive",
		`Authorization: Basic dXNlcjpwYXNzd29yZA==`,
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			a := baseAlert()
			a.Summary = input
			a.Details = map[string]string{"diagnostic": input}
			clean, err := SanitizeAlert(a)
			if err != nil {
				t.Fatal(err)
			}
			if clean.Summary != "[REDACTED]" || clean.Details["diagnostic"] != "[REDACTED]" {
				t.Fatalf("secret-marked value was partially preserved: %#v", clean)
			}
		})
	}
}

func TestSanitizeAlertPreservesBoundedNonSecretProse(t *testing.T) {
	a := baseAlert()
	a.Summary = `token_count=5`
	a.Details = map[string]string{
		"diagnostic":  `{"message":"multi word but safe"}`,
		"relay":       `delivery failed for "primary relay" after 3 attempts`,
		"token_count": "5",
	}
	clean, err := SanitizeAlert(a)
	if err != nil {
		t.Fatal(err)
	}
	if clean.Summary != a.Summary || clean.Details["diagnostic"] != a.Details["diagnostic"] || clean.Details["relay"] != a.Details["relay"] || clean.Details["token_count"] != "5" {
		t.Fatalf("valid alert text changed: %#v", clean)
	}
}

func TestSanitizeAlertRejectsSecretMarkedIdentifiersBeforeBounding(t *testing.T) {
	secret := strings.Repeat("identifier", 30) + " password=secret"
	tests := []struct {
		name   string
		mutate func(*Alert)
	}{
		{name: "id", mutate: func(a *Alert) { a.ID = secret }},
		{name: "class", mutate: func(a *Alert) { a.Class = secret }},
		{name: "correlation id", mutate: func(a *Alert) { a.CorrelationID = secret }},
		{name: "resource type", mutate: func(a *Alert) { a.Resource.Type = secret }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := baseAlert()
			tt.mutate(&a)
			if _, err := SanitizeAlert(a); err == nil || !strings.Contains(err.Error(), "secret markers") {
				t.Fatalf("secret-marked identifier accepted: %#v err=%v", a, err)
			}
		})
	}
}

func TestSanitizeAlertChecksSecretDetailKeysBeforeTruncation(t *testing.T) {
	prefix := strings.Repeat("detail", 16)
	secretName := prefix + ".password"
	safeCollision := prefix + ".token_count"
	a := baseAlert()
	a.Details = map[string]string{
		secretName:    "hunter2",
		safeCollision: "5",
	}
	clean, err := SanitizeAlert(a)
	if err != nil {
		t.Fatal(err)
	}
	key := boundToken(secretName, 64)
	if got := clean.Details[key]; got != "[REDACTED]" {
		t.Fatalf("secret suffix disappeared during detail-key bounding: key=%q value=%q details=%#v", key, got, clean.Details)
	}
	if strings.Contains(strings.Join(detailValues(clean.Details), " "), "hunter2") {
		t.Fatalf("secret detail value survived sanitization: %#v", clean.Details)
	}
}

func TestSanitizeAlertPreservesSafeTokenCountIdentifiers(t *testing.T) {
	a := baseAlert()
	a.ID = "token_count=5"
	a.Class = "token_count=5"
	a.CorrelationID = "token_count=5"
	a.Resource.Type = "token_count=5"
	a.Details = map[string]string{"token_count": "5"}
	clean, err := SanitizeAlert(a)
	if err != nil {
		t.Fatal(err)
	}
	if clean.ID != a.ID || clean.Class != a.Class || clean.CorrelationID != a.CorrelationID || clean.Resource.Type != a.Resource.Type || clean.Details["token_count"] != "5" {
		t.Fatalf("safe token-count identifiers changed: %#v", clean)
	}
}

func TestSanitizeDeliveryEvidenceUsesFieldSpecificValidation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	valid := DeliveryEvidence{
		Transport: "email", MessageID: "<alert-1@example.test>", GeneratedAt: now,
		From: "alerts@example.test", Sender: "sender@example.test",
		SigningFingerprint: "0123456789ABCDEF0123456789ABCDEF01234567",
		SenderIdentityID:   "system:alerts@example.test", SenderIdentityClass: "system",
		PolicyVersion: "gmf-exact-sender-v1", IdentityStateRef: "openpgp:0123456789ABCDEF0123456789ABCDEF01234567",
		VerificationResult: "valid_exact_sender", Workflow: "notification",
	}
	if got := SanitizeDeliveryEvidence(valid); got != valid {
		t.Fatalf("valid evidence changed: got=%#v want=%#v", got, valid)
	}

	tests := []struct {
		name   string
		value  string
		mutate func(*DeliveryEvidence, string)
		get    func(DeliveryEvidence) string
	}{
		{name: "transport", value: "email@example.test", mutate: func(e *DeliveryEvidence, v string) { e.Transport = v }, get: func(e DeliveryEvidence) string { return e.Transport }},
		{name: "message id", value: "not-a-message-id", mutate: func(e *DeliveryEvidence, v string) { e.MessageID = v }, get: func(e DeliveryEvidence) string { return e.MessageID }},
		{name: "from", value: "Alerts <alerts@example.test>", mutate: func(e *DeliveryEvidence, v string) { e.From = v }, get: func(e DeliveryEvidence) string { return e.From }},
		{name: "sender", value: "Sender <sender@example.test>", mutate: func(e *DeliveryEvidence, v string) { e.Sender = v }, get: func(e DeliveryEvidence) string { return e.Sender }},
		{name: "fingerprint", value: "not-hex", mutate: func(e *DeliveryEvidence, v string) { e.SigningFingerprint = v }, get: func(e DeliveryEvidence) string { return e.SigningFingerprint }},
		{name: "identity id", value: "system identity", mutate: func(e *DeliveryEvidence, v string) { e.SenderIdentityID = v }, get: func(e DeliveryEvidence) string { return e.SenderIdentityID }},
		{name: "identity class", value: "system:admin", mutate: func(e *DeliveryEvidence, v string) { e.SenderIdentityClass = v }, get: func(e DeliveryEvidence) string { return e.SenderIdentityClass }},
		{name: "policy", value: "gmf=1", mutate: func(e *DeliveryEvidence, v string) { e.PolicyVersion = v }, get: func(e DeliveryEvidence) string { return e.PolicyVersion }},
		{name: "state ref", value: "openpgp=state", mutate: func(e *DeliveryEvidence, v string) { e.IdentityStateRef = v }, get: func(e DeliveryEvidence) string { return e.IdentityStateRef }},
		{name: "verification", value: "valid;sender", mutate: func(e *DeliveryEvidence, v string) { e.VerificationResult = v }, get: func(e DeliveryEvidence) string { return e.VerificationResult }},
		{name: "workflow", value: "notification/../../secret", mutate: func(e *DeliveryEvidence, v string) { e.Workflow = v }, get: func(e DeliveryEvidence) string { return e.Workflow }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := valid
			tt.mutate(&in, tt.value)
			if got := tt.get(SanitizeDeliveryEvidence(in)); got != "" {
				t.Fatalf("invalid %s evidence survived as %q", tt.name, got)
			}
		})
	}
}

func TestSendAlertRemovesSecretMarkersFromPersistedEvidence(t *testing.T) {
	secret := "password=supersecret"
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered, Evidence: DeliveryEvidence{
		Transport: secret, MessageID: secret, From: secret, Sender: secret,
		SigningFingerprint: secret, SenderIdentityID: secret, SenderIdentityClass: secret,
		PolicyVersion: secret, IdentityStateRef: secret, VerificationResult: secret, Workflow: secret,
	}}}
	record, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), baseAlert())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(record.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "password") || strings.Contains(string(encoded), "supersecret") || record.Evidence != (DeliveryEvidence{}) {
		t.Fatalf("secret-marked evidence persisted: %s", encoded)
	}
}

func detailValues(details map[string]string) []string {
	values := make([]string, 0, len(details))
	for _, value := range details {
		values = append(values, value)
	}
	return values
}

func TestSanitizeAlertRejectsInvalidUTF8AndTruncatesOnRuneBoundary(t *testing.T) {
	a := baseAlert()
	a.Summary = string([]byte{'b', 'a', 'd', 0xff})
	if _, err := SanitizeAlert(a); err == nil {
		t.Fatal("invalid UTF-8 alert accepted")
	}
	a = baseAlert()
	a.Summary = strings.Repeat("é", 300)
	clean, err := SanitizeAlert(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Summary) > 512 || !utf8.ValidString(clean.Summary) {
		t.Fatalf("invalid bounded summary len=%d value=%q", len(clean.Summary), clean.Summary)
	}
}

func TestSanitizeDeliveryReasonRejectsProseSecretsAndOversize(t *testing.T) {
	for _, input := range []string{"smtp password=secret", "human prose", strings.Repeat("x", 257), string([]byte{0xff})} {
		if got := SanitizeDeliveryReason(input); got != "delivery_reason_redacted" {
			t.Fatalf("reason %q sanitized to %q", input, got)
		}
	}
	if got := SanitizeDeliveryReason("signed_email_delivered;verification=valid_exact_sender"); got != "signed_email_delivered;verification=valid_exact_sender" {
		t.Fatalf("safe reason changed to %q", got)
	}
}

func TestSanitizeAlertNormalizesAllWhitespaceInTokens(t *testing.T) {
	a := baseAlert()
	a.Class = "Backup\tFailure\nCritical"
	clean, err := SanitizeAlert(a)
	if err != nil {
		t.Fatal(err)
	}
	if clean.Class != "backup-failure-critical" {
		t.Fatalf("unexpected normalized class %q", clean.Class)
	}
}

func TestSendAlertBoundsSummaryAndDetails(t *testing.T) {
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	a := baseAlert()
	a.Title = strings.Repeat("t", 200)
	a.Summary = strings.Repeat("s", 900)
	a.Details = map[string]string{"blob": strings.Repeat("x", 1500)}
	got, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Alert.Title) > 120 || len(got.Alert.Summary) > 512 || len(got.Alert.Details["blob"]) > 1024 {
		t.Fatalf("not bounded: %#v", got.Alert)
	}
	a.Details = map[string]string{"raw_log": "a\nb\nc\nd\ne"}
	if _, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), a); err == nil {
		t.Fatal("raw multiline log was accepted")
	}
}

func TestBackendReceivesOnlySanitizedAlertContract(t *testing.T) {
	backend := &fakeBackend{res: DeliveryResult{Status: StatusDelivered}}
	if _, err := (Service{Backend: backend, Recorder: NewMemoryRecorder()}).SendAlert(context.Background(), baseAlert()); err != nil {
		t.Fatal(err)
	}
	if backend.got.ID == "" || backend.got.Resource.ID != "sess-1" {
		t.Fatalf("backend did not receive alert contract: %#v", backend.got)
	}
	// The backend interface is intentionally only SendAlert(ctx, Alert): no DB,
	// control-plane store, approval callback, or mutation handle is passed.
}
