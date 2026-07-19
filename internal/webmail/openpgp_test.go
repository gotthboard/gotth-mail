package webmail

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"strings"
	"testing"
	"time"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestOpenPGPMIMESignerProducesVerifiableExactSenderSignature(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	msg, err := BuildMIME(Draft{From: "smoke@example.test", To: "rcpt@example.test", Subject: "signed smoke", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	signed, status, err := (OpenPGPMIMESigner{Entity: entity, Now: fixedOpenPGPTime}).SignMIME(context.Background(), identity, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Signed || status.Identity != identity.Address || status.Fingerprint != identity.Fingerprint {
		t.Fatalf("bad signing status: %#v", status)
	}
	for _, want := range []string{"multipart/signed", "protocol=\"application/pgp-signature\"", "micalg=pgp-sha256", "BEGIN PGP SIGNATURE"} {
		if !bytes.Contains(signed, []byte(want)) {
			t.Fatalf("signed MIME missing %q in\n%s", want, signed)
		}
	}
	verified, err := (OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}).VerifyExactSender(context.Background(), signed, identity)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.Signed || verified.Identity != identity.Address || verified.Fingerprint != identity.Fingerprint {
		t.Fatalf("bad verify status: %#v", verified)
	}
	if err := ValidateOpenPGPMIME(signed); err != nil {
		t.Fatal(err)
	}
}

func TestOpenPGPMIMEVerifierRejectsFingerprintAndSenderMismatch(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	msg, err := BuildMIME(Draft{From: "smoke@example.test", To: "rcpt@example.test", Subject: "signed smoke", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := (OpenPGPMIMESigner{Entity: entity, Now: fixedOpenPGPTime}).SignMIME(context.Background(), identity, msg)
	if err != nil {
		t.Fatal(err)
	}
	verifier := OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}
	if _, err := verifier.VerifyExactSender(context.Background(), signed, Identity{Address: "smoke@example.test", Fingerprint: strings.Repeat("0", len(identity.Fingerprint))}); err == nil || !strings.Contains(err.Error(), "exact sender") {
		t.Fatalf("fingerprint mismatch accepted: %v", err)
	}
	if _, err := verifier.VerifyExactSender(context.Background(), signed, Identity{Address: "other@example.test", Fingerprint: identity.Fingerprint}); err == nil || !strings.Contains(err.Error(), "exact sender") {
		t.Fatalf("sender mismatch accepted: %v", err)
	}
}

func TestOpenPGPMIMESignerRejectsWrongIdentityBeforeSigning(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	msg, err := BuildMIME(Draft{From: "smoke@example.test", To: "rcpt@example.test", Subject: "signed smoke", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = (OpenPGPMIMESigner{Entity: entity, Now: fixedOpenPGPTime}).SignMIME(context.Background(), Identity{Address: "other@example.test", Fingerprint: entityFingerprint(entity)}, msg)
	if err == nil || !strings.Contains(err.Error(), "sender identity") {
		t.Fatalf("wrong sender identity accepted: %v", err)
	}
}

func TestOpenPGPMIMEVerifierRejectsTamperedSignedPart(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	msg, err := BuildMIME(Draft{From: "smoke@example.test", To: "rcpt@example.test", Subject: "signed smoke", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := (OpenPGPMIMESigner{Entity: entity, Now: fixedOpenPGPTime}).SignMIME(context.Background(), identity, msg)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(signed, []byte("hello"), []byte("hullo"), 1)
	if _, err := (OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}).VerifyExactSender(context.Background(), tampered, identity); err == nil {
		t.Fatal("tampered signed MIME accepted")
	}
}

func testOpenPGPEntity(t *testing.T, name, email string) *protonpgp.Entity {
	t.Helper()
	entity, err := protonpgp.NewEntity(name, "", email, &packet.Config{DefaultHash: crypto.SHA256, Time: fixedOpenPGPTime, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	return entity
}

func entityFingerprint(e *protonpgp.Entity) string {
	return strings.ToUpper(fmt.Sprintf("%X", e.PrimaryKey.Fingerprint))
}

func fixedOpenPGPTime() time.Time { return time.Unix(1700000000, 0).UTC() }
