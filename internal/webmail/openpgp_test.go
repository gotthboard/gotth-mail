package webmail

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"mime"
	"strings"
	"testing"
	"time"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
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
	_, signature, err := splitOpenPGPMIME(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := requireArmoredDetachedSignatureHash(signature, crypto.SHA256); err != nil {
		t.Fatalf("micalg advertised SHA-256 but signature packet disagreed: %v", err)
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

func TestOpenPGPMIMESignerRejectsNonSHA256SelectedBySigningKey(t *testing.T) {
	entity, err := protonpgp.NewEntity("P-384 Sender", "", "p384@example.test", &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        fixedOpenPGPTime,
		Algorithm:   packet.PubKeyAlgoECDSA,
		Curve:       packet.CurveNistP384,
	})
	if err != nil {
		t.Fatal(err)
	}

	// go-crypto treats DefaultHash as a preference. Its P-384 signing path
	// selects SHA-384 even when SHA-256 was configured.
	var probe bytes.Buffer
	if err := protonpgp.ArmoredDetachSign(&probe, entity, strings.NewReader("probe"), &packet.Config{DefaultHash: crypto.SHA256, Time: fixedOpenPGPTime}); err != nil {
		t.Fatal(err)
	}
	if err := requireArmoredDetachedSignatureHash(probe.Bytes(), crypto.SHA384); err != nil {
		t.Fatalf("test key did not exercise the non-SHA256 path: %v", err)
	}
	if err := ValidateOpenPGPMIMESHA256SigningKey(entity.PrimaryKey); !errors.Is(err, ErrOpenPGPMIMEUnsupportedHash) {
		t.Fatalf("P-384 signing key capability check = %v, want %v", err, ErrOpenPGPMIMEUnsupportedHash)
	}

	identity := Identity{Address: "p384@example.test", Fingerprint: entityFingerprint(entity)}
	msg, err := BuildMIME(Draft{From: identity.Address, To: "rcpt@example.test", Subject: "signed smoke", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	signed, status, err := (OpenPGPMIMESigner{Entity: entity, Now: fixedOpenPGPTime}).SignMIME(context.Background(), identity, msg)
	if err == nil || !errors.Is(err, ErrOpenPGPMIMEUnsupportedHash) || !strings.Contains(err.Error(), "uses SHA-384, want SHA-256") {
		t.Fatalf("non-SHA256 signature was not rejected: %v", err)
	}
	if signed != nil || status.Signed {
		t.Fatalf("non-SHA256 signature escaped into MIME: signed=%d status=%#v", len(signed), status)
	}
}

func TestOpenPGPMIMEVerifierRequiresOneCanonicalDetachedSignatureArmorBlock(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	signed := signedOpenPGPMIMEForTest(t, entity, identity, false)
	signedPart, signature, err := splitOpenPGPMIME(signed)
	if err != nil {
		t.Fatal(err)
	}
	packetBytes, err := decodeArmoredDetachedSignature(signature, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	withHeader := bytes.Replace(signature,
		[]byte("-----BEGIN PGP SIGNATURE-----\n\n"),
		[]byte("-----BEGIN PGP SIGNATURE-----\nVersion: injected\n\n"), 1)
	if bytes.Equal(withHeader, signature) {
		t.Fatal("test did not add an armor header")
	}
	twoPackets := append(append([]byte(nil), packetBytes...), packetBytes...)
	tests := []struct {
		name      string
		signature []byte
		want      string
	}{
		{name: "non-whitespace prefix", signature: append([]byte("garbage\n"), signature...), want: "canonical armor block"},
		{name: "non-whitespace suffix", signature: append(append([]byte(nil), signature...), []byte("\ngarbage")...), want: "canonical armor block"},
		{name: "multiple armor blocks", signature: append(append([]byte(nil), signature...), signature...), want: "canonical armor block"},
		{name: "non-canonical armor header", signature: withHeader, want: "contains headers"},
		{name: "multiple signature packets", signature: armorSignaturePacketsForTest(t, twoPackets), want: "multiple packets"},
	}
	verifier := OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := rewrapSignedEntityWithSignatureForTest(t, signed, signedPart, tc.signature)
			if _, err := verifier.VerifyExactSender(context.Background(), wrapped, identity); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ambiguous detached signature armor error = %v, want %q", err, tc.want)
			}
		})
	}

	t.Run("surrounding whitespace is not an extra block", func(t *testing.T) {
		withWhitespace := append([]byte(" \r\n\t"), signature...)
		withWhitespace = append(withWhitespace, []byte("\r\n \t")...)
		wrapped := rewrapSignedEntityWithSignatureForTest(t, signed, signedPart, withWhitespace)
		if _, err := verifier.VerifyExactSender(context.Background(), wrapped, identity); err != nil {
			t.Fatalf("surrounding signature whitespace rejected: %v", err)
		}
	})
}

func TestOpenPGPMIMEVerifierRejectsCryptographicallyValidHashMicalgMismatch(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	signed := signedOpenPGPMIMEForTest(t, entity, identity, false)
	signedPart, _, err := splitOpenPGPMIME(signed)
	if err != nil {
		t.Fatal(err)
	}

	// Keep the wrapper's micalg=pgp-sha256 but replace its detached signature
	// with a cryptographically valid SHA-384 signature over the same raw entity.
	mismatched := rewrapSignedEntityForTest(t, signed, signedPart, entity, crypto.SHA384)
	mismatchedPart, signature, err := splitOpenPGPMIME(mismatched)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mismatchedPart, signedPart) {
		t.Fatal("test changed the raw signed entity")
	}
	if _, err := protonpgp.CheckArmoredDetachedSignature(protonpgp.EntityList{entity}, bytes.NewReader(mismatchedPart), bytes.NewReader(signature), &packet.Config{Time: fixedOpenPGPTime}); err != nil {
		t.Fatalf("test signature was not cryptographically valid: %v", err)
	}
	if _, err := (OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}).VerifyExactSender(context.Background(), mismatched, identity); err == nil || !strings.Contains(err.Error(), "hash algorithm") {
		t.Fatalf("valid signature with dishonest micalg was accepted: %v", err)
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

func TestOpenPGPMIMEVerifierRejectsTamperedAuthoritativeHeaders(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	msg, err := BuildMIME(Draft{
		From: "smoke@example.test", To: "rcpt@example.test", Subject: "signed smoke", Body: "hello",
		MessageID: "<stable-message@example.test>", Date: fixedOpenPGPTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := (OpenPGPMIMESigner{Entity: entity, Now: fixedOpenPGPTime}).SignMIME(context.Background(), identity, msg)
	if err != nil {
		t.Fatal(err)
	}
	verifier := OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}
	for _, tc := range []struct {
		name, old, new string
	}{
		{"message id", "Message-ID: <stable-message@example.test>", "Message-ID: <forged-message@example.test>"},
		{"date", "Date: Tue, 14 Nov 2023 22:13:20 +0000", "Date: Tue, 14 Nov 2023 22:14:20 +0000"},
		{"subject", "Subject: signed smoke", "Subject: forged smoke"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := bytes.Replace(signed, []byte(tc.old), []byte(tc.new), 1)
			if bytes.Equal(tampered, signed) {
				t.Fatalf("test did not find header %q", tc.old)
			}
			if _, err := verifier.VerifyExactSender(context.Background(), tampered, identity); err == nil {
				t.Fatalf("tampered %s accepted", tc.name)
			}
		})
	}
}

func TestOpenPGPMIMEVerifierAuthenticatesRawSignedEntityHeaders(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	signed := signedOpenPGPMIMEForTest(t, entity, identity, false)
	marker := []byte("X-GopherMailForge-Signed-From: " + identity.Address + "\r\n")
	for _, tc := range []struct {
		name, insertion string
	}{
		{"extra content header", "Content-Description: unsigned injection\r\n"},
		{"duplicate content header", "Content-Type: text/plain; charset=utf-8\r\n"},
		{"extra gophermailforge header", "X-GopherMailForge-Unsigned-Assertion: injected\r\n"},
		{"duplicate gophermailforge header", "X-GopherMailForge-Signed-From: " + identity.Address + "\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := bytes.Replace(signed, marker, append([]byte(tc.insertion), marker...), 1)
			if bytes.Equal(tampered, signed) {
				t.Fatal("test did not modify the signed MIME entity")
			}
			if _, err := (OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}).VerifyExactSender(context.Background(), tampered, identity); err == nil {
				t.Fatal("unsigned signed-entity header injection accepted")
			}
		})
	}
}

func TestOpenPGPMIMEVerifierRejectsAmbiguousOuterHeaders(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	signed := signedOpenPGPMIMEForTest(t, entity, identity, true)
	outer, _, err := readCanonicalMIMEEntity(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"From", "Sender", "Reply-To", "Message-ID", "Date", "Subject", "MIME-Version", "Content-Type",
	} {
		t.Run(field, func(t *testing.T) {
			value, err := uniqueHeaderValue(outer.Header, field, true)
			if err != nil {
				t.Fatal(err)
			}
			line := []byte(field + ": " + value + "\r\n")
			tampered := bytes.Replace(signed, line, append(append([]byte(nil), line...), line...), 1)
			if bytes.Equal(tampered, signed) {
				t.Fatalf("test did not duplicate %s", field)
			}
			if _, err := (OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}).VerifyExactSender(context.Background(), tampered, identity); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("duplicate outer %s accepted: %v", field, err)
			}
		})
	}
}

func TestOpenPGPMIMEVerifierRejectsCryptographicallyValidDuplicateSignedHeaders(t *testing.T) {
	entity := testOpenPGPEntity(t, "Smoke Sender", "smoke@example.test")
	identity := Identity{Address: "smoke@example.test", Fingerprint: entityFingerprint(entity)}
	signed := signedOpenPGPMIMEForTest(t, entity, identity, true)
	signedPart, _, err := splitOpenPGPMIME(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		field, insertedValue string
	}{
		{field: "Content-Type"},
		{field: "Content-Description", insertedValue: "ambiguous"},
		{field: "X-GopherMailForge-Signed-From"},
		{field: "X-GopherMailForge-Signed-Sender"},
		{field: "X-GopherMailForge-Signed-Reply-To"},
		{field: "X-GopherMailForge-Extension", insertedValue: "ambiguous"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			part, _, err := readCanonicalMIMEEntity(signedPart)
			if err != nil {
				t.Fatal(err)
			}
			var ambiguous []byte
			if tc.insertedValue == "" {
				value, err := uniqueHeaderValue(part.Header, tc.field, true)
				if err != nil {
					t.Fatal(err)
				}
				line := []byte(tc.field + ": " + value + "\r\n")
				ambiguous = bytes.Replace(signedPart, line, append(append([]byte(nil), line...), line...), 1)
			} else {
				marker := []byte("X-GopherMailForge-Signed-From: " + identity.Address + "\r\n")
				line := []byte(tc.field + ": " + tc.insertedValue + "\r\n")
				duplicate := append(append([]byte(nil), line...), line...)
				ambiguous = bytes.Replace(signedPart, marker, append(duplicate, marker...), 1)
			}
			if bytes.Equal(ambiguous, signedPart) {
				t.Fatalf("test did not duplicate %s", tc.field)
			}
			resigned := rewrapSignedEntityForTest(t, signed, ambiguous, entity, crypto.SHA256)
			if _, err := (OpenPGPMIMEVerifier{KeyRing: protonpgp.EntityList{entity}, Now: fixedOpenPGPTime}).VerifyExactSender(context.Background(), resigned, identity); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatalf("cryptographically valid duplicate %s accepted: %v", tc.field, err)
			}
		})
	}
}

func signedOpenPGPMIMEForTest(t *testing.T, entity *protonpgp.Entity, identity Identity, includeRoutingHeaders bool) []byte {
	t.Helper()
	msg, err := BuildMIME(Draft{
		From: identity.Address, To: "rcpt@example.test", Subject: "signed smoke", Body: "hello",
		MessageID: "<stable-message@example.test>", Date: fixedOpenPGPTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if includeRoutingHeaders {
		msg = bytes.Replace(msg, []byte("To: "), []byte("Sender: "+identity.Address+"\r\nReply-To: "+identity.Address+"\r\nTo: "), 1)
	}
	signed, _, err := (OpenPGPMIMESigner{Entity: entity, Now: fixedOpenPGPTime}).SignMIME(context.Background(), identity, msg)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func rewrapSignedEntityForTest(t *testing.T, signed, signedPart []byte, entity *protonpgp.Entity, hash crypto.Hash) []byte {
	t.Helper()
	var signature bytes.Buffer
	if err := protonpgp.ArmoredDetachSign(&signature, entity, bytes.NewReader(signedPart), &packet.Config{DefaultHash: hash, Time: fixedOpenPGPTime}); err != nil {
		t.Fatal(err)
	}
	if err := requireArmoredDetachedSignatureHash(signature.Bytes(), hash); err != nil {
		t.Fatalf("test signature did not use %s: %v", hash, err)
	}
	if _, err := protonpgp.CheckArmoredDetachedSignature(protonpgp.EntityList{entity}, bytes.NewReader(signedPart), bytes.NewReader(signature.Bytes()), &packet.Config{DefaultHash: hash, Time: fixedOpenPGPTime}); err != nil {
		t.Fatalf("test did not produce a valid detached signature: %v", err)
	}
	return rewrapSignedEntityWithSignatureForTest(t, signed, signedPart, signature.Bytes())
}

func rewrapSignedEntityWithSignatureForTest(t *testing.T, signed, signedPart, signature []byte) []byte {
	t.Helper()
	outer, body, err := readCanonicalMIMEEntity(signed)
	if err != nil {
		t.Fatal(err)
	}
	contentType, err := uniqueHeaderValue(outer.Header, "Content-Type", true)
	if err != nil {
		t.Fatal(err)
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		t.Fatalf("parse boundary: %v", err)
	}
	boundary := params["boundary"]
	var out bytes.Buffer
	out.Write(signed[:len(signed)-len(body)])
	out.WriteString("--" + boundary + "\r\n")
	out.Write(signedPart)
	out.WriteString("\r\n--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/pgp-signature\r\n\r\n")
	out.Write(signature)
	if !bytes.HasSuffix(signature, []byte("\r\n")) {
		out.WriteString("\r\n")
	}
	out.WriteString("\r\n--" + boundary + "--\r\n")
	return out.Bytes()
}

func armorSignaturePacketsForTest(t *testing.T, packetBytes []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := armor.Encode(&out, protonpgp.SignatureType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(packetBytes); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
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
