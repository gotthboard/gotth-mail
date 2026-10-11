package webmail

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	protonpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func forwardFixture(t *testing.T) (SignedForwardBuilder, ForwardMessage, *RuntimeRegistry, string, *protonpgp.Entity) {
	t.Helper()
	entity := testOpenPGPEntity(t, "Forwarding", "forward@example.test")
	dir := t.TempDir()
	key := filepath.Join(dir, "synthetic.asc")
	writeRuntimePrivateKey(t, key, entity, 0600)
	secret := writeRuntimeFile(t, dir, "synthetic-password", []byte("test-only"), 0600)
	identity := Identity{Address: "forward@example.test", Fingerprint: entityFingerprint(entity)}
	registry, err := NewRuntimeRegistry(RuntimeConfig{IMAPAddr: "localhost:143", SMTPAddr: "localhost:25", SMTPAuthMechanism: "cram-md5", Mailboxes: []RuntimeMailbox{{Address: identity.Address, SigningFingerprint: identity.Fingerprint, PrivateKeyFile: key, IMAPPasswordFile: secret, SMTPPasswordFile: secret}}})
	if err != nil {
		t.Fatal(err)
	}
	registry.now = fixedOpenPGPTime
	return SignedForwardBuilder{Resolver: registry, Signer: registry, Verifier: registry}, ForwardMessage{Identity: identity, CapturedOriginal: []byte("From: remote@outside.test\n\noriginal\n"), MessageID: "<new-forward@example.test>", Date: fixedOpenPGPTime()}, registry, key, entity
}

func TestSignedForwardPreservesCapturedOriginal(t *testing.T) {
	builder, req, _, _, _ := forwardFixture(t)
	originals := [][]byte{
		[]byte("From: remote@outside.test\r\nReply-To: other@outside.test\r\nMessage-ID: <old@outside.test>\r\nDate: Tue, 01 Jan 2019 00:00:00 +0000\r\nCc: hidden@outside.test\r\nReferences: <thread@outside.test>\r\nIn-Reply-To: <thread@outside.test>\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nx=FF=0A\r\n"),
		[]byte("From: remote@outside.test\nContent-Transfer-Encoding: base64\n\nYWJj\n"),
		{'b', 0, 255, '\r', '\n', 128, '\n', ' ', '\t'},
		[]byte("not a parsed RFC5322 message; opaque capture"),
	}
	for _, original := range originals {
		req.CapturedOriginal = original
		before := bytes.Clone(original)
		signed, status, err := builder.Build(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !status.Signed || status.Identity != req.Identity.Address || status.Fingerprint != req.Identity.Fingerprint {
			t.Fatal("wrong identity evidence")
		}
		if !bytes.Equal(before, original) {
			t.Fatal("capture mutated")
		}
		assertForwardMessage(t, signed, req)
		for _, field := range []string{"From: forward@example.test", "Reply-To: forward@example.test", "Subject: Forwarded message", "Message-ID: <new-forward@example.test>"} {
			tampered := bytes.Replace(signed, []byte(field), []byte(field+"x"), 1)
			if _, err := builder.Verifier.VerifyExactSender(context.Background(), tampered, req.Identity); err == nil {
				t.Fatalf("tampered %s accepted", field)
			}
		}
		tampered := bytes.Replace(signed, []byte("responsibility"), []byte("responsibilitY"), 1)
		if bytes.Equal(tampered, signed) {
			t.Fatal("tamper fixture did not modify content")
		}
		if _, err := builder.Verifier.VerifyExactSender(context.Background(), tampered, req.Identity); err == nil {
			t.Fatal("tampered signed body accepted")
		}
	}
}

func assertForwardMessage(t *testing.T, signed []byte, req ForwardMessage) {
	t.Helper()
	for i, b := range signed {
		if b > 127 || b == '\n' && (i == 0 || signed[i-1] != '\r') || b == '\r' && (i+1 == len(signed) || signed[i+1] != '\n') {
			t.Fatalf("not seven-bit CRLF at byte %d: 0x%02x", i, b)
		}
	}
	for _, line := range bytes.Split(signed, []byte("\r\n")) {
		if bytes.HasSuffix(line, []byte(" ")) || bytes.HasSuffix(line, []byte("\t")) {
			t.Fatal("trailing whitespace")
		}
	}
	outer, err := mail.ReadMessage(bytes.NewReader(signed))
	if err != nil {
		t.Fatal(err)
	}
	for field, want := range map[string]string{"From": req.Identity.Address, "Reply-To": req.Identity.Address, "To": "undisclosed-recipients:;", "Message-ID": req.MessageID, "Subject": "Forwarded message"} {
		if outer.Header.Get(field) != want {
			t.Fatalf("%s=%q want %q", field, outer.Header.Get(field), want)
		}
	}
	date, err := mail.ParseDate(outer.Header.Get("Date"))
	if err != nil || !date.Equal(req.Date.Truncate(time.Second)) {
		t.Fatal("wrong new Date")
	}
	for _, field := range []string{"Sender", "Cc", "Bcc", "References", "In-Reply-To"} {
		if outer.Header.Get(field) != "" {
			t.Fatalf("inherited %s", field)
		}
	}
	mt, params, err := mime.ParseMediaType(outer.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/signed" {
		t.Fatal("not signed MIME")
	}
	mr := multipart.NewReader(outer.Body, params["boundary"])
	entity, err := mr.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	mixed, mp, err := mime.ParseMediaType(entity.Header.Get("Content-Type"))
	if err != nil || mixed != "multipart/mixed" {
		t.Fatal("not mixed content")
	}
	parts := multipart.NewReader(entity, mp["boundary"])
	text, err := parts.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(text)
	if err != nil || !bytes.Contains(body, []byte("not original authorship")) {
		t.Fatal("missing responsibility disclaimer")
	}
	attachment, err := parts.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	disposition, dp, err := mime.ParseMediaType(attachment.Header.Get("Content-Disposition"))
	if err != nil || disposition != "attachment" || dp["filename"] != "original.eml" {
		t.Fatal("wrong attachment disposition")
	}
	if attachment.Header.Get("Content-Type") != "application/octet-stream" || attachment.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatal("wrong opaque transfer type")
	}
	encoded, err := io.ReadAll(attachment)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(encoded, []byte("\r\n")) {
		if len(line) > 76 {
			t.Fatal("base64 line too long")
		}
	}
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, bytes.NewReader(encoded)))
	if err != nil || !bytes.Equal(decoded, req.CapturedOriginal) {
		t.Fatal("captured bytes changed")
	}
	if _, err = parts.NextRawPart(); err != io.EOF {
		t.Fatal("extra mixed part")
	}
	sig, err := mr.NextRawPart()
	if err != nil || sig.Header.Get("Content-Type") == "" {
		t.Fatal("missing detached signature")
	}
	if _, err = mr.NextRawPart(); err != io.EOF {
		t.Fatal("extra signature part")
	}
}

func TestSignedForwardInputDenials(t *testing.T) {
	builder, req, _, _, _ := forwardFixture(t)
	for name, mutate := range map[string]func(*ForwardMessage){
		"empty":             func(r *ForwardMessage) { r.CapturedOriginal = nil },
		"large":             func(r *ForwardMessage) { r.CapturedOriginal = make([]byte, MaxForwardOriginalBytes+1) },
		"address injection": func(r *ForwardMessage) { r.Identity.Address = "forward@example.test\nBcc: victim@example.test" },
		"display name":      func(r *ForwardMessage) { r.Identity.Address = "Forward <forward@example.test>" },
		"fingerprint":       func(r *ForwardMessage) { r.Identity.Fingerprint = "not-hex" },
		"unicode id":        func(r *ForwardMessage) { r.MessageID = "<nëw@example.test>" },
		"missing id":        func(r *ForwardMessage) { r.MessageID = "" },
		"id injection":      func(r *ForwardMessage) { r.MessageID = "<new@example.test>\nBcc: x@y.test" },
		"id control":        func(r *ForwardMessage) { r.MessageID = "<new\x00@example.test>" },
		"zero time":         func(r *ForwardMessage) { r.Date = time.Time{} },
		"year overflow":     func(r *ForwardMessage) { r.Date = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		t.Run(name, func(t *testing.T) {
			r := req
			mutate(&r)
			out, status, err := builder.Build(context.Background(), r)
			if err == nil || out != nil || status != (SignatureStatus{}) {
				t.Fatal("invalid input returned output")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, status, err := builder.Build(ctx, req)
	if err == nil || out != nil || status != (SignatureStatus{}) {
		t.Fatal("canceled build returned output")
	}
	for _, b := range []SignedForwardBuilder{{}, {Signer: builder.Signer, Verifier: builder.Verifier}, {Resolver: builder.Resolver, Verifier: builder.Verifier}, {Resolver: builder.Resolver, Signer: builder.Signer}} {
		out, status, err := b.Build(context.Background(), req)
		if err == nil || out != nil || status != (SignatureStatus{}) {
			t.Fatal("missing dependency returned output")
		}
	}
}

func TestSignedForwardRealLifecycleDenials(t *testing.T) {
	for _, name := range []string{"missing", "mismatch", "unknown identity", "revoked", "expired", "duplicate entity", "unsupported hash"} {
		t.Run(name, func(t *testing.T) {
			builder, req, registry, key, entity := forwardFixture(t)
			switch name {
			case "missing":
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			case "mismatch":
				req.Identity.Fingerprint = strings.Repeat("0", 40)
			case "unknown identity":
				req.Identity.Address = "unconfigured@example.test"
			case "revoked":
				if err := entity.RevokeKey(packet.KeyRetired, "synthetic", &packet.Config{DefaultHash: crypto.SHA256, Time: fixedOpenPGPTime}); err != nil {
					t.Fatal(err)
				}
				writeRuntimePrivateKey(t, key, entity, 0600)
			case "expired":
				var err error
				entity, err = protonpgp.NewEntity("Expired", "", req.Identity.Address, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, DefaultHash: crypto.SHA256, KeyLifetimeSecs: 1, Time: fixedOpenPGPTime})
				if err != nil {
					t.Fatal(err)
				}
				req.Identity.Fingerprint = entityFingerprint(entity)
				entry := registry.mailboxes[req.Identity.Address]
				entry.SigningFingerprint = req.Identity.Fingerprint
				registry.mailboxes[req.Identity.Address] = entry
				registry.now = func() time.Time { return fixedOpenPGPTime().Add(time.Hour) }
				writeRuntimePrivateKey(t, key, entity, 0600)
			case "duplicate entity":
				var duplicated bytes.Buffer
				for range 2 {
					if err := entity.SerializePrivate(&duplicated, &packet.Config{DefaultHash: crypto.SHA256, Time: fixedOpenPGPTime}); err != nil {
						t.Fatal(err)
					}
				}
				parsed, err := protonpgp.ReadKeyRing(bytes.NewReader(duplicated.Bytes()))
				if err != nil || len(parsed) != 2 {
					t.Fatalf("fixture must contain two readable entities: count=%d err=%v", len(parsed), err)
				}
				var encoded bytes.Buffer
				w, err := armor.Encode(&encoded, protonpgp.PrivateKeyType, nil)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = w.Write(duplicated.Bytes()); err != nil {
					t.Fatal(err)
				}
				if err = w.Close(); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(key, encoded.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			case "unsupported hash":
				var err error
				entity, err = protonpgp.NewEntity("Unsupported", "", req.Identity.Address, &packet.Config{Algorithm: packet.PubKeyAlgoECDSA, Curve: packet.CurveNistP384, DefaultHash: crypto.SHA256, Time: fixedOpenPGPTime})
				if err != nil {
					t.Fatal(err)
				}
				req.Identity.Fingerprint = entityFingerprint(entity)
				entry := registry.mailboxes[req.Identity.Address]
				entry.SigningFingerprint = req.Identity.Fingerprint
				registry.mailboxes[req.Identity.Address] = entry
				writeRuntimePrivateKey(t, key, entity, 0600)
			}
			out, status, err := builder.Build(context.Background(), req)
			if err == nil || out != nil || status != (SignatureStatus{}) {
				t.Fatal("unusable lifecycle returned output")
			}
		})
	}
}

func TestSignedForwardFramingBoundsUseProductionHelpers(t *testing.T) {
	for _, n := range []int{0, 1, 56, 57, 58, 1 << 20, 19156674, MaxForwardOriginalBytes - 1, MaxForwardOriginalBytes} {
		t.Run(fmt.Sprintf("size-%d", n), func(t *testing.T) {
			wantEncoded := independentForwardBase64FramedBytes(t, n)
			gotEncoded, ok := forwardBase64FramedBytes(int64(n))
			if !ok || gotEncoded != wantEncoded {
				t.Fatalf("encoded=%d ok=%t want=%d", gotEncoded, ok, wantEncoded)
			}
			gotMixed, ok := forwardMixedMessageBound(n)
			if !ok || int64(gotMixed) != wantEncoded+1557 {
				t.Fatalf("mixed=%d ok=%t want=%d", gotMixed, ok, wantEncoded+1557)
			}
		})
	}
}

func TestSignedForwardSizeBoundary(t *testing.T) {
	const wantOriginal = 50 << 20
	const wantSigned = 72796392
	if MaxForwardOriginalBytes != wantOriginal {
		t.Fatalf("original limit=%d want %d", MaxForwardOriginalBytes, wantOriginal)
	}
	if MaxForwardSignedBytes != wantSigned {
		t.Fatalf("signed limit=%d want %d", MaxForwardSignedBytes, wantSigned)
	}
	if got, want := forwardBase64FramedBytesForTest(wantOriginal), 71744676; got != want {
		t.Fatalf("encoded original bytes=%d want %d", got, want)
	}
	builder, req, _, _, _ := forwardFixture(t)
	original := make([]byte, 64<<20)
	for i := range original {
		original[i] = byte(i)
	}
	for _, n := range []int{1, 56, 57, 58, 1 << 20, 19156674, wantOriginal - 1, wantOriginal, wantOriginal + 1, 64 << 20} {
		req.CapturedOriginal = original[:n]
		out, status, err := builder.Build(context.Background(), req)
		if n > wantOriginal {
			if err == nil || out != nil || status != (SignatureStatus{}) {
				t.Fatalf("overlimit size %d returned bytes", n)
			}
			continue
		}
		if err != nil {
			t.Fatalf("size %d rejected: %v", n, err)
		}
		if len(out) > MaxForwardSignedBytes {
			t.Fatalf("size %d signed output=%d cap=%d", n, len(out), MaxForwardSignedBytes)
		}
		assertForwardMessage(t, out, req)
		if n == wantOriginal {
			if _, err := ParseRawMessage("forward", "INBOX", out); err == nil {
				t.Fatal("display parser accepted full-size forwarded original")
			}
		}
	}
}

func TestSignedForwardMaxMetadataAtFullSize(t *testing.T) {
	address := maxValidForwardAddress()
	entity := testOpenPGPEntity(t, "Full Size Forwarding", address)
	dir := t.TempDir()
	key := filepath.Join(dir, "synthetic.asc")
	writeRuntimePrivateKey(t, key, entity, 0600)
	secret := writeRuntimeFile(t, dir, "synthetic-password", []byte("test-only"), 0600)
	identity := Identity{Address: address, Fingerprint: entityFingerprint(entity)}
	registry, err := NewRuntimeRegistry(RuntimeConfig{IMAPAddr: "localhost:143", SMTPAddr: "localhost:25", SMTPAuthMechanism: "cram-md5", Mailboxes: []RuntimeMailbox{{Address: identity.Address, SigningFingerprint: identity.Fingerprint, PrivateKeyFile: key, IMAPPasswordFile: secret, SMTPPasswordFile: secret}}})
	if err != nil {
		t.Fatal(err)
	}
	registry.now = fixedOpenPGPTime
	req := ForwardMessage{
		Identity:         identity,
		CapturedOriginal: bytes.Repeat([]byte{0xa5}, MaxForwardOriginalBytes),
		MessageID:        "<" + strings.Repeat("a", 251) + "@b>",
		Date:             time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	if len(req.Identity.Address) != 254 || len(req.MessageID) != 255 {
		t.Fatalf("fixture lengths address=%d messageID=%d", len(req.Identity.Address), len(req.MessageID))
	}
	if len(req.Identity.Fingerprint) != 40 && len(req.Identity.Fingerprint) != 64 {
		t.Fatalf("unexpected real fingerprint length=%d", len(req.Identity.Fingerprint))
	}
	t.Logf("real OpenPGP fingerprint length=%d", len(req.Identity.Fingerprint))
	builder := SignedForwardBuilder{Resolver: registry, Signer: registry, Verifier: registry}
	out, status, err := builder.Build(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Signed || status.Identity != req.Identity.Address || status.Fingerprint != req.Identity.Fingerprint {
		t.Fatal("wrong identity evidence")
	}
	if len(out) > MaxForwardSignedBytes {
		t.Fatalf("signed output=%d cap=%d", len(out), MaxForwardSignedBytes)
	}
	assertForwardMessage(t, out, req)
}

func TestSignedForwardRejectsOversizeBeforeDependencies(t *testing.T) {
	for _, n := range []int{MaxForwardOriginalBytes + 1, 64 << 20} {
		t.Run(fmt.Sprintf("size-%d", n), func(t *testing.T) {
			_, req, _, _, _ := forwardFixture(t)
			req.CapturedOriginal = make([]byte, n)
			var resolverCalls, signerCalls, verifierCalls int
			builder := SignedForwardBuilder{
				Resolver: forwardResolverFunc(func(context.Context, string, string, string) (Identity, error) {
					resolverCalls++
					return Identity{}, errors.New("resolver must not run")
				}),
				Signer: forwardSignerFunc(func(context.Context, Identity, []byte) ([]byte, SignatureStatus, error) {
					signerCalls++
					return nil, SignatureStatus{}, errors.New("signer must not run")
				}),
				Verifier: forwardVerifierFunc(func(context.Context, []byte, Identity) (SignatureStatus, error) {
					verifierCalls++
					return SignatureStatus{}, errors.New("verifier must not run")
				}),
			}
			out, status, err := builder.Build(context.Background(), req)
			if err == nil || out != nil || status != (SignatureStatus{}) || resolverCalls != 0 || signerCalls != 0 || verifierCalls != 0 {
				t.Fatalf("oversize reached dependencies or returned output: resolver=%d signer=%d verifier=%d out=%t signed=%t err=%v", resolverCalls, signerCalls, verifierCalls, out != nil, status.Signed, err)
			}
		})
	}
}

func independentForwardBase64FramedBytes(t *testing.T, n int) int64 {
	t.Helper()
	if n < 0 {
		t.Fatal("negative size")
	}
	groups := int64(n / 3)
	if n%3 != 0 {
		groups++
	}
	lines := int64(n / 57)
	if n%57 != 0 {
		lines++
	}
	return groups*4 + lines*2
}

func forwardBase64FramedBytesForTest(n int) int {
	groups := (n + 2) / 3
	lines := (n + 56) / 57
	return groups*4 + lines*2
}

func maxValidForwardAddress() string {
	return strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
}

// Seam failures supplement, not replace, the real crypto/lifecycle tests.
type forwardResolverFunc func(context.Context, string, string, string) (Identity, error)

func (f forwardResolverFunc) ResolveSender(c context.Context, p, a, s string) (Identity, error) {
	return f(c, p, a, s)
}

type forwardSignerFunc func(context.Context, Identity, []byte) ([]byte, SignatureStatus, error)

func (f forwardSignerFunc) SignMIME(c context.Context, i Identity, b []byte) ([]byte, SignatureStatus, error) {
	return f(c, i, b)
}

type forwardVerifierFunc func(context.Context, []byte, Identity) (SignatureStatus, error)

func (f forwardVerifierFunc) VerifyExactSender(c context.Context, b []byte, i Identity) (SignatureStatus, error) {
	return f(c, b, i)
}

func TestSignedForwardDependencyFailuresReturnNoOutput(t *testing.T) {
	base, req, _, _, _ := forwardFixture(t)
	for _, name := range []string{"resolver error", "resolver mismatch", "sign error", "sign status", "verify error", "verify status", "empty signed", "oversized signed"} {
		t.Run(name, func(t *testing.T) {
			b := base
			signCalls, verifyCalls := 0, 0
			b.Signer = forwardSignerFunc(func(c context.Context, i Identity, m []byte) ([]byte, SignatureStatus, error) {
				signCalls++
				switch name {
				case "sign error":
					return []byte("unsigned"), SignatureStatus{}, errors.New("SECRET dependency detail")
				case "sign status":
					return []byte("unsigned"), SignatureStatus{}, nil
				case "empty signed":
					return nil, SignatureStatus{Signed: true, Identity: i.Address, Fingerprint: i.Fingerprint}, nil
				case "oversized signed":
					return make([]byte, MaxForwardSignedBytes+1), SignatureStatus{Signed: true, Identity: i.Address, Fingerprint: i.Fingerprint}, nil
				}
				return base.Signer.SignMIME(c, i, m)
			})
			b.Verifier = forwardVerifierFunc(func(c context.Context, m []byte, i Identity) (SignatureStatus, error) {
				verifyCalls++
				if name == "verify error" {
					return SignatureStatus{}, errors.New("SECRET dependency detail")
				}
				if name == "verify status" {
					return SignatureStatus{}, nil
				}
				return base.Verifier.VerifyExactSender(c, m, i)
			})
			if strings.HasPrefix(name, "resolver ") {
				b.Resolver = forwardResolverFunc(func(context.Context, string, string, string) (Identity, error) {
					if name == "resolver error" {
						return Identity{}, errors.New("SECRET dependency detail")
					}
					return Identity{Address: "other@example.test", Fingerprint: req.Identity.Fingerprint}, nil
				})
			}
			out, status, err := b.Build(context.Background(), req)
			if err == nil || out != nil || status != (SignatureStatus{}) {
				t.Fatal("dependency failure returned output")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("dependency error leaked")
			}
			if strings.HasPrefix(name, "resolver ") && signCalls != 0 {
				t.Fatal("signer called after resolver failure")
			}
			if !strings.HasPrefix(name, "verify ") && verifyCalls != 0 {
				t.Fatal("verifier called after earlier failure")
			}
		})
	}
}

// Benchmark includes resolution/key-file reload, MIME, real signing and verification.
// It is an operation-cost observation, not a speedup or delivery-throughput claim.
func BenchmarkSignedForward(b *testing.B) {
	entity, err := protonpgp.NewEntity("Forwarding", "", "forward@example.test", &packet.Config{DefaultHash: crypto.SHA256, Time: fixedOpenPGPTime, RSABits: 2048})
	if err != nil {
		b.Fatal(err)
	}
	var raw bytes.Buffer
	if err := entity.SerializePrivate(&raw, nil); err != nil {
		b.Fatal(err)
	}
	key := filepath.Join(b.TempDir(), "synthetic-key")
	if err := os.WriteFile(key, raw.Bytes(), 0600); err != nil {
		b.Fatal(err)
	}
	identity := Identity{Address: "forward@example.test", Fingerprint: entityFingerprint(entity)}
	registry := &RuntimeRegistry{mailboxes: map[string]RuntimeMailbox{identity.Address: {Address: identity.Address, SigningFingerprint: identity.Fingerprint, PrivateKeyFile: key}}, now: fixedOpenPGPTime}
	builder := SignedForwardBuilder{Resolver: registry, Signer: registry, Verifier: registry}
	for _, tc := range []struct {
		name string
		size int
	}{{"empty-denied", 0}, {"one-byte", 1}, {"small-1KiB", 1024}, {"typical-64KiB", 64 << 10}, {"large-1MiB", 1 << 20}, {"historical-19MiB", 19156674}, {"full-50MiB", 50 << 20}} {
		b.Run(tc.name, func(b *testing.B) {
			req := ForwardMessage{Identity: identity, CapturedOriginal: bytes.Repeat([]byte{255}, tc.size), MessageID: "<benchmark@example.test>", Date: fixedOpenPGPTime()}
			b.ReportAllocs()
			b.SetBytes(int64(tc.size))
			b.ResetTimer()
			for b.Loop() {
				out, _, err := builder.Build(context.Background(), req)
				if tc.size == 0 {
					if err == nil || out != nil {
						b.Fatal("empty accepted")
					}
				} else if err != nil || len(out) == 0 {
					b.Fatal("signed build failed", err)
				}
			}
		})
	}
}

func TestSignedForwardOutputLimitBeforeVerification(t *testing.T) {
	base, req, _, _, _ := forwardFixture(t)
	for _, size := range []int{MaxForwardSignedBytes - 1, MaxForwardSignedBytes, MaxForwardSignedBytes + 1} {
		calls := 0
		b := base
		b.Signer = forwardSignerFunc(func(context.Context, Identity, []byte) ([]byte, SignatureStatus, error) {
			return bytes.Repeat([]byte{'x'}, size), SignatureStatus{Signed: true, Identity: req.Identity.Address, Fingerprint: req.Identity.Fingerprint}, nil
		})
		b.Verifier = forwardVerifierFunc(func(context.Context, []byte, Identity) (SignatureStatus, error) {
			calls++
			return SignatureStatus{}, errors.New("intentional verification denial")
		})
		out, _, err := b.Build(context.Background(), req)
		if out != nil || err == nil {
			t.Fatal("synthetic unverified output escaped")
		}
		want := 1
		if size > MaxForwardSignedBytes {
			want = 0
		}
		if calls != want {
			t.Fatalf("size%d verify calls%d want%d", size, calls, want)
		}
	}
	b := base
	b.Signer = forwardSignerFunc(func(context.Context, Identity, []byte) ([]byte, SignatureStatus, error) {
		return bytes.Repeat([]byte{'\n'}, MaxForwardSignedBytes), SignatureStatus{Signed: true, Identity: req.Identity.Address, Fingerprint: req.Identity.Fingerprint}, nil
	})
	calls := 0
	b.Verifier = forwardVerifierFunc(func(context.Context, []byte, Identity) (SignatureStatus, error) {
		calls++
		return SignatureStatus{}, errors.New("must not reach verifier")
	})
	out, _, err := b.Build(context.Background(), req)
	if err == nil || out != nil || calls != 0 {
		t.Fatal("canonicalization growth exceeded output limit")
	}
}

func TestSignedForwardAlreadyCanonicalSigner(t *testing.T) {
	b, req, _, _, _ := forwardFixture(t)
	signer := b.Signer
	b.Signer = forwardSignerFunc(func(c context.Context, i Identity, m []byte) ([]byte, SignatureStatus, error) {
		raw, status, err := signer.SignMIME(c, i, m)
		if err != nil {
			return nil, status, err
		}
		raw = bytes.ReplaceAll(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
		return raw, status, nil
	})
	out, _, err := b.Build(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertForwardMessage(t, out, req)
}

func TestSignedForwardCancellationAfterDependencies(t *testing.T) {
	base, req, _, _, _ := forwardFixture(t)
	for _, stage := range []string{"resolve", "sign", "verify"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := base
			signCalls, verifyCalls := 0, 0
			b.Resolver = forwardResolverFunc(func(c context.Context, p, a, s string) (Identity, error) {
				i, err := base.Resolver.ResolveSender(c, p, a, s)
				if stage == "resolve" {
					cancel()
				}
				return i, err
			})
			b.Signer = forwardSignerFunc(func(c context.Context, i Identity, m []byte) ([]byte, SignatureStatus, error) {
				signCalls++
				raw, status, err := base.Signer.SignMIME(c, i, m)
				if stage == "sign" {
					cancel()
				}
				return raw, status, err
			})
			b.Verifier = forwardVerifierFunc(func(c context.Context, m []byte, i Identity) (SignatureStatus, error) {
				verifyCalls++
				status, err := base.Verifier.VerifyExactSender(c, m, i)
				if stage == "verify" {
					cancel()
				}
				return status, err
			})
			out, status, err := b.Build(ctx, req)
			if !errors.Is(err, context.Canceled) || out != nil || status != (SignatureStatus{}) {
				t.Fatal("canceled build returned output")
			}
			if stage == "resolve" && signCalls != 0 {
				t.Fatal("sign after cancel")
			}
			if stage != "verify" && verifyCalls != 0 {
				t.Fatal("verify after cancel")
			}
		})
	}
}

// Deterministic cancellation at the first encoding chunk; no timing race.
type forwardEncodingContext struct {
	context.Context
	cancel context.CancelFunc
	calls  int
}

func (c *forwardEncodingContext) Err() error {
	c.calls++
	if c.calls == 4 {
		c.cancel()
	}
	return c.Context.Err()
}
func TestSignedForwardCancellationDuringEncoding(t *testing.T) {
	b, req, _, _, _ := forwardFixture(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &forwardEncodingContext{Context: parent, cancel: cancel}
	signCalls := 0
	b.Signer = forwardSignerFunc(func(context.Context, Identity, []byte) ([]byte, SignatureStatus, error) {
		signCalls++
		return nil, SignatureStatus{}, errors.New("must not sign after cancellation")
	})
	out, status, err := b.Build(ctx, req)
	if !errors.Is(err, context.Canceled) || out != nil || status != (SignatureStatus{}) || signCalls != 0 || ctx.calls != 4 {
		t.Fatal("encoding cancellation did not stop signing")
	}
}

func TestSignedForwardMessageIDGrammar(t *testing.T) {
	b, req, registry, _, _ := forwardFixture(t)
	for _, id := range []string{"<@>", "<a@>", "<@example.test>", "<a..b@example.test>", "<.a@b>", "<a.@b>", "<a@.b>", "<a@b.>", "<a@b..c>", "<a:b@c>", "<a@b,c>", "<a@b@c>", "<a@[127.0.0.1]>", "<\"a\"@b>", "<a(b)@c>", "<a\\b@c>", "<a@b;>", "<a@b> ", "<" + strings.Repeat("a", 252) + "@b>"} {
		t.Run(id, func(t *testing.T) {
			req.MessageID = id
			calls := 0
			b.Resolver = forwardResolverFunc(func(c context.Context, p, a, s string) (Identity, error) {
				calls++
				return registry.ResolveSender(c, p, a, s)
			})
			out, status, err := b.Build(context.Background(), req)
			if err == nil || out != nil || status != (SignatureStatus{}) || calls != 0 {
				t.Fatalf("malformed ID returned output=%t signed=%t error=%t resolverCalls=%d", out != nil, status.Signed, err != nil, calls)
			}
		})
	}
	b.Resolver = registry
	for _, id := range []string{"<a@b>", "<new-forward@example.test>", "<a.b+tag@host.example>", "<a@b/>", "<" + strings.Repeat("a", 251) + "@b>", "<!#$%&'*+-/=?^_" + string(rune(96)) + "{|}~@EXAMPLE.test>"} {
		t.Run("valid-"+id, func(t *testing.T) {
			req.MessageID = id
			out, status, err := b.Build(context.Background(), req)
			if err != nil || !status.Signed {
				t.Fatal("valid ID rejected", err)
			}
			assertForwardMessage(t, out, req)
		})
	}
}

// Fixed synthetic P256 fixture generated once, never regenerated in CI.
// Its final signature octet is whitespace; trimming corrupts the last entity.
func TestSignedForwardBinaryKeyRegression(t *testing.T) {
	raw, err := os.ReadFile("testdata/synthetic-whitespace.pgp")
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256.Sum256(raw); hex.EncodeToString(got[:]) != "fbc7918e856947a3ef5331f93669ade507692ac4ecff1b4b56a5d1f7cb4a9f35" {
		t.Fatal("fixture digest changed")
	}
	entities, err := protonpgp.ReadKeyRing(bytes.NewReader(raw))
	if err != nil || len(entities) != 1 {
		t.Fatal("single fixture invalid", err)
	}
	duplicate := append(bytes.Clone(raw), raw...)
	full, err := protonpgp.ReadKeyRing(bytes.NewReader(duplicate))
	if err != nil || len(full) != 2 {
		t.Fatal("untrimmed duplicate oracle", err)
	}
	trimmed := bytes.TrimSpace(duplicate)
	partial, err := protonpgp.ReadKeyRing(bytes.NewReader(trimmed))
	if err != nil || len(partial) != 1 || len(trimmed) != len(duplicate)-1 {
		t.Fatal("trim corruption oracle", err)
	}
	t.Logf("single=%d untrimmed=%d trimmed=%d bytes=%d duplicateBytes=%d trimmedBytes=%d duplicateSHA256=%x trimmedSHA256=%x", len(entities), len(full), len(partial), len(raw), len(duplicate), len(trimmed), sha256.Sum256(duplicate), sha256.Sum256(trimmed))
	for _, tc := range []struct {
		name string
		raw  []byte
		deny bool
	}{{"binary-single-whitespace", raw, false}, {"binary-duplicate", duplicate, true}, {"armor-duplicate", forwardArmor(t, duplicate), true}, {"armor-single", forwardArmor(t, raw), false}} {
		t.Run(tc.name, func(t *testing.T) {
			_, req, _, key, _ := forwardFixture(t)
			id := Identity{Address: req.Identity.Address, Fingerprint: entityFingerprint(entities[0])}
			// Registry validates at construction; initialize with valid armor then replace
			// bytes to exercise per-operation reload in the real builder.
			if err := os.WriteFile(key, forwardArmor(t, raw), 0600); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(filepath.Dir(key), "synthetic-password")
			r, err := NewRuntimeRegistry(RuntimeConfig{IMAPAddr: "localhost:143", SMTPAddr: "localhost:25", SMTPAuthMechanism: "cram-md5", Mailboxes: []RuntimeMailbox{{Address: id.Address, SigningFingerprint: id.Fingerprint, PrivateKeyFile: key, IMAPPasswordFile: secret, SMTPPasswordFile: secret}}})
			if err != nil {
				t.Fatal(err)
			}
			r.now = func() time.Time { return time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC) }
			req.Identity = id
			req.Date = r.now()
			if err := os.WriteFile(key, tc.raw, 0600); err != nil {
				t.Fatal(err)
			}
			b := SignedForwardBuilder{Resolver: r, Signer: r, Verifier: r}
			out, status, err := b.Build(context.Background(), req)
			if tc.deny {
				if err == nil || out != nil || status != (SignatureStatus{}) {
					t.Fatalf("ambiguous key admitted: output=%t signed=%t error=%t", out != nil, status.Signed, err != nil)
				}
				return
			}
			if err != nil || !status.Signed {
				t.Fatal("valid binary/armor rejected", err)
			}
			assertForwardMessage(t, out, req)
		})
	}
}
func forwardArmor(t *testing.T, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := armor.Encode(&b, protonpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
