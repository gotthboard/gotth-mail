package webmail

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"os"
	"strings"
	"testing"
)

func TestParseRawMessageHostileMultipartFixture(t *testing.T) {
	raw, err := os.ReadFile("../../test/fixtures/webmail/hostile-multipart.eml")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := ParseRawMessage("42", "INBOX", raw)
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != "42" || msg.Folder != "INBOX" || !strings.Contains(msg.From, "evil@example.test") || !strings.Contains(msg.To, "user@example.test") {
		t.Fatalf("bad envelope: %#v", msg)
	}
	if msg.BodyText != "plain body" {
		t.Fatalf("body text=%q", msg.BodyText)
	}
	if !strings.Contains(msg.BodyHTML, "<script>") || !strings.Contains(msg.BodyHTML, "javascript:bad") {
		t.Fatalf("parser should preserve hostile html as data for render boundary: %q", msg.BodyHTML)
	}
	clean := SanitizeHTML(msg.BodyHTML)
	for _, bad := range []string{"<script", "javascript:", "onclick=", "https://tracker.example.test"} {
		if strings.Contains(clean, bad) {
			t.Fatalf("sanitized html still contains %q: %s", bad, clean)
		}
	}
	if len(msg.Attachments) != 1 || !msg.HasAttachments {
		t.Fatalf("attachments=%#v", msg.Attachments)
	}
	a := msg.Attachments[0]
	if strings.Contains(a.Filename, "..") || strings.Contains(a.Filename, "/") || a.Filename == "../../evil.txt" {
		t.Fatalf("unsafe filename=%q", a.Filename)
	}
	if a.ContentType != "text/plain" || string(a.Content) != "payload" || a.Size != int64(len("payload")) {
		t.Fatalf("bad attachment=%#v", a)
	}
}

func TestParseRawMessageRejectsPartFloodFixture(t *testing.T) {
	raw, err := os.ReadFile("../../test/fixtures/webmail/mime-part-flood.eml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRawMessage("flood", "INBOX", raw); err == nil || !strings.Contains(err.Error(), "part limit") {
		t.Fatalf("part flood accepted err=%v", err)
	}
}

func TestParseRawMessageRejectsInvalidMultipartBoundary(t *testing.T) {
	raw := []byte("From: a@example.test\r\nTo: b@example.test\r\nSubject: bad\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed\r\n\r\nbody")
	if _, err := ParseRawMessage("bad", "INBOX", raw); err == nil || !strings.Contains(err.Error(), "invalid multipart boundary") {
		t.Fatalf("invalid boundary accepted err=%v", err)
	}
}

func TestParseRawMessageRejectsEncodedPartOverflow(t *testing.T) {
	base64Exact := strings.Repeat("QUFB", int(maxMIMEPartBytes/4))
	base64Over := base64Exact + "\nQUFB"
	base64FullDecoded := decodeBase64Fixture(t, base64Over)
	if got, want := len(base64FullDecoded), int(maxMIMEPartBytes/4*3)+3; got != want {
		t.Fatalf("base64 full decoded length=%d want=%d", got, want)
	}
	if prefixDecoded := decodeBase64Fixture(t, base64Over[:maxMIMEPartBytes+1]); !bytes.Equal(prefixDecoded, base64FullDecoded[:len(prefixDecoded)]) || len(prefixDecoded) != int(maxMIMEPartBytes/4*3) {
		t.Fatalf("base64 cap+1 prefix is not a clean truncated valid prefix: got=%d full=%d", len(prefixDecoded), len(base64FullDecoded))
	}

	qpBelow := qpEncodedFiller(int(maxMIMEPartBytes - 1))
	if got, want := len(qpBelow), int(maxMIMEPartBytes-1); got != want {
		t.Fatalf("quoted-printable below fixture encoded length=%d want=%d", got, want)
	}
	qpBelowDecoded := decodeQuotedPrintableFixture(t, qpBelow)
	if got, want := len(qpBelowDecoded), len(qpBelow); got != want {
		t.Fatalf("quoted-printable below decoded length=%d want=%d", got, want)
	}
	qpExact := qpEncodedFiller(int(maxMIMEPartBytes))
	qpOver := qpEncodedOverrunFixture()
	qpFullDecoded := decodeQuotedPrintableFixture(t, qpOver)
	if got, want := len(qpFullDecoded), qpOverDecodedLen(); got != want || !bytes.HasSuffix(qpFullDecoded, []byte("B")) {
		t.Fatalf("quoted-printable full decoded length=%d want=%d suffix=%q", got, want, qpFullDecoded[len(qpFullDecoded)-1:])
	}
	if prefixDecoded := decodeQuotedPrintableFixture(t, qpOver[:maxMIMEPartBytes+1]); !bytes.Equal(prefixDecoded, qpFullDecoded[:len(prefixDecoded)]) || len(prefixDecoded) >= len(qpFullDecoded) {
		t.Fatalf("quoted-printable cap+1 prefix is not a clean truncated valid prefix: prefix=%d full=%d", len(prefixDecoded), len(qpFullDecoded))
	}

	t.Run("base64 exact boundary", func(t *testing.T) {
		msg, err := ParseRawMessage("base64-exact", "INBOX", rawTransferMessage("base64", base64Exact))
		if err != nil {
			t.Fatalf("exact base64 boundary rejected: %v", err)
		}
		if got, want := len(msg.BodyText), int(maxMIMEPartBytes/4*3); got != want {
			t.Fatalf("base64 exact decoded length=%d want=%d", got, want)
		}
	})
	t.Run("base64 encoded overflow", func(t *testing.T) {
		if _, err := ParseRawMessage("base64-over", "INBOX", rawTransferMessage("base64", base64Over)); err == nil || !strings.Contains(err.Error(), "mime part too large") {
			t.Fatalf("base64 encoded overflow accepted err=%v", err)
		}
	})
	t.Run("quoted-printable exact boundary", func(t *testing.T) {
		if _, err := ParseRawMessage("qp-exact", "INBOX", rawTransferMessage("quoted-printable", qpExact)); err != nil {
			t.Fatalf("exact quoted-printable boundary rejected: %v", err)
		}
	})
	t.Run("quoted-printable encoded overflow", func(t *testing.T) {
		if _, err := ParseRawMessage("qp-over", "INBOX", rawTransferMessage("quoted-printable", qpOver)); err == nil || !strings.Contains(err.Error(), "mime part too large") {
			t.Fatalf("quoted-printable encoded overflow accepted err=%v", err)
		}
	})
	t.Run("multipart quoted-printable below boundary", func(t *testing.T) {
		msg, err := ParseRawMessage("multipart-qp-below", "INBOX", rawMultipartTransferMessage("quoted-printable", qpBelow))
		if err != nil {
			t.Fatalf("multipart below quoted-printable boundary rejected: %v", err)
		}
		if got, want := []byte(msg.BodyText), qpBelowDecoded; !bytes.Equal(got, want) {
			t.Fatalf("multipart quoted-printable below decoded mismatch: got len=%d want len=%d", len(got), len(want))
		}
	})
	t.Run("multipart quoted-printable exact boundary", func(t *testing.T) {
		msg, err := ParseRawMessage("multipart-qp-exact", "INBOX", rawMultipartTransferMessage("quoted-printable", qpExact))
		if err != nil {
			t.Fatalf("multipart exact quoted-printable boundary rejected: %v", err)
		}
		want := string(decodeQuotedPrintableFixture(t, qpExact))
		if msg.BodyText != want {
			t.Fatalf("multipart quoted-printable exact decoded mismatch: got len=%d want len=%d", len(msg.BodyText), len(want))
		}
	})
	t.Run("multipart quoted-printable encoded overflow", func(t *testing.T) {
		if _, err := ParseRawMessage("multipart-qp-over", "INBOX", rawMultipartTransferMessage("quoted-printable", qpOver)); err == nil || !strings.Contains(err.Error(), "mime part too large") {
			t.Fatalf("multipart quoted-printable encoded overflow accepted err=%v", err)
		}
	})
	t.Run("multipart base64 compatibility", func(t *testing.T) {
		msg, err := ParseRawMessage("multipart-base64", "INBOX", rawMultipartTransferMessage("base64", "QUJD"))
		if err != nil {
			t.Fatalf("multipart base64 rejected: %v", err)
		}
		if msg.BodyText != "ABC" {
			t.Fatalf("multipart base64 decoded body=%q", msg.BodyText)
		}
	})
	t.Run("plain overflow", func(t *testing.T) {
		plainOver := append(rawTransferMessage("", ""), bytes.Repeat([]byte{'x'}, int(maxMIMEPartBytes)+1)...)
		if _, err := ParseRawMessage("plain-over", "INBOX", plainOver); err == nil || !strings.Contains(err.Error(), "mime part too large") {
			t.Fatalf("plain overflow accepted err=%v", err)
		}
	})
	t.Run("malformed quoted-printable still reports decoder error", func(t *testing.T) {
		if _, err := ParseRawMessage("qp-bad", "INBOX", rawTransferMessage("quoted-printable", strings.Repeat("A", 80)+"=\r")); err == nil || strings.Contains(err.Error(), "mime part too large") {
			t.Fatalf("malformed quoted-printable did not preserve decoder error err=%v", err)
		}
	})
}

func rawTransferMessage(encoding, body string) []byte {
	var b strings.Builder
	b.WriteString("From: a@example.test\r\nTo: b@example.test\r\nSubject: encoded limit\r\nContent-Type: text/plain; charset=utf-8\r\n")
	if encoding != "" {
		b.WriteString("Content-Transfer-Encoding: ")
		b.WriteString(encoding)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

func rawMultipartTransferMessage(encoding, body string) []byte {
	const boundary = "encoded-limit-boundary"
	var b strings.Builder
	b.WriteString("From: a@example.test\r\nTo: b@example.test\r\nSubject: multipart encoded limit\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=")
	b.WriteString(boundary)
	b.WriteString("\r\n\r\n--")
	b.WriteString(boundary)
	b.WriteString("\r\nContent-Type: text/plain; charset=utf-8\r\n")
	if encoding != "" {
		b.WriteString("Content-Transfer-Encoding: ")
		b.WriteString(encoding)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	b.WriteString("\r\n--")
	b.WriteString(boundary)
	b.WriteString("--\r\n")
	return []byte(b.String())
}

func qpEncodedFiller(n int) string {
	var b strings.Builder
	b.Grow(n)
	for n > 0 {
		if n > 72 {
			b.WriteString(strings.Repeat("A", 70))
			b.WriteString("\r\n")
			n -= 72
			continue
		}
		b.WriteString(strings.Repeat("A", n))
		n = 0
	}
	return b.String()
}

func qpEncodedOverrunFixture() string {
	const block = "=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=\r\n"
	blocks := int(maxMIMEPartBytes / int64(len(block)))
	remainder := int(maxMIMEPartBytes+1) - blocks*len(block)
	return strings.Repeat(block, blocks) + strings.Repeat("=41", remainder/3) + "=\n" + "=42"
}

func qpOverDecodedLen() int {
	const block = "=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=41=\r\n"
	blocks := int(maxMIMEPartBytes / int64(len(block)))
	remainder := int(maxMIMEPartBytes+1) - blocks*len(block)
	return blocks*24 + remainder/3 + 1
}

func decodeBase64Fixture(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, strings.NewReader(encoded)))
	if err != nil {
		t.Fatalf("invalid base64 fixture: %v", err)
	}
	return decoded
}

func decodeQuotedPrintableFixture(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(encoded)))
	if err != nil {
		t.Fatalf("invalid quoted-printable fixture: %v", err)
	}
	return decoded
}
