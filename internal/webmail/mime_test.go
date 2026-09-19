package webmail

import (
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
