package httpui

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

func TestRecoveryArtifactPinWrap(t *testing.T) {
	cases := []struct {
		name, pin string
		valid     bool
	}{
		{"zero", "sha256:" + strings.Repeat("0", 64), true},
		{"mixed", "sha256:" + strings.Repeat("0123456789abcdef", 4), true},
		{"high", "sha256:" + strings.Repeat("f", 64), true},
		{"empty", "", false}, {"short", "sha256:", false},
		{"63", "sha256:" + strings.Repeat("1", 63), false},
		{"65", "sha256:" + strings.Repeat("1", 65), false},
		{"uppercase", "sha256:" + strings.Repeat("A", 64), false},
		{"unicode", "sha256:" + strings.Repeat("é", 32), false},
		{"markup", "<script>alert(1)</script>&\"'", false},
	}
	var reference string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := extensionRecoveryView{Pin: tc.pin, PreviousPin: "sha256:" + strings.Repeat("9", 64), Theme: "light", ActionURL: "/admin/extensions/fixed?theme=light", CSRF: "csrf<&", Operation: "delete_secrets", PreviewID: "preview-fixed", Confirmation: "confirm-fixed", Revision: 3}
			var buf bytes.Buffer
			if err := extensionMetadataRecoveryDocument(view).Render(context.Background(), &buf); err != nil {
				t.Fatal(err)
			}
			doc, err := html.Parse(strings.NewReader(buf.String()))
			if err != nil {
				t.Fatal(err)
			}
			var artifact *html.Node
			var walk func(*html.Node)
			walk = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "dt" && n.FirstChild != nil && n.FirstChild.Data == "Artifact" {
					for q := n.NextSibling; q != nil; q = q.NextSibling {
						if q.Type == html.ElementNode {
							if q.Data != "dd" {
								t.Fatal("artifact is not a definition")
							}
							artifact = q
							break
						}
					}
				}
				for q := n.FirstChild; q != nil; q = q.NextSibling {
					walk(q)
				}
			}
			walk(doc)
			if artifact == nil {
				t.Fatal("artifact missing")
			}
			var text strings.Builder
			breaks := 0
			for n := artifact.FirstChild; n != nil; n = n.NextSibling {
				switch n.Type {
				case html.TextNode:
					text.WriteString(n.Data)
				case html.ElementNode:
					if n.Data != "wbr" || len(n.Attr) != 0 || n.FirstChild != nil {
						t.Fatal("unexpected artifact markup")
					}
					breaks++
				default:
					t.Fatal("unexpected artifact node")
				}
			}
			if text.String() != tc.pin {
				t.Fatal("artifact text changed")
			}
			want := 0
			if tc.valid {
				want = 4
			}
			if breaks != want {
				t.Errorf("break opportunities=%d want=%d", breaks, want)
			}
			if tc.valid {
				expected := "<dd>" + tc.pin[:7] + "<wbr>" + tc.pin[7:23] + "<wbr>" + tc.pin[23:39] + "<wbr>" + tc.pin[39:55] + "<wbr>" + tc.pin[55:] + "</dd>"
				if !strings.Contains(buf.String(), expected) {
					t.Error("missing exact bounded 20-byte wrapping markup")
				}
			}
			for artifact.FirstChild != nil {
				artifact.RemoveChild(artifact.FirstChild)
			}
			var normalized bytes.Buffer
			if err := html.Render(&normalized, doc); err != nil {
				t.Fatal(err)
			}
			if reference == "" {
				reference = normalized.String()
			} else if normalized.String() != reference {
				t.Fatal("non-artifact document/forms changed")
			}
		})
	}
}
