package generatedmsgid

import "testing"

func TestValidGeneratedMessageIDCorpus(t *testing.T) {
	valid := []string{"<new-forward@example.test>", "<x@y>", "<A.!#$%&'*+-/=?^_`{|}~@example.test>", "<local.part@sub.example.test>"}
	for _, id := range valid {
		if !Valid(id) {
			t.Fatalf("valid generated Message-ID rejected: %q", id)
		}
	}
	invalid := []string{"", "new-forward@example.test", "<new-forward..bad@example.test>", "<.bad@example.test>", "<bad.@example.test>", "<new forward@example.test>", "<@example.test>", "<local@>", "<local@[127.0.0.1]>", "<local@bad..test>"}
	for _, id := range invalid {
		if Valid(id) {
			t.Fatalf("invalid generated Message-ID accepted: %q", id)
		}
	}
}
