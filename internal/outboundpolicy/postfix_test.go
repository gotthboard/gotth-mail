package outboundpolicy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeCommandRunner struct {
	output []byte
	err    error
	path   string
	args   []string
}

func (f *fakeCommandRunner) Run(_ context.Context, path string, args []string, _ int) ([]byte, error) {
	f.path = path
	f.args = append([]string(nil), args...)
	return append([]byte(nil), f.output...), f.err
}

func TestPostfixBoundaryInspectsStructuredQueueAndHoldsExactID(t *testing.T) {
	runner := &fakeCommandRunner{output: []byte(
		`{"queue_name":"deferred","queue_id":"Other0VXxznjll","arrival_time":1,"message_size":12,"sender":"other@example.test","recipients":[{"address":"x@example.test"}]}` + "\n" +
			`{"queue_name":"deferred","queue_id":"3Pt2mN2VXxznjll","arrival_time":1700000000,"message_size":512,"sender":"Sender@Example.TEST","recipients":[{"address":"outside@Example.NET."},{"address":"local@example.test"}]}` + "\n"),
	}
	boundary := PostfixBoundary{
		Runner:         runner,
		PostqueuePath:  "/usr/sbin/postqueue",
		PostsuperPath:  "/usr/sbin/postsuper",
		InstanceID:     "mail.example.test",
		MaxOutputBytes: 1 << 20,
	}
	metadata, err := boundary.Inspect(context.Background(), "3Pt2mN2VXxznjll")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Held || metadata.EnvelopeSender != "Sender@example.test" || len(metadata.Recipients) != 2 || len(metadata.ArrivalFingerprint) != 64 {
		t.Fatalf("metadata=%+v", metadata)
	}
	if runner.path != "/usr/sbin/postqueue" || len(runner.args) != 1 || runner.args[0] != "-j" {
		t.Fatalf("postqueue invocation=%q %q", runner.path, runner.args)
	}
	if err := boundary.Hold(context.Background(), metadata.QueueID); err != nil {
		t.Fatal(err)
	}
	if runner.path != "/usr/sbin/postsuper" || len(runner.args) != 2 || runner.args[0] != "-h" || runner.args[1] != metadata.QueueID {
		t.Fatalf("postsuper invocation=%q %q", runner.path, runner.args)
	}
	if err := boundary.Release(context.Background(), metadata.QueueID); err != nil {
		t.Fatal(err)
	}
	if runner.path != "/usr/sbin/postsuper" || len(runner.args) != 2 || runner.args[0] != "-H" || runner.args[1] != metadata.QueueID {
		t.Fatalf("postsuper release invocation=%q %q", runner.path, runner.args)
	}
}

func TestPostfixBoundaryFailsClosedOnChangingDuplicateOrUnsafeInput(t *testing.T) {
	line := `{"queue_name":"deferred","queue_id":"3Pt2mN2VXxznjll","arrival_time":1700000000,"message_size":512,"sender":"sender@example.test","recipients":[{"address":"local@example.test"}]}`
	changed := strings.Replace(line, `"queue_name":"deferred"`, `"queue_name":"hold"`, 1)
	runner := &fakeCommandRunner{output: []byte(line + "\n" + changed + "\n")}
	boundary := PostfixBoundary{Runner: runner, PostqueuePath: "/usr/sbin/postqueue", PostsuperPath: "/usr/sbin/postsuper", InstanceID: "mail.example.test", MaxOutputBytes: 1 << 20}
	if _, err := boundary.Inspect(context.Background(), "3Pt2mN2VXxznjll"); err == nil {
		t.Fatal("changing duplicate queue metadata accepted")
	}
	for _, queueID := range []string{"ALL", "-", "../../ALL", "ABCDEF1234567890"} {
		if err := boundary.Hold(context.Background(), queueID); err == nil {
			t.Fatalf("unsafe queue ID %q accepted", queueID)
		}
		if err := boundary.Release(context.Background(), queueID); err == nil {
			t.Fatalf("unsafe queue ID %q released", queueID)
		}
	}
}

func TestPostfixBoundaryRejectsMalformedMissingAndOversizedOutput(t *testing.T) {
	tests := []struct {
		name   string
		output []byte
		runErr error
	}{
		{name: "malformed", output: []byte("not-json\n")},
		{name: "missing", output: []byte(`{"queue_name":"deferred","queue_id":"Other0VXxznjll","arrival_time":1,"message_size":12,"sender":"other@example.test","recipients":[{"address":"x@example.test"}]}` + "\n")},
		{name: "oversized", output: []byte(strings.Repeat("x", 1025))},
		{name: "command failure", runErr: errors.New("postqueue failed")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeCommandRunner{output: tc.output, err: tc.runErr}
			boundary := PostfixBoundary{Runner: runner, PostqueuePath: "/usr/sbin/postqueue", PostsuperPath: "/usr/sbin/postsuper", InstanceID: "mail.example.test", MaxOutputBytes: 1024}
			if _, err := boundary.Inspect(context.Background(), "3Pt2mN2VXxznjll"); err == nil {
				t.Fatal("invalid postqueue output accepted")
			}
		})
	}
}

func TestQueueArrivalFingerprintIsCanonical(t *testing.T) {
	left, err := QueueArrivalFingerprint("Mail.Example.TEST.", "3Pt2mN2VXxznjll", 1700000000, 512, "Sender@Example.TEST.", []string{"b@example.test", "a@BÜCHER.example"})
	if err != nil {
		t.Fatal(err)
	}
	right, err := QueueArrivalFingerprint("mail.example.test", "3Pt2mN2VXxznjll", 1700000000, 512, "Sender@example.test", []string{"a@xn--bcher-kva.example", "b@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if left != right || len(left) != 64 {
		t.Fatalf("fingerprints=%q/%q", left, right)
	}
}
