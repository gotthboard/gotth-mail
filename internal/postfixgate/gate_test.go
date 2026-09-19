package postfixgate

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"forgejo/gotthboard/gotth-mail/internal/outboundpolicy"
)

type fakeInspector struct {
	metadata outboundpolicy.QueueMetadata
	err      error
}

func (f fakeInspector) Inspect(context.Context, string) (outboundpolicy.QueueMetadata, error) {
	return f.metadata, f.err
}

type fakeController struct {
	decisions  map[string]outboundpolicy.Decision
	registered int
	reconciled int
	err        error
}

func (f *fakeController) Register(context.Context, outboundpolicy.QueueAdmissionRequest) error {
	f.registered++
	return f.err
}
func (f *fakeController) Decide(_ context.Context, _ string, recipient string) (outboundpolicy.Decision, error) {
	if f.err != nil {
		return outboundpolicy.Decision{}, f.err
	}
	return f.decisions[recipient], nil
}
func (f *fakeController) Reconcile(context.Context, string) error {
	f.reconciled++
	return f.err
}

type fakeRelay struct {
	calls int
	body  []byte
}

func (f *fakeRelay) Submit(_ context.Context, _ string, _ []string, message []byte) error {
	f.calls++
	f.body = append([]byte(nil), message...)
	return nil
}

func TestGateRegistersChecksEveryRecipientThenRelays(t *testing.T) {
	metadata := gateMetadata()
	control := &fakeController{decisions: map[string]outboundpolicy.Decision{
		"one@example.net": {Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted},
		"two@example.net": {Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonSameDomain},
	}}
	relay := &fakeRelay{}
	err := (Gate{Inspector: fakeInspector{metadata: metadata}, Control: control, Relay: relay}).Deliver(context.Background(), DeliveryRequest{
		QueueID: metadata.QueueID,
		Deliveries: []outboundpolicy.QueueDelivery{{
			OriginalRecipient: "one@example.net", Recipient: "one@example.net",
		}},
	}, bytes.NewBufferString("Subject: test\r\n\r\nbody\r\n"))
	if err != nil || control.registered != 1 || control.reconciled != 0 || relay.calls != 1 || !bytes.Contains(relay.body, []byte("body")) {
		t.Fatalf("registered=%d reconciled=%d relay=%d err=%v", control.registered, control.reconciled, relay.calls, err)
	}
}

func TestGateHoldsWholeMixedRecipientMessageBeforeRelay(t *testing.T) {
	metadata := gateMetadata()
	control := &fakeController{decisions: map[string]outboundpolicy.Decision{
		"one@example.net": {Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted},
		"two@example.net": {Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonPolicyHold},
	}}
	relay := &fakeRelay{}
	err := (Gate{Inspector: fakeInspector{metadata: metadata}, Control: control, Relay: relay}).Deliver(context.Background(), DeliveryRequest{
		QueueID: metadata.QueueID,
		Deliveries: []outboundpolicy.QueueDelivery{{
			OriginalRecipient: "one@example.net", Recipient: "one@example.net",
		}},
	}, bytes.NewBufferString("message"))
	if err == nil || control.reconciled != 1 || relay.calls != 0 {
		t.Fatalf("reconciled=%d relay=%d err=%v", control.reconciled, relay.calls, err)
	}
}

func TestGateFailsClosedBeforeReadingOrRelaying(t *testing.T) {
	metadata := gateMetadata()
	control := &fakeController{err: errors.New("database down")}
	relay := &fakeRelay{}
	err := (Gate{Inspector: fakeInspector{metadata: metadata}, Control: control, Relay: relay}).Deliver(context.Background(), DeliveryRequest{
		QueueID: metadata.QueueID,
		Deliveries: []outboundpolicy.QueueDelivery{{
			OriginalRecipient: "one@example.net", Recipient: "one@example.net",
		}},
	}, strings.NewReader(strings.Repeat("x", 1024)))
	if err == nil || relay.calls != 0 {
		t.Fatalf("relay=%d err=%v", relay.calls, err)
	}
}

func TestGateRetryAndReplayRecheckCurrentPolicy(t *testing.T) {
	metadata := gateMetadata()
	control := &fakeController{decisions: map[string]outboundpolicy.Decision{
		"one@example.net": {Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted},
		"two@example.net": {Action: outboundpolicy.ActionOK, Reason: outboundpolicy.ReasonUnrestricted},
	}}
	relay := &fakeRelay{}
	gate := Gate{Inspector: fakeInspector{metadata: metadata}, Control: control, Relay: relay}
	request := DeliveryRequest{QueueID: metadata.QueueID, Deliveries: []outboundpolicy.QueueDelivery{{OriginalRecipient: "one@example.net", Recipient: "one@example.net"}}}
	if err := gate.Deliver(context.Background(), request, bytes.NewBufferString("first")); err != nil {
		t.Fatal(err)
	}
	control.decisions["two@example.net"] = outboundpolicy.Decision{Action: outboundpolicy.ActionDefer, Reason: outboundpolicy.ReasonPolicyHold}
	if err := gate.Deliver(context.Background(), request, bytes.NewBufferString("retry")); err == nil {
		t.Fatal("retry bypassed changed policy")
	}
	if control.registered != 2 || control.reconciled != 1 || relay.calls != 1 {
		t.Fatalf("registered=%d reconciled=%d relay=%d", control.registered, control.reconciled, relay.calls)
	}
}

func gateMetadata() outboundpolicy.QueueMetadata {
	return outboundpolicy.QueueMetadata{
		QueueID:            "BCDFGHJKLMNPz6789",
		ArrivalFingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EnvelopeSender:     "user@example.test",
		Recipients:         []string{"one@example.net", "two@example.net"},
	}
}
