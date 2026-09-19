package outboundpolicy

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "ascii case and terminal dot", in: "Example.TEST.", want: "example.test"},
		{name: "unicode lookup form", in: "BÜCHER.example", want: "xn--bcher-kva.example"},
		{name: "unicode dot", in: "example\u3002test", want: "example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeDomain(tt.in)
			if err != nil {
				t.Fatalf("NormalizeDomain(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDomain(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeDomainRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", ".", "..", ".example.test", "example.test..", "bad_domain.test", "a..test", "-bad.test", "bad-.test"} {
		in := in
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			if got, err := NormalizeDomain(in); err == nil {
				t.Fatalf("NormalizeDomain(%q) = %q, want error", in, got)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		req  Request
		want Decision
	}{
		{
			name: "unrestricted compatibility default",
			req:  Request{Stage: StageSubmission, Recipient: "outside@example.net", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}}},
			want: Decision{Action: ActionOK, Reason: ReasonUnrestricted},
		},
		{
			name: "exact domain allowed after IDNA normalization",
			req:  Request{Stage: StageSubmission, Recipient: "user@xn--bcher-kva.example", Governing: []GoverningDomain{{Domain: "BÜCHER.example.", Scope: ScopeSameDomainOnly, Revision: 3}}},
			want: Decision{Action: ActionOK, Reason: ReasonSameDomain, Revisions: map[string]uint64{"xn--bcher-kva.example": 3}},
		},
		{
			name: "subdomain rejected",
			req:  Request{Stage: StageSubmission, Recipient: "user@sub.example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeSameDomainOnly, Revision: 2}}},
			want: Decision{Action: ActionReject, Reason: ReasonRecipientForbidden, Revisions: map[string]uint64{"example.test": 2}},
		},
		{
			name: "other hosted domain rejected",
			req:  Request{Stage: StageSubmission, Recipient: "user@other.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeSameDomainOnly, Revision: 2}}},
			want: Decision{Action: ActionReject, Reason: ReasonRecipientForbidden, Revisions: map[string]uint64{"example.test": 2}},
		},
		{
			name: "transport mismatch holds",
			req:  Request{Stage: StageTransport, QueueID: "3Pt2mN2VXxznjll", Recipient: "user@outside.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeSameDomainOnly, Revision: 4}}},
			want: Decision{Action: ActionDefer, Reason: ReasonPolicyHold, Revisions: map[string]uint64{"example.test": 4}},
		},
		{
			name: "conflicting restricted domains reject",
			req:  Request{Stage: StageSubmission, Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeSameDomainOnly, Revision: 1}, {Domain: "other.test", Scope: ScopeSameDomainOnly, Revision: 7}}},
			want: Decision{Action: ActionReject, Reason: ReasonCrossDomainConflict, Revisions: map[string]uint64{"example.test": 1, "other.test": 7}},
		},
		{
			name: "identical duplicate authority is idempotent",
			req:  Request{Stage: StageSubmission, Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeSameDomainOnly, Revision: 2}, {Domain: "EXAMPLE.TEST.", Scope: ScopeSameDomainOnly, Revision: 2}}},
			want: Decision{Action: ActionOK, Reason: ReasonSameDomain, Revisions: map[string]uint64{"example.test": 2}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := Evaluate(tt.req)
			assertDecision(t, got, tt.want)
		})
	}
}

func TestEvaluateFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []Request{
		{Stage: StageSubmission, Recipient: "user@example.test"},
		{Stage: "bad", Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}}},
		{Stage: StageTransport, Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}}},
		{Stage: StageSubmission, Recipient: "not-an-address", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}}},
		{Stage: StageSubmission, Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "bad_domain.test", Scope: ScopeSameDomainOnly, Revision: 1}}},
		{Stage: StageSubmission, Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: "invalid", Revision: 1}}},
		{Stage: StageSubmission, Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeSameDomainOnly}}},
		{Stage: StageTransport, QueueID: "../../ALL", Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}}},
		{Stage: StageSubmission, Recipient: "user@example.test", Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}, {Domain: "EXAMPLE.TEST.", Scope: ScopeSameDomainOnly, Revision: 1}}},
		{Stage: StageSubmission, Recipient: strings.Repeat("a", maxEnvelopeRecipientBytes+1), Governing: []GoverningDomain{{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}}},
	}
	overLimit := make([]GoverningDomain, maxGoverningDomains+1)
	for i := range overLimit {
		overLimit[i] = GoverningDomain{Domain: "example.test", Scope: ScopeUnrestricted, Revision: 1}
	}
	tests = append(tests, Request{Stage: StageSubmission, Recipient: "user@example.test", Governing: overLimit})
	for i, req := range tests {
		got := Evaluate(req)
		if got.Action != ActionDefer || got.Reason != ReasonUnavailable {
			t.Fatalf("case %d: Evaluate(%+v) = %+v, want defer/%s", i, req, got, ReasonUnavailable)
		}
	}
}

func TestValidLongQueueID(t *testing.T) {
	t.Parallel()
	for _, queueID := range []string{"3Pt2mN2VXxznjll", "BBBBBB0000zb"} {
		if !validLongQueueID(queueID) {
			t.Fatalf("validLongQueueID(%q) = false", queueID)
		}
	}
	for _, queueID := range []string{"", "ABCDEF1234567890", "3Pt2mN2VXx", "3Pt2mN2VXxz", "3Pt2mN2VXxznjll/ALL", "3Pt2mN2Vaxznjll"} {
		if validLongQueueID(queueID) {
			t.Fatalf("validLongQueueID(%q) = true", queueID)
		}
	}
}

func assertDecision(t *testing.T, got, want Decision) {
	t.Helper()
	if got.Action != want.Action || got.Reason != want.Reason {
		t.Fatalf("decision = %+v, want %+v", got, want)
	}
	if len(got.Revisions) != len(want.Revisions) {
		t.Fatalf("revisions = %#v, want %#v", got.Revisions, want.Revisions)
	}
	for domain, revision := range want.Revisions {
		if got.Revisions[domain] != revision {
			t.Fatalf("revision[%q] = %d, want %d", domain, got.Revisions[domain], revision)
		}
	}
}
