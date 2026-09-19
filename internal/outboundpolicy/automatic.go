package outboundpolicy

import "errors"

type AutomaticKind string

const (
	AutomaticNotification  AutomaticKind = "notification"
	AutomaticAutoresponder AutomaticKind = "autoresponder"
	AutomaticDSN           AutomaticKind = "dsn"
	AutomaticBounce        AutomaticKind = "bounce"
)

type AutomaticDisposition string

const (
	AutomaticAdmitted      AutomaticDisposition = "admitted"
	AutomaticPolicyBlocked AutomaticDisposition = "policy_blocked"
	AutomaticRetry         AutomaticDisposition = "retry"
)

type AutomaticOutcome struct {
	Disposition    AutomaticDisposition `json:"disposition"`
	GenerateBounce bool                 `json:"generate_bounce"`
}

// ClassifyAutomaticDecision maps the shared policy contract to one terminal
// automatic-mail disposition. A blocked or uncertain automatic message never
// generates another bounce, preventing policy-induced loops.
// Complexity: time and auxiliary space O(1).
func ClassifyAutomaticDecision(kind AutomaticKind, decision Decision, policyErr error) (AutomaticOutcome, error) {
	if !validAutomaticKind(kind) {
		return AutomaticOutcome{}, errors.New("invalid automatic mail kind")
	}
	if policyErr != nil || decision.Action == ActionDefer {
		return AutomaticOutcome{Disposition: AutomaticRetry, GenerateBounce: false}, nil
	}
	if decision.Action == ActionReject {
		return AutomaticOutcome{Disposition: AutomaticPolicyBlocked, GenerateBounce: false}, nil
	}
	if decision.Action != ActionOK {
		return AutomaticOutcome{Disposition: AutomaticRetry, GenerateBounce: false}, nil
	}
	return AutomaticOutcome{Disposition: AutomaticAdmitted, GenerateBounce: false}, nil
}

// validAutomaticKind recognizes the complete automatic-mail contract.
// Complexity: time and auxiliary space O(1).
func validAutomaticKind(kind AutomaticKind) bool {
	switch kind {
	case AutomaticNotification, AutomaticAutoresponder, AutomaticDSN, AutomaticBounce:
		return true
	default:
		return false
	}
}
