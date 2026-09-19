package outboundpolicy

import "strings"

// AuthenticatedIdentity separates one Postfix-authenticated identity into the
// authority class resolved by the policy store. A system identity is useful
// only when its exact durable ID exists and is enabled; all other identities
// remain mailbox names and must resolve as enabled mailboxes.
// Complexity: time O(n), Omega(1); auxiliary space O(1), where n is the
// bounded authenticated identity length.
func AuthenticatedIdentity(identity string) (mailbox, systemSenderID string) {
	if strings.HasPrefix(identity, "system:") {
		return "", identity
	}
	return identity, ""
}
