package generatedmsgid

import "strings"

// Valid recognizes the generated RFC5322 section 3.6.4 Message-ID subset used by forwarding.
// It accepts only <dot-atom-text@dot-atom-text>, ASCII atext, and at most 255 bytes including brackets.
// Complexity: time O(n), Omega(1), tight Theta(n); auxiliary space O(1), Omega(1), tight Theta(1), where n is bounded input bytes.
func Valid(id string) bool {
	if len(id) < 5 || len(id) > 255 || id[0] != '<' || id[len(id)-1] != '>' {
		return false
	}
	at, atom := false, false
	for i := 1; i < len(id)-1; i++ {
		c := id[i]
		switch c {
		case '@':
			if at || !atom {
				return false
			}
			at = true
			atom = false
		case '.':
			if !atom {
				return false
			}
			atom = false
		default:
			if !isAtext(c) {
				return false
			}
			atom = true
		}
	}
	return at && atom
}

// isAtext recognizes one ASCII atext byte for the generated-ID subset.
// Complexity: time O(1), Omega(1), tight Theta(1); auxiliary space O(1), Omega(1), tight Theta(1).
func isAtext(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-/=?^_`{|}~", rune(c))
}
