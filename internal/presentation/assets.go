package presentation

import _ "embed"

// HTMX 2.0.10 and its unmodified 0BSD license are retained together.
//
//go:embed assets/htmx-2.0.10.min.js
var htmx string

// HTMX returns the immutable string view, not a mutable byte slice.
// Complexity: time O(1), Omega(1), Theta(1); auxiliary space O(1),
// Omega(1), Theta(1): returning a string descriptor copies no asset bytes.
func HTMX() string { return htmx }
