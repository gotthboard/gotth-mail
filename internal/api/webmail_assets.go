package api

import _ "embed"

// htmx 2.0.10 is vendored from the project's 0BSD-licensed upstream release.
// The matching license is retained beside the asset.
//
//go:embed assets/htmx-2.0.10.min.js
var webmailHTMX string
