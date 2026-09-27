package api

import "forgejo/gotthboard/gotth-mail/internal/presentation"

// Preserve the existing webmail asset; all surfaces share one embedded copy.
var webmailHTMX = presentation.HTMX()
