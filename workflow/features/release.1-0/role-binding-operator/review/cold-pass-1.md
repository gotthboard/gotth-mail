# Cold review 1

## Decision

FINDINGS FIXED.

The implementation silently trimmed the opaque OIDC issuer and subject before
authorization lookup. That weakened the promised exact identity tuple. It now
rejects padded values and has regression coverage. The CLI parser also rejects
empty values and preview-time confirmation flags rather than tolerating
ambiguous input.
