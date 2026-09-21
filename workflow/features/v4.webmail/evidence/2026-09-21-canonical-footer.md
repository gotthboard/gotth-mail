# Canonical GOTTH webmail footer evidence — 2026-09-21

## Requirement

Danny established the GOTTH Board footer/status-bar presentation as the
canonical footer for every GOTTH web project and explicitly requested it on
GOTTH Mail webmail.

## Scope

- Add the fixed-dark GOTTH footer to `/webmail` only.
- Render `Powered by GOTTH Mail`, the validated build version, page time, and
  template time.
- Preserve the existing OIDC, CSRF, IMAP, SMTP, CSP, and API boundaries.
- Keep the current immutable test deployment as the rollback target.

## Implementation

- The server assembles the static webmail shell into a bounded
  `strings.Builder`, HTML-escapes the build identity, and appends whole
  millisecond page/template timings.
- The stylesheet matches the supplied footer's dark bar, top rule, muted
  labels, highlighted project name, bright values, generous desktop inset,
  and responsive wrapping.
- No commit hash, source-tree state, hostname, or other internal metadata is
  rendered.

## Verification

- `git diff --check`
- `go test ./internal/api`
- `go test ./...`
- `go test -race ./internal/api -run
  'TestWebmail(ShellIsReachableWithoutRoundcube|FooterEscapesReleaseIdentity)$'`
- `node scripts/webmail-browser-smoke.mjs`
  - verified footer content and millisecond fields in Chromium;
  - verified the exact dark background, top rule, desktop inset/alignment, and
    narrow-layout visibility;
  - retained the existing authenticated read/compose/draft/browser checks.
- Focused Go coverage reports `renderWebmailApp` at 100%. The enclosing
  `registerWebmail` function reports 8.2% under the focused two-test selector
  because it registers the entire webmail API; the changed `/webmail` GET path
  is exercised, while unrelated IMAP/draft/action handlers are intentionally
  outside this feature's focused coverage calculation and remain covered by
  the full suite.

## Deployment

The live test deployment and rollback evidence are maintained on the target
host so they can name the exact built commit and immutable release directory.
