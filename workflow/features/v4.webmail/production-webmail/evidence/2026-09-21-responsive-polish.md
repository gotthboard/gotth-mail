# Responsive Web Mail and DNS administration polish

Date: 2026-09-21 CDT

## Scope

This post-alpha change repairs responsive presentation only. It preserves the
existing authenticated mail and DNS-administration mechanisms, the canonical
GOTTH footer, and the released `v1.0.0-alpha.1` rollback point.

The bounded change covers:

- desktop pane widths that cannot exceed available viewport space;
- a separately scrollable mail action strip with search kept visible;
- deterministic single-pane drill-down through portrait tablet widths;
- mobile account-header reflow;
- a bounded, vertically scrollable mobile composer;
- labelled DNS-record cards on tablet and mobile widths.

## Baseline defects

The live alpha at 390 CSS pixels placed search beyond a 936-pixel command
strip and crowded the signed-in mailbox against the theme action. At 768 CSS
pixels it retained the desktop breakpoint and could inherit pane widths wider
than the viewport. The composer used a fixed full-viewport grid without an
explicit short-screen scroll path.

## Verification

- `GOMAXPROCS=2 go test -p=1 ./internal/api ./internal/httpui -count=1`: pass.
- `git diff --check`: pass.
- Development-host browser, full test, and deployed browser results are added
  before handoff.

Performance benchmarking is not applicable: this change adds no request,
storage, serialization, or mail-processing path. Its acceptance boundary is
layout, interaction, and overflow behavior in Chromium.
