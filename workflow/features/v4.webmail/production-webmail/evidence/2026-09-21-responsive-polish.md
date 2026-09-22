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
- `go test -p=4 ./...`: pass on `development` with caches and temporary build
  state held on `/tank` and `/t`.
- `go test -race -p=2 ./internal/api ./internal/httpui -count=1`: pass on
  `development`.
- `node scripts/webmail-browser-smoke.mjs`: pass after exercising 1280x900
  desktop, 768x1024 tablet, and 390x844 phone metrics.
- A first cold review rejected visual/keyboard-order disagreement in the
  narrow command bar. The search form now remains after the action strip in
  both DOM and visual order. The browser smoke proves its bounded visibility.
- A second cold review found no remaining responsive, trust-boundary, or
  desktop-regression defect.
- `git diff --check`: pass.

## Live candidate

- Source commit: `26c0f1a32dccd737f2c898f0233cc6045f2bf8c7`.
- Source-state digest:
  `32c14c3d922e78351c8eca382bb1d7a1c57dfed3cb3ab832156e7115e96f4f96`.
- Control-plane image:
  `sha256:575f2674b7afba6f03ff1cdcab5f29b61ccf5e91a93fc2a66792cc3e703be386`.
- Deployment:
  `/opt/gotth-mail-test/releases/dev-responsive-26c0f1a-20260922T011951Z`.
- Forgejo and GitHub expose the same candidate branch head.
- All six containers are healthy; Caddy and the deployment unit are active;
  ports 25, 143, 465, 587, and 993 remain reachable.
- Authenticated live Chromium proved Web Mail at 390, 768, and 1280 CSS pixels,
  folder-to-list navigation, an exactly viewport-bounded scrollable composer,
  visible search, and zero page-level horizontal overflow.
- Authenticated live Chromium proved DNS administration as labelled cards at
  390 CSS pixels and as its ordinary table at 1280 CSS pixels, again with zero
  page-level horizontal overflow.
- The candidate deliberately reports `Version: dev`; it does not rewrite or
  impersonate immutable `v1.0.0-alpha.1`.
- Rollback remains the untouched release
  `/opt/gotth-mail-test/releases/v1.0.0-alpha.1-123341a`.

Performance benchmarking is not applicable: this change adds no request,
storage, serialization, or mail-processing path. Its acceptance boundary is
layout, interaction, and overflow behavior in Chromium.
