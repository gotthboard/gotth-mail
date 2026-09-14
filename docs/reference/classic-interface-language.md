# GOTTH Mail classic interface language

## Purpose

GOTTH Mail uses a familiar, information-dense desktop mail workflow inspired
by classic three-pane mail clients, including Outlook Classic, without copying
another product's branding or assets. The result must remain visibly and
legally distinct GOTTH Mail.

This visual language applies to end-user webmail and, where the same patterns
fit, the separate administration interface. Shared presentation must never
merge their authority: webmail remains a mail client, while administrative
mutations remain control-plane operations.

## Desktop composition

The primary desktop webmail view contains three independently understandable
regions:

1. a left navigation pane for accounts, favorites, folders, and unread counts;
2. a dense, sortable message list showing sender, subject preview, received
   time, flags, and attachment state; and
3. a reading pane that can be placed to the right, placed below the list, or
   hidden.

A traditional command bar exposes the current primary actions, including new
message, reply, reply all, forward, delete, move, mark, rules, and search.
Pane dimensions are resizable within accessible minimums. View preferences
must not alter message or control-plane authority.

## Interaction

- Folder and message lists support predictable keyboard focus, arrow-key
  movement, selection, activation, and documented shortcuts.
- Context menus may accelerate common work, but every menu action has an
  equivalent visible command and keyboard-accessible path.
- Sortable columns expose their current sort direction semantically, not by
  color or icon alone.
- Commands reflect selection and permission state and cannot reveal or invoke
  actions the current actor is not authorized to perform.
- Resizing, pane placement, selection, and navigation use HTMX or small
  progressive-enhancement behavior. Core read, compose, and administrative
  workflows remain usable without a client-side SPA runtime.

## Responsive behavior

Desktop density must not become a squeezed three-column mobile layout. At
narrow widths the interface collapses into a deterministic drill-down:

```text
accounts/folders -> message list -> message reader or composer
```

Back navigation preserves the user's prior folder, list window, and safe
selection state. Touch targets meet accessibility sizing requirements even
when the desktop presentation uses compact rows.

## Visual system

- Use restrained GOTTH blue and neutral gray tokens with clear borders,
  compact spacing, and strong selected/focused states.
- Provide light and dark themes with equivalent contrast and status meaning.
- Use original GOTTH icons or appropriately licensed icon sets. Every
  icon-only control requires an accessible name and visible focus state.
- The administration interface may share typography, spacing, colors, icons,
  commands, tables, and navigation patterns, but it remains visually explicit
  when an action changes server or organization state.

## Intellectual-property boundary

"Outlook Classic-inspired" describes workflow familiarity and information
density only. GOTTH Mail must not copy Microsoft trademarks, logos, copyrighted
icons, product artwork, exact screen compositions, proprietary text, or exact
branding. Screens must use GOTTH Mail names, original assets, and the design
tokens defined by this project.

## Security and accessibility invariants

The classic presentation cannot weaken existing boundaries:

- hostile HTML mail remains data governed by the renderer and CSP;
- remote content, attachment, URL, and exact-sender policies remain enforced;
- color is never the only carrier of state;
- all pointer interactions have keyboard-accessible equivalents;
- focus order follows the visible pane order and survives responsive changes;
- zoom, text reflow, reduced motion, and high-contrast operation are supported;
- webmail never writes canonical control-plane state directly; and
- familiarity must never disguise a privileged or destructive operation.
