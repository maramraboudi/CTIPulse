# CTI-Pulse Design

<!-- impeccable:design-schema 1 -->

## Surface

The primary surface is an operational analyst dashboard with a high-density CVE ledger, a left filter rail, and evidence-led detail pages.

## Visual Direction

- Dark charcoal operational top bar.
- Cool pale-blue-gray working surface.
- White evidence panels with restrained borders.
- Cyan/teal used for active controls and analyst links.
- Semantic priority states use red, amber, ochre, and green-gray.

## Typography

Use Segoe UI or a comparable system sans serif. Headlines and labels share the same family; hierarchy comes from size and weight rather than decorative type treatments.

## Layout

- Desktop: fixed 220px filter rail beside the intelligence workspace.
- Dashboard metrics share one compact summary strip.
- Data uses a horizontally scrollable table at narrow widths.
- Detail pages use a two-column evidence grid on desktop and one column on mobile.

## Components

- Search and select controls use familiar native affordances.
- Primary actions use a single teal button vocabulary.
- Priority badges use compact, high-contrast labels.
- Tables use clear headers and restrained row separators.
- CVE links use teal text and remain underlined on hover.
- Loading, empty, error, keyboard-focus, and 404 states use semantic copy.

## Interaction

Keep transitions brief and state-focused. Do not add decorative page-load sequences or unexplained motion.

## Accessibility

- Use semantic landmarks and headings.
- Keep visible keyboard focus.
- Preserve at least 4.5:1 text contrast.
- Label all filters and controls.
- Never communicate priority through color alone.
