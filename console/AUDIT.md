# Impeccable Audit — Certael Operator Console

Final audit date: 2026-07-18
Target: `Core/console`
Approved direction: forensic case dossier, dark-only, WCAG 2.2 AA

## Audit Health Score

| # | Dimension | Score | Key finding |
|---|---|---:|---|
| 1 | Accessibility | 4 | Semantic landmarks, labeled controls, visible focus, keyboard drill-in restoration, live async status, and non-color state labels are present. |
| 2 | Performance | 3 | The production bundle is reasonable at 121.2 kB gzip, but the application is still delivered as one route-level bundle. |
| 3 | Responsive design | 4 | Desktop master-detail, tablet reflow, narrow drill-in, text wrapping, isolated table scrolling, and 44 px controls are implemented. |
| 4 | Theming | 4 | The locked dark palette is fully tokenized; verified foreground pairs range from 5.53:1 to 16.43:1. |
| 5 | Anti-patterns | 4 | No gradients, glass, card grid, neon SOC styling, fake metrics, decorative risk graphics, inert controls, or unresolved hard-ban detector findings. |
| **Total** |  | **19/20** | **Excellent — minor optimization opportunity only** |

## Anti-pattern verdict

Pass. The interface does not read as a generic generated dashboard. It uses a deliberate evidence-dossier composition, restrained forensic palette, semantic tables and timelines, exact consequence language, and meaningful monospace only for machine values. Both Impeccable detector scopes return zero findings.

## Executive summary

- Audit health: **19/20 (Excellent)**
- Unresolved issues: **0 P0, 0 P1, 1 P2, 0 P3**
- WCAG AA blockers: **none verified**
- Hard-ban patterns: **none detected**
- Production build: **passes**

## Detailed finding

### [P2] Route-level code splitting is not yet used

- Location: `src/App.tsx` and the Vite production entry
- Category: Performance
- Impact: Initial download includes all case tabs and dialogs even when an operator only needs the queue. At 117.1 kB gzip this is not release-blocking, but future economy and relationship workflows will grow it.
- Standard: Performance optimization; no WCAG failure.
- Recommendation: Split future major workflows at route or tab boundaries before their feature bundles land.
- Suggested command: `$impeccable optimize`

## Positive findings

- Cursor pagination exposes explicit previous/next controls and keeps each queue page bounded to 25 cases.
- Search now includes searchable metadata; category, rule, signal, risk, confidence, and chronology filters use labeled native controls.
- Clicking an evidence rule returns to page one, applies that rule filter, and selects deterministic rule sorting.
- Case metadata editing and case-taxonomy settings preserve labels, required fields, permissions, conflict versions, and audit reasons.
- Case selection remains a native button inside a semantic list and announces current selection.
- Narrow drill-in moves focus into the case and restores it to the originating row on return.
- Loading, errors, empty results, mutation success, and permission failures have programmatic status.
- Restrictive actions require a target, explicit reason, delegated authorization, consequence review, and a second confirmation.
- State and integrity are communicated with text and iconography, never color alone.
- Tables retain semantic headers and isolate horizontal overflow to the table region.
- Palette contrast checks: evidence text 16.43:1, quiet text 8.89:1, muted labels 5.53:1, cyan focus/action 9.43:1.

## Verification evidence

- Desktop browser inspection of queue, pagination, dossier, metadata editor, and settings at the default viewport.
- Tablet browser inspection at 1024×768; header overflow found and repaired.
- Narrow browser inspection at 390×844 for queue, dossier drill-in, and the complete settings path; an unreachable mobile Settings destination was found and repaired.
- Keyboard search shortcut verified to focus the labeled search field.
- Large-result state inspected with 36 cases across a 25-case first page and 11-case second page.
- Rule-click behavior verified to reset pagination, apply `circular-transfer`, and switch sorting to Rule.
- Authentication loading and BFF failure states inspected.
- `detect.mjs --json src/App.tsx src/styles/app.css src/styles/tokens.css`: zero findings.
- `tsc -b && vite build`: passes.

## Recommended action

1. **[P2] `$impeccable optimize`**: add route-level splitting when the next substantial console workflow is introduced.
2. **`$impeccable polish`**: rerun after that extension to preserve the approved visual direction.

Re-run `$impeccable audit` after future console extensions to keep the score from regressing.
