# Design

The visual world of the SecretScanner-K8s report, recorded from the built page
(`python/report_generator/templates/report.html.j2`), not from intention.

## The world: chart recorder

The report is the chart of a continuous-paper instrument — a seismograph, an
ECG, a bench plotter. The scan is an instrument pass over the manifests: the pen
runs flat while the files are clean and deflects where a credential is found.
Everything else on the sheet is the record around that trace: a ruled field form
at the top, a rubber stamp for the verdict, a tabular reading below.

The category default this refuses is the security dashboard — severity donut,
counter cards, dark slate, a table that scrolls sideways.

## Truth rule

**The drawing comes from the data.** The horizontal position of a deflection is
the finding's real file and line; the height is its severity. A decorative trace
would make the sheet lie, which is the worst possible defect in a tool whose
promise is that it never leaks and never invents. `report_generator/chart.py`
owns this, and its tests assert it (position follows line number, height follows
severity, a clean scan stays on the baseline, and the output is byte-identical
between runs because `docs/index.html` is committed and CI diffs it).

## Palette

Light is the primary scene: a printed sheet read at a desk.

| Token | Light | Dark | Role |
| :--- | :--- | :--- | :--- |
| `--paper` | `#e9e5d6` | `#22231f` | sheet stock |
| `--ink` | `#26292b` | `#e9e5d6` | pen graphite |
| `--ink-soft` | `#5d5b50` | `#a8a496` | captions, secondary |
| `--rule` / `--rule-strong` | 42% / 72% ink | 34% / 62% ink | ruled lines |
| `--grid-fine` / `--grid-coarse` | sage `rgba(143,168,145,…)` | same hue, lower alpha | printed measurement grid |
| `--critical` | `#a8291d` | `#e8796a` | crimson pen |
| `--high` | `#a2600f` | `#d79a55` | amber pen |
| `--medium` | `#7d6310` | `#c8b264` | ochre pen |
| `--low` | `#3d647f` | `#8fb2cc` | indigo pen |
| `--clear` | `#3f6b45` | `#86b98a` | clean-scan stamp |

Dark mode is the same sheet under a bench lamp: paper becomes graphite, the
printed grid survives as a faint phosphor, pen colours lift to stay legible.

## Materials

- `assets/plates/paper-ground.png` — the sheet's grain, sampled from the
  approved comp, flattened of row and column structure so only fibre remains,
  mirror-tiled to 192px. Applied over the whole page at 42% under `multiply`.
- `assets/plates/stamp-ink.png` — the same patch pushed through a steep alpha
  curve so a third of it drops out; it masks the status stamp, which is how a
  rubber stamp prints dry.
- The measurement grid is drawn as SVG patterns inside the chart, never as a
  page-wide overlay: it belongs to the chart paper, not to the document.

Both plates carry their provenance embedded in the PNG (`embed-prompt.mjs`).

## Typography

Two faces, both embedded as base64 WOFF2 so the report stays a single file with
no network request. SIL OFL 1.1; licences ship in `report_generator/fonts/`.

- **Archivo Narrow** (`--face-label`) — field captions, column headers, the
  scale, the stamp, the title. Condensed, letterspaced, uppercase.
- **Sometype Mono** (`--face-data`) — every value, coordinate, rule id and
  number. Tabular figures throughout.

Ranked against the comp crop by `font-match.mjs`; Sometype Mono was the closest
monospace in the candidate set (distance 1.65). The catalogue's own top-ranked
face was a handwriting script, an artefact of fingerprinting a whole table
region rather than a letterform, and was not used.

## Components

- **Record form** — a ruled grid of caption-over-value fields, five per row on
  wide screens, three at 1200px, two at 860px. The last field spans two columns
  so no cell is left half-ruled.
- **Status stamp** — live text (`PASSED` / `FINDINGS DETECTED` / `SCAN ERROR`),
  rotated 2.2°, 4px rule, masked with the dry-ink plate. Never a raster: the
  string changes with the scan.
- **Chart band** — SVG at a 1000×240 viewBox: printed grid, severity guides
  with lettered scale, one polyline for the trace, coloured ink over each
  deflection, a marker per finding, drop lines, file blocks and a file axis
  positioned from the block geometry.
- **Reading** — a ruled log, one line per finding, alternating row tint. The
  full remediation and field path are always in the markup; a script clamps them
  to one line and a click, Enter or Space expands the row. Printing ignores the
  clamp.

## Severity is never colour alone

Each severity carries a distinct glyph — triangle (critical), circle (high),
diamond (medium), bar (low) — on the chart and in the table, so the sheet
survives greyscale printing and colour blindness.

## Motion

One authored moment: the pen draws the trace once on load
(`stroke-dashoffset`, 1500ms, exponential ease-out), and each event inks in
after the pen passes it. Everything is static under
`prefers-reduced-motion: reduce`.

## Interaction

All progressive enhancement; the sheet is complete with the script removed.

- Clicking a deflection cites its row: the row opens, highlights and scrolls
  into view.
- Severity filters hide rows and fade the matching deflections.
- Rows expand on click or keyboard.
- On narrow screens the chart scrolls horizontally instead of shrinking to an
  unreadable line — the paper rolls.

## Browser surfaces

Selection, caret, scrollbar and focus ring are themed from the palette rather
than left at browser defaults.

## Constraints this world must respect

One self-contained HTML file. No CDN, no external font, no network request, no
build step beyond Jinja2. Deterministic output, because CI compares the
committed `docs/index.html` against a fresh render.
