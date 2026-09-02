"""Plot the scan as a chart recorder trace.

The report's visual world is a continuous paper chart: the scan is an
instrument pass over the manifests and every finding is a deflection of the
pen. That only means anything if the drawing comes from the data, so every
coordinate here is derived from the scan itself:

- the horizontal axis is the scanned files in reading order, each file holding
  a block of equal width;
- inside a block, a finding sits at a position proportional to its line number;
- the height of a deflection is its severity.

The trace must be byte-identical for identical input: ``docs/index.html`` is
committed and CI fails when a fresh render differs. Nothing here uses
``random``; the baseline tremor comes from a fixed-seed integer generator.
"""

from typing import Any, Dict, List, Sequence

# Internal SVG units. The viewBox is fixed; the page scales it.
CHART_WIDTH = 1000.0
CHART_HEIGHT = 240.0

# Baseline and the four severity altitudes, in SVG units from the top.
BASELINE_Y = 205.0
SEVERITY_Y = {
    "low": 168.0,
    "medium": 132.0,
    "high": 92.0,
    "critical": 48.0,
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

# Marker shape per severity, so severity survives greyscale and colour blindness.
SEVERITY_GLYPH = {
    "critical": "triangle",
    "high": "circle",
    "medium": "diamond",
    "low": "bar",
}

# The severity scale is lettered inside the SVG so it can never drift out of
# register with the lines it labels; this is the gutter it occupies.
PLOT_LEFT = 92.0
PLOT_RIGHT = CHART_WIDTH - 12.0
SAMPLES = 480
PEAK_WIDTH = 11.0
TREMOR_AMPLITUDE = 0.85


def _tremor(samples: int) -> List[float]:
    """Deterministic baseline tremor: a paper trace is never perfectly flat.

    A linear congruential generator with a fixed seed keeps the same output on
    every machine and every run, which is what the committed report needs.
    """
    values: List[float] = []
    state = 0x5EC5CA11
    previous = 0.0
    for _ in range(samples):
        state = (1103515245 * state + 12345) % 2147483648
        target = ((state / 2147483648.0) - 0.5) * 2.0
        # Smooth the sequence so the pen wobbles instead of jumping.
        previous = previous * 0.62 + target * 0.38
        values.append(previous * TREMOR_AMPLITUDE)
    return values


def _severity_key(severity: str) -> str:
    key = (severity or "").strip().lower()
    return key if key in SEVERITY_Y else "low"


def _blocks(affected_files: Sequence[str], findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One horizontal block per file.

    Blocks follow the order the findings are numbered in, so the numbers on the
    chart read left to right and match the reading below it. Affected files that
    produced no finding of their own trail after them.
    """
    files: List[str] = []
    for entry in findings:
        path = entry.get("file")
        if path and path not in files:
            files.append(path)
    for path in affected_files:
        if path and path not in files:
            files.append(path)
    if not files:
        return []

    span = (PLOT_RIGHT - PLOT_LEFT) / len(files)
    blocks = []
    for index, file_path in enumerate(files):
        start = PLOT_LEFT + span * index
        lines = [int(f.get("line") or 0) for f in findings if f.get("file") == file_path]
        blocks.append(
            {
                "file": file_path,
                "start": start,
                "end": start + span,
                "center": start + span / 2.0,
                "max_line": max(lines) if lines else 0,
            }
        )
    return blocks


def _event_x(block: Dict[str, Any], line: int) -> float:
    """Position inside a file block, proportional to the line number.

    With a single finding the block has no scale to speak of, so the event sits
    at the block's centre rather than pretending to a precision the data cannot
    support.
    """
    inner_start = block["start"] + 26.0
    inner_end = block["end"] - 26.0
    if inner_end <= inner_start or block["max_line"] <= 0:
        return block["center"]
    ratio = min(max(line / float(block["max_line"]), 0.0), 1.0)
    return inner_start + (inner_end - inner_start) * ratio


def build_chart(findings: Sequence[Dict[str, Any]], affected_files: Sequence[str]) -> Dict[str, Any]:
    """Return everything the template needs to draw the chart."""
    blocks = _blocks(affected_files, findings)

    events: List[Dict[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        block = next((b for b in blocks if b["file"] == finding.get("file")), None)
        if block is None:
            continue
        severity = _severity_key(finding.get("severity", ""))
        events.append(
            {
                "index": index,
                "x": round(_event_x(block, int(finding.get("line") or 0)), 2),
                "y": SEVERITY_Y[severity],
                "severity": severity,
                "glyph": SEVERITY_GLYPH[severity],
                "rule_id": finding.get("rule_id", ""),
                "file": finding.get("file", ""),
                "line": finding.get("line", 0),
                "column": finding.get("column", 0),
            }
        )

    tremor = _tremor(SAMPLES)
    points: List[str] = []
    # Each event also collects the stretch of trace it owns, so the deflection
    # can be inked in its severity colour over the graphite line, the way a
    # multi-pen recorder marks an event.
    peak_points: List[List[str]] = [[] for _ in events]
    for sample in range(SAMPLES):
        x = PLOT_LEFT + (PLOT_RIGHT - PLOT_LEFT) * (sample / float(SAMPLES - 1))
        y = BASELINE_Y + tremor[sample]
        for event in events:
            distance = x - event["x"]
            if abs(distance) > PEAK_WIDTH * 3:
                continue
            # A pen deflection: a narrow bell, plus the overshoot a real
            # recorder leaves on the way back down.
            bell = 2.718281828 ** (-(distance * distance) / (2 * PEAK_WIDTH * PEAK_WIDTH / 9))
            y -= (BASELINE_Y - event["y"]) * bell
            if 0 < distance < PEAK_WIDTH * 2.2:
                y += (BASELINE_Y - event["y"]) * 0.06 * bell * (distance / PEAK_WIDTH)
        point = f"{round(x, 2)},{round(y, 2)}"
        points.append(point)
        for position, event in enumerate(events):
            if abs(x - event["x"]) <= PEAK_WIDTH * 2.4:
                peak_points[position].append(point)

    for position, event in enumerate(events):
        event["peak"] = " ".join(peak_points[position])

    return {
        "width": CHART_WIDTH,
        "height": CHART_HEIGHT,
        "baseline_y": BASELINE_Y,
        "plot_left": PLOT_LEFT,
        "plot_right": PLOT_RIGHT,
        "severity_levels": [
            {"severity": key, "y": SEVERITY_Y[key], "label": key.upper()} for key in SEVERITY_ORDER
        ],
        "trace": " ".join(points),
        "events": events,
        "blocks": [
            {
                "file": block["file"],
                "start": round(block["start"], 2),
                "end": round(block["end"], 2),
                "center": round(block["center"], 2),
            }
            for block in blocks
        ],
    }
