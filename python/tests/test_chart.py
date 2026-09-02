from report_generator.chart import BASELINE_Y, SEVERITY_Y, build_chart


def finding(rule_id, severity, file_path, line, column=1):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": file_path,
        "line": line,
        "column": column,
    }


def test_events_carry_real_coordinates_and_severity_height():
    findings = [
        finding("internal.aws-access-key-id", "critical", "a.yaml", 12),
        finding("internal.sensitive-env-var", "high", "a.yaml", 40),
        finding("internal.shannon-entropy", "medium", "b.yaml", 7),
    ]
    chart = build_chart(findings, ["a.yaml", "b.yaml"])

    assert [event["index"] for event in chart["events"]] == [1, 2, 3]
    assert [event["file"] for event in chart["events"]] == ["a.yaml", "a.yaml", "b.yaml"]
    assert [event["line"] for event in chart["events"]] == [12, 40, 7]

    # Height is severity, and a taller severity sits closer to the top.
    assert chart["events"][0]["y"] == SEVERITY_Y["critical"]
    assert chart["events"][1]["y"] == SEVERITY_Y["high"]
    assert chart["events"][2]["y"] == SEVERITY_Y["medium"]
    assert chart["events"][0]["y"] < chart["events"][1]["y"] < chart["events"][2]["y"]

    # Severity is also a distinct shape, so the chart survives greyscale.
    assert [event["glyph"] for event in chart["events"]] == ["triangle", "circle", "diamond"]


def test_horizontal_position_follows_the_line_number():
    findings = [
        finding("r1", "critical", "a.yaml", 5),
        finding("r2", "critical", "a.yaml", 90),
    ]
    chart = build_chart(findings, ["a.yaml"])
    early, late = chart["events"]

    assert early["x"] < late["x"], "a finding further down the file sits further right"


def test_blocks_follow_the_numbering_so_the_chart_reads_left_to_right():
    # Findings are numbered in the order the report lists them; the chart must
    # place block one at the left, whatever the alphabetical order of the paths.
    findings = [finding("r1", "low", "b.yaml", 3), finding("r2", "low", "a.yaml", 3)]
    chart = build_chart(findings, ["a.yaml", "b.yaml"])

    assert [block["file"] for block in chart["blocks"]] == ["b.yaml", "a.yaml"]
    assert chart["blocks"][0]["end"] <= chart["blocks"][1]["start"] + 0.01

    first, second = chart["events"]
    assert first["index"] == 1 and second["index"] == 2
    assert first["x"] < second["x"]


def test_a_clean_scan_leaves_the_pen_on_the_baseline():
    chart = build_chart([], [])

    assert chart["events"] == []
    assert chart["blocks"] == []

    ys = [float(point.split(",")[1]) for point in chart["trace"].split(" ")]
    assert all(abs(y - BASELINE_Y) < 1.5 for y in ys), "no findings means no deflection"


def test_trace_is_byte_identical_between_runs():
    # docs/index.html is committed and CI fails when a fresh render differs, so
    # the drawing may never depend on randomness.
    findings = [finding("r1", "critical", "a.yaml", 12)]
    first = build_chart(findings, ["a.yaml"])
    second = build_chart(findings, ["a.yaml"])

    assert first["trace"] == second["trace"]


def test_deflection_reaches_its_severity_height():
    findings = [finding("r1", "critical", "a.yaml", 20)]
    chart = build_chart(findings, ["a.yaml"])

    peak = min(float(point.split(",")[1]) for point in chart["trace"].split(" "))
    assert abs(peak - SEVERITY_Y["critical"]) < 4, "the pen actually reaches the critical line"


def test_a_finding_is_plotted_even_when_the_file_list_disagrees():
    # The chart is a reading of the findings, so a finding never disappears
    # from it because an aggregate list is out of step.
    findings = [finding("r1", "critical", "ghost.yaml", 3)]
    chart = build_chart(findings, ["a.yaml"])

    assert [event["file"] for event in chart["events"]] == ["ghost.yaml"]
    assert [block["file"] for block in chart["blocks"]] == ["ghost.yaml", "a.yaml"]
