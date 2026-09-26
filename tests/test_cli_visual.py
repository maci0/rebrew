"""Terminal layout shared by the progress commands.

These tests call the renderers the commands print with, and check the plain
text: titles stay short, a partial bar is mixed, a full bar has no empty
cells, and a second percentage is labeled as a different quantity.
"""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from rebrew.present import BAR_WIDTH, filled_cells


def _console(monkeypatch: pytest.MonkeyPatch, module: object) -> StringIO:
    buf = StringIO()
    monkeypatch.setattr(
        module,
        "console",
        Console(
            file=buf, force_terminal=True, width=120, height=40, no_color=True, highlight=False
        ),
    )
    return buf


def _bar_line(text: str) -> str:
    for line in text.splitlines():
        blocks = "".join(ch for ch in line if ch in "█░")
        if len(blocks) >= BAR_WIDTH and set(blocks) <= {"█", "░"}:
            return blocks[:BAR_WIDTH]
    raise AssertionError("no bar line in:\n" + text)


def test_full_bar_has_no_empty_cells() -> None:
    assert filled_cells(10, 10) == BAR_WIDTH
    assert "░" not in ("█" * filled_cells(10, 10) + "░" * (BAR_WIDTH - filled_cells(10, 10)))


def test_zero_bar_has_no_filled_cells() -> None:
    assert filled_cells(0, 10) == 0


def test_partial_bar_is_mixed() -> None:
    filled = filled_cells(1, 2)
    assert 0 < filled < BAR_WIDTH


def test_status_bars_are_labeled(monkeypatch: pytest.MonkeyPatch) -> None:
    import rebrew.status as status_mod
    from rebrew.status import StatusReport, _render_terminal

    buf = _console(monkeypatch, status_mod)
    _render_terminal(
        StatusReport(
            target="server.dll",
            binary="/home/maci/server.dll",
            arch="x86_32",
            total_functions=4,
            covered_functions=4,
            status_counts={"EXACT": 2, "RELOC": 2},
            matched_bytes=50,
            total_text_bytes=100,
            data_verified=1,
            data_unchecked=1,
            data_verified_bytes=25,
            data_total_bytes=100,
            data_sections={".data": {"verified": 1, "drift": 0, "unchecked": 1}},
        )
    )
    out = buf.getvalue()
    assert "/home/" not in out.split("╮", 1)[0]
    assert "50.0% of .text" in out
    assert "25.0% of data" in out
    text_bar = _bar_line(out)
    assert "█" in text_bar and "░" in text_bar


def test_status_full_text_bar_is_solid(monkeypatch: pytest.MonkeyPatch) -> None:
    import rebrew.status as status_mod
    from rebrew.status import StatusReport, _render_terminal

    buf = _console(monkeypatch, status_mod)
    _render_terminal(
        StatusReport(
            target="server.dll",
            binary="server.dll",
            total_functions=1,
            covered_functions=1,
            status_counts={"EXACT": 1},
            matched_bytes=80,
            total_text_bytes=80,
        )
    )
    bar = _bar_line(buf.getvalue())
    assert "░" not in bar
    assert bar.count("█") == BAR_WIDTH


def test_data_summary_bar_matches_section(monkeypatch: pytest.MonkeyPatch) -> None:
    from rebrew.data_render import render_summary
    from rebrew.data_scan import GlobalEntry, ScanResult

    buf = StringIO()
    console = Console(
        file=buf, force_terminal=True, width=160, height=40, no_color=True, highlight=False
    )
    scan = ScanResult(
        globals={
            "g_x": GlobalEntry(
                name="g_x", va=0x1000, type_str="int", section=".data", annotated=True
            )
        }
    )
    render_summary(console, scan, {".data": {"va": 0x1000, "size": 256}})
    out = buf.getvalue()
    assert "/home/" not in out
    assert "1.6%" in out
    assert ".data" in out
    bar = _bar_line(out)
    assert "█" in bar and "░" in bar


def test_data_summary_full_section_bar_is_solid() -> None:
    from io import StringIO

    from rebrew.data_render import render_summary
    from rebrew.data_scan import GlobalEntry, ScanResult

    buf = StringIO()
    console = Console(
        file=buf, force_terminal=True, width=160, height=40, no_color=True, highlight=False
    )
    scan = ScanResult(
        globals={
            "g_x": GlobalEntry(
                name="g_x", va=0x1000, type_str="int", section=".data", annotated=True
            )
        }
    )
    render_summary(console, scan, {".data": {"va": 0x1000, "size": 4}})
    bar = _bar_line(buf.getvalue())
    assert "░" not in bar
    assert "100.0%" in buf.getvalue() or "100%" in buf.getvalue()


def test_todo_headline_bar(monkeypatch: pytest.MonkeyPatch) -> None:
    import rebrew.todo as todo_mod
    from rebrew.todo import render_matched_headline

    buf = _console(monkeypatch, todo_mod)
    render_matched_headline(1, 2)
    out = buf.getvalue()
    assert "50.0% byte-matched" in out
    bar = _bar_line(out)
    assert "█" in bar and "░" in bar
    assert "/home/" not in out


def test_verify_summary_bar_and_short_title(monkeypatch: pytest.MonkeyPatch) -> None:
    import rebrew.verify as verify_mod
    from rebrew.verify import render_verify_summary

    buf = _console(monkeypatch, verify_mod)
    render_verify_summary(
        [
            {
                "va": "0x1000",
                "name": "near_fn",
                "size": 20,
                "status": "NEAR_MATCHING",
                "match_percent": 40,
                "delta": 3,
                "similarity": 10,
            },
            {
                "va": "0x2000",
                "name": "exact_fn",
                "size": 8,
                "status": "EXACT",
                "match_percent": 100,
                "delta": 0,
            },
        ]
    )
    out = buf.getvalue()
    assert "Verification Summary" in out
    assert "/home/" not in out
    assert "40.0%" in out
    assert "█" in out and "░" in out


def test_batch_summary_uses_the_shared_bar(monkeypatch: pytest.MonkeyPatch) -> None:
    import rebrew.test as test_mod
    from rebrew.test import print_batch_status_rows

    buf = _console(monkeypatch, test_mod)
    print_batch_status_rows({"EXACT": 1, "RELOC": 1}, 2)
    out = buf.getvalue()
    assert "50.0%" in out
    bar = _bar_line(out)
    assert "█" in bar and "░" in bar
    assert len(bar) == BAR_WIDTH

    buf2 = _console(monkeypatch, test_mod)
    print_batch_status_rows({"EXACT": 4}, 4)
    solid = _bar_line(buf2.getvalue())
    assert "░" not in solid
    assert solid.count("█") == BAR_WIDTH


def test_doctor_title_is_the_target_name(monkeypatch: pytest.MonkeyPatch) -> None:
    import rebrew.doctor as doctor_mod
    from rebrew.doctor import CheckResult, DoctorReport, render_doctor

    buf = _console(monkeypatch, doctor_mod)
    render_doctor(
        DoctorReport(
            target="server.dll",
            checks=[CheckResult(name="Binary", status="pass", message="ok", fix="")],
        )
    )
    out = buf.getvalue()
    assert "server.dll" in out
    assert "/home/" not in out
    assert "Binary" in out
