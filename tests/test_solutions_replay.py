"""Replay safety of GA run log wins past the dedupe tail window."""

import json
lazy from pathlib import Path

import pytest

from rebrew.matcher import solutions as solutions_module
from rebrew.matcher.solutions import iter_ga_runs, record_ga_run


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    (tmp_path / ".rebrew").mkdir()
    return tmp_path


def test_win_replay_past_tail_window(project_root: Path) -> None:
    p = project_root / ".rebrew" / "ga_runs.jsonl"
    win = {
        "ts": "2026-01-01T00:00:00+00:00",
        "target": "SERVER",
        "va": "0x1000",
        "symbol": "_win",
        "matched": True,
        "score": 0.0,
        "cflags": "/O2",
        "size": 4,
    }
    losses = [
        {
            "ts": "2026-01-01T00:00:00+00:00",
            "target": "SERVER",
            "va": f"0x{i:04x}",
            "symbol": f"_l{i}",
            "matched": False,
        }
        for i in range(25_000)
    ]
    p.write_text("\n".join([json.dumps(win), *(json.dumps(x) for x in losses)]) + "\n")
    assert p.stat().st_size > solutions_module._TAIL_READ_BYTES
    record_ga_run(
        project_root,
        target="SERVER",
        va=0x1000,
        symbol="_win",
        matched=True,
        score=0.0,
        cflags="/O2",
        size=4,
    )
    wins = [r for r in iter_ga_runs(project_root) if r.get("matched")]
    assert len(wins) == 1


def test_va_spelling_dedupes(project_root: Path) -> None:
    record_ga_run(project_root, target="SERVER", va=0x1000, symbol="_a", matched=True)
    record_ga_run(project_root, target="SERVER", va="0x1000", symbol="_a", matched=True)
    record_ga_run(project_root, target="SERVER", va="4096", symbol="_a", matched=True)
    assert len(list(iter_ga_runs(project_root))) == 1
