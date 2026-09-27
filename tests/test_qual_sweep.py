"""Tests for :mod:`rebrew.qual_sweep` candidate selection.

The sweep compiles every candidate qualifier in parallel and keeps one
winner, so its choice has to depend on the candidate list rather than on how
the pool scheduled the compiles. These drive ``main`` with a stub scorer:
a docker compile is not needed to pin the ordering rule.
"""

from __future__ import annotations

import time
from pathlib import Path
from types import SimpleNamespace

import rebrew.qual_sweep
from rebrew.qual_sweep import main

SOURCE = """// FUNCTION: DEMO 0x10001000
int demo(int arg)
{
	int a;
	int b;
	a = arg;
	return a + b;
}
"""


def _prepare(monkeypatch: object, tmp_path: Path, score: object) -> Path:
    src = tmp_path / "demo.c"
    src.write_text(SOURCE, encoding="utf-8")
    cfg = SimpleNamespace(root=tmp_path)
    sel = SimpleNamespace(symbol="_demo@4", size=12)
    monkeypatch.setattr(rebrew.qual_sweep, "require_config", lambda **k: cfg)  # type: ignore[attr-defined]
    monkeypatch.setattr(
        rebrew.qual_sweep, "select_annotation", lambda *a, **k: (src, sel, 0x10001000)
    )  # type: ignore[attr-defined]
    monkeypatch.setattr(  # type: ignore[attr-defined]
        rebrew.qual_sweep, "resolve_compile_overrides", lambda *a, **k: ("msvc-6.0", "/O2")
    )
    monkeypatch.setattr(rebrew.qual_sweep, "score_fn", score)  # type: ignore[attr-defined]
    return src


class TestWinnerIsIndependentOfThreadOrder:
    def test_tied_candidates_pick_the_first_in_declaration_order(
        self, monkeypatch, tmp_path
    ) -> None:
        """Two declarations, identical scores: the earlier one wins.

        The winner is picked with a strict ``>``, so a tie is settled by the
        order candidates are collected in. Draining the pool with
        ``as_completed`` made that order the compile finish order, so the
        declaration the sweep kept, and the source it wrote, changed from run
        to run with identical inputs. The first candidate is the one made
        slow here: under completion order the fast second candidate arrives
        first and takes the win, which is what this asserts does not happen.
        """
        slow_decl = "volatile int a;"

        def score(cfg: object, path: Path, *args: object) -> tuple[float, int]:
            text = path.read_text(encoding="utf-8")
            if "volatile" in text:
                if slow_decl in text:
                    time.sleep(0.5)
                return (50.0, 12)
            return (0.0, 12)

        src = _prepare(monkeypatch, tmp_path, score)

        main(
            source=str(src),
            va=None,
            symbol=None,
            rounds=1,
            jobs=2,
            dry_run=False,
            json_output=False,
            target=None,
        )

        text = src.read_text(encoding="utf-8")
        assert "volatile int a;" in text
        assert "volatile int b;" not in text
