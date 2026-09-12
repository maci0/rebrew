"""Tests for :mod:`rebrew.climb` -- statement chunking and the hill-climb search.

The CLI layer needs a project and a docker compile, so these drive the search
itself through ``_climb`` with a stub scorer: that is where the logic lives, and
the stub makes the expected winning order explicit.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from pathlib import Path

import rebrew.climb
from rebrew.climb import _climb, _function_span, _statements, _swap, _within_size_budget

REPO_SRC = str(Path(rebrew.climb.__file__).resolve().parents[1])

SOURCE = """// FUNCTION: SERVER 0x10001000
// demo
int demo(int arg)
{
\tint a;
\ta = arg;

\tif (a > 3) {
\t\ta = 5;
\t}

\tb = a;
\treturn b;
}
"""


def _lines() -> list[str]:
    return SOURCE.splitlines(keepends=True)


class TestFunctionSpan:
    def test_span_covers_body_to_closing_brace(self) -> None:
        lines = _lines()
        lo, hi = _function_span(lines, "_demo")
        assert lines[lo].startswith("int demo(int arg)")
        assert lines[hi].strip() == "}"

    def test_symbol_without_leading_underscore(self) -> None:
        lo, _ = _function_span(_lines(), "demo")
        assert "demo" in _lines()[lo]

    def test_stdcall_decoration_is_stripped(self) -> None:
        # `_demo@4` is the decorated name of `demo`; the source never writes
        # the "@4", so the lookup must strip it as well as the leading `_`.
        lines = _lines()
        lo, hi = _function_span(lines, "_demo@4")
        assert lines[lo].startswith("int demo(int arg)")
        assert lines[hi].strip() == "}"

    def test_prototype_before_definition_is_skipped(self) -> None:
        lines = (
            "int demo(int arg);\n"
            "\n"
            "struct Thing {\n"
            "\tint a;\n"
            "\tint b;\n"
            "};\n"
            "\n"
            "int demo(int arg)\n"
            "{\n"
            "\treturn arg;\n"
            "}\n"
        ).splitlines(keepends=True)
        lo, hi = _function_span(lines, "demo")
        assert lines[lo].startswith("int demo(int arg)") and not lines[lo].rstrip().endswith(";")
        assert lines[hi].strip() == "}"


class TestStatements:
    def test_multiline_block_is_one_statement(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        texts = ["".join(lines[a : b + 1]).strip() for a, b in chunks]
        assert "int a;" in texts[0]
        assert any(t.startswith("if (a > 3)") and t.endswith("}") for t in texts), texts

    def test_declaration_and_assignment_are_separate(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        texts = ["".join(lines[a : b + 1]).strip() for a, b in chunks]
        assert texts[0] == "int a;"
        assert texts[1] == "a = arg;"

    def test_nested_braces_do_not_split(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        joined = ["".join(lines[a : b + 1]) for a, b in chunks]
        assert sum(1 for text in joined if text.lstrip().startswith("if (a > 3)")) == 1


class TestScoreAligned:
    def _result(self, monkeypatch):
        from types import SimpleNamespace

        import rebrew.near_diag

        result = SimpleNamespace(obj_bytes=b"obj", full_obj_size=12, reloc_offsets=[])
        monkeypatch.setattr(rebrew.climb, "compile_and_compare", lambda *a, **k: result)
        return result, rebrew.near_diag

    def test_score_is_pairs_dominated_with_hunks_as_tie_break(self, monkeypatch, tmp_path) -> None:
        """pairs * 1000 - hunks: distance first, region count breaks ties.

        Scoring aligned bytes instead let one long instruction outweigh two
        short ones (1886 -> 2004 bytes was worth only 740 -> 743 pairs), and
        pairs alone tied two candidates that differ in how many places they
        differ.
        """
        from types import SimpleNamespace

        _result, nd = self._result(monkeypatch)

        def insn(mnemonic: str, op: str = "") -> object:
            return SimpleNamespace(mnemonic=mnemonic, op_str=op)

        streams = {
            b"obj": [insn("mov"), insn("ret"), insn("call", "0x1")],
            b"target": [insn("mov"), insn("ret"), insn("jmp", "0x2")],
        }
        monkeypatch.setattr(nd, "disasm_insns", lambda code, *a, **k: list(streams[code]))
        cfg = SimpleNamespace(capstone_arch="CS_ARCH_X86", capstone_mode="CS_MODE_32")

        score, obj_len = rebrew.climb._score_aligned(
            cfg, tmp_path / "f.c", "_f", b"target", "/O2", {}, 0x1000, None
        )

        assert score == 2 * 1000 - 1  # two pairs, one hunk
        assert obj_len == 12


class TestSwap:
    def test_swaps_two_statement_ranges(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        swapped = _swap(lines, chunks[0], chunks[1])
        texts = ["".join(swapped[a : b + 1]).strip() for a, b in chunks]
        assert texts[0] == "a = arg;"
        assert texts[1] == "int a;"


class TestSizeBudget:
    """Matched bytes alone can be raised by emitting more code, so a candidate
    is admissible only while it stays within the function's own divergence from
    the target's length."""

    def test_compiling_candidate_inside_budget_is_kept(self) -> None:
        assert _within_size_budget(900.0, 3681, 3689, 8)

    def test_candidate_that_grows_further_is_refused(self) -> None:
        assert not _within_size_budget(861.0, 3706, 3689, 8)

    def test_candidate_that_shrinks_closer_is_kept(self) -> None:
        assert _within_size_budget(500.0, 3689, 3689, 8)

    def test_exact_length_raises_the_bar_to_zero(self) -> None:
        assert _within_size_budget(2434.0, 2434, 2434, 0)
        assert not _within_size_budget(2433.0, 2433, 2434, 0)

    def test_failed_compile_is_refused_whatever_the_length(self) -> None:
        assert not _within_size_budget(-1.0, 3689, 3689, 8)


class TestClimb:
    def test_finds_the_swap_the_scorer_prefers(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        want = _swap(lines, chunks[0], chunks[1])

        def score(candidate: list[str]) -> float:
            return 100.0 if candidate == want else 0.0

        result, best, moves = _climb(lines, chunks, score, passes=2, symbol="demo")
        assert result == want
        assert best == 100.0
        assert len(moves) == 1

    def test_leaves_the_source_alone_when_nothing_improves(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))

        def score(_: list[str]) -> float:
            return 42.0

        result, best, moves = _climb(lines, chunks, score, passes=2, symbol="demo")
        assert result == lines
        assert best == 42.0
        assert moves == []

    def test_stops_after_one_sweep_without_improvement(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        calls = 0

        def score(_: list[str]) -> float:
            nonlocal calls
            calls += 1
            return 0.0

        _climb(lines, chunks, score, passes=5, symbol="demo")
        # one baseline call plus a single sweep over the adjacent pairs
        assert calls == 1 + max(len(chunks) - 1, 0)

    def test_on_move_reports_each_accepted_move(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        want = _swap(lines, chunks[0], chunks[1])
        seen: list[dict[str, int | float]] = []

        def score(candidate: list[str]) -> float:
            return 100.0 if candidate == want else 0.0

        _climb(lines, chunks, score, passes=1, symbol="demo", on_move=seen.append)
        assert [move["index"] for move in seen] == [0]
        assert seen[0]["after"] == 100.0

    def test_no_progress_callback_when_nothing_is_kept(self) -> None:
        lines = _lines()
        chunks = _statements(lines, *_function_span(lines, "demo"))
        seen: list[dict[str, int | float]] = []

        def score(_: list[str]) -> float:
            return 7.0

        _climb(lines, chunks, score, passes=1, symbol="demo", on_move=seen.append)
        assert seen == []


class TestCommentAndLiteralSafety:
    """Depth/statement tracking must ignore comments and string/char literals."""

    def test_line_comment_inside_string_is_not_stripped(self) -> None:
        lines = (
            'int demo(int arg)\n{\n\tconst char *url = "http://example/x";\n\treturn arg;\n}\n'
        ).splitlines(keepends=True)
        lo, hi = _function_span(lines, "demo")
        chunks = _statements(lines, lo, hi)
        texts = ["".join(lines[a : b + 1]).strip() for a, b in chunks]
        assert texts[0] == 'const char *url = "http://example/x";'
        assert texts[1] == "return arg;"
        assert lines[hi].strip() == "}"

    def test_braces_inside_string_do_not_change_depth(self) -> None:
        lines = ('int demo(void)\n{\n\tputs("{");\n\treturn 0;\n}\n').splitlines(keepends=True)
        lo, hi = _function_span(lines, "demo")
        chunks = _statements(lines, lo, hi)
        assert lines[hi].strip() == "}"
        texts = ["".join(lines[a : b + 1]).strip() for a, b in chunks]
        assert texts[0] == 'puts("{");'
        assert texts[1] == "return 0;"

    def test_multiline_block_comment_braces_ignored(self) -> None:
        lines = (
            "/* decompiled reference:\n"
            "int demo(void) {\n"
            "    if (x) { y(); }\n"
            "}\n"
            "*/\n"
            "int demo(void)\n"
            "{\n"
            "\treturn 0;\n"
            "}\n"
        ).splitlines(keepends=True)
        lo, hi = _function_span(lines, "demo")
        assert lo == 5 and lines[lo].startswith("int demo(void)")
        assert lines[hi].strip() == "}"
        assert len(_statements(lines, lo, hi)) == 1


class TestRestoreOnSignal:
    """Scoring writes candidates into the real source, so a signal that skips
    the normal and exception paths must still put the original back."""

    def test_sigterm_restores_the_source(self, tmp_path: Path) -> None:
        source = tmp_path / "probe.c"
        original = "int demo(void) { return 0; }\n"
        source.write_text(original)
        script = tmp_path / "probe.py"
        script.write_text(
            "import os, signal, sys\n"
            "from pathlib import Path\n"
            f"sys.path.insert(0, {REPO_SRC!r})\n"
            "from rebrew.climb import _install_restore_handler\n"
            "path = Path(sys.argv[1])\n"
            "original = path.read_text()\n"
            "_install_restore_handler(path, original, 'utf-8')\n"
            "path.write_text('int demo(void) { return 1; }\\n')\n"
            "os.kill(os.getpid(), signal.SIGTERM)\n"
        )
        proc = subprocess.run(
            [sys.executable, str(script), str(source)],
            capture_output=True,
            env={**os.environ, "PYTHONPATH": REPO_SRC},
            timeout=60,
        )
        assert proc.returncode == -signal.SIGTERM
        assert source.read_text() == original
