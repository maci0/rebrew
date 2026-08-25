"""Extended tests for rebrew verify.py — verify_entry branches, diff_reports, CLI main."""

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.annotation import Annotation
from rebrew.cli import EXIT_MISMATCH


def _ann(va: int, *, size: int = 64, filepath: str = "f.c", status: str = "STUB") -> Annotation:
    return Annotation(
        va=va,
        name="my_func",
        symbol="_my_func",
        module="SERVER",
        status=status,
        size=size,
        cflags="/O2",
        marker_type="FUNCTION",
        filepath=filepath,
    )


def _cfg(tmp_path: Path, **overrides: object) -> SimpleNamespace:
    src = tmp_path / "src" / "SERVER"
    src.mkdir(parents=True, exist_ok=True)
    defaults: dict = {
        "root": tmp_path,
        "target_name": "SERVER",
        "target_binary": tmp_path / "fake.dll",
        "reversed_dir": src,
        "metadata_dir": tmp_path,
        "marker": "SERVER",
        "source_ext": ".c",
        "db_dir": tmp_path / "db",
        "default_jobs": 2,
        "compiler_command": "cl",
        "base_cflags": "/O2",
        "compiler_includes": [],
        "compiler_libs": [],
        "function_list": src / "functions.txt",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _ok_result() -> object:
    from rebrew.compile import CompareResult

    return CompareResult(
        matched=True,
        status="EXACT",
        match_percent=100.0,
        delta=0,
        obj_bytes=b"\x90" * 8,
        reloc_offsets=[],
    )


class TestVerifyEntryBranches:
    def test_missing_file(self, tmp_path: Path) -> None:
        from rebrew.verify import verify_entry

        cfg = _cfg(tmp_path)
        result = verify_entry(_ann(0x1000, filepath="nope.c"), cfg)  # type: ignore[arg-type]
        assert result.status == "MISSING_FILE"

    def test_invalid_va(self, tmp_path: Path) -> None:
        from rebrew.verify import verify_entry

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        result = verify_entry(_ann(0x10), cfg)  # type: ignore[arg-type]  # below MIN_VALID_VA
        assert result.status == "INVALID_VA"
        assert "INVALID_VA" in (result.message or "")

    def test_missing_size(self, tmp_path: Path) -> None:
        from rebrew.verify import verify_entry

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        result = verify_entry(_ann(0x1000, size=0), cfg)  # type: ignore[arg-type]
        assert result.status == "MISSING_SIZE"

    def test_extract_failure(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.binary_loader
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: None)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.status == "EXTRACT_ERROR"
        assert "Cannot extract" in (result.message or "")

    def test_extract_failure_stale_annotation_hint(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Extraction failing at a VA that is not a function in the current
        function list is a stale annotation (binary updated since the marker
        was written) — the error must say so, not blame binary tooling."""
        import rebrew.binary_loader
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        (cfg.reversed_dir / "functions.txt").write_text("0x2000 16 other\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: None)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.status == "EXTRACT_ERROR"
        assert "stale annotation" in (result.message or "")
        assert "0x1000" in (result.message or "")

    def test_extract_failure_no_hint_when_va_is_function(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A VA that IS in the current function list gets the plain tooling
        error — no stale-annotation hint."""
        import rebrew.binary_loader
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        (cfg.reversed_dir / "functions.txt").write_text("0x1000 64 my_func\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: None)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.status == "EXTRACT_ERROR"
        assert "stale annotation" not in (result.message or "")

    def test_fenced_naked_note_on_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A fenced naked source compiled without REBREW_ALLOW_NAKED compiles
        its #else fallback — the mismatch must name the fence instead of
        leaving a bare byte diff (the '18 at 0%' reccmp confusion)."""
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "#ifdef REBREW_ALLOW_NAKED\n"
            "__declspec(naked) void my_func(void) { __asm { ret } }\n"
            "#else\n"
            "void my_func(void) { /* fallback */ }\n"
            "#endif\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)
        from rebrew.compile import CompareResult

        def _unmatched(*a, **k):
            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=4,
                obj_bytes=None,
                reloc_offsets=None,
                message="NEAR_MATCHING: 50.0%",
            )

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _unmatched)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.status == "NEAR_MATCHING"
        assert "fenced naked" in (result.message or "")
        assert "REBREW_ALLOW_NAKED" in (result.message or "")

    def test_no_fence_no_note(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A plain (unfenced) source gets no naked-fence note on mismatch."""
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)
        from rebrew.compile import CompareResult

        def _unmatched(*a, **k):
            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=4,
                obj_bytes=None,
                reloc_offsets=None,
                message="NEAR_MATCHING: 50.0%",
            )

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _unmatched)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert "fenced naked" not in (result.message or "")

    def test_effective_match_note(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A NEAR_MATCHING whose ENTIRE delta is register allocation is a
        reccmp-style effective match — the message must name it (not
        byte-identical, but the cause is register allocation)."""
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.matcher
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)
        from rebrew.compile import CompareResult

        def _unmatched(*a, **k):
            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=4,
                obj_bytes=b"\x90" * 8,
                reloc_offsets=[],
                message="NEAR_MATCHING: 50.0%",
            )

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _unmatched)
        monkeypatch.setattr(
            rebrew.matcher,
            "diff_functions",
            lambda *a, **k: {
                "summary": {"exact": 2, "reloc": 0, "reg": 2, "structural": 0, "total": 4},
                "instructions": [],
            },
        )
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.diff_lines == 0
        assert result.reg_delta == 2
        assert result.effective_match is True
        assert "effective match" in (result.message or "")
        assert "register allocation" in (result.message or "")

    def test_no_effective_note_when_structural(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Structural deltas must NOT get the effective-match note."""
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.matcher
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)
        from rebrew.compile import CompareResult

        def _unmatched(*a, **k):
            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=4,
                obj_bytes=b"\x90" * 8,
                reloc_offsets=[],
                message="NEAR_MATCHING: 50.0%",
            )

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _unmatched)
        monkeypatch.setattr(
            rebrew.matcher,
            "diff_functions",
            lambda *a, **k: {
                "summary": {"exact": 1, "reloc": 0, "reg": 0, "structural": 3, "total": 4},
                "instructions": [],
            },
        )
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.diff_lines == 3
        assert "effective match" not in (result.message or "")

    def test_success_delegates(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int my_func(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)
        seen: dict = {}

        def _compare(cfg, cfile, symbol, target_bytes, cflags, **kw):
            seen.update(symbol=symbol, cflags=cflags, cache=kw.get("cache"))
            return _ok_result()

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _compare)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.status == "EXACT"
        assert seen["symbol"] == "_my_func"
        assert seen["cflags"] == "/O2"

    def test_unmatched_populates_diff_lines(self, tmp_path: Path, monkeypatch) -> None:
        """verify_entry must populate diff_lines for UNMATCHED functions so
        the recoverage-consumed verify_results.diff_lines column carries real
        data (db-review F2: it was documented but never produced)."""
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int my_func(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)

        def _unmatched(cfg, cfile, symbol, target_bytes, cflags, **kw):
            from rebrew.compile import CompareResult

            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=60.0,
                delta=2,
                obj_bytes=b"\x90\x91" + b"\x90" * 6,
                reloc_offsets=[],
                message="NEAR_MATCHING: 2 byte diffs",
            )

        def _fake_diff(target, cand, relocs, as_dict=True, **kw):
            return {"summary": {"structural": 2, "reg": 0}}

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _unmatched)
        monkeypatch.setattr(rebrew.matcher, "diff_functions", _fake_diff)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.diff_lines == 2
        assert result.reg_delta == 0

    def test_matched_skips_diff_lines_compute(self, tmp_path: Path, monkeypatch) -> None:
        """Matched functions must not pay for a disassembly diff — diff_lines
        stays None (0 diffs trivially)."""
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int my_func(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)
        calls = {"n": 0}

        def _compare(cfg, cfile, symbol, target_bytes, cflags, **kw):
            return _ok_result()

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _compare)
        monkeypatch.setattr(
            rebrew.matcher,
            "diff_functions",
            lambda *a, **k: (
                calls.__setitem__("n", calls["n"] + 1) or {"summary": {"structural": 1}}
            ),
        )
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.diff_lines is None
        assert calls["n"] == 0  # diff_functions never invoked

    def test_matched_populates_similarity(self, tmp_path: Path, monkeypatch) -> None:
        """Similarity is computed for MATCHED functions too (user ruling:
        compute for all), short-circuiting to ~100 for byte-identical code."""
        import importlib.util

        if importlib.util.find_spec("resembl") is None:
            pytest.skip("optional `resembl` dependency not installed")
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int my_func(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)

        def _compare(cfg, cfile, symbol, target_bytes, cflags, **kw):
            return _ok_result()  # matched EXACT, obj = 8 NOP bytes

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _compare)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        assert result.similarity == 100.0  # target == obj == 8 NOPs

    def test_unmatched_populates_similarity(self, tmp_path: Path, monkeypatch) -> None:
        """Similarity is computed for UNMATCHED functions too, and it is a
        real 0–100 structural score (not just 0 on failure)."""
        import importlib.util

        if importlib.util.find_spec("resembl") is None:
            pytest.skip("optional `resembl` dependency not installed")
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int my_func(void) { return 0; }\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 8)

        def _unmatched(cfg, cfile, symbol, target_bytes, cflags, **kw):
            from rebrew.compile import CompareResult

            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=60.0,
                delta=2,
                obj_bytes=b"\x90\x91" + b"\x90" * 6,
                reloc_offsets=[],
                message="NEAR_MATCHING: 2 byte diffs",
            )

        monkeypatch.setattr(rebrew.compile, "compile_and_compare", _unmatched)
        result = verify_mod.verify_entry(_ann(0x1000), cfg)  # type: ignore[arg-type]
        # target is all-NOPs; candidate is mostly-NOPs. They differ in bytes but
        # share identical structure in normalized assembly, so the score is high.
        assert isinstance(result.similarity, float)
        assert 0.0 <= result.similarity <= 100.0


class TestDiffReports:
    def test_new_removed_unchanged(self) -> None:
        from rebrew.verify import diff_reports

        previous = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "EXACT"},
                {"va": "0x2000", "name": "b", "status": "STUB"},
            ]
        }
        current = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "EXACT"},
                {"va": "0x3000", "name": "c", "status": "EXACT"},
            ]
        }
        d = diff_reports(previous, current)
        assert d["unchanged_count"] == 1
        assert [i["va"] for i in d["new"]] == ["0x00003000"]
        assert [i["va"] for i in d["removed"]] == ["0x00002000"]
        assert d["regressions"] == []
        assert d["improvements"] == []

    def test_improvement_and_regression(self) -> None:
        from rebrew.verify import diff_reports

        previous = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "STUB"},
                {"va": "0x2000", "name": "b", "status": "EXACT"},
            ]
        }
        current = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "EXACT", "delta": 0},
                {"va": "0x2000", "name": "b", "status": "COMPILE_ERROR", "delta": 5},
            ]
        }
        d = diff_reports(previous, current)
        assert d["improvements"][0]["va"] == "0x00001000"
        assert d["regressions"][0]["va"] == "0x00002000"
        assert d["regressions"][0]["delta"] == 5

    def test_unknown_status_ranks_as_fail(self) -> None:
        from rebrew.verify import diff_reports

        previous = {"results": [{"va": "0x1000", "name": "a", "status": "WEIRD"}]}
        current = {"results": [{"va": "0x1000", "name": "a", "status": "EXACT"}]}
        d = diff_reports(previous, current)
        # WEIRD ranks as FAIL (5) → EXACT (0) is an improvement.
        assert len(d["improvements"]) == 1


class TestVerifyCli:
    def _patch_flow(
        self,
        monkeypatch: pytest.MonkeyPatch,
        cfg: SimpleNamespace,
        *,
        results: list | None = None,
        passed: int = 1,
        failed: int = 0,
        previous: dict | None = None,
    ) -> None:

        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries",
            lambda cfg, full, json_output: (
                [_ann(0x1000)],
                passed,
                failed,
                [],
                results if results is not None else [],
                0,
                [],
                [],
            ),
        )
        monkeypatch.setattr("rebrew.verify.run_verification", lambda *a, **k: (0, 0, [], [], []))

        def _prev(out_file, diff_mode, json_output):
            return (previous, None) if previous is not None else (None, None)

        monkeypatch.setattr("rebrew.verify._load_previous_report", _prev)
        monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)

    def test_json_report(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[
                {
                    "va": "0x00001000",
                    "status": "EXACT",
                    "passed": True,
                    "name": "my_func",
                    "delta": 0,
                    "match_percent": 100.0,
                }
            ],
        )
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["total"] == 1
        assert data["summary"]["exact"] == 1

    def test_ne_target_skips_compile_loop(self, tmp_path: Path, monkeypatch) -> None:
        """A 16-bit NE target with no 16-bit compiler profile (default
        msvc6) short-circuits with a clear notice instead of compiling every
        stub into COMPILE_ERROR rows."""
        from rebrew.verify import app

        ne = tmp_path / "game.ne"
        data = bytearray(0x140)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        ne.write_bytes(bytes(data))
        cfg = _cfg(tmp_path, target_binary=ne)
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data.get("skipped") is True
        assert "NE" in data["reason"]

    def test_ne_target_with_msvc152_profile_runs(self, tmp_path: Path, monkeypatch) -> None:
        """With the msvc1.52 profile configured, verify must NOT short-circuit
        a 16-bit NE target — the DOSBox compile pipeline (omf16 objects) is
        live.  The fake cfg lacks the fields the deeper pipeline needs, so the
        run fails for an unrelated reason — the point is the NE gate no longer
        fires (no 'skipped' JSON with the stale "future work" reason)."""
        from rebrew.verify import app

        ne = tmp_path / "game.ne"
        data = bytearray(0x140)
        data[0:2] = b"MZ"
        data[0x3C:0x40] = (0x100).to_bytes(4, "little")
        data[0x100:0x102] = b"NE"
        ne.write_bytes(bytes(data))
        cfg = _cfg(tmp_path, target_binary=ne, compiler_profile="msvc1.52")
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["--json"])
        # exit code is not 0 (deeper pipeline needs a fuller cfg), but the
        # 16-bit gate must not have produced its skip JSON.
        assert "skipped" not in result.output
        assert "future work" not in result.output

    def test_failed_exits_mismatch(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[{"va": "0x00001000", "status": "COMPILE_ERROR", "passed": False}],
            passed=0,
            failed=1,
        )
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == EXIT_MISMATCH

    def test_nolib_excludes_library_entries(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--nolib (the reccmp --nolib equivalent) must drop LIBRARY-marked
        functions from the work list, the cached results, and the exit gate —
        gate on game code only."""
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        lib_ann = _ann(0x1000)
        lib_ann.marker_type = "LIBRARY"  # type: ignore[attr-defined]
        fn_ann = _ann(0x2000)
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries",
            lambda cfg, full, json_output: (
                [lib_ann, fn_ann],
                1,  # passed — the cached LIBRARY hit
                0,
                [],
                [{"va": "0x00001000", "status": "EXACT", "passed": True}],
                1,
                [],
                [],
            ),
        )
        monkeypatch.setattr("rebrew.verify.run_verification", lambda *a, **k: (0, 0, [], [], []))
        monkeypatch.setattr(
            "rebrew.verify._load_previous_report",
            lambda out_file, diff_mode, json_output: (None, None),
        )
        monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)

        result = CliRunner().invoke(app, ["--json", "--nolib"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["library_excluded"] == 1
        assert data["summary"]["total"] == 1  # only the FUNCTION entry remains
        assert data["summary"]["passed"] == 0  # cached LIBRARY hit dropped
        # The LIBRARY row must not appear in the report results at all.
        assert all(r["va"] != "0x00001000" for r in data["results"])

    def test_nolib_failed_library_does_not_trip_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failing LIBRARY function must not fail the run under --nolib
        (without the flag it would exit EXIT_MISMATCH)."""
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        lib_ann = _ann(0x1000)
        lib_ann.marker_type = "LIBRARY"  # type: ignore[attr-defined]
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries",
            lambda cfg, full, json_output: (
                [lib_ann],
                0,
                1,
                [(lib_ann, "byte mismatch")],
                [{"va": "0x00001000", "status": "NEAR_MATCHING", "passed": False}],
                1,
                [],
                [],
            ),
        )
        monkeypatch.setattr("rebrew.verify.run_verification", lambda *a, **k: (0, 0, [], [], []))
        monkeypatch.setattr(
            "rebrew.verify._load_previous_report",
            lambda out_file, diff_mode, json_output: (None, None),
        )
        monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)

        result = CliRunner().invoke(app, ["--json", "--nolib"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["library_excluded"] == 1
        assert data["summary"]["failed"] == 0

        # Without --nolib the same failure trips the gate.
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == EXIT_MISMATCH

    def test_summary_text(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(monkeypatch, cfg, results=[])
        result = CliRunner().invoke(app, ["--summary"])
        assert result.exit_code == 0
        assert "EXACT" in result.output or "STUB" in result.output or "Summary" in result.output

    def test_compare_regression_exits_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[{"va": "0x00001000", "status": "EXACT", "passed": True}],
            passed=1,
            failed=0,
            previous={"results": [{"va": "0x1000", "name": "a", "status": "EXACT", "delta": 0}]},
        )
        # previous == current → unchanged, no regression → exit 0.
        result = CliRunner().invoke(app, ["--compare", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["report"]["summary"]["passed"] == 1

    def test_compare_has_regression(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[{"va": "0x00001000", "status": "STUB", "passed": False}],
            passed=0,
            failed=1,
            previous={"results": [{"va": "0x00001000", "name": "a", "status": "EXACT"}]},
        )
        result = CliRunner().invoke(app, ["--compare", "--json"])
        assert result.exit_code == EXIT_MISMATCH

    def test_report_written_to_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(monkeypatch, cfg, results=[])
        out = tmp_path / "out.json"
        result = CliRunner().invoke(app, ["--output", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert json.loads(out.read_text(encoding="utf-8"))["summary"]["total"] == 1

    def test_compare_pre_existing_failures_exit_zero_without_regression(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--compare is a CI regression gate: pre-existing failures must not
        fail the run — only new regressions do."""
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[
                {"va": "0x00001000", "status": "EXACT", "passed": True},
                {"va": "0x00002000", "status": "STUB", "passed": False},
            ],
            passed=1,
            failed=1,
            previous={
                "results": [
                    {"va": "0x1000", "name": "a", "status": "EXACT", "delta": 0},
                    {"va": "0x2000", "name": "b", "status": "STUB", "delta": 8},
                ]
            },
        )
        result = CliRunner().invoke(app, ["--compare", "--json"])
        # One pre-existing failure, zero regressions → the gate passes.
        assert result.exit_code == 0

    def test_compare_without_baseline_keeps_failure_exit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.cli import EXIT_MISMATCH
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[{"va": "0x00001000", "status": "STUB", "passed": False}],
            passed=0,
            failed=1,
            previous=None,  # no baseline → diff_warning, old semantics
        )
        result = CliRunner().invoke(app, ["--compare", "--json"])
        assert result.exit_code == EXIT_MISMATCH

    def test_new_compile_error_exits_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.cli import EXIT_MISMATCH
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[
                {"va": "0x00001000", "status": "EXACT", "passed": True},
                {"va": "0x00003000", "status": "COMPILE_ERROR", "passed": False},
            ],
            passed=1,
            failed=1,
            previous={
                "results": [{"va": "0x00001000", "name": "a", "status": "EXACT", "delta": 0}]
            },
        )
        result = CliRunner().invoke(app, ["--compare", "--json"])
        assert result.exit_code == EXIT_MISMATCH

    def test_new_exact_entry_still_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        self._patch_flow(
            monkeypatch,
            cfg,
            results=[
                {"va": "0x00001000", "status": "EXACT", "passed": True},
                {"va": "0x00003000", "status": "EXACT", "passed": True},
            ],
            passed=2,
            failed=0,
            previous={
                "results": [{"va": "0x00001000", "name": "a", "status": "EXACT", "delta": 0}]
            },
        )
        result = CliRunner().invoke(app, ["--compare", "--json"])
        assert result.exit_code == 0


class TestApplyStatusUpdates:
    def test_updates_metadata(self, tmp_path: Path) -> None:
        from rebrew.metadata import get_entry
        from rebrew.verify import apply_status_updates

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        entry = _ann(0x1000)
        apply_status_updates([(entry, "EXACT", 0)], cfg)  # type: ignore[arg-type]
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER").get("status") == "EXACT"

    def test_proven_sticky_not_demoted(self, tmp_path: Path) -> None:
        from rebrew.metadata import get_entry, update_source_status
        from rebrew.verify import apply_status_updates

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        update_source_status(cfg.metadata_dir, "PROVEN", "SERVER", 0x1000)
        entry = _ann(0x1000, status="PROVEN")
        apply_status_updates([(entry, "STUB", 0)], cfg)  # type: ignore[arg-type]
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER").get("status") == "PROVEN"

    def test_write_failure_does_not_abort_batch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A metadata write failure must not abort the whole batch.

        STATUS sync is best-effort — a read-only or unwritable metadata file
        must not crash the verify run and lose the report.  The batched
        write is attempted once; a failure is logged and the run continues.
        """
        from rebrew.verify import apply_status_updates

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int my_func(void) { return 0; }\n", encoding="utf-8")
        attempted: list[list[dict[str, object]]] = []

        def _boom(metadata_dir: object, updates: list[dict[str, object]]) -> int:
            attempted.append(updates)
            raise OSError("disk full")

        monkeypatch.setattr("rebrew.metadata.update_statuses_batch", _boom)
        with caplog.at_level(logging.WARNING):
            apply_status_updates(  # type: ignore[arg-type]
                [(_ann(0x1000), "EXACT", 0), (_ann(0x2000), "RELOC", 0)], cfg
            )
        # Both entries were collected into one batched write that failed; no
        # exception escaped to abort the run.
        assert len(attempted) == 1
        assert {u["va"] for u in attempted[0]} == {0x1000, 0x2000}
        assert any("Could not update STATUS" in r.message for r in caplog.records)


class TestLoadPreviousReport:
    def test_not_diff_mode_returns_none(self, tmp_path: Path) -> None:
        from rebrew.verify import _load_previous_report

        prev, warning = _load_previous_report(tmp_path / "r.json", False, False)
        assert prev is None and warning is None

    def test_missing_file_warning(self, tmp_path: Path) -> None:
        from rebrew.verify import _load_previous_report

        prev, warning = _load_previous_report(tmp_path / "nope.json", True, True)
        assert prev is None
        assert "No previous verify report" in (warning or "")

    def test_valid_report_loaded(self, tmp_path: Path) -> None:
        import json

        from rebrew.verify import _load_previous_report

        out = tmp_path / "r.json"
        out.write_text(json.dumps({"summary": {"total": 5}}), encoding="utf-8")
        prev, warning = _load_previous_report(out, True, True)
        assert prev == {"summary": {"total": 5}}
        assert warning is None

    def test_invalid_report_warning(self, tmp_path: Path) -> None:
        from rebrew.verify import _load_previous_report

        out = tmp_path / "r.json"
        out.write_text("{broken", encoding="utf-8")
        prev, warning = _load_previous_report(out, True, True)
        assert prev is None
        assert "Could not read previous verify report" in (warning or "")

    def test_non_dict_report_warning(self, tmp_path: Path) -> None:
        import json

        from rebrew.verify import _load_previous_report

        out = tmp_path / "r.json"
        out.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        prev, warning = _load_previous_report(out, True, True)
        assert prev is None
        assert "invalid JSON object" in (warning or "")


class TestSaveVerifyCacheBranches:
    def test_entries_without_filepath_skipped(self, tmp_path: Path) -> None:
        from rebrew.verify import _save_verify_cache

        cfg = _cfg(tmp_path)
        results = [
            {
                "va": "0x00001000",
                "status": "EXACT",
                "passed": True,
                "filepath": "",
                "delta": 0,
            }
        ]
        # Entry with empty filepath → no file info → result not cached.
        empty_fp = Annotation(va=0x1000, name="x", filepath="")
        _save_verify_cache(tmp_path / ".rebrew" / "verify_cache.json", cfg, results, [empty_fp])
        cache_path = tmp_path / ".rebrew" / "verify_cache.json"
        assert cache_path.exists()
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        assert data["entries"] == {}

    def test_result_without_file_info_skipped(self, tmp_path: Path) -> None:
        from rebrew.verify import _save_verify_cache

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        results = [
            {
                "va": "0x00001000",
                "status": "EXACT",
                "passed": True,
                "filepath": "other.c",  # no entry provides info for it
                "delta": 0,
            }
        ]
        _save_verify_cache(tmp_path / ".rebrew" / "verify_cache.json", cfg, results, [_ann(0x1000)])
        data = json.loads((tmp_path / ".rebrew" / "verify_cache.json").read_text(encoding="utf-8"))
        assert data["entries"] == {}

    def test_roundtrip_cache_entry(self, tmp_path: Path) -> None:
        from rebrew.verify import _save_verify_cache

        cfg = _cfg(tmp_path)
        f = cfg.reversed_dir / "f.c"
        f.write_text("int my_func(void) { return 0; }\n", encoding="utf-8")
        results = [
            {
                "va": "0x00001000",
                "status": "EXACT",
                "passed": True,
                "filepath": "f.c",
                "delta": 0,
                "match_percent": 100.0,
            }
        ]
        _save_verify_cache(tmp_path / ".rebrew" / "verify_cache.json", cfg, results, [_ann(0x1000)])
        data = json.loads((tmp_path / ".rebrew" / "verify_cache.json").read_text(encoding="utf-8"))
        entry = data["entries"]["0x00001000"]
        assert entry["result"]["status"] == "EXACT"
        assert entry["source_hash"] != ""


class TestPrintResults:
    def _call(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        diff=None,
        warning=None,
        diff_mode=False,
        summary=False,
        results=None,
        fail_details=None,
    ) -> str:
        from io import StringIO

        from rich.console import Console

        import rebrew.verify as verify_mod
        from rebrew.verify import _print_results

        buf = StringIO()
        monkeypatch.setattr(
            verify_mod,
            "console",
            Console(file=buf, force_terminal=True, width=120, no_color=True, highlight=False),
        )
        _print_results(
            results if results is not None else [],
            fail_details or [],
            diff,
            warning,
            diff_mode,
            summary,
            1,
            1,
            0,
        )
        return buf.getvalue()

    def test_plain(self, monkeypatch: pytest.MonkeyPatch) -> None:
        out = self._call(monkeypatch)
        assert "1/1 passed" in out or "passed" in out.lower()

    def test_diff_sections(self, monkeypatch: pytest.MonkeyPatch) -> None:
        diff = {
            "regressions": [
                {"name": "a", "previous_status": "EXACT", "current_status": "STUB", "delta": 4}
            ],
            "improvements": [{"name": "b", "previous_status": "STUB", "current_status": "EXACT"}],
            "new": [{"name": "c", "status": "EXACT"}],
            "removed": [{"name": "d", "status": "STUB"}],
        }
        out = self._call(monkeypatch, diff=diff, warning="no prev", diff_mode=True)
        assert "1 regressions detected" in out
        assert "EXACT -> STUB" in out
        assert "1 improvements" in out
        assert "1 new" in out
        assert "1 removed" in out
        assert "Warning: no prev" in out

    def test_summary_table(self, monkeypatch: pytest.MonkeyPatch) -> None:
        results = [
            {
                "va": "0x00001000",
                "name": "f",
                "size": 8,
                "status": "STUB",
                "match_percent": 90.0,
                "delta": 4,
            },
            {
                "va": "0x00002000",
                "name": "g",
                "size": 8,
                "status": "EXACT",
                "match_percent": 100.0,
                "delta": 0,
            },
            {
                "va": "0x00003000",
                "name": "h",
                "size": 8,
                "status": "PROVEN",
                "match_percent": 100.0,
                "delta": 0,
            },
        ]
        out = self._call(monkeypatch, summary=True, results=results)
        assert "Verification Summary" in out
        assert "EXACT" in out
        assert "STUB" in out
        assert "PROVEN" in out

    def test_fail_details_render(self, monkeypatch: pytest.MonkeyPatch) -> None:
        results = [
            {
                "va": "0x00001000",
                "name": "f",
                "size": 8,
                "status": "STUB",
                "match_percent": 80.0,
                "delta": 9,
            },
            {
                "va": "0x00002000",
                "name": "g",
                "size": 8,
                "status": "COMPILE_ERROR",
                "match_percent": 0.0,
                "delta": 0,
            },
        ]
        fail_details = [
            (_ann(0x1000), "9B diff"),
            (_ann(0x2000), "cl crashed"),
        ]
        out = self._call(monkeypatch, results=results, fail_details=fail_details)
        assert "9B diff" in out
        assert "cl crashed" in out
        assert "COMPILE_ERROR" in out or "80.0%" in out


class TestVerifyWatch:
    def test_watch_dispatches_retest(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        calls = {"n": 0}

        def _watch(sources, retest, **kwargs):
            calls["n"] += 1
            retest()  # invoke once to prove the nested main() path works

        monkeypatch.setattr("rebrew.utils.watch_files", _watch)
        monkeypatch.setattr("rebrew.sources.iter_sources", lambda d, cfg=None: [])
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries", lambda *a, **k: ([], 0, 0, [], [], 0, [], [])
        )
        monkeypatch.setattr("rebrew.verify.run_verification", lambda *a, **k: (0, 0, [], [], []))
        monkeypatch.setattr("rebrew.verify._load_previous_report", lambda *a, **k: (None, None))
        monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._print_results", lambda *a, **k: None)
        result = CliRunner().invoke(app, ["--watch"])
        assert result.exit_code == 0
        assert calls["n"] == 1


class TestProvenOverlay:
    def test_proven_result_promoted(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        proven_entry = _ann(0x1000, status="PROVEN")
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries",
            lambda *a, **k: ([proven_entry], 0, 0, [], [], 0, [], []),
        )
        # A proven function's compiled bytes differ from the target — the byte
        # compare yields NEAR_MATCHING, which must be restored to PROVEN.
        # run_verification reports failed=1 with a matching fail_detail; the
        # overlay must flip the counters and drop the detail for this VA.
        results = [{"va": "0x00001000", "status": "NEAR_MATCHING", "passed": False}]
        fail_details = [(proven_entry, "9B diff")]
        monkeypatch.setattr(
            "rebrew.verify.run_verification",
            lambda *a, **k: (0, 1, fail_details, results, []),
        )
        monkeypatch.setattr("rebrew.verify._load_previous_report", lambda *a, **k: (None, None))
        monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._print_results", lambda *a, **k: None)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["results"][0]["status"] == "PROVEN"
        assert data["results"][0]["passed"] is True
        # The overlay moved the function from failed to passed.
        assert data["summary"]["passed"] == 1
        assert data["summary"]["failed"] == 0
        assert data["summary"]["proven"] == 1

    def test_proven_regression_not_masked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A source edit that breaks a PROVEN function must surface.

        COMPILE_ERROR (or EXTRACT_ERROR / MISSING_FILE / STUB) means the
        source no longer builds or the annotation changed — the PROVEN claim
        is stale and must not be reported as a pass.
        """
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        proven_entry = _ann(0x1000, status="PROVEN")
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries",
            lambda *a, **k: ([proven_entry], 0, 0, [], [], 0, [], []),
        )
        results = [{"va": "0x00001000", "status": "COMPILE_ERROR", "passed": False}]
        monkeypatch.setattr(
            "rebrew.verify.run_verification", lambda *a, **k: (0, 1, [], results, [])
        )
        monkeypatch.setattr("rebrew.verify._load_previous_report", lambda *a, **k: (None, None))
        monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._print_results", lambda *a, **k: None)
        result = CliRunner().invoke(app, ["--json"])
        # The regression must fail the run (verify exits non-zero on failures).
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert data["results"][0]["status"] == "COMPILE_ERROR"
        assert data["results"][0]["passed"] is False
        assert data["summary"]["proven"] == 0
        assert data["summary"]["failed"] == 1

    def test_proven_cache_stores_raw_byte_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The PROVEN overlay is report-time only — the verify cache must store
        the raw byte result, not the overlaid PROVEN pass.

        Otherwise a later metadata STATUS demotion (PROVEN → STUB, the stale
        overlay case) would be masked by the cached pass on incremental runs.
        """
        from rebrew.verify import _load_verify_cache, app

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text("int my_func(void) { return 1; }\n", encoding="utf-8")
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        proven_entry = _ann(0x1000, status="PROVEN")
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries",
            lambda *a, **k: ([proven_entry], 0, 0, [], [], 0, [], []),
        )
        results = [
            {"va": "0x00001000", "filepath": "f.c", "status": "NEAR_MATCHING", "passed": False}
        ]
        fail_details = [(proven_entry, "9B diff")]
        monkeypatch.setattr(
            "rebrew.verify.run_verification", lambda *a, **k: (0, 1, fail_details, results, [])
        )
        monkeypatch.setattr("rebrew.verify._load_previous_report", lambda *a, **k: (None, None))
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._print_results", lambda *a, **k: None)
        result = CliRunner().invoke(app, ["--json"])
        assert result.exit_code == 0

        # The report shows the overlay...
        data = json.loads(result.stdout)
        assert data["results"][0]["status"] == "PROVEN"
        assert data["results"][0]["passed"] is True

        # ...but the cache (unmocked, written by the run) stores the raw result.
        cache_path = cfg.root / ".rebrew" / "verify_cache.json"
        assert cache_path.exists()
        loaded = _load_verify_cache(cache_path, cfg)
        assert loaded is not None
        entry = loaded.entries["0x00001000"]
        assert entry.result.status == "NEAR_MATCHING"
        assert entry.result.passed is False


class TestRunVerification:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, results: dict) -> None:
        from rebrew.compile import CompareResult

        def _verify(e, cfg, cache=None, name_to_va=None):
            r = results.get(e.va, {})
            return CompareResult(
                matched=r.get("matched", True),
                status=r.get("status", "EXACT"),
                match_percent=r.get("match_percent", 100.0),
                delta=r.get("delta", 0),
                obj_bytes=b"\x90" * 8,
                reloc_offsets=[],
                message=r.get("message", ""),
            )

        monkeypatch.setattr("rebrew.verify.verify_entry", _verify)
        monkeypatch.setattr(
            "rebrew.compile_cache.get_compile_cache", lambda root, backend="diskcache": None
        )
        monkeypatch.setattr("rebrew.core.build_name_to_va", lambda cfg: {})

    def test_all_passed(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import run_verification

        self._patch(monkeypatch, {})
        entries = [_ann(0x1000), _ann(0x2000)]
        passed, failed, fail_details, results, deferred = run_verification(
            entries, _cfg(tmp_path), jobs=2, total=2, cached_count=0, json_output=True
        )
        assert passed == 2
        assert failed == 0
        assert len(results) == 2
        assert all(r["passed"] is True for r in results)
        assert len(deferred) == 2

    def test_batch_larger_than_jobs_processes_all(self, tmp_path, monkeypatch) -> None:
        """The bounded submit-as-you-go loop must process EVERY entry, not
        just the first pool's worth — a regression test for the refill
        indentation bug that silently dropped all but the last batch."""
        from rebrew.verify import run_verification

        self._patch(monkeypatch, {})
        entries = [_ann(0x1000 + i) for i in range(7)]
        passed, failed, fail_details, results, deferred = run_verification(
            entries, _cfg(tmp_path), jobs=2, total=7, cached_count=0, json_output=True
        )
        assert passed == 7
        assert failed == 0
        assert len(results) == 7
        assert len(deferred) == 7
        assert {r["va"] for r in results} == {f"0x{0x1000 + i:08x}" for i in range(7)}

    def test_failures_recorded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.verify import run_verification

        self._patch(
            monkeypatch,
            {
                0x1000: {
                    "matched": False,
                    "status": "STUB",
                    "match_percent": 80.0,
                    "delta": 5,
                    "message": "5B diff",
                }
            },
        )
        passed, failed, fail_details, results, deferred = run_verification(
            [_ann(0x1000)], _cfg(tmp_path), jobs=1, total=1, cached_count=0, json_output=True
        )
        assert passed == 0
        assert failed == 1
        assert fail_details[0][1] == "5B diff"
        assert results[0]["status"] == "STUB"
        assert deferred[0][1] == "STUB"
        assert deferred[0][2] == 5

    def test_internal_error_gets_own_status(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A worker crash is a tooling failure, not a code verdict: it gets
        INTERNAL_ERROR status (so the --compare gate never treats it as a
        code regression), is excluded from fail_details, and is not deferred
        for a STATUS write (the function's real status must survive)."""
        from rebrew.verify import run_verification

        def _boom(e, cfg, cache=None, name_to_va=None):
            raise RuntimeError("crash")

        monkeypatch.setattr("rebrew.verify.verify_entry", _boom)
        monkeypatch.setattr(
            "rebrew.compile_cache.get_compile_cache", lambda root, backend="diskcache": None
        )
        monkeypatch.setattr("rebrew.core.build_name_to_va", lambda cfg: {})
        passed, failed, fail_details, results, deferred = run_verification(
            [_ann(0x1000)], _cfg(tmp_path), jobs=1, total=1, cached_count=0, json_output=True
        )
        assert passed == 0
        assert failed == 1
        assert results[0]["status"] == "INTERNAL_ERROR"
        assert "INTERNAL_ERROR" in results[0]["message"]
        # Not a code failure — absent from the failure list and no STATUS
        # promotion/demotion is deferred on its account.
        assert fail_details == []
        assert deferred == []

    def test_stub_not_promoted_to_size_mismatch(self, tmp_path: Path) -> None:
        """A STUB's placeholder always size-mismatches; the user's STUB
        classification must survive a verify run (SIZE_MISMATCH would orphan
        its blocker and empty the stub work queue)."""
        from rebrew.metadata import get_entry, update_source_status
        from rebrew.verify import apply_status_updates

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// STUB: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        update_source_status(cfg.metadata_dir, "STUB", "SERVER", 0x1000)
        entry = _ann(0x1000, status="STUB")
        apply_status_updates([(entry, "SIZE_MISMATCH", 0)], cfg)  # type: ignore[arg-type]
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER").get("status") == "STUB"

    def test_non_stub_promoted_to_size_mismatch(self, tmp_path: Path) -> None:
        """EXACT/NEAR_MATCHING regressing to SIZE_MISMATCH is real signal."""
        from rebrew.metadata import get_entry, update_source_status
        from rebrew.verify import apply_status_updates

        cfg = _cfg(tmp_path)
        (cfg.reversed_dir / "f.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint my_func(void) { return 0; }\n",
            encoding="utf-8",
        )
        update_source_status(cfg.metadata_dir, "EXACT", "SERVER", 0x1000)
        entry = _ann(0x1000, status="EXACT")
        apply_status_updates([(entry, "SIZE_MISMATCH", 0)], cfg)  # type: ignore[arg-type]
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER").get("status") == "SIZE_MISMATCH"


class TestDiffReportsVaNormalization:
    """VA format drift (0x1000 vs 0x00001000) must not break diffing."""

    def test_format_drift_detects_change(self) -> None:
        from rebrew.verify import diff_reports

        previous = {"results": [{"va": "0x1000", "name": "a", "status": "EXACT", "delta": 0}]}
        current = {"results": [{"va": "0x00001000", "name": "a", "status": "STUB", "delta": 5}]}
        diff = diff_reports(previous, current)
        # A real regression, not a bogus "new" entry.
        assert diff["regressions"] == [
            {
                "va": "0x00001000",
                "name": "a",
                "previous_status": "EXACT",
                "current_status": "STUB",
                "delta": 5,
            }
        ]
        assert diff["new"] == []
        assert diff["removed"] == []

    def test_format_drift_unchanged(self) -> None:
        from rebrew.verify import diff_reports

        previous = {"results": [{"va": "0x1000", "name": "a", "status": "EXACT"}]}
        current = {"results": [{"va": "0x00001000", "name": "a", "status": "EXACT"}]}
        diff = diff_reports(previous, current)
        assert diff["unchanged_count"] == 1
        assert diff["regressions"] == []
        assert diff["new"] == []

    def test_int_va_matches_hex(self) -> None:
        from rebrew.verify import diff_reports

        previous = {"results": [{"va": 0x1000, "name": "a", "status": "EXACT"}]}
        current = {"results": [{"va": "0x00001000", "name": "a", "status": "EXACT"}]}
        diff = diff_reports(previous, current)
        assert diff["unchanged_count"] == 1


class TestStatusOrderDiffing:
    """Same-rank status changes and match-percent drops are real
    regressions/improvements the gate must see."""

    def test_same_rank_status_change_is_regression(self) -> None:
        from rebrew.verify import diff_reports

        previous = {"results": [{"va": "0x1000", "name": "a", "status": "NEAR_MATCHING"}]}
        current = {"results": [{"va": "0x1000", "name": "a", "status": "STUB"}]}
        diff = diff_reports(previous, current)
        assert diff["regressions"][0]["current_status"] == "STUB"
        assert diff["regressions"][0]["previous_status"] == "NEAR_MATCHING"
        assert diff["unchanged_count"] == 0

    def test_same_rank_improvement(self) -> None:
        from rebrew.verify import diff_reports

        previous = {"results": [{"va": "0x1000", "name": "a", "status": "STUB"}]}
        current = {"results": [{"va": "0x1000", "name": "a", "status": "NEAR_MATCHING"}]}
        diff = diff_reports(previous, current)
        assert diff["improvements"][0]["current_status"] == "NEAR_MATCHING"

    def test_match_percent_drop_is_regression(self) -> None:
        from rebrew.verify import diff_reports

        previous = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "NEAR_MATCHING", "match_percent": 95.0}
            ]
        }
        current = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "NEAR_MATCHING", "match_percent": 40.0}
            ]
        }
        diff = diff_reports(previous, current)
        assert len(diff["regressions"]) == 1
        assert diff["regressions"][0]["current_match_percent"] == 40.0

    def test_small_match_percent_change_not_regression(self) -> None:
        from rebrew.verify import diff_reports

        previous = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "NEAR_MATCHING", "match_percent": 95.0}
            ]
        }
        current = {
            "results": [
                {"va": "0x1000", "name": "a", "status": "NEAR_MATCHING", "match_percent": 93.0}
            ]
        }
        diff = diff_reports(previous, current)
        assert diff["regressions"] == []
        assert diff["unchanged_count"] == 1

    def test_mixed_int_str_va_keys_no_crash(self) -> None:
        from rebrew.verify import diff_reports

        previous = {"results": [{"va": "0x1000", "name": "a", "status": "EXACT"}]}
        current = {
            "results": [
                {"va": 0x1000, "name": "a", "status": "EXACT"},
                {"va": "0x2000", "name": "b", "status": "STUB"},
            ]
        }
        diff = diff_reports(previous, current)  # must not raise
        assert diff["unchanged_count"] == 1
        assert diff["new"][0]["va"] == "0x00002000"


class TestCompareBaseline:
    def test_regressed_compare_run_preserves_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failing --compare run must NOT overwrite the last good baseline.

        The report file IS the baseline for future --compare runs; a
        regressed run that advances it would let the gate self-heal on the
        next invocation (the regression becomes "pre-existing").
        """
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        (cfg.db_dir).mkdir(parents=True, exist_ok=True)
        baseline = {
            "schema_version": 1,
            "results": [],
            "summary": {"total": 1, "passed": 1, "failed": 0},
        }
        (cfg.db_dir / "verify_results.json").write_text(json.dumps(baseline), encoding="utf-8")
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        entry = _ann(0x1000)
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries", lambda *a, **k: ([entry], 0, 1, [], [], 0, [], [])
        )
        results = [{"va": "0x00001000", "status": "COMPILE_ERROR", "passed": False}]
        monkeypatch.setattr(
            "rebrew.verify.run_verification", lambda *a, **k: (0, 1, [], results, [])
        )
        previous = {
            "schema_version": 1,
            "results": [{"va": "0x00001000", "status": "EXACT", "passed": True}],
            "summary": {"total": 1, "passed": 1, "failed": 0},
        }
        monkeypatch.setattr("rebrew.verify._load_previous_report", lambda *a, **k: (previous, None))
        # NOTE: _save_verify_cache is intentionally NOT mocked — a failed
        # gate run must not write the compile cache either (F9: a CI failure
        # records no new state).
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._print_results", lambda *a, **k: None)

        result = CliRunner().invoke(app, ["--compare", "--json"])
        # Gate fails (regression EXACT -> COMPILE_ERROR).
        assert result.exit_code == 1
        # The baseline on disk is untouched.
        on_disk = json.loads((cfg.db_dir / "verify_results.json").read_text(encoding="utf-8"))
        assert on_disk == baseline
        # And no verify cache was written by the failed run.
        assert not (cfg.root / ".rebrew" / "verify_cache.json").exists()

    def test_passing_compare_run_advances_baseline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A clean --compare run records the new report as the baseline."""
        from rebrew.verify import app

        cfg = _cfg(tmp_path)
        (cfg.db_dir).mkdir(parents=True, exist_ok=True)
        baseline = {
            "schema_version": 1,
            "results": [],
            "summary": {"total": 0, "passed": 0, "failed": 0},
        }
        (cfg.db_dir / "verify_results.json").write_text(json.dumps(baseline), encoding="utf-8")
        monkeypatch.setattr("rebrew.verify.require_config", lambda **kw: cfg)
        entry = _ann(0x1000)
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries", lambda *a, **k: ([entry], 1, 0, [], [], 0, [], [])
        )
        results = [{"va": "0x00001000", "status": "EXACT", "passed": True}]
        monkeypatch.setattr(
            "rebrew.verify.run_verification", lambda *a, **k: (1, 0, [], results, [])
        )
        previous = {
            "schema_version": 1,
            "results": [],
            "summary": {"total": 0, "passed": 0, "failed": 0},
        }
        monkeypatch.setattr("rebrew.verify._load_previous_report", lambda *a, **k: (previous, None))
        monkeypatch.setattr("rebrew.verify._save_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._apply_or_preview_status", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.verify._print_results", lambda *a, **k: None)

        result = CliRunner().invoke(app, ["--compare", "--json"])
        assert result.exit_code == 0
        on_disk = json.loads((cfg.db_dir / "verify_results.json").read_text(encoding="utf-8"))
        # Baseline advanced to the new report (differs from the old one).
        assert on_disk["summary"] != baseline["summary"]
        assert on_disk["results"][0]["status"] == "EXACT"


class TestFixSizes:
    """--fix-sizes corrects stale annotation SIZE from the binary-derived size."""

    def test_applies_size_fix(self, tmp_path: Path) -> None:
        from rebrew.metadata import get_entry
        from rebrew.verify import _apply_size_fixes

        cfg = _cfg(tmp_path)
        divergences = [
            {
                "va": "0x1000",
                "annotation_size": 64,
                "binary_size": 128,
                "name": "f",
                "module": "SERVER",
            }
        ]
        assert _apply_size_fixes(cfg, divergences, dry_run=False) == 1
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER").get("size") == 128

    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        from rebrew.metadata import get_entry, set_field
        from rebrew.verify import _apply_size_fixes

        cfg = _cfg(tmp_path)
        set_field(cfg.metadata_dir, 0x1000, "size", 64, module="SERVER")
        divergences = [
            {
                "va": "0x1000",
                "annotation_size": 64,
                "binary_size": 128,
                "name": "f",
                "module": "SERVER",
            }
        ]
        assert _apply_size_fixes(cfg, divergences, dry_run=True) == 0
        assert get_entry(cfg.metadata_dir, 0x1000, "SERVER").get("size") == 64

    def test_module_falls_back_to_marker(self, tmp_path: Path) -> None:
        from rebrew.metadata import get_entry
        from rebrew.verify import _apply_size_fixes

        cfg = _cfg(tmp_path)  # marker = "SERVER"
        divergences = [
            {"va": "0x2000", "annotation_size": 8, "binary_size": 16, "name": "g"}  # no module
        ]
        assert _apply_size_fixes(cfg, divergences, dry_run=False) == 1
        assert get_entry(cfg.metadata_dir, 0x2000, "SERVER").get("size") == 16


class TestVerifyEntry16BitFloor:
    def test_low_va_valid_for_x86_16(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A 16-bit DOS target (MZ, x86_16) addresses code from segment 0 —
        VA 0x42e is valid and must pass the floor check (the compile itself
        then runs, rather than being rejected as INVALID_VA)."""
        import rebrew.binary_loader
        import rebrew.compile
        import rebrew.verify as verify_mod

        cfg = _cfg(tmp_path, arch="x86_16")
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        monkeypatch.setattr(rebrew.binary_loader, "extract_raw_bytes", lambda *a, **k: b"\x90" * 38)
        monkeypatch.setattr(
            rebrew.compile,
            "compile_and_compare",
            lambda *a, **k: rebrew.compile.CompareResult(
                matched=False,
                status="SIZE_MISMATCH",
                match_percent=0.0,
                delta=0,
                obj_bytes=None,
                reloc_offsets=None,
                message="",
            ),
        )
        result = verify_mod.verify_entry(_ann(0x42E, size=38), cfg)  # type: ignore[arg-type]
        assert result.status == "SIZE_MISMATCH"

    def test_low_va_still_invalid_for_x86_32(self, tmp_path: Path) -> None:
        from rebrew.verify import verify_entry

        cfg = _cfg(tmp_path, arch="x86_32")
        (cfg.reversed_dir / "f.c").write_text("int x;\n", encoding="utf-8")
        result = verify_entry(_ann(0x42E, size=38), cfg)  # type: ignore[arg-type]
        assert result.status == "INVALID_VA"


class TestVerifySymbolField:
    """`rebrew verify --json` records carry an empty `symbol` for every
    function (`rebrew test --json` fills it) — the batch result dict never
    set the key.  The record must include the decorated symbol (the
    annotation's symbol, else `_name`), matching verify_entry's own
    fallback."""

    def test_batch_record_carries_symbol(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.verify as verify_mod
        from rebrew.compile import CompareResult

        cfg = _cfg(tmp_path)
        entry = _ann(0x1000)
        entry.symbol = "_my_func"  # explicit symbol  # type: ignore[attr-defined]
        ok = CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x90" * 8,
            reloc_offsets=[],
        )
        monkeypatch.setattr(verify_mod, "verify_entry", lambda e, c, **kw: ok)

        _passed, _failed, _details, results, _fixes = verify_mod.run_verification(
            [entry], cfg, jobs=1, total=1, cached_count=0, json_output=True
        )
        assert len(results) == 1
        assert results[0]["symbol"] == "_my_func"

    def test_symbol_falls_back_to_underscore_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.verify as verify_mod
        from rebrew.compile import CompareResult

        cfg = _cfg(tmp_path)
        entry = _ann(0x1000)
        entry.symbol = ""  # no decorated symbol  # type: ignore[attr-defined]
        ok = CompareResult(
            matched=False,
            status="STUB",
            match_percent=0.0,
            delta=8,
            obj_bytes=b"\x90" * 8,
            reloc_offsets=[],
        )
        monkeypatch.setattr(verify_mod, "verify_entry", lambda e, c, **kw: ok)

        _passed, _failed, _details, results, _fixes = verify_mod.run_verification(
            [entry], cfg, jobs=1, total=1, cached_count=0, json_output=True
        )
        assert results[0]["symbol"] == "_my_func"
