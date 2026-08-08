"""Extended tests for rebrew verify.py — verify_entry branches, diff_reports, CLI main."""

import json
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
        assert result.status == "COMPILE_ERROR"
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
        assert result.status == "COMPILE_ERROR"
        assert "Cannot extract" in (result.message or "")

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

        def _watch(sources, retest):
            calls["n"] += 1
            retest()  # invoke once to prove the nested main() path works

        monkeypatch.setattr("rebrew.utils.watch_files", _watch)
        monkeypatch.setattr("rebrew.cli.iter_sources", lambda d, cfg=None: [])
        monkeypatch.setattr(
            "rebrew.verify.prepare_entries", lambda *a, **k: ([], 0, 0, [], [], 0, [])
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
            "rebrew.verify.prepare_entries", lambda *a, **k: ([proven_entry], 0, 1, [], [], 0, [])
        )
        # A proven function's compiled bytes differ from the target — the byte
        # compare yields NEAR_MATCHING, which must be restored to PROVEN.
        results = [{"va": "0x00001000", "status": "NEAR_MATCHING", "passed": False}]
        monkeypatch.setattr(
            "rebrew.verify.run_verification", lambda *a, **k: (0, 0, [], results, [])
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
            "rebrew.verify.prepare_entries", lambda *a, **k: ([proven_entry], 0, 0, [], [], 0, [])
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
        monkeypatch.setattr("rebrew.compile_cache.get_compile_cache", lambda root: None)
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

    def test_internal_error_counts_as_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.verify import run_verification

        def _boom(e, cfg, cache=None, name_to_va=None):
            raise RuntimeError("crash")

        monkeypatch.setattr("rebrew.verify.verify_entry", _boom)
        monkeypatch.setattr("rebrew.compile_cache.get_compile_cache", lambda root: None)
        monkeypatch.setattr("rebrew.core.build_name_to_va", lambda cfg: {})
        passed, failed, fail_details, results, deferred = run_verification(
            [_ann(0x1000)], _cfg(tmp_path), jobs=1, total=1, cached_count=0, json_output=True
        )
        assert passed == 0
        assert failed == 1
        assert results[0]["status"] == "COMPILE_ERROR"
        assert "INTERNAL_ERROR" in results[0]["message"]

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
