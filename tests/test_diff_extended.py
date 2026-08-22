"""Tests for rebrew diff.py — run_diff branches and CLI main."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer
from typer.testing import CliRunner

from rebrew.cli import EXIT_ERROR, EXIT_MISMATCH


def _params(**overrides: object) -> SimpleNamespace:
    defaults: dict = {
        "seed_src": "int f(void) { return 0; }",
        "seed_c": Path("/tmp/f.c"),
        "cl": "cl.exe",
        "inc": [],
        "cflags": "/O2",
        "symbol": "_f",
        "msvc_env": {},
        "cc": None,
        "timeout": 30,
        "cfg": SimpleNamespace(metadata_dir=Path("/tmp/meta"), compile_timeout=30),
        "va_int": 0x1000,
        "target_bytes": b"\x55\x8b\xec\x5d\xc3",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _summary(**overrides: object) -> dict:
    s: dict = {
        "instructions": [],
        "summary": {"structural": 0, "total": 4, "exact": 4},
    }
    s.update(overrides)
    return s


def _patch_matcher(
    monkeypatch: pytest.MonkeyPatch,
    *,
    obj: bytes = b"\x55\x8b\xec\x5d\xc3",
    summary: dict | None = None,
    sim: object | None = None,
) -> None:
    import rebrew.matcher as matcher

    def _build(*_a: object, **_k: object) -> object:
        return SimpleNamespace(ok=True, obj_bytes=obj, reloc_offsets=[], error_msg="")

    monkeypatch.setattr(matcher, "build_candidate_obj_only", _build)
    monkeypatch.setattr(
        matcher,
        "diff_functions",
        lambda *a, **k: summary if summary is not None else _summary(),
    )
    if sim is None:
        sim = SimpleNamespace(
            total_insns=4,
            exact=4,
            reloc_only=0,
            register_only=0,
            structural=0,
            mnemonic_match_ratio=1.0,
            structural_ratio=1.0,
            flag_sensitive=False,
        )
    monkeypatch.setattr(matcher, "structural_similarity", lambda *a, **k: sim)


def _call_run_diff(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mismatches_only: bool = False,
    register_aware: bool = False,
    csv_output: bool = False,
    fix_blocker: bool = False,
    json_output: bool = False,
    summary: dict | None = None,
    obj: bytes = b"\x55\x8b\xec\x5d\xc3",
    sim: object | None = None,
) -> None:
    from rebrew.diff import run_diff

    _patch_matcher(monkeypatch, obj=obj, summary=summary, sim=sim)
    run_diff(
        "f.c",
        mismatches_only,
        register_aware,
        csv_output,
        fix_blocker,
        json_output,
        _params(),
    )


class TestRunDiff:
    def test_build_failure_exits_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import rebrew.matcher as matcher
        from rebrew.diff import run_diff

        monkeypatch.setattr(
            matcher,
            "build_candidate_obj_only",
            lambda *a, **kw: SimpleNamespace(ok=False, obj_bytes=None, error_msg="cl crashed"),
        )
        with pytest.raises(typer.Exit) as exc:
            run_diff("f.c", False, False, False, False, False, _params())
        assert exc.value.exit_code == EXIT_ERROR

    def test_obj_truncated_to_target(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict = {}

        import rebrew.matcher as matcher
        from rebrew.diff import run_diff

        def _diff(target, obj, relocs, **kw):
            seen["obj_len"] = len(obj)
            return _summary()

        monkeypatch.setattr(
            matcher,
            "build_candidate_obj_only",
            lambda *a, **kw: SimpleNamespace(
                ok=True, obj_bytes=b"\x00" * 100, reloc_offsets=[], error_msg=""
            ),
        )
        monkeypatch.setattr(matcher, "diff_functions", _diff)
        monkeypatch.setattr(
            matcher,
            "structural_similarity",
            lambda *a, **k: SimpleNamespace(
                total_insns=0,
                exact=0,
                reloc_only=0,
                register_only=0,
                structural=0,
                mnemonic_match_ratio=0.0,
                structural_ratio=0.0,
                flag_sensitive=False,
            ),
        )
        run_diff("f.c", False, False, False, False, False, _params(target_bytes=b"\x00" * 8))
        assert seen["obj_len"] == 8

    def test_json_output_with_blockers(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        summary = _summary(
            instructions=[
                {
                    "match": "RR",
                    "target": {"disasm": "mov eax, ebx"},
                    "candidate": {"disasm": "mov eax, ecx"},
                }
            ]
        )
        _call_run_diff(monkeypatch, json_output=True, summary=summary)
        out = json.loads(capsys.readouterr().out)
        assert out["blockers"] == ["register allocation"]
        assert "structural_similarity" in out

    def test_json_missing_tail_summary(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        """A short candidate (target-only rows) gains a missing_tail summary:
        the not-yet-decompiled instruction count + first/last target insn."""
        summary = _summary(
            instructions=[
                {
                    "match": "==",
                    "target": {"disasm": "mov eax, 1"},
                    "candidate": {"disasm": "mov eax, 1"},
                },
                {"match": "**", "target": {"disasm": "call 0xcf26"}, "candidate": None},
                {"match": "**", "target": {"disasm": "ret"}, "candidate": None},
            ]
        )
        _call_run_diff(monkeypatch, json_output=True, summary=summary)
        out = json.loads(capsys.readouterr().out)
        assert out["missing_tail"] == {
            "count": 2,
            "first": "call 0xcf26",
            "last": "ret",
        }

    def test_missing_tail_absent_when_no_gap(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        summary = _summary(
            instructions=[
                {
                    "match": "==",
                    "target": {"disasm": "mov eax, 1"},
                    "candidate": {"disasm": "mov eax, 1"},
                }
            ]
        )
        _call_run_diff(monkeypatch, json_output=True, summary=summary)
        out = json.loads(capsys.readouterr().out)
        assert "missing_tail" not in out

    def test_csv_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        summary = _summary(
            instructions=[
                {
                    "index": 0,
                    "match": "**",
                    "target": {"bytes": "55", "disasm": "push ebp"},
                    "candidate": {"bytes": "90", "disasm": "nop"},
                },
                {
                    "index": 1,
                    "match": "==",
                    "target": {"bytes": "c3", "disasm": "ret"},
                    "candidate": {"bytes": "c3", "disasm": "ret"},
                },
            ]
        )
        _call_run_diff(monkeypatch, csv_output=True, mismatches_only=True, summary=summary)
        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        assert lines[0].startswith("Index,Match")
        assert len(lines) == 2  # header + only the ** row
        assert "push ebp" in lines[1]

    def test_terminal_output_with_blockers(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        summary = _summary(
            instructions=[
                {
                    "match": "**",
                    "target": {"disasm": "jg short loc"},
                    "candidate": {"disasm": "jl short loc"},
                }
            ]
        )
        _call_run_diff(monkeypatch, summary=summary)  # must not raise
        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "Auto-classified blockers:" in output
        assert "jump condition swap" in output

    def test_fix_blocker_writes_metadata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.diff import run_diff
        from rebrew.metadata import get_entry

        meta_dir = tmp_path / "meta"
        meta_dir.mkdir()
        seed = tmp_path / "f.c"
        seed.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        p = _params(seed_c=seed, cfg=SimpleNamespace(metadata_dir=meta_dir, compile_timeout=30))
        summary = _summary(
            instructions=[
                {
                    "match": "RR",
                    "target": {"disasm": "mov eax, ebx"},
                    "candidate": {"disasm": "mov eax, ecx"},
                }
            ]
        )
        _patch_matcher(monkeypatch, summary=summary, obj=b"\x90\x8b\xec\x5d\xc3")
        run_diff("f.c", False, False, False, True, False, p)
        entry = get_entry(meta_dir, 0x1000, "SERVER")
        assert "register allocation" in entry.get("blocker", "")
        assert entry.get("blocker_delta", 0) > 0

    def test_fix_blocker_clears_when_no_blockers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.diff import run_diff
        from rebrew.metadata import get_entry, update_field

        meta_dir = tmp_path / "meta"
        meta_dir.mkdir()
        seed = tmp_path / "f.c"
        seed.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        update_field(meta_dir, 0x1000, "blocker", "old blocker", "SERVER")
        update_field(meta_dir, 0x1000, "blocker_delta", 7, "SERVER")
        p = _params(seed_c=seed, cfg=SimpleNamespace(metadata_dir=meta_dir, compile_timeout=30))
        _patch_matcher(monkeypatch, summary=_summary())
        run_diff("f.c", False, False, False, True, False, p)
        entry = get_entry(meta_dir, 0x1000, "SERVER")
        assert entry.get("blocker", "") == ""
        assert entry.get("blocker_delta") is None

    def test_fix_blocker_dry_run_does_not_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        """--fix-blocker --dry-run must preview without touching metadata."""
        from rebrew.diff import run_diff
        from rebrew.metadata import get_entry

        meta_dir = tmp_path / "meta"
        meta_dir.mkdir()
        seed = tmp_path / "f.c"
        seed.write_text("// FUNCTION: SERVER 0x1000\nint f(void) { return 0; }\n", encoding="utf-8")
        p = _params(seed_c=seed, cfg=SimpleNamespace(metadata_dir=meta_dir, compile_timeout=30))
        summary = _summary(
            instructions=[
                {
                    "match": "RR",
                    "target": {"disasm": "mov eax, ebx"},
                    "candidate": {"disasm": "mov eax, ecx"},
                }
            ]
        )
        _patch_matcher(monkeypatch, summary=summary, obj=b"\x90\x8b\xec\x5d\xc3")
        run_diff("f.c", False, False, False, True, False, p, dry_run=True)
        # Blockers were classified but nothing was written.
        entry = get_entry(meta_dir, 0x1000, "SERVER")
        assert not entry.get("blocker")
        assert entry.get("blocker_delta") is None
        # The preview is future-tense and names the blocker.
        captured = capsys.readouterr()
        assert "Would update BLOCKER" in captured.out + captured.err
        assert "register allocation" in captured.out + captured.err

    def test_structural_diffs_exit_mismatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        summary = _summary(summary={"structural": 2, "total": 4, "exact": 2})
        with pytest.raises(typer.Exit) as exc:
            _call_run_diff(monkeypatch, summary=summary)
        assert exc.value.exit_code == EXIT_MISMATCH

    def test_clean_diff_no_exit(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _call_run_diff(monkeypatch, summary=_summary())  # no structural → no exit
        captured = capsys.readouterr()
        output = captured.out + captured.err
        # A perfect diff must not classify blockers or report structural loss.
        assert "Auto-classified blockers" not in output
        assert "Structural similarity" in output
        assert "4 exact" in output
        assert "100.0%" in output


class TestDiffCli:
    def test_invalid_format_errors(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.diff import app

        monkeypatch.setattr("rebrew.diff.require_config", lambda **kw: SimpleNamespace())
        result = CliRunner().invoke(app, ["--format", "xml", "f.c"])
        assert result.exit_code != 0
        assert "--format must be" in result.output

    def test_dispatch_to_run_diff(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from rebrew.diff import app

        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.diff.require_config", lambda **kw: cfg)
        seen: dict = {}
        monkeypatch.setattr(
            "rebrew.match.resolve_build_params",
            lambda *a, **k: _params(),
        )

        def _run_diff(seed_c, mm, rr, csv, fix, json_out, p, **kwargs):
            seen.update(seed_c=seed_c, mm=mm, csv=csv)

        monkeypatch.setattr("rebrew.diff.run_diff", _run_diff)
        result = CliRunner().invoke(app, ["--mismatches-only", "--format", "csv", "f.c"])
        assert result.exit_code == 0
        assert seen["seed_c"] == "f.c"
        assert seen["mm"] is True
        assert seen["csv"] is True

    def test_watch_enters_watch_mode_and_retests(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.diff import app

        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.diff.require_config", lambda **kw: cfg)
        monkeypatch.setattr("rebrew.match.resolve_build_params", lambda *a, **k: _params())

        seen: dict = {}

        def _run_diff(seed_c, mm, rr, csv, fix, json_out, p, **kwargs):
            seen.update(seed_c=seed_c, csv=csv, json_out=json_out)

        monkeypatch.setattr("rebrew.diff.run_diff", _run_diff)
        captured: dict = {}
        monkeypatch.setattr(
            "rebrew.utils.watch_files",
            lambda paths, retest: captured.update(paths=paths, retest=retest),
        )
        result = CliRunner().invoke(app, ["--watch", "f.c"])
        assert result.exit_code == 0
        # First invocation must enter watch mode, not run the diff itself.
        assert seen == {}
        (watched,) = captured["paths"]
        assert watched == Path("f.c").resolve()
        # Re-invoking the retest re-enters main() with watch=False.
        captured["retest"]()
        assert seen["seed_c"] == "f.c"
        assert seen["json_out"] is False

    def test_watch_va_reentry_keeps_va_targeting(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Watch re-entry from a bare-VA positional must keep VA targeting.

        Previously the retest re-entered main() with the resolved path, so a
        multi-function file lost the VA and fell back to its first annotation.
        """
        from rebrew.diff import app

        cfg = SimpleNamespace(
            metadata_dir=tmp_path,
            reversed_dir=tmp_path / "src",
            marker="SERVER",
            source_ext=".c",
        )
        monkeypatch.setattr("rebrew.diff.require_config", lambda **kw: cfg)
        # resolve_source_arg is imported inside main() from rebrew.cli.
        monkeypatch.setattr("rebrew.cli.resolve_source_arg", lambda cfg, arg: "src/dir/f.c")

        va_calls: list[str | None] = []

        def _resolve_build_params(
            cfg, seed_c, cl, inc, cflags, symbol, target_va, target_size, ignore_lint, json_output
        ):
            va_calls.append(target_va)
            return _params()

        monkeypatch.setattr("rebrew.match.resolve_build_params", _resolve_build_params)
        monkeypatch.setattr("rebrew.diff.run_diff", lambda *a, **k: None)
        captured: dict = {}
        monkeypatch.setattr(
            "rebrew.utils.watch_files",
            lambda paths, retest: captured.update(paths=paths, retest=retest),
        )
        result = CliRunner().invoke(app, ["--watch", "0x1000"])
        assert result.exit_code == 0
        assert va_calls == ["0x1000"]  # first pass targets the VA
        captured["retest"]()  # watch re-entry must target the VA too
        assert va_calls == ["0x1000", "0x1000"]


class TestMissingGlobalHints:
    def test_detects_zero_operand(self) -> None:
        from rebrew.diff import _missing_global_hints

        rows = [
            {
                "target": {"disasm": "mov eax, dword ptr [0x10034640]"},
                "candidate": {"disasm": "mov eax, dword ptr [0]"},
            },
            {"target": {"disasm": "push ebp"}, "candidate": {"disasm": "push ebp"}},
        ]
        hints = _missing_global_hints(rows)
        assert len(hints) == 1
        assert hints[0]["candidate"] == "mov eax, dword ptr [0]"
        assert "0x10034640" in hints[0]["target"]

    def test_dedupes_and_ignores_clean(self) -> None:
        from rebrew.diff import _missing_global_hints

        rows = [
            {"target": {"disasm": "a"}, "candidate": {"disasm": "mov ecx, dword ptr [0]"}},
            {"target": {"disasm": "b"}, "candidate": {"disasm": "mov ecx, dword ptr [0]"}},
            {"target": {"disasm": "c"}, "candidate": {"disasm": "xor eax, eax"}},
        ]
        hints = _missing_global_hints(rows)
        assert len(hints) == 1  # deduped
        assert "xor eax, eax" not in [h["candidate"] for h in hints]


class TestResolveGlobalNames:
    def test_rewrites_known_addresses(self) -> None:
        from rebrew.diff import _resolve_global_names

        cfg = SimpleNamespace(
            metadata_dir=Path("/tmp/meta"),
            reversed_dir=Path("/tmp/src"),
            marker="SERVER",
            source_ext=".c",
            target_name="SERVER",
        )
        rows = [
            {
                "target": {"disasm": "mov eax, dword ptr [0x10027078]"},
                "candidate": {"disasm": "mov eax, dword ptr [0]"},
            }
        ]
        # build_name_to_va needs a real data scan; patch the map builder.
        import rebrew.diff as diff_mod

        diff_mod._global_name_map = lambda cfg: {0x10027078: "g_log_level_table"}
        _resolve_global_names(rows, cfg)
        assert rows[0]["target"]["disasm"] == "mov eax, dword ptr [g_log_level_table]"
