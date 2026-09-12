"""Tests for test.py result-dict builders and reloc helpers."""

from pathlib import Path
from typing import Any

import pytest
import typer

from rebrew.compile import CompareResult
from rebrew.test import (
    _expand_reloc_offsets,
    _select_annotation_for_va,
    build_result_dict_from_compare,
)


class TestExpandRelocOffsets:
    def test_expands_4byte_windows(self) -> None:
        assert _expand_reloc_offsets([0, 8], limit=20) == {0, 1, 2, 3, 8, 9, 10, 11}

    def test_clamps_to_limit(self) -> None:
        assert _expand_reloc_offsets([6], limit=8) == {6, 7}

    def test_empty(self) -> None:
        assert _expand_reloc_offsets([], limit=10) == set()


class TestSelectAnnotationForVa:
    """--va on a (possibly multi-function) file must select the annotation AT
    that VA — was lint_annos[0], silently testing the wrong function."""

    @staticmethod
    def _annos() -> list[object]:
        from types import SimpleNamespace as NS

        return [
            NS(va=0x1000, symbol="_f1", size=12, module="S"),
            NS(va=0x2000, symbol="_f2", size=16, module="S"),
        ]

    def test_selects_matching_annotation(self) -> None:
        ann = _select_annotation_for_va(self._annos(), "0x2000", False)
        assert ann is not None
        assert ann.va == 0x2000
        assert ann.symbol == "_f2"

    def test_first_annotation_not_chosen_for_second_va(self) -> None:
        # The regression: requesting the SECOND function's VA used to return
        # the FIRST annotation (its symbol tested against the wrong address).
        ann = _select_annotation_for_va(self._annos(), "0x2000", False)
        assert ann.symbol != "_f1"

    def test_returns_none_when_no_annotation_matches(self) -> None:
        assert _select_annotation_for_va(self._annos(), "0x9999", False) is None

    def test_empty_annotation_list(self) -> None:
        assert _select_annotation_for_va([], "0x1000", False) is None


class TestBuildResultDictFromCompare:
    def test_matched_exact(self) -> None:
        cmp = CompareResult(
            matched=True,
            status="EXACT",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x55",
            reloc_offsets=[],
            message="match",
        )
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 1, cmp, b"\x55")
        assert d["status"] == "EXACT"
        assert d["match_count"] == 1
        assert d["total"] == 1
        assert d["mismatches"] == []

    def test_reloc_status(self) -> None:
        cmp = CompareResult(
            matched=True,
            status="RELOC",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x55\x89",
            reloc_offsets=[0],
            message="reloc",
        )
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 2, cmp, b"\x55\x89")
        assert d["status"] == "RELOC"
        assert d["match_count"] == 2
        assert d["reloc_count"] == 1

    def test_partial_near_matching(self) -> None:
        cmp = CompareResult(
            matched=False,
            status="NEAR_MATCHING",
            match_percent=80.0,
            delta=1,
            obj_bytes=b"\x55\x89",
            reloc_offsets=[],
            message="diff",
        )
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 2, cmp, b"\x55\x90")
        assert d["status"] == "NEAR_MATCHING"
        assert d["match_count"] == 2  # round(0.8 * 2)
        assert len(d["mismatches"]) == 1  # offset 1 differs

    def test_error_status(self) -> None:
        cmp = CompareResult(
            matched=False,
            status="COMPILE_ERROR",
            match_percent=0.0,
            delta=0,
            obj_bytes=None,
            reloc_offsets=None,
            message="syntax",
        )
        d = build_result_dict_from_compare("f.c", "_f", "", 0, cmp, b"")
        assert d["status"] == "COMPILE_ERROR"
        assert d["obj_size"] == 0
        assert d["mismatches"] == []

    def test_size_mismatch_reports_full_obj_size(self) -> None:
        """A SIZE_MISMATCH truncates cmp.obj_bytes to the target length — the
        JSON must report the full compiled size (total/obj_size), not the
        common-prefix slice, so --fix-sizes output is self-consistent."""
        cmp = CompareResult(
            matched=False,
            status="SIZE_MISMATCH",
            match_percent=100.0,
            delta=3,
            obj_bytes=b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00",  # truncated (orig 12B)
            reloc_offsets=[5],
            message="SIZE_MISMATCH",
            full_obj_size=12,
        )
        d = build_result_dict_from_compare(
            "f.c", "_f", "0x1000", 9, cmp, b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01"
        )
        assert d["status"] == "SIZE_MISMATCH"
        assert d["obj_size"] == 12
        assert d["total"] == 12
        assert d["match_count"] == 12  # 100% of the full length
        assert d["size"] == 9  # the annotation value passed through

    def test_fixed_size_match_dict(self) -> None:
        """After --fix-sizes reclassifies as matched, the dict must carry the
        corrected status and full sizes."""
        cmp = CompareResult(
            matched=True,
            status="RELOC",
            match_percent=100.0,
            delta=0,
            obj_bytes=b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00",  # truncated view
            reloc_offsets=[5],
            message="RELOC-NORM MATCH (1 relocs)",
            full_obj_size=12,
        )
        d = build_result_dict_from_compare(
            "f.c", "_f", "0x1000", 12, cmp, b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01"
        )
        assert d["status"] == "RELOC"
        assert d["total"] == 12
        assert d["match_count"] == 12
        assert d["obj_size"] == 12


class TestSizePersistence:
    """`rebrew test --va --size` must persist the resolved SIZE to metadata so
    downstream tools (diff, near-diag) can resolve it without re-supplying it."""

    def test_persists_size_on_promote(self, tmp_path: Path, monkeypatch: Any) -> None:
        import shutil

        from typer.testing import CliRunner

        from rebrew.compile import CompareResult
        from rebrew.main import app as umbrella

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text("// FUNCTION: X 0x1000\nint f(void) { return 1; }\n")

        def _fake_compile(*a, **k):
            return CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"\xc3",
                reloc_offsets=[],
            )

        monkeypatch.setattr("rebrew.test.compile_and_compare", _fake_compile)
        result = CliRunner().invoke(
            umbrella,
            ["test", "src/x/f.c", "--va", "0x1000", "--size", "4", "--symbol", "_f"],
        )
        assert result.exit_code == 0, result.output
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        assert "size = 4" in meta

    def test_va_promotes_under_selected_module_not_first(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """`rebrew test multi.c --va 0x2000` on a multi-module file must write
        SIZE/CFLAGS/STATUS under the SECOND function's module, not the first's
        (the old code used lint_annos[0] for every write — a phantom
        (first_module, 0x2000) entry while the real one stayed stale).  An
        empty marker means the parser keeps every module in the file."""
        import shutil

        from typer.testing import CliRunner

        from rebrew.compile import CompareResult
        from rebrew.main import app as umbrella

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\nmarker = ""\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "multi.c").write_text(
            "// FUNCTION: SERVER 0x1000\nint f1(void) { return 1; }\n\n"
            "// FUNCTION: CLIENT 0x2000\nint f2(void) { return 2; }\n"
        )

        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"\xc3",
                reloc_offsets=[],
            ),
        )
        result = CliRunner().invoke(
            umbrella,
            ["test", "src/x/multi.c", "--va", "0x2000", "--size", "8", "--symbol", "_f2"],
        )
        assert result.exit_code == 0, result.output
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        # The CLIENT entry got the SIZE + EXACT status; no phantom SERVER.0x2000.
        assert "CLIENT.0x00002000" in meta
        assert "size = 8" in meta
        assert 'status = "EXACT"' in meta
        assert "SERVER.0x00002000" not in meta
        # The first function's entry is untouched (no status written for it).
        assert "SERVER.0x00001000" not in meta

    def test_no_promote_skips_size_write(self, tmp_path: Path, monkeypatch: Any) -> None:
        import shutil

        from typer.testing import CliRunner

        from rebrew.compile import CompareResult
        from rebrew.main import app as umbrella

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text("// FUNCTION: TEST 0x1000\nint f(void) { return 1; }\n")

        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"\xc3",
                reloc_offsets=[],
            ),
        )
        result = CliRunner().invoke(
            umbrella,
            [
                "test",
                "src/x/f.c",
                "--va",
                "0x1000",
                "--size",
                "4",
                "--symbol",
                "_f",
                "--no-promote",
            ],
        )
        assert result.exit_code == 0, result.output
        meta_path = tmp_path / "src" / "rebrew-functions.toml"
        assert not meta_path.exists() or "size = 4" not in meta_path.read_text()


class TestFixSize:
    """`rebrew test --fix-sizes` corrects a stale SIZE annotation when ALL
    common bytes match (the compiled size is the definitive evidence), and
    must NOT touch the size when the mismatch is a real byte difference."""

    def _project(self, tmp_path: Path, monkeypatch: Any) -> None:
        import shutil

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text("// FUNCTION: X 0x1000\nvoid __stdcall f(int a) { g = a; }\n")

    def _size_mismatch_result(self, match_percent: float) -> CompareResult:
        return CompareResult(
            matched=False,
            status="SIZE_MISMATCH",
            match_percent=match_percent,
            delta=3,
            # Truncated to the (stale) annotated size 9; full compiled size 12.
            obj_bytes=b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00",
            reloc_offsets=[5],
            message="SIZE_MISMATCH",
            full_obj_size=12,
            full_obj_bytes=b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x04\x00",
        )

    @staticmethod
    def _real_binary_bytes() -> bytes:
        # The 12-byte "real" function at 0x1000; the 9-byte slice is the stale
        # annotation (missing `ret 4`).  Reloc slot 5-8 differs between
        # compiled (a3 00000000) and binary (a3 20 da 03 01).
        return b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xc2\x04\x00"

    def test_fixes_size_and_promotes(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: self._size_mismatch_result(100.0),
        )
        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: self._real_binary_bytes()[:size],
        )
        result = CliRunner().invoke(
            umbrella,
            [
                "test",
                "src/x/f.c",
                "--va",
                "0x1000",
                "--size",
                "9",
                "--symbol",
                "_f",
                "--fix-sizes",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        assert "size = 12" in meta
        assert 'status = "RELOC"' in meta

    def test_real_mismatch_not_fixed(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        # 90% common-prefix match: real byte differences → --fix-sizes no-op.
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: self._size_mismatch_result(90.0),
        )
        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: self._real_binary_bytes()[:size],
        )
        result = CliRunner().invoke(
            umbrella,
            [
                "test",
                "src/x/f.c",
                "--va",
                "0x1000",
                "--size",
                "9",
                "--symbol",
                "_f",
                "--fix-sizes",
                "--json",
            ],
        )
        assert result.exit_code == 1, result.output
        meta_path = tmp_path / "src" / "rebrew-functions.toml"
        assert not meta_path.exists() or "size = 12" not in meta_path.read_text()

    def test_dry_run_previews_without_writing(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: self._size_mismatch_result(100.0),
        )
        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: self._real_binary_bytes()[:size],
        )
        result = CliRunner().invoke(
            umbrella,
            [
                "test",
                "src/x/f.c",
                "--va",
                "0x1000",
                "--size",
                "9",
                "--symbol",
                "_f",
                "--fix-sizes",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "would fix SIZE 9 → 12" in result.output
        meta_path = tmp_path / "src" / "rebrew-functions.toml"
        assert not meta_path.exists() or "size = 12" not in meta_path.read_text()

    def test_fix_sizes_writes_the_va_selected_module(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A multi-marker file: `--va` picks the addressed module, so the
        corrected SIZE lands under B, never under the file's first module A."""
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        # No marker filter: a genuinely multi-module file (module A and B are
        # not the project's target marker, so `marker = ""` keeps both).
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\nmarker = ""\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src = tmp_path / "src" / "x" / "f.c"
        src.write_text(
            "// FUNCTION: A 0x1000\n"
            "void __stdcall f(int a) { g = a; }\n"
            "// FUNCTION: B 0x2000\n"
            "void __stdcall f2(int a) { g = a; }\n"
        )
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: self._size_mismatch_result(100.0),
        )
        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: self._real_binary_bytes()[:size],
        )
        result = CliRunner().invoke(
            umbrella,
            [
                "test",
                "src/x/f.c",
                "--va",
                "0x2000",
                "--size",
                "9",
                "--symbol",
                "f2",
                "--fix-sizes",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        assert '"B.0x00002000"' in meta
        assert "size = 12" in meta
        assert "A.0x00002000" not in meta


class TestUnchangedStatusCachePatch:
    """A refused promotion with the SAME status still carries fresh metrics:
    the single-file path must patch the verify cache so status/todo see the
    improved match_percent (the batch path patches every result)."""

    def test_single_path_patches_unchanged_status(self, tmp_path: Path, monkeypatch: Any) -> None:
        import shutil

        from typer.testing import CliRunner

        from rebrew.compile import CompareResult
        from rebrew.main import app as umbrella

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text("// FUNCTION: X 0x1000\nint f(void) { return 1; }\n")
        # The annotation already carries the same status the compile yields, so
        # should_promote_status refuses the write and only the cache patch runs.
        (tmp_path / "src" / "rebrew-functions.toml").write_text(
            '["X.0x00001000"]\nstatus = "NEAR_MATCHING"\n'
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=3,
                obj_bytes=b"\x90\x90\x90\x90",
                reloc_offsets=[],
            ),
        )
        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes", lambda binpath, va, size: b"\x90\x90\x90\x90"[:size]
        )
        monkeypatch.setattr("rebrew.test.update_source_status", lambda *a, **k: None)
        patched: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        monkeypatch.setattr(
            "rebrew.test._patch_verify_cache",
            lambda *a, **k: patched.append((a, k)),
        )

        result = CliRunner().invoke(
            umbrella,
            ["test", "src/x/f.c", "--va", "0x1000", "--size", "4", "--symbol", "_f", "--json"],
        )
        assert result.exit_code == 1, result.output
        assert len(patched) == 1
        args, kwargs = patched[0]
        assert args[1] == 0x1000
        assert args[2] == "NEAR_MATCHING"
        assert args[3] == 2  # 50% of 4 bytes
        assert args[4] == 4
        assert kwargs["delta"] == 3


class TestCflagsPersistence:
    """`rebrew test --cflags` must persist the explicit override so verify
    recompiles with the flags that produced the match (else an /O1 EXACT
    match is demoted to NEAR_MATCHING by project-default recompiles)."""

    def _run(self, tmp_path: Path, monkeypatch: Any, *extra: str) -> None:
        import shutil

        from typer.testing import CliRunner

        from rebrew.compile import CompareResult
        from rebrew.main import app as umbrella

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text("// FUNCTION: X 0x1000\nint f(void) { return 1; }\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"\xc3",
                reloc_offsets=[],
            ),
        )
        result = CliRunner().invoke(
            umbrella,
            ["test", "src/x/f.c", "--va", "0x1000", "--size", "4", "--symbol", "_f", *extra],
        )
        assert result.exit_code == 0, result.output

    def test_persists_explicit_cflags(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._run(tmp_path, monkeypatch, "--cflags", "/O1")
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        assert 'cflags = "/O1"' in meta

    def test_no_cflags_no_persist(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._run(tmp_path, monkeypatch)
        meta = (tmp_path / "src" / "rebrew-functions.toml").read_text()
        assert "cflags" not in meta


class TestCliSizeLintSuppression:
    """`rebrew test --va --size` must not report "Invalid SIZE: 0" for a
    fresh function whose annotation lacks a Size: line (CLI size is
    authoritative for the lint pass)."""

    def test_cli_size_suppresses_lint_error(self, tmp_path: Path, monkeypatch: Any) -> None:
        import shutil

        from typer.testing import CliRunner

        from rebrew.compile import CompareResult
        from rebrew.main import app as umbrella

        fixture = Path(__file__).parent / "fixtures" / "mini_pe.exe"
        (tmp_path / "original").mkdir()
        shutil.copy(fixture, tmp_path / "original" / "x.exe")
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "original/x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text(
            "// FUNCTION: TEST 0x1000\nint f(void) { return 1; }\n"  # no Size: line
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"\xc3",
                reloc_offsets=[],
            ),
        )
        result = CliRunner().invoke(
            umbrella,
            ["test", "src/x/f.c", "--va", "0x1000", "--size", "4", "--symbol", "_f"],
        )
        assert result.exit_code == 0, result.output
        assert "Invalid SIZE" not in result.output


class TestMultiFixSize:
    """The multi-function path (`rebrew test multi.c` with no --va/--size)
    must also honor --fix-sizes: all-common-bytes-match SIZE_MISMATCHes write
    the compiled size and promote, without leaving the file."""

    @staticmethod
    def _ann(size: int = 9) -> Any:
        from rebrew.annotation import Annotation

        return Annotation(
            marker_type="FUNCTION",
            module="X",
            va=0x1000,
            size=size,
            symbol="_f",
            source="void f(int a) { g = a; }",
        )

    def test_fixes_size_in_multi_path(self, tmp_path: Path, monkeypatch: Any) -> None:
        from types import SimpleNamespace as NS

        import rebrew.test as testmod

        (tmp_path / "f.c").write_text("// FUNCTION: X 0x1000\nvoid f(int a) { g = a; }\n")
        cfg = NS(
            target_binary=str(tmp_path / "x.bin"),
            metadata_dir=tmp_path,
            reversed_dir=tmp_path,
            marker="X",
            default_jobs=1,
            compile_timeout=60,
        )
        # 12-byte real function: 9-byte annotation slice is stale (missing ret 4).
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xc2\x04\x00")

        writes: list[tuple[str, int, int]] = []

        def _fake_compile(cfg_, src, cflags, workdir, obj_name=None, toolchain=None):
            return str(tmp_path / "f.obj"), ""

        def _fake_parse(obj_path, sym):
            # Full compiled 12 bytes; reloc at offset 5.
            from rebrew.matcher.parsers import CoffRelocRecord

            return (
                b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x04\x00",
                {5: "_g"},
                [CoffRelocRecord(offset=5, type=6, symbol="_g")],
            )

        def _fake_compare(obj, tgt, relocs, **kw):
            return True, 9, 9, [5], []

        def _fake_set_fields(metadata_dir, updates):
            for u in updates:
                writes.append((u["module"], u["va"], u["fields"]["size"]))
            return len(updates)

        monkeypatch.setattr(testmod, "compile_to_obj", _fake_compile)
        monkeypatch.setattr(testmod, "parse_obj_symbol_and_relocs", _fake_parse)
        monkeypatch.setattr(testmod, "smart_reloc_compare", _fake_compare)
        monkeypatch.setattr(testmod, "set_fields_batch", _fake_set_fields)

        # extract_raw_bytes must slice by size (the evidence check re-extracts
        # at the full compiled size).
        def _fake_extract(binpath, va, size):
            return (tmp_path / "x.bin").read_bytes()[:size]

        monkeypatch.setattr(testmod, "extract_raw_bytes", _fake_extract)
        # Suppress status promotion side effects (validated by the single-path
        # CLI tests).
        monkeypatch.setattr(testmod, "update_source_status", lambda *a, **k: None)
        monkeypatch.setattr(testmod, "_patch_verify_cache", lambda *a, **k: None)

        testmod._test_multi(
            cfg,
            str(tmp_path / "f.c"),
            [self._ann()],
            None,
            fix_sizes=True,
        )
        assert writes == [("X", 0x1000, 12)]

    def test_no_fix_without_flag(self, tmp_path: Path, monkeypatch: Any) -> None:
        from types import SimpleNamespace as NS

        import rebrew.test as testmod

        (tmp_path / "f.c").write_text("// FUNCTION: X 0x1000\nvoid f(int a) { g = a; }\n")
        cfg = NS(
            target_binary=str(tmp_path / "x.bin"),
            metadata_dir=tmp_path,
            reversed_dir=tmp_path,
            marker="X",
            default_jobs=1,
            compile_timeout=60,
        )
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xc2\x04\x00")

        writes: list[tuple[str, int, int]] = []

        def _fake_compile(cfg_, src, cflags, workdir, obj_name=None, toolchain=None):
            return str(tmp_path / "f.obj"), ""

        def _fake_parse(obj_path, sym):
            from rebrew.matcher.parsers import CoffRelocRecord

            return (
                b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x04\x00",
                {5: "_g"},
                [CoffRelocRecord(offset=5, type=6, symbol="_g")],
            )

        def _fake_compare(obj, tgt, relocs, **kw):
            return True, 9, 9, [5], []

        monkeypatch.setattr(testmod, "compile_to_obj", _fake_compile)
        monkeypatch.setattr(testmod, "parse_obj_symbol_and_relocs", _fake_parse)
        monkeypatch.setattr(testmod, "smart_reloc_compare", _fake_compare)
        monkeypatch.setattr(
            testmod,
            "set_fields_batch",
            lambda metadata_dir, updates: (
                writes.extend((u["module"], u["va"], u["fields"]["size"]) for u in updates)
                or len(updates)
            ),
        )
        monkeypatch.setattr(
            testmod,
            "extract_raw_bytes",
            lambda binpath, va, size: (tmp_path / "x.bin").read_bytes()[:size],
        )
        monkeypatch.setattr(testmod, "update_source_status", lambda *a, **k: None)
        monkeypatch.setattr(testmod, "_patch_verify_cache", lambda *a, **k: None)

        with pytest.raises(typer.Exit) as exc_info:
            testmod._test_multi(
                cfg,
                str(tmp_path / "f.c"),
                [self._ann()],
                None,
                fix_sizes=False,
            )
        # SIZE_MISMATCH is unmatched → exit 1 per the documented contract.
        assert exc_info.value.exit_code == 1
        assert writes == []

    def test_overlong_candidate_is_size_mismatch_not_stub(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        """A 20B compiled symbol against an 8B annotation is a real
        SIZE_MISMATCH (over-long), not an 8B stub body — the classifier needs
        the pre-truncation lengths."""
        from types import SimpleNamespace as NS

        import rebrew.test as testmod

        (tmp_path / "f.c").write_text("// FUNCTION: X 0x1000\nvoid f(void) { g(); }\n")
        cfg = NS(
            target_binary=str(tmp_path / "x.bin"),
            metadata_dir=tmp_path,
            reversed_dir=tmp_path,
            marker="X",
            default_jobs=1,
            compile_timeout=60,
        )
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01")

        def _fake_parse(obj_path, sym):
            # 20 compiled bytes; the 8B annotation truncates the common prefix.
            return (bytes(range(20)), {}, [])

        def _fake_compare(obj, tgt, relocs, **kw):
            return True, len(obj), len(obj), [], []

        captured: list[Any] = []

        monkeypatch.setattr(
            testmod, "compile_to_obj", lambda *a, **k: (str(tmp_path / "f.obj"), "")
        )
        monkeypatch.setattr(testmod, "parse_obj_symbol_and_relocs", _fake_parse)
        monkeypatch.setattr(testmod, "smart_reloc_compare", _fake_compare)
        monkeypatch.setattr(
            testmod,
            "extract_raw_bytes",
            lambda b, va, size: (tmp_path / "x.bin").read_bytes()[:size],
        )
        monkeypatch.setattr(testmod, "update_source_status", lambda *a, **k: None)
        monkeypatch.setattr(testmod, "_patch_verify_cache", lambda *a, **k: None)
        monkeypatch.setattr(testmod, "json_print", lambda payload: captured.append(payload))

        ann = self._ann(size=8)
        with pytest.raises(typer.Exit):
            testmod._test_multi(
                cfg,
                str(tmp_path / "f.c"),
                [ann],
                None,
                json_output=True,
                fix_sizes=False,
            )
        row = captured[0]["results"][0]
        assert row["status"] == "SIZE_MISMATCH", row
        assert row["obj_size"] == 20, row
        assert row["total"] == 20, row


class TestFixSizeEvidence:
    """--fix-sizes's evidence gate must refuse a fix when the region beyond
    the common prefix hides a mismatch — the false-fix hazard."""

    @staticmethod
    def _cfg(tmp_path: Path) -> Any:
        from types import SimpleNamespace as NS

        return NS(target_binary=str(tmp_path / "x.bin"))

    def test_extension_tail_matches(self, tmp_path: Path, monkeypatch: Any) -> None:
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xc2\x04\x00")
        # compiled 12B > annotated 9B; tail (ret 4) matches the binary.
        from rebrew.test import _fix_size_evidence_ok

        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: Path(binpath).read_bytes()[:size],
        )
        ok = _fix_size_evidence_ok(
            self._cfg(tmp_path),
            0x1000,
            b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x04\x00",  # reloc at 5
            b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01",
            [5],
        )
        assert ok is True

    def test_extension_tail_differs_refuses(self, tmp_path: Path, monkeypatch: Any) -> None:
        # The annotated slice cut the function short AND the tail differs —
        # fixing the size would hide unreproduced code.
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xeb\x05\x00")
        from rebrew.test import _fix_size_evidence_ok

        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: Path(binpath).read_bytes()[:size],
        )
        ok = _fix_size_evidence_ok(
            self._cfg(tmp_path),
            0x1000,
            b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x04\x00",
            b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01",
            [5],
        )
        assert ok is False

    def test_annotation_extra_padding_allowed(self, tmp_path: Path) -> None:
        # Annotation 12B > compiled 9B; extra bytes are int3 padding.
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xcc\xcc\xcc")
        from rebrew.test import _fix_size_evidence_ok

        ok = _fix_size_evidence_ok(
            self._cfg(tmp_path),
            0x1000,
            b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00",
            b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xcc\xcc\xcc",
            [5],
        )
        assert ok is True

    def test_annotation_extra_real_code_refuses(self, tmp_path: Path) -> None:
        # Annotation 12B > compiled 9B; extra bytes are REAL code (partial
        # reproduction hazard — shrinking the size would false-EXACT).
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xe8\x00\x00")
        from rebrew.test import _fix_size_evidence_ok

        ok = _fix_size_evidence_ok(
            self._cfg(tmp_path),
            0x1000,
            b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00",
            b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xe8\x00\x00",
            [5],
        )
        assert ok is False

    def test_equal_lengths_trivially_ok(self, tmp_path: Path) -> None:
        (tmp_path / "x.bin").write_bytes(b"\x55\x8b\xec")
        from rebrew.test import _fix_size_evidence_ok

        assert (
            _fix_size_evidence_ok(self._cfg(tmp_path), 0x1000, b"\x55\x8b\xec", b"\x55\x8b\xec", [])
            is True
        )


class TestFixSizeDisasmFallback:
    """--fix-sizes's evidence gate falls back to the disassembly extent when
    the padding/extension checks refuse — a discovery boundary merged the
    NEXT function into the annotation (real code beyond the compiled end)."""

    def test_merged_boundary_allowed_when_extent_matches(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew.test import _fix_size_evidence_ok

        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: b"",
        )
        monkeypatch.setattr(
            "rebrew.test._disasm_extent",
            lambda cfg, va: 10,  # matches compiled
        )
        from types import SimpleNamespace as NS

        cfg = NS(target_binary=str(tmp_path / "x.bin"))
        # annotation 22B, compiled 10B, extra bytes are REAL code (e8...)
        compiled = bytes.fromhex("8b 44 24 04 83 c0 01 c2 04 00")
        target = compiled + bytes.fromhex("e8 00 00 00 00 e9 00 00 00 00 00 00")
        ok = _fix_size_evidence_ok(cfg, 0x1000, compiled, target, [])
        assert ok is True

    def test_merged_boundary_refused_when_extent_mismatches(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from rebrew.test import _fix_size_evidence_ok

        monkeypatch.setattr(
            "rebrew.test.extract_raw_bytes",
            lambda binpath, va, size: b"",
        )
        monkeypatch.setattr(
            "rebrew.test._disasm_extent",
            lambda cfg, va: 22,  # function continues
        )
        from types import SimpleNamespace as NS

        cfg = NS(target_binary=str(tmp_path / "x.bin"))
        target = b"\x8b\x44\x24\x04\xc2\x04\x00" + b"\xe8\x00\x00\x00\x00" * 3
        ok = _fix_size_evidence_ok(cfg, 0x1000, b"\x8b\x44\x24\x04\xc2\x04\x00", target, [])
        assert ok is False

    def test_extent_none_refuses(self, tmp_path: Path, monkeypatch: Any) -> None:
        from rebrew.test import _fix_size_evidence_ok

        monkeypatch.setattr("rebrew.test.extract_raw_bytes", lambda *a, **k: b"")
        monkeypatch.setattr("rebrew.test._disasm_extent", lambda cfg, va: None)
        from types import SimpleNamespace as NS

        cfg = NS(target_binary=str(tmp_path / "x.bin"))
        target = b"\x8b\x44\x24\x04\xc2\x04\x00" + b"\xe8\x00\x00\x00\x00" * 3
        ok = _fix_size_evidence_ok(cfg, 0x1000, b"\x8b\x44\x24\x04\xc2\x04\x00", target, [])
        assert ok is False


class TestMultiCachePatchDelta:
    """`_test_multi` must patch the verify cache with the real byte delta.

    Recomputing `total - match_count` yields 0 for a SIZE_MISMATCH (the object
    is truncated to the target length), which `todo` reads as a "0B diff — try
    flag sweep" quick-win.
    """

    def test_multi_patch_receives_the_byte_delta(self, tmp_path: Path, monkeypatch: Any) -> None:
        from types import SimpleNamespace as NS

        import rebrew.test as testmod
        from rebrew.annotation import Annotation

        (tmp_path / "f.c").write_text("// FUNCTION: X 0x1000\nvoid f(int a) { g = a; }\n")
        cfg = NS(
            target_binary=str(tmp_path / "x.bin"),
            metadata_dir=tmp_path,
            reversed_dir=tmp_path,
            marker="X",
            default_jobs=1,
            compile_timeout=60,
        )
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01\xc2\x04\x00")
        ann = Annotation(
            marker_type="FUNCTION",
            module="X",
            va=0x1000,
            size=12,
            symbol="_f",
            source="void f(int a) { g = a; }",
        )

        def _fake_compile(cfg_, src, cflags, workdir, obj_name=None, toolchain=None):
            return str(tmp_path / "f.obj"), ""

        def _fake_parse(obj_path, sym):
            return (b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x04\x00", {}, [])

        # 9 of 12 bytes match: NEAR_MATCHING with a real byte delta.
        _obj = b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x04\x00"
        # Target differs in 2 bytes → the compare's real byte delta is 2.
        _tgt = b"\x8b\x44\x24\x04\xa3\x00\x00\x00\x00\xc2\x99\x99"

        def _fake_compare(obj, tgt, relocs, **kw):
            return False, 9, 12, [], []

        captured: list[dict[str, Any]] = []

        def _fake_patch(cfg_, va, status, match_count, total, **kwargs):
            captured.append({"va": va, "status": status, **kwargs})

        import typer

        monkeypatch.setattr(testmod, "compile_to_obj", _fake_compile)
        monkeypatch.setattr(testmod, "parse_obj_symbol_and_relocs", _fake_parse)
        monkeypatch.setattr(testmod, "smart_reloc_compare", _fake_compare)
        monkeypatch.setattr(testmod, "update_source_status", lambda *a, **k: None)
        monkeypatch.setattr(testmod, "_patch_verify_cache", _fake_patch)
        monkeypatch.setattr(testmod, "extract_raw_bytes", lambda *a, **k: _tgt)

        # A NEAR_MATCHING result exits 1 by the documented contract.
        with pytest.raises(typer.Exit):
            testmod._test_multi(cfg, str(tmp_path / "f.c"), [ann], None)

        assert captured, "the multi path did not patch the verify cache"
        # The real byte delta, not the recomputed `total - match_count` (which
        # is 0 here because the object is truncated to the target length).
        assert captured[0]["delta"] == 2, captured
