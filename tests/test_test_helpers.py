"""Tests for test.py result-dict builders and reloc helpers."""

from pathlib import Path
from typing import Any

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
        common-prefix slice, so --fix-size output is self-consistent."""
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
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 9, cmp, b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01")
        assert d["status"] == "SIZE_MISMATCH"
        assert d["obj_size"] == 12
        assert d["total"] == 12
        assert d["match_count"] == 12  # 100% of the full length
        assert d["size"] == 9  # the annotation value passed through

    def test_fixed_size_match_dict(self) -> None:
        """After --fix-size reclassifies as matched, the dict must carry the
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
        d = build_result_dict_from_compare("f.c", "_f", "0x1000", 12, cmp, b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01")
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
            '[compiler]\nprofile = "msvc6"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text("// FUNCTION: TEST 0x1000\nint f(void) { return 1; }\n")

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
        meta = (tmp_path / "src" / "rebrew-function.toml").read_text()
        assert "size = 4" in meta

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
            '[compiler]\nprofile = "msvc6"\n'
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
        meta_path = tmp_path / "src" / "rebrew-function.toml"
        assert not meta_path.exists() or "size = 4" not in meta_path.read_text()


class TestFixSize:
    """`rebrew test --fix-size` corrects a stale SIZE annotation when ALL
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
            '[compiler]\nprofile = "msvc6"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text(
            "// FUNCTION: X 0x1000\nvoid __stdcall f(int a) { g = a; }\n"
        )

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
        )

    def test_fixes_size_and_promotes(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: self._size_mismatch_result(100.0),
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
                "--fix-size",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        meta = (tmp_path / "src" / "rebrew-function.toml").read_text()
        assert "size = 12" in meta
        assert "status = \"RELOC\"" in meta

    def test_real_mismatch_not_fixed(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        # 90% common-prefix match: real byte differences → --fix-size no-op.
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: self._size_mismatch_result(90.0),
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
                "--fix-size",
                "--json",
            ],
        )
        assert result.exit_code == 1, result.output
        meta_path = tmp_path / "src" / "rebrew-function.toml"
        assert not meta_path.exists() or "size = 12" not in meta_path.read_text()

    def test_dry_run_previews_without_writing(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: self._size_mismatch_result(100.0),
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
                "--fix-size",
                "--dry-run",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "would fix SIZE 9 → 12" in result.output
        meta_path = tmp_path / "src" / "rebrew-function.toml"
        assert not meta_path.exists() or "size = 12" not in meta_path.read_text()


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
            '[compiler]\nprofile = "msvc6"\n'
        )
        src_dir = tmp_path / "src" / "x"
        src_dir.mkdir(parents=True)
        (src_dir / "f.c").write_text("// FUNCTION: TEST 0x1000\nint f(void) { return 1; }\n")
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
        meta = (tmp_path / "src" / "rebrew-function.toml").read_text()
        assert 'cflags = "/O1"' in meta

    def test_no_cflags_no_persist(self, tmp_path: Path, monkeypatch: Any) -> None:
        self._run(tmp_path, monkeypatch)
        meta = (tmp_path / "src" / "rebrew-function.toml").read_text()
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
            '[compiler]\nprofile = "msvc6"\n'
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
    must also honor --fix-size: all-common-bytes-match SIZE_MISMATCHes write
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
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01")  # 9B

        writes: list[tuple[str, int, int]] = []

        def _fake_compile(cfg_, src, cflags, workdir, obj_name=None):
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
        # extract_raw_bytes must return the 9-byte annotation-sized slice.
        monkeypatch.setattr(
            testmod,
            "extract_raw_bytes",
            lambda binpath, va, size: (tmp_path / "x.bin").read_bytes(),
        )
        # Suppress status promotion side effects (validated by the single-path
        # CLI tests).
        monkeypatch.setattr(testmod, "update_source_status", lambda *a, **k: None)
        monkeypatch.setattr(testmod, "_patch_verify_cache", lambda *a, **k: None)

        testmod._test_multi(
            cfg,
            str(tmp_path / "f.c"),
            [self._ann()],
            None,
            fix_size=True,
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
        (tmp_path / "x.bin").write_bytes(b"\x8b\x44\x24\x04\xa3\x20\xda\x03\x01")

        writes: list[tuple[str, int, int]] = []

        def _fake_compile(cfg_, src, cflags, workdir, obj_name=None):
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
            lambda metadata_dir, updates: writes.extend(
                (u["module"], u["va"], u["fields"]["size"]) for u in updates
            )
            or len(updates),
        )
        monkeypatch.setattr(
            testmod,
            "extract_raw_bytes",
            lambda binpath, va, size: (tmp_path / "x.bin").read_bytes(),
        )
        monkeypatch.setattr(testmod, "update_source_status", lambda *a, **k: None)
        monkeypatch.setattr(testmod, "_patch_verify_cache", lambda *a, **k: None)

        testmod._test_multi(
            cfg,
            str(tmp_path / "f.c"),
            [self._ann()],
            None,
            fix_size=False,
        )
        assert writes == []
