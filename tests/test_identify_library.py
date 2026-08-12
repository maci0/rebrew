"""Tests for rebrew identify-library — the combined library-identification pass."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from typer.testing import CliRunner

from rebrew.identify_library import (
    LibCandidate,
    _infer_module,
    collect_candidates,
    write_candidates,
)
from rebrew.main import app

FIXTURES = Path(__file__).parent / "fixtures"


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        root=tmp_path,
        target_binary=FIXTURES / "mini_pe.exe",
        reversed_dir=tmp_path / "src",
        metadata_dir=tmp_path,
        library_modules=["ZLIB", "MSVCRT"],
        target_name="SERVER",
        marker="SERVER",
    )


class TestInferModule:
    def test_crt_prefix(self) -> None:
        assert _infer_module("_malloc", "ZLIB") == "MSVCRT"
        assert _infer_module("memcpy", "ZLIB") == "MSVCRT"

    def test_unclassified_uses_default(self) -> None:
        assert _infer_module("DeflateInit", "ZLIB") == "ZLIB"


class TestCollectCandidates:
    def test_merge_precedence_crt_wins(self, tmp_path: Path, monkeypatch) -> None:
        """Same VA from all three backends: CRT outranks FLIRT outranks import."""
        crt = [
            LibCandidate(
                va=0x1000,
                name="_malloc",
                module="MSVCRT",
                kind="crt",
                confidence=0.9,
                source_ref="crt/malloc.c",
            )
        ]
        flirt = [
            LibCandidate(va=0x1000, name="_malloc", module="MSVCRT", kind="flirt", confidence=0.5)
        ]
        imp = [
            LibCandidate(
                va=0x1000, name="GetTickCount", module="MSVCRT", kind="import", confidence=0.3
            )
        ]
        monkeypatch.setattr("rebrew.identify_library._crt_candidates", lambda cfg: crt)
        monkeypatch.setattr("rebrew.identify_library._flirt_candidates", lambda cfg, m: flirt)
        monkeypatch.setattr("rebrew.identify_library._import_candidates", lambda cfg, m: imp)
        out = collect_candidates(_cfg(tmp_path))
        assert len(out) == 1
        assert out[0].kind == "crt"

    def test_distinct_vas_all_kept_sorted(self, tmp_path: Path, monkeypatch) -> None:
        imp = [
            LibCandidate(va=0x2000, name="b", module="MSVCRT", kind="import", confidence=0.3),
            LibCandidate(va=0x1000, name="a", module="MSVCRT", kind="import", confidence=0.3),
        ]
        monkeypatch.setattr("rebrew.identify_library._crt_candidates", lambda cfg: [])
        monkeypatch.setattr("rebrew.identify_library._flirt_candidates", lambda cfg, m: [])
        monkeypatch.setattr("rebrew.identify_library._import_candidates", lambda cfg, m: imp)
        out = collect_candidates(_cfg(tmp_path))
        assert [c.va for c in out] == [0x1000, 0x2000]

    def test_import_fills_gap_next_to_flirt(self, tmp_path: Path, monkeypatch) -> None:
        flirt = [
            LibCandidate(va=0x3000, name="_free", module="MSVCRT", kind="flirt", confidence=0.5)
        ]
        imp = [
            LibCandidate(
                va=0x4000, name="GetTickCount", module="MSVCRT", kind="import", confidence=0.3
            )
        ]
        monkeypatch.setattr("rebrew.identify_library._crt_candidates", lambda cfg: [])
        monkeypatch.setattr("rebrew.identify_library._flirt_candidates", lambda cfg, m: flirt)
        monkeypatch.setattr("rebrew.identify_library._import_candidates", lambda cfg, m: imp)
        out = collect_candidates(_cfg(tmp_path))
        assert {(c.va, c.kind) for c in out} == {(0x3000, "flirt"), (0x4000, "import")}


class TestWriteCandidates:
    def test_writes_new_entries_skips_existing(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir).mkdir()
        cands = [
            LibCandidate(va=0x1000, name="_malloc", module="MSVCRT", kind="crt", confidence=0.9),
            LibCandidate(
                va=0x2000, name="DeflateInit", module="ZLIB", kind="flirt", confidence=0.5
            ),
        ]
        written = write_candidates(cfg, cands, existing={0x1000})
        assert written == 1  # only the ZLIB entry is new

        header = cfg.reversed_dir / "library_zlib.h"
        text = header.read_text(encoding="utf-8")
        assert "// LIBRARY: ZLIB 0x00002000" in text
        assert "// DeflateInit" in text
        assert not (cfg.reversed_dir / "library_msvcrt.h").exists()

    def test_idempotent_second_run_writes_nothing(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir).mkdir()
        cands = [
            LibCandidate(va=0x1000, name="_malloc", module="MSVCRT", kind="flirt", confidence=0.5)
        ]
        assert write_candidates(cfg, cands, existing=set()) == 1
        # Everything is now annotated → second run writes 0.
        existing = {c.va for c in cands}
        assert write_candidates(cfg, cands, existing=existing) == 0

    def test_high_confidence_crt_writes_source(self, tmp_path: Path, monkeypatch) -> None:
        cfg = _cfg(tmp_path)
        (cfg.reversed_dir).mkdir()
        calls: list[object] = []
        monkeypatch.setattr(
            "rebrew.annotation.update_annotation_key",
            lambda *a, **k: calls.append((a, k)),
        )
        cands = [
            LibCandidate(
                va=0x1000,
                name="_malloc",
                module="MSVCRT",
                kind="crt",
                confidence=0.9,
                source_ref="crt/malloc.c",
            ),
            LibCandidate(
                va=0x2000,
                name="_free",
                module="MSVCRT",
                kind="crt",
                confidence=0.5,
                source_ref="crt/free.c",
            ),
        ]
        write_candidates(cfg, cands, existing=set())
        assert len(calls) == 1  # only the 0.9-confidence match gets SOURCE
        args, _kwargs = calls[0]
        assert args[2] == "SOURCE"
        assert args[3] == "crt/malloc.c"


class TestIdentifyLibraryCli:
    def test_json_purity_on_fixture(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """With no CRT indexes / flirt_sigs, the report is still pure JSON."""
        root = tmp_path / "proj"
        (root / "original").mkdir(parents=True)
        (root / "src" / "S").mkdir(parents=True)
        (root / "bin" / "S").mkdir(parents=True)
        (root / "original" / "mini_pe.exe").write_bytes((FIXTURES / "mini_pe.exe").read_bytes())
        (root / "rebrew-project.toml").write_text(
            """\
[project]
name = "p"
default_target = "S"
jobs = 1

[targets."S"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/S"
function_list = "src/S/functions.txt"
bin_dir = "bin/S"
marker = "S"

[compiler]
profile = "gcc-pe"
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
""",
            encoding="utf-8",
        )
        monkeypatch.chdir(root)
        result = CliRunner().invoke(app, ["identify-library", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)  # pure JSON
        assert payload["identified"] == 0
        assert payload["to_write"] == 0

    def test_dry_run_lists_candidates(self, tmp_path: Path, monkeypatch) -> None:
        cfg = _cfg(tmp_path)
        monkeypatch.setattr(
            "rebrew.identify_library.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr(
            "rebrew.identify_library.collect_candidates",
            lambda cfg, module: [
                LibCandidate(
                    va=0x1000, name="_malloc", module="MSVCRT", kind="flirt", confidence=0.5
                )
            ],
        )
        monkeypatch.setattr("rebrew.identify_library._existing_vas", lambda cfg: set())
        result = CliRunner().invoke(app, ["identify-library", "--dry-run"])
        assert result.exit_code == 0
        assert "_malloc" in result.output
        assert "to write" in result.output


class TestImportModuleFromDll:
    """Corpus regression: DirectDrawCreate is DirectX, not MSVCRT."""

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:

        return SimpleNamespace(
            root=tmp_path,
            target_binary=tmp_path / "x.exe",
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
            library_modules=["MSVCRT"],
        )

    def test_import_stub_uses_dll_module(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.identify_library import _import_candidates

        monkeypatch.setattr(
            "rebrew.imports.find_import_stubs",
            lambda path: {0x40DCE0: "DirectDrawCreate", 0x40DC00: "_malloc"},
        )
        monkeypatch.setattr(
            "rebrew.imports.parse_imports",
            lambda path: [
                {"dll": "DDRAW.dll", "name": "DirectDrawCreate", "iat_va": 1},
                {"dll": "msvcrt.dll", "name": "_malloc", "iat_va": 2},
            ],
        )
        out = _import_candidates(self._cfg(tmp_path), "MSVCRT")
        by_name = {c.name: c.module for c in out}
        assert by_name["DirectDrawCreate"] == "DDRAW"  # not MSVCRT
        assert by_name["_malloc"] == "MSVCRT"

    def test_unknown_import_falls_back_to_heuristic(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.identify_library import _import_candidates

        monkeypatch.setattr("rebrew.imports.find_import_stubs", lambda path: {0x1000: "WeirdAPI"})
        monkeypatch.setattr("rebrew.imports.parse_imports", lambda path: [])
        out = _import_candidates(self._cfg(tmp_path), "MSVCRT")
        assert out[0].module == "MSVCRT"  # heuristic default


class TestBuildSigs:
    """identify-library --build-sigs generates .pat files from toolchain libs."""

    def _project_with_lib(self, tmp_path: Path) -> SimpleNamespace:
        from bin_util import make_coff_obj, make_lib_archive

        root = tmp_path / "proj"
        lib_dir = root / "tools" / "msvc-6.0-win32" / "VC98" / "Lib"
        lib_dir.mkdir(parents=True)
        obj = make_coff_obj(
            bytes.fromhex("55 8b ec 83 ec 10 57 56 c7 45 fc 00 00 00 00 8b 45 fc 5f 5e 5d c3"),
            func_symbol="_myfunc",
        )
        (lib_dir / "LIBCMT.lib").write_bytes(make_lib_archive([("myfunc.obj", obj)]))
        (root / "src").mkdir()
        return SimpleNamespace(
            root=root,
            target_binary=tmp_path / "x.exe",
            reversed_dir=root / "src",
            metadata_dir=tmp_path,
            library_modules=["MSVCRT"],
        )

    def test_build_flirt_sigs_writes_pat(self, tmp_path: Path) -> None:
        from rebrew.identify_library import build_flirt_sigs

        cfg = self._project_with_lib(tmp_path)
        n = build_flirt_sigs(cfg)
        assert n == 1
        pat = cfg.root / "flirt_sigs" / "libcmt_vc6.pat"
        assert pat.is_file()
        text = pat.read_text(encoding="utf-8")
        assert text.endswith("---\n")  # sigmake terminator
        assert "_myfunc" in text

    def test_no_lib_dir_returns_zero(self, tmp_path: Path) -> None:
        from rebrew.identify_library import build_flirt_sigs

        cfg = SimpleNamespace(
            root=tmp_path,
            target_binary=tmp_path / "x.exe",
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
        )
        assert build_flirt_sigs(cfg) == 0

    def test_cli_build_sigs_dry_run(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.identify_library import app

        cfg = self._project_with_lib(tmp_path)
        monkeypatch.setattr(
            "rebrew.identify_library.require_config", lambda target=None, json_mode=False: cfg
        )
        monkeypatch.setattr("rebrew.identify_library.collect_candidates", lambda cfg, module: [])
        monkeypatch.setattr("rebrew.identify_library._existing_vas", lambda cfg: set())
        result = CliRunner().invoke(app, ["--build-sigs", "--dry-run", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["sigs_written"] == 1
        assert payload["identified"] == 0


class TestSigFileModuleAttribution:
    """H3: module attribution from sig-file names + zlib prefixes."""

    def test_known_stems(self) -> None:
        from rebrew.identify_library import _module_from_sig_file

        assert _module_from_sig_file("msvcrt_vc6.pat", "X") == "MSVCRT"
        assert _module_from_sig_file("libcmt_vc6.pat", "X") == "MSVCRT"
        assert _module_from_sig_file("zlib_vc6.pat", "X") == "ZLIB"

    def test_unknown_stem_uppercased(self) -> None:
        from rebrew.identify_library import _module_from_sig_file

        assert _module_from_sig_file("mylib_vc6.pat", "X") == "MYLIB"
        assert _module_from_sig_file("weird.pat", "X") == "WEIRD"

    def test_zlib_prefixes(self) -> None:
        from rebrew.identify_library import _infer_module

        assert _infer_module("deflateInit", "X") == "ZLIB"
        assert _infer_module("inflate", "X") == "ZLIB"
        assert _infer_module("adler32", "X") == "ZLIB"
        assert _infer_module("_crc32", "X") == "ZLIB"
        assert _infer_module("memcpy", "X") == "MSVCRT"  # CRT still wins

    def test_flirt_uses_file_module(self, tmp_path: Path, monkeypatch) -> None:
        """A zlib_vc6.pat hit gets ZLIB, not the CRT default."""
        from rebrew.identify_library import _flirt_candidates

        root = tmp_path / "proj"
        (root / "flirt_sigs").mkdir(parents=True)
        # A minimal .pat line for a recognizable function.
        (root / "flirt_sigs" / "zlib_vc6.pat").write_text(
            "558BEC8B05........5DC3 00 0000 000B :0000 _deflate\n---\n",
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=root,
            target_binary=tmp_path / "x.exe",
            reversed_dir=root / "src",
            metadata_dir=tmp_path,
            library_modules=["MSVCRT"],
        )
        # The fixture PE's .text matches the pattern lead bytes.
        monkeypatch.setattr(
            "rebrew.binary_loader.load_binary",
            lambda path: SimpleNamespace(
                sections={".text": SimpleNamespace(va=0x401000, file_offset=0x200, raw_size=512)},
                data=(b"\x00" * 0x200)
                + bytes.fromhex("55 8b ec 8b 05 00 00 00 00 5d c3")
                + b"\x00" * 300,
            ),
        )
        out = _flirt_candidates(cfg, "MSVCRT")
        assert any(c.name == "_deflate" and c.module == "ZLIB" for c in out)


class TestBuildSigsRobustness:
    """One corrupt .lib must not abort sig generation for the rest."""

    def test_corrupt_lib_skipped_not_abort(self, tmp_path: Path) -> None:
        from rebrew.identify_library import build_flirt_sigs

        lib_dir = tmp_path / "tools" / "msvc-6.0-win32" / "VC98" / "Lib"
        lib_dir.mkdir(parents=True)
        # A valid lib with a real function + a corrupt one.
        from bin_util import make_coff_obj, make_lib_archive

        obj = make_coff_obj(
            bytes.fromhex("55 8b ec 83 ec 10 57 56 c7 45 fc 00 00 00 00 8b 45 fc 5f 5e 5d c3"),
            func_symbol="_good",
        )
        (lib_dir / "GOOD.LIB").write_bytes(make_lib_archive([("good.obj", obj)]))
        (lib_dir / "MAPI.LIB").write_bytes(b"not an archive at all")
        cfg = SimpleNamespace(
            root=tmp_path,
            target_binary=tmp_path / "x.exe",
            reversed_dir=tmp_path / "src",
            metadata_dir=tmp_path,
        )
        n = build_flirt_sigs(cfg)
        assert n == 1  # the good lib still produced a .pat
        assert (cfg.root / "flirt_sigs" / "good_vc6.pat").is_file()


@given(st.from_regex(r"[a-z0-9_]+_vc\d+\.(?:pat|sig)", fullmatch=True))
@settings(max_examples=100, deadline=None)
def test_module_from_sig_file_properties(filename: str) -> None:
    """Attribution is deterministic, uppercase, and never empty."""
    from rebrew.identify_library import _module_from_sig_file

    module = _module_from_sig_file(filename, "FALLBACK")
    assert module == module.upper()
    assert module
    # Known stems keep their canonical mapping regardless of the _vcN suffix.
    import re

    stem = re.sub(r"_vc\d+$", "", filename).lower()
    if stem in ("msvcrt", "libcmt", "libc"):
        assert module == "MSVCRT"
    elif stem == "zlib":
        assert module == "ZLIB"
