"""Tests for rebrew.cross_import — cross-target function import.

Covers the pure matching core (structural signatures), the two-PE fixture
scenario (shared functions at different VAs, differing and absent functions),
the import mechanics (marker remap + SIZE, file write, verify + STATUS), and
the CLI wiring.  The gcc-pe end-to-end test runs a real compile+verify
round-trip when the native toolchain is installed (it is on this host).
"""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from bin_util import make_pe

import rebrew.cross_import as ci

# Hand-crafted 32-bit x86 blobs: shared prologue/epilogue, distinct bodies.
F1 = bytes.fromhex("55 8b ec 8b 05 00 00 00 00 5d c3")  # mov eax, [x]
F2 = bytes.fromhex("55 8b ec e8 00 00 00 00 5d c3")  # call
F3 = bytes.fromhex("55 8b ec 83 c0 01 5d c3")  # add eax, 1
G = bytes.fromhex("55 8b ec 83 ec 08 8b 45 08 03 45 0c 5d c3")  # different

# VAs inside the two PEs (image_base 0x400000 + .text at 0x1000).
# PE_A: F1 @ 0x401000, F2 @ 0x401010, F3 @ 0x401020
# PE_B: F1 @ 0x401040, F2 @ 0x401050, G  @ 0x401060  (same code, different VAs)
A_F1, A_F2, A_F3 = 0x401000, 0x401010, 0x401020
B_F1, B_F2, B_G = 0x401040, 0x401050, 0x401060


def _place(slots: dict[int, bytes], total: int) -> bytes:
    arr = bytearray(total)
    for off, blob in slots.items():
        arr[off : off + len(blob)] = blob
    return bytes(arr)


def _pe_a() -> bytes:
    return make_pe(_place({0x00: F1, 0x10: F2, 0x20: F3}, 0x30))


def _pe_b() -> bytes:
    return make_pe(_place({0x40: F1, 0x50: F2, 0x60: G}, 0x70))


def _sig(blob: bytes, va: int = 0) -> dict[str, Any]:
    sig = ci._disasm_signature(blob, va, "CS_ARCH_X86", "CS_MODE_32")
    assert sig is not None
    return sig


class TestCrossMatch:
    """The pure matching core — no cfg, hand-crafted signatures."""

    def test_identical_pair_matches(self) -> None:
        dest = {0x1000: _sig(F1)}
        src = {0x2000: _sig(F1), 0x3000: _sig(F2)}
        assert ci.cross_match(dest, src) == {0x1000: (0x2000, 100.0)}

    def test_differing_function_skipped(self) -> None:
        """G shares the prologue/epilogue with F1 but is a different function:
        it scores 92.9 — below the 95 default, so no import."""
        dest = {0x1000: _sig(G)}
        src = {0x2000: _sig(F1), 0x3000: _sig(F2)}
        assert ci.cross_match(dest, src) == {}

    def test_threshold_excludes_low_score(self) -> None:
        # F1 vs F2 score ~44: structural siblings, not the same function.
        dest = {0x1000: _sig(F1)}
        src = {0x2000: _sig(F2)}
        assert ci.cross_match(dest, src, min_score=95.0) == {}
        assert ci.cross_match(dest, src, min_score=40.0) != {}

    def test_ambiguous_runner_up_skipped(self) -> None:
        """Two identical source functions → gap 0 → destination untouched."""
        dest = {0x1000: _sig(F1)}
        src = {0x2000: _sig(F1), 0x3000: _sig(F1)}
        assert ci.cross_match(dest, src, min_gap=5.0) == {}

    def test_empty_sides(self) -> None:
        assert ci.cross_match({0x1000: _sig(F1)}, {}) == {}
        assert ci.cross_match({}, {0x2000: _sig(F1)}) == {}


class TestTwoPEFixture:
    """The real scenario: shared functions at different VAs across binaries."""

    def _sigs(self, path: Path, blobs: dict[int, bytes]) -> dict[int, dict[str, Any]]:
        from rebrew.binary_loader import extract_raw_bytes

        out: dict[int, dict[str, Any]] = {}
        for va, blob in blobs.items():
            code = extract_raw_bytes(path, va, len(blob))
            out[va] = _sig(code, va)
        return out

    def test_shared_functions_found_across_targets(self, tmp_path: Path) -> None:
        pa = tmp_path / "a.exe"
        pb = tmp_path / "b.exe"
        pa.write_bytes(_pe_a())
        pb.write_bytes(_pe_b())

        dst = self._sigs(pb, {B_F1: F1, B_F2: F2, B_G: G})
        src = self._sigs(pa, {A_F1: F1, A_F2: F2, A_F3: F3})

        out = ci.cross_match(dst, src, min_score=95.0)
        # Exactly the shared pair at the default threshold; the differing
        # function (G, 92.9) is skipped, and F3 is absent from the
        # destination so nothing imports for it.
        assert out == {B_F1: (A_F1, 100.0), B_F2: (A_F2, 100.0)}


class TestMarkerRewrite:
    def test_line_style_remaps_module_va_size(self) -> None:
        src = "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        out = ci._rewrite_marker(src, "DST", 0x401040, 13)
        lines = out.splitlines()
        assert lines[0] == "// FUNCTION: DST 0x401040"
        assert lines[1] == "// SIZE: 13"
        assert out.count("// SIZE:") == 1

    def test_block_comment_style_remapped(self) -> None:
        src = "/* FUNCTION: SRC 0x401000 */\nint f1(void){ return 1; }\n"
        out = ci._rewrite_marker(src, "DST", 0x401040, 13)
        assert "/* FUNCTION: DST 0x401040 */" in out
        assert "// SIZE: 13" in out

    def test_size_inserted_when_missing(self) -> None:
        src = "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n"
        out = ci._rewrite_marker(src, "DST", 0x401040, 13)
        lines = out.splitlines()
        assert lines[0] == "// FUNCTION: DST 0x401040"
        assert lines[1] == "// SIZE: 13"

    def test_no_marker_raises(self) -> None:
        with pytest.raises(ValueError):
            ci._rewrite_marker("int f1(void){return 1;}\n", "DST", 1, 1)

    def test_stacked_markers_collapsed_to_destination(self) -> None:
        """A shared multi-version source stacks one marker per target; the
        imported copy must carry ONLY the destination marker (stale VAs must
        not leak into the destination's reversed_dir)."""
        src = (
            "// FUNCTION: V1 0x401000\n// SIZE: 11\n"
            "// FUNCTION: V2 0x501000\n// SIZE: 11\n"
            "int common(void){ return 1; }\n"
        )
        out = ci._rewrite_marker(src, "V3", 0x601000, 13)
        markers = [line for line in out.splitlines() if "FUNCTION:" in line]
        assert markers == ["// FUNCTION: V3 0x601000"]
        assert "// SIZE: 13" in out
        assert "int common(void)" in out

    def test_multi_function_markers_kept(self) -> None:
        """A genuinely multi-function source keeps its later markers — only
        STACKED leading blocks (the shared-source pattern) are collapsed."""
        src = (
            "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n"
            "// FUNCTION: SRC 0x401010\nint f2(void){ return 2; }\n"
        )
        out = ci._rewrite_marker(src, "DST", 0x601000, 11)
        markers = [line.strip() for line in out.splitlines() if "FUNCTION:" in line]
        assert markers == ["// FUNCTION: DST 0x601000", "// FUNCTION: SRC 0x401010"]


class TestImportMechanics:
    def _cfg(self, tmp_path: Path, target: str, binary: Path) -> SimpleNamespace:
        rev = tmp_path / f"src_{target}"
        rev.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            root=tmp_path,
            target_name=target,
            reversed_dir=rev,
            metadata_dir=tmp_path,
            target_binary=binary,
            function_list=tmp_path / f"{target}.txt",
        )

    def test_import_writes_file_and_verifies(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        (cfg_src.reversed_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n",
            encoding="utf-8",
        )
        (cfg_dst.reversed_dir / "f1.c").write_text(
            "// FUNCTION: DST 0x401040\n// SIZE: 0\nint f1(void){ return 0; }\n",
            encoding="utf-8",
        )

        from rebrew.compile import CompareResult

        seen: dict[str, Any] = {}

        def fake_verify(entry, cfg, cache=None, **kw):
            seen["entry"] = entry
            return CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="EXACT MATCH",
            )

        monkeypatch.setattr("rebrew.verify.verify_entry", fake_verify)
        applied: list[Any] = []
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda fixes, cfg: applied.append((fixes, cfg)),
        )

        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="f1.c")
        assert res["action"] == "imported"
        assert res["status"] == "EXACT"
        text = (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
        assert "// FUNCTION: DST 0x401040" in text
        assert "// SIZE: 11" in text
        assert seen["entry"].va == B_F1
        assert seen["entry"].size == 11
        assert applied and applied[0][0][0][1] == "EXACT"

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        (cfg_src.reversed_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n", encoding="utf-8"
        )
        before = (
            (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
            if (cfg_dst.reversed_dir / "f1.c").exists()
            else ""
        )

        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("verify must not run")),
        )
        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dry_run=True)
        assert res["action"] == "would-import"
        after = (
            (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
            if (cfg_dst.reversed_dir / "f1.c").exists()
            else ""
        )
        assert after == before

    def test_missing_source_file_reports_error(self, tmp_path: Path) -> None:
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "nope.c", 11)
        assert res["status"] == "READ_ERROR"

    def test_conflicting_destination_file_refused(self, tmp_path: Path) -> None:
        """Importing to a filename that already annotates a DIFFERENT VA must
        refuse — silently overwriting would delete another function's source."""
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        (cfg_src.reversed_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n", encoding="utf-8"
        )
        # The destination has an UNRELATED f1.c for a different VA.
        (cfg_dst.reversed_dir / "f1.c").write_text(
            "// FUNCTION: DST 0x999000\nint other(void){ return 9; }\n", encoding="utf-8"
        )

        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["status"] == "TARGET_CONFLICT"
        # The destination file is untouched.
        text = (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
        assert "// FUNCTION: DST 0x999000" in text
        assert "other" in text

    def test_destination_own_file_overwritten(self, tmp_path: Path, monkeypatch) -> None:
        """The destination's OWN annotation file (same VA) is overwritten as
        intended — that is the normal import target."""
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        (cfg_src.reversed_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n", encoding="utf-8"
        )
        (cfg_dst.reversed_dir / "f1.c").write_text(
            "// FUNCTION: DST 0x401040\nint f1(void){ return 0; }\n", encoding="utf-8"
        )

        from rebrew.compile import CompareResult

        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda *a, **k: CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="EXACT MATCH",
            ),
        )
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)

        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="f1.c")
        assert res["action"] == "imported"
        text = (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
        assert "// FUNCTION: DST 0x401040" in text


class TestCLI:
    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(
            "[project]\nname = 'probe'\ndefault_target = 'DST'\n"
            "[compiler]\nprofile = 'msvc6'\ncommand = 'CL.EXE'\n"
            "[targets.SRC]\nbinary = 'a.exe'\n"
            "[targets.DST]\nbinary = 'b.exe'\n",
            encoding="utf-8",
        )
        (tmp_path / "a.exe").write_bytes(_pe_a())
        (tmp_path / "b.exe").write_bytes(_pe_b())
        return tmp_path

    def test_same_target_guard(self, tmp_path: Path, monkeypatch) -> None:
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(umbrella, ["cross-import", "--from", "DST"])
        assert result.exit_code != 0
        assert "--from must name a different target" in result.output

    def test_json_flow_with_mocked_import(self, tmp_path: Path, monkeypatch) -> None:
        import json as json_mod

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(
            "rebrew.cross_import.matched_source_bytes", lambda cfg: {A_F1: F1, A_F2: F2}
        )
        monkeypatch.setattr(
            "rebrew.cross_import.unmatched_dest_bytes",
            lambda cfg, only_va=None: {B_F1: F1, B_F2: F2},
        )
        monkeypatch.setattr(
            "rebrew.cross_import.cross_match", lambda d, s, **k: {B_F1: (A_F1, 100.0)}
        )
        monkeypatch.setattr("rebrew.cross_import._registry", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.cross_import._annotations_by_va",
            lambda cfg: {B_F1: ("STUB", "f1.c"), A_F1: ("EXACT", "f1.c")},
        )
        monkeypatch.setattr(
            "rebrew.cross_import.import_function",
            lambda *a, **k: {
                "dst_va": "0x401040",
                "src_va": "0x401000",
                "score": 100.0,
                "action": "imported",
                "status": "EXACT",
                "filepath": "f1.c",
                "message": "",
            },
        )

        runner = CliRunner()
        result = runner.invoke(
            umbrella,
            ["cross-import", "--from", "SRC", "--json", "--dry-run"],
        )
        assert result.exit_code == 0, result.output
        payload = json_mod.loads(result.output)
        assert payload["from"] == "SRC"
        assert payload["results"][0]["action"] == "imported"


class TestGccPeEndToEnd:
    """Real compile+verify round-trip with the native gcc-pe toolchain."""

    @pytest.mark.skipif(
        shutil.which("i686-w64-mingw32-gcc") is None,
        reason="gcc-pe toolchain not installed",
    )
    def test_import_compiles_and_verifies(self, tmp_path: Path) -> None:
        from rebrew.config import ProjectConfig

        pa = tmp_path / "a.exe"
        pb = tmp_path / "b.exe"
        pa.write_bytes(_pe_a())
        pb.write_bytes(_pe_b())

        def _cfg(target: str, binary: Path) -> ProjectConfig:
            rev = tmp_path / f"src_{target}"
            rev.mkdir(parents=True, exist_ok=True)
            fl = tmp_path / f"{target}.txt"
            if target == "SRC":
                fl.write_text(
                    f"0x{A_F1:08x} {len(F1)} f1\n0x{A_F2:08x} {len(F2)} f2\n", encoding="utf-8"
                )
            else:
                fl.write_text(
                    f"0x{B_F1:08x} {len(F1)} f1\n0x{B_F2:08x} {len(F2)} f2\n", encoding="utf-8"
                )
            return ProjectConfig(
                root=tmp_path,
                target_name=target,
                target_binary=binary,
                reversed_dir=rev,
                function_list=fl,
                compiler_command="i686-w64-mingw32-gcc",
                compiler_profile="gcc-pe",
                # gcc-pe projects set gcc-style flags explicitly (the MSVC
                # "/O2 /Gd" / "/nologo /c /MT" defaults are invalid for gcc).
                base_cflags="",
                cflags="-O2",
                compiler_includes="",
                compiler_libs="",
            )

        cfg_src = _cfg("SRC", pa)
        cfg_dst = _cfg("DST", pb)
        # Source side: a matched function (metadata STATUS EXACT) with a
        # compilable source file.
        from rebrew.metadata import update_source_status

        update_source_status(cfg_src.metadata_dir, "EXACT", "SRC", A_F1)
        (cfg_src.reversed_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n",
            encoding="utf-8",
        )
        (cfg_dst.reversed_dir / "f1.c").write_text(
            "// FUNCTION: DST 0x401040\n// SIZE: 0\nint f1(void){ return 0; }\n",
            encoding="utf-8",
        )

        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", len(F1), dst_file="f1.c")
        # The round-trip must produce a REAL verification outcome — not a
        # tooling failure.  Byte-exactness is not guaranteed (gcc-pe matches
        # structurally per docs/TOOLCHAIN.md), so accept any compare verdict.
        assert res["status"] not in (
            "COMPILE_ERROR",
            "EXTRACT_ERROR",
            "INTERNAL_ERROR",
            "READ_ERROR",
        ), res
        text = (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
        assert "// FUNCTION: DST 0x401040" in text
