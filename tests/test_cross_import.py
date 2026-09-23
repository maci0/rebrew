"""Tests for rebrew.cross_import — cross-target function import.

Covers the pure matching core (structural signatures), the two-PE fixture
scenario (shared functions at different VAs, differing and absent functions),
the import mechanics (marker remap + SIZE, file write, verify + STATUS), and
the CLI wiring.  The mingw-16.2.0 end-to-end test runs a real compile+verify
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
    sig = ci.disasm_signature(blob, va, "CS_ARCH_X86", "CS_MODE_32")
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
            "// FUNCTION: DST 0x601000\nint f1(void){ return 1; }\n"
            "// FUNCTION: DST 0x601010\nint f2(void){ return 2; }\n"
        )
        out = ci._rewrite_marker(src, "DST", 0x601000, 11)
        markers = [line.strip() for line in out.splitlines() if "FUNCTION:" in line]
        assert markers == ["// FUNCTION: DST 0x601000", "// FUNCTION: DST 0x601010"]

    def test_foreign_target_marker_dropped(self) -> None:
        """A later marker for ANOTHER target goes, with its key-value block.

        Keeping it left the copy carrying a module the destination target does
        not own, which lint rejects (E012) and which names a VA this target has
        never matched.  Data markers count: `// DATA: SERVER 0x...` is the same
        error as a foreign FUNCTION marker.
        """
        src = (
            "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n"
            "// DATA: SRC 0x401008\n\n"
            "// FUNCTION: SRC 0x401010\n// SIZE: 8\nint f2(void){ return 2; }\n"
        )
        out = ci._rewrite_marker(src, "DST", 0x601000, 11)
        assert "SRC" not in out
        assert "// SIZE: 8" not in out
        assert "int f2(void){ return 2; }" in out  # the body stays

    def test_size_rewrite_stops_at_block_boundary(self) -> None:
        """The SIZE rewrite must stay inside the imported marker's own block —
        a scan to EOF clobbered the NEXT function's SIZE line."""
        src = (
            "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n"
            "// FUNCTION: DST 0x601010\n// SIZE: 8\nint f2(void){ return 2; }\n"
        )
        out = ci._rewrite_marker(src, "DST", 0x601000, 11)
        lines = out.splitlines()
        assert lines[0] == "// FUNCTION: DST 0x601000"
        assert lines[1] == "// SIZE: 11"  # inserted into f1's own block
        assert "// SIZE: 8" in out  # f2's SIZE untouched


class TestExtractSingleFunction:
    def test_single_function_source_unchanged(self) -> None:
        src = "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n"
        assert ci._extract_function_text(src, 0x401000) == src

    def test_multi_function_keeps_only_matched_block(self) -> None:
        """Copying a whole multi-function SERVER file into GOLDTL leaked every
        co-resident marker (lint E012) and duplicated the other functions.
        The matched function must import alone with its preamble."""
        src = (
            '#include "h.h"\n'
            "// FUNCTION: SERVER 0x401000\nint f1(void){ return 1; }\n"
            "// FUNCTION: SERVER 0x401010\nint f2(void){ return 2; }\n"
        )
        out = ci._extract_function_text(src, 0x401000)
        assert out is not None
        assert "f1" in out
        assert "f2" not in out
        assert out.count("FUNCTION:") == 1
        assert out.startswith('#include "h.h"')

    def test_multi_function_second_block(self) -> None:
        src = (
            "// FUNCTION: SERVER 0x401000\nint f1(void){ return 1; }\n"
            "// FUNCTION: SERVER 0x401010\nint f2(void){ return 2; }\n"
        )
        out = ci._extract_function_text(src, 0x401010)
        assert out is not None
        assert "f2" in out and "f1" not in out
        assert out.count("FUNCTION:") == 1

    def test_unknown_va_returns_none(self) -> None:
        src = "// FUNCTION: SERVER 0x401000\nint f1(void){ return 1; }\n"
        assert ci._extract_function_text(src, 0x999999) is None

    def test_import_emits_only_matched_function(self, tmp_path: Path, monkeypatch) -> None:
        """End-to-end: a SERVER multi-function file imports ONLY f1 into GOLDTL,
        re-tagged — no foreign markers survive, no co-resident body duplicated."""
        import rebrew.cross_import as ci_mod

        rev_src = tmp_path / "src_SERVER"
        rev_src.mkdir(parents=True)
        rev_dst = tmp_path / "src_GOLDTL"
        rev_dst.mkdir(parents=True)

        cfg_src = SimpleNamespace(
            root=tmp_path,
            target_name="GOLDTL",
            reversed_dir=rev_src,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "server.dll",
            source_ext=".c",
            marker="SERVER",
            posix_style=True,
        )
        cfg_dst = SimpleNamespace(
            root=tmp_path,
            target_name="DST",
            reversed_dir=rev_dst,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "goldtl.exe",
            source_ext=".c",
            marker="DST",
            posix_style=False,
        )
        (rev_src / "shared.c").write_text(
            '#include "shared.h"\n'
            "// FUNCTION: SERVER 0x401000\nint f1(void){ return 1; }\n"
            "// FUNCTION: SERVER 0x401010\nint f2(void){ return 2; }\n"
        )

        from rebrew.compile import CompareResult

        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda *a, **k: CompareResult(
                matched=True,
                status="RELOC",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="RELOC",
            ),
        )
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)
        monkeypatch.setattr(ci_mod, "_source_flags", lambda *a, **k: "")

        res = ci_mod.import_function(cfg_dst, cfg_src, 0x601000, 0x401000, "shared.c", 11)
        assert res["action"] == "imported"
        text = (rev_dst / "shared.c").read_text(encoding="utf-8")
        assert "// FUNCTION: DST 0x601000" in text
        assert text.count("FUNCTION:") == 1
        assert "int f2" not in text


class TestOnlyVaGuard:
    def test_only_va_does_not_bypass_matched_status(self, monkeypatch) -> None:
        """``--va`` on an already matched destination function must not re-add
        it through the disassembler (that path skipped the status filter)."""
        cfg = SimpleNamespace()
        monkeypatch.setattr(ci, "_annotations_by_va", lambda cfg: {0x401040: ("EXACT", "f1.c")})
        monkeypatch.setattr(ci, "_registry", lambda cfg: {0x401040: {"canonical_size": 16}})
        monkeypatch.setattr(ci, "_disasm_sizes", lambda cfg, vas: ({0x401040: 16}, []))
        monkeypatch.setattr(ci, "_target_bytes_by_va", lambda cfg, vas: dict.fromkeys(vas, b"\xc3"))
        assert ci.unmatched_dest_bytes(cfg, only_va=0x401040) == {}

    def test_only_va_sizeless_unmatched_still_matched(self, monkeypatch) -> None:
        """A NOT-matched VA without a registry size still gets the disasm size
        (the guard must only block the matched case)."""
        cfg = SimpleNamespace()
        monkeypatch.setattr(ci, "_annotations_by_va", lambda cfg: {0x401040: ("STUB", "f1.c")})
        monkeypatch.setattr(ci, "_registry", lambda cfg: {})
        monkeypatch.setattr(ci, "_disasm_sizes", lambda cfg, vas: ({0x401040: 16}, []))
        monkeypatch.setattr(ci, "_target_bytes_by_va", lambda cfg, vas: dict.fromkeys(vas, b"\xc3"))
        assert set(ci.unmatched_dest_bytes(cfg, only_va=0x401040)) == {0x401040}


class TestImportMechanics:
    def _cfg(
        self, tmp_path: Path, target: str, binary: Path, marker: str | None = None
    ) -> SimpleNamespace:
        rev = tmp_path / f"src_{target}"
        rev.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            root=tmp_path,
            target_name=target,
            reversed_dir=rev,
            metadata_dir=tmp_path,
            target_binary=binary,
            source_ext=".c",
            marker=marker if marker is not None else target,
            posix_style=False,
        )

    def test_annotations_by_va_uses_the_marker_not_the_target_name(self, tmp_path: Path) -> None:
        """The real parser must be filtered by ``marker``.

        Annotations carry the marker (``// FUNCTION: FIXT 0x...``), never the
        target name, so filtering by ``target_name`` finds nothing and every
        cross-import reports an empty source set.
        """
        cfg = self._cfg(tmp_path, "fixture.dll", tmp_path / "a.exe", marker="FIXT")
        (cfg.reversed_dir / "f1.c").write_text(
            "// FUNCTION: FIXT 0x00401040\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        (tmp_path / "rebrew-functions.toml").write_text(
            '["FIXT.0x00401040"]\nstatus = "EXACT"\nsize = 11\n'
        )
        assert ci._annotations_by_va(cfg) == {0x401040: ("EXACT", "f1.c")}

    def test_source_symbol_comes_from_the_definition(self, tmp_path: Path) -> None:
        """A leading prototype or ``extern`` must not name the import.

        Those lines parse as definitions once ``extract_function_name_from_line``
        appends ``{}``, so the old first-line heuristic named the import after
        a symbol the object never defines: verification failed with
        ``EXTRACT_ERROR: Symbol '_LogMessageInternal' not found in .obj`` and
        the import landed with no usable status.
        """
        src = tmp_path / "f1.c"
        src.write_text(
            "void __cdecl LogMessageInternal(char*, unsigned int, char*, int);\n"
            "extern int g_counter;\n"
            "int __cdecl f1(int value)\n"
            "{\n"
            "    return value + g_counter;\n"
            "}\n"
        )
        assert ci._source_name(src) == "f1"
        assert ci._source_symbol(src) == "_f1"

    def test_source_name_falls_back_to_the_stem(self, tmp_path: Path) -> None:
        """Nothing parseable in the file: the stem is still the answer."""
        src = tmp_path / "f2.c"
        src.write_text("// no code here\n")
        assert ci._source_name(src) == "f2"

    def test_import_mirrors_the_source_path_and_records_flags(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """The copy keeps the source's relative path, and its flags.

        Flattening to the bare name made two imports out of one multi-function
        source collide (TARGET_CONFLICT) and dropped the directory depth the
        copy's relative ``#include``s assume; the recorded flags carry the
        source directory, which is what makes those includes resolve.
        """
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        sub = cfg_src.reversed_dir / "Units" / "vfs"
        sub.mkdir(parents=True)
        (sub / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// CFLAGS: /O1 /Gd\nint f1(void){ return 1; }\n",
            encoding="utf-8",
        )

        from rebrew.compile import CompareResult

        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda entry, cfg, cache=None, **kw: CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="EXACT MATCH",
            ),
        )
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda fixes, cfg: None)

        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "Units/vfs/f1.c", 11)
        assert res["action"] == "imported"
        assert res["filepath"] == "Units/vfs/f1.c"
        assert (cfg_dst.reversed_dir / "Units" / "vfs" / "f1.c").exists()

        from rebrew.metadata import load_metadata

        assert load_metadata(cfg_dst.metadata_dir)[("DST", B_F1)]["cflags"] == f"/O1 /Gd /I{sub}"

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

    def test_legacy_encoded_source_is_read_and_preserved(self, tmp_path: Path, monkeypatch) -> None:
        """A cp1252 source (0xE9 in a comment) must not crash the import, and
        the destination keeps the detected encoding instead of being re-encoded
        as UTF-8."""
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        body = b"// FUNCTION: SRC 0x401000\n// SIZE: 11\n// caf\xe9\nint f1(void){ return 1; }\n"
        (cfg_src.reversed_dir / "f1.c").write_bytes(body)

        from rebrew.compile import CompareResult

        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda entry, cfg, cache=None, **kw: CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="EXACT MATCH",
            ),
        )
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda fixes, cfg: None)

        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="f1.c")
        assert res["status"] == "EXACT"
        assert b"caf\xe9" in (cfg_dst.reversed_dir / "f1.c").read_bytes()

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


class TestSizelessMatching:
    """Sizeless registry entries match via the disassembly-derived extent.

    A registry without sizes (discovery-only catalogs) must still import:
    ret-terminated functions size from the disassembler, with an explicit
    warning; ones the disassembler cannot size surface the
    "sizeless, use --va" guidance instead of vanishing silently.
    """

    def _cfg(self, tmp_path: Path, target: str, binary: Path) -> SimpleNamespace:
        rev = tmp_path / f"src_{target}"
        rev.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            root=tmp_path,
            target_name=target,
            reversed_dir=rev,
            metadata_dir=tmp_path,
            target_binary=binary,
        )

    def test_disasm_sizes_ret_only(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "x.exe").write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "DST", tmp_path / "x.exe")
        monkeypatch.setattr(
            "rebrew.binary_loader.function_extent_from_disasm",
            lambda _p, _va, with_kind=False: (11, "ret") if with_kind else 11,
        )
        sizes, refused = ci._disasm_sizes(cfg, [A_F1, A_F2])
        assert sizes == {A_F1: 11, A_F2: 11}
        assert refused == []

    def test_disasm_sizes_refuses_jmp_and_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "x.exe").write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "DST", tmp_path / "x.exe")

        def fake_extent(_p: Path, va: int, with_kind: bool = False):  # type: ignore[no-untyped-def]
            if va == A_F1:
                return (8, "jmp") if with_kind else 8
            return None

        monkeypatch.setattr("rebrew.binary_loader.function_extent_from_disasm", fake_extent)
        sizes, refused = ci._disasm_sizes(cfg, [A_F1, A_F2])
        assert sizes == {}
        assert refused == [A_F1, A_F2]

    def test_unmatched_dest_bytes_sizeless_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pa = tmp_path / "a.exe"
        pa.write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "DST", pa)
        monkeypatch.setattr(ci, "_annotations_by_va", lambda _c: {A_F1: ("STUB", "f1.c")})
        monkeypatch.setattr(ci, "_registry", lambda _c: {A_F1: {"canonical_size": 0}})
        monkeypatch.setattr(
            "rebrew.binary_loader.function_extent_from_disasm",
            lambda _p, _va, with_kind=False: (len(F1), "ret") if with_kind else len(F1),
        )
        out = ci.unmatched_dest_bytes(cfg)
        assert out[A_F1] == F1

    def test_unmatched_dest_bytes_only_va_sizeless(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pa = tmp_path / "a.exe"
        pa.write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "DST", pa)
        monkeypatch.setattr(ci, "_annotations_by_va", lambda _c: {A_F1: ("STUB", "f1.c")})
        monkeypatch.setattr(ci, "_registry", lambda _c: {A_F1: {"canonical_size": 0}})
        monkeypatch.setattr(
            "rebrew.binary_loader.function_extent_from_disasm",
            lambda _p, _va, with_kind=False: (len(F1), "ret") if with_kind else len(F1),
        )
        out = ci.unmatched_dest_bytes(cfg, only_va=A_F1)
        assert out[A_F1] == F1

    def test_matched_source_bytes_sizeless_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pa = tmp_path / "a.exe"
        pa.write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "SRC", pa)
        monkeypatch.setattr(ci, "_annotations_by_va", lambda _c: {A_F1: ("EXACT", "f1.c")})
        monkeypatch.setattr(ci, "_registry", lambda _c: {A_F1: {"canonical_size": 0}})
        monkeypatch.setattr(
            "rebrew.binary_loader.function_extent_from_disasm",
            lambda _p, _va, with_kind=False: (len(F1), "ret") if with_kind else len(F1),
        )
        out = ci.matched_source_bytes(cfg)
        assert out[A_F1] == F1


class TestCLI:
    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(
            "[project]\nname = 'probe'\ndefault_target = 'DST'\n"
            "[compiler]\nprofile = 'msvc-6.0'\ncommand = 'CL.EXE'\n"
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

    def test_limit_zero_imports_nothing(self, tmp_path: Path, monkeypatch) -> None:
        """--limit 0 must import zero functions; the old guard ran after the
        first import was already appended."""
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
            "rebrew.cross_import.cross_match",
            lambda d, s, **k: {B_F1: (A_F1, 100.0), B_F2: (A_F2, 100.0)},
        )
        monkeypatch.setattr("rebrew.cross_import._registry", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.cross_import._annotations_by_va",
            lambda cfg: {B_F1: ("STUB", "f1.c"), A_F1: ("EXACT", "f1.c")},
        )
        calls: list[Any] = []

        def _fake_import(*a: Any, **k: Any) -> dict[str, Any]:
            calls.append(a)
            return {
                "dst_va": "0x401040",
                "src_va": "0x401000",
                "score": 100.0,
                "action": "imported",
                "status": "EXACT",
                "filepath": "f1.c",
                "message": "",
            }

        monkeypatch.setattr("rebrew.cross_import.import_function", _fake_import)
        runner = CliRunner()
        result = runner.invoke(
            umbrella, ["cross-import", "--from", "SRC", "--json", "--limit", "0"]
        )
        assert result.exit_code == 0, result.output
        assert calls == []

    def test_sizeless_refusal_row(self, tmp_path: Path, monkeypatch) -> None:
        """A sizeless dest VA the disassembler cannot size gets the
        'sizeless, use --va' row instead of vanishing silently."""
        import json as json_mod

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("rebrew.cross_import.matched_source_bytes", lambda cfg: {A_F1: F1})
        monkeypatch.setattr(
            "rebrew.cross_import.unmatched_dest_bytes",
            lambda cfg, only_va=None: {B_F1: F1},
        )
        monkeypatch.setattr(
            "rebrew.cross_import.cross_match", lambda d, s, **k: {B_F1: (A_F1, 100.0)}
        )
        monkeypatch.setattr("rebrew.cross_import._registry", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.cross_import._annotations_by_va",
            lambda cfg: {B_F1: ("STUB", "f1.c"), A_F1: ("EXACT", "f1.c")},
        )
        # B_F1 sized by disassembly, 0x499999 refused by it.
        monkeypatch.setattr(
            "rebrew.cross_import.sizeless_dest_vas",
            lambda cfg: ({B_F1: len(F1)}, [0x499999]),
        )
        monkeypatch.setattr(
            "rebrew.cross_import.import_function",
            lambda *a, **k: {
                "dst_va": "0x00401040",
                "src_va": "0x00401000",
                "score": 100.0,
                "action": "would-import",
                "status": "",
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
        rows = {r["dst_va"]: r for r in payload["results"]}
        refused = rows["0x00499999"]
        assert refused["action"] == "skipped"
        assert "sizeless function" in refused["message"]
        assert "--va" in refused["message"]

    def test_disasm_sized_import_carries_warning(self) -> None:
        """The sizing warning fills an empty message but never overwrites
        a real verification message."""
        res = ci.merge_sizeless_warning({"message": ""}, 11)
        assert "disassembly-derived extent" in res["message"]
        assert "--va" in res["message"]
        res = ci.merge_sizeless_warning({"message": "real mismatch"}, 11)
        assert res["message"] == "real mismatch"
        res = ci.merge_sizeless_warning({"message": ""}, None)
        assert res["message"] == ""


class TestMingwEndToEnd:
    """Real compile+verify round-trip with the native mingw-16.2.0 toolchain."""

    @pytest.mark.skipif(
        shutil.which("i686-w64-mingw32-gcc") is None,
        reason="mingw-16.2.0 toolchain not installed",
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
                compiler_command="i686-w64-mingw32-gcc",
                compiler_profile="mingw-16.2.0",
                # mingw-16.2.0 projects set gcc-style flags explicitly (the MSVC
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
        # tooling failure.  Byte-exactness is not guaranteed (mingw-16.2.0 matches
        # structurally per docs/TOOLCHAIN.md), so accept any compare verdict.
        assert res["status"] not in (
            "COMPILE_ERROR",
            "EXTRACT_ERROR",
            "INTERNAL_ERROR",
            "READ_ERROR",
        ), res
        text = (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
        assert "// FUNCTION: DST 0x401040" in text


class TestRewriteMarkerSizeAndLineEndings:
    def test_block_comment_size_is_replaced(self) -> None:
        """The parser accepts `/* SIZE: N */` and is last-wins, so inserting a
        second `// SIZE` before it left the SOURCE size in force and verify
        sliced the wrong length."""
        import rebrew.cross_import as ci

        src = "/* FUNCTION: SRC 0x401000 */\n/* SIZE: 11 */\nint f(void) { return 0; }\n"
        out = ci._rewrite_marker(src, "DST", 0x601000, 13)
        assert "// SIZE: 13" in out
        assert "SIZE: 11" not in out

    def test_crlf_line_endings_preserved(self) -> None:
        import rebrew.cross_import as ci

        src = "// FUNCTION: SRC 0x401000\r\n// SIZE: 11\r\nint f(void) { return 0; }\r\n"
        out = ci._rewrite_marker(src, "DST", 0x601000, 13)
        lines = out.splitlines(keepends=True)
        assert lines[0] == "// FUNCTION: DST 0x601000\r\n"
        assert lines[1] == "// SIZE: 13\r\n"
        assert all(line.endswith("\r\n") for line in lines if line.strip())


class TestSharedImport:
    """`--shared`: stack the destination marker onto one file (ADR-010)."""

    def test_stack_marker_prepends_destination_block(self) -> None:
        src = "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        out = ci._stack_marker(src, "DST", 0x601000, 13)
        lines = out.splitlines()
        assert lines[0] == "// FUNCTION: DST 0x601000"
        assert lines[1] == "// SIZE: 13"
        assert "// FUNCTION: SRC 0x401000" in out
        assert "int f1(void)" in out

    def test_stack_marker_idempotent(self) -> None:
        src = "// FUNCTION: DST 0x601000\n// SIZE: 13\nint f1(void){ return 1; }\n"
        assert ci._stack_marker(src, "DST", 0x601000, 13) == src

    def test_shared_import_stacks_in_place(self, tmp_path: Path, monkeypatch) -> None:
        rev = tmp_path / "src_shared"
        rev.mkdir(parents=True)
        src_file = rev / "f1.c"
        src_file.write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n",
            encoding="utf-8",
        )
        cfg_src = SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=rev,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "a.exe",
            source_ext=".c",
            marker="SRC",
            posix_style=False,
        )
        dst_rev = tmp_path / "src_DST"
        dst_rev.mkdir(parents=True)
        cfg_dst = SimpleNamespace(
            root=tmp_path,
            target_name="DST",
            reversed_dir=dst_rev,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "b.exe",
            source_ext=".c",
            marker="DST",
            posix_style=False,
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
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")

        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["action"] == "imported-shared"
        text = src_file.read_text(encoding="utf-8")
        assert "// FUNCTION: DST 0x401040" in text
        assert "// FUNCTION: SRC 0x401000" in text
        assert not (dst_rev / "f1.c").exists()  # no copy: one file serves both


class TestPromoteToShared:
    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        rev = tmp_path / "src_SRC"
        rev.mkdir(parents=True, exist_ok=True)
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=shared,
            marker="SRC",
        )

    def test_promote_moves_preserving_path(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        sub = cfg.reversed_dir / "Units" / "vfs"
        sub.mkdir(parents=True)
        (sub / "f1.c").write_text("// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n")
        res = ci.promote_to_shared(cfg, "Units/vfs/f1.c")
        assert res["action"] == "promoted"
        assert (cfg.shared_dir / "Units" / "vfs" / "f1.c").is_file()
        assert not (cfg.reversed_dir / "Units" / "vfs" / "f1.c").exists()

    def test_promote_dry_run_moves_nothing(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "f1.c").write_text("x")
        res = ci.promote_to_shared(cfg, "f1.c", dry_run=True)
        assert res["action"] == "would-promote"
        assert (cfg.reversed_dir / "f1.c").is_file()

    def test_promote_conflict_when_shared_exists(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "f1.c").write_text("x")
        (cfg.shared_dir / "f1.c").write_text("y")
        res = ci.promote_to_shared(cfg, "f1.c")
        assert res["action"] == "error"
        assert res["status"] == "TARGET_CONFLICT"

    def test_promote_no_shared_dir_errors(self, tmp_path: Path) -> None:
        cfg = self._cfg(tmp_path)
        cfg.shared_dir = None
        (cfg.reversed_dir / "f1.c").write_text("x")
        res = ci.promote_to_shared(cfg, "f1.c")
        assert res["action"] == "error"
        assert res["status"] == "NO_SHARED_DIR"

    def test_shared_import_auto_promotes(self, tmp_path: Path, monkeypatch) -> None:
        """--shared on a source still in the per-target tree moves it under
        src/shared first, so the stacked marker lands on the scanned file."""
        rev = tmp_path / "src_SRC"
        rev.mkdir(parents=True)
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        (rev / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        cfg_src = SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=shared,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "a.exe",
            source_ext=".c",
            marker="SRC",
            posix_style=False,
        )
        dst_rev = tmp_path / "src_DST"
        dst_rev.mkdir(parents=True)
        cfg_dst = SimpleNamespace(
            root=tmp_path,
            target_name="DST",
            reversed_dir=dst_rev,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "b.exe",
            source_ext=".c",
            marker="DST",
            posix_style=False,
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
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")

        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["action"] == "imported-shared"

    def test_cli_shared_promotes_before_stacking(self, tmp_path: Path, monkeypatch) -> None:
        """The CLI --shared path moves a per-target source under src/shared
        first, so the stacked marker lands on the file every target scans."""
        from typer.testing import CliRunner

        (tmp_path / "rebrew-project.toml").write_text(
            "[project]\nname = 'probe'\ndefault_target = 'DST'\nshared_dir = 'src/shared'\n"
            "[compiler]\nprofile = 'msvc-6.0'\ncommand = 'CL.EXE'\n"
            "[targets.SRC]\nbinary = 'a.exe'\n"
            "[targets.DST]\nbinary = 'b.exe'\n",
            encoding="utf-8",
        )
        (tmp_path / "a.exe").write_bytes(b"MZ")
        (tmp_path / "b.exe").write_bytes(b"MZ")
        (tmp_path / "src" / "SRC").mkdir(parents=True)
        (tmp_path / "src" / "DST").mkdir(parents=True)
        (tmp_path / "src" / "shared").mkdir(parents=True)
        (tmp_path / "src" / "SRC" / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("rebrew.cross_import.matched_source_bytes", lambda cfg: {A_F1: F1})
        monkeypatch.setattr(
            "rebrew.cross_import.unmatched_dest_bytes",
            lambda cfg, only_va=None: {B_F1: F1},
        )
        monkeypatch.setattr(
            "rebrew.cross_import.cross_match", lambda d, s, **k: {B_F1: (A_F1, 100.0)}
        )
        monkeypatch.setattr(
            "rebrew.cross_import._registry", lambda cfg: {B_F1: {"canonical_size": 11}}
        )
        monkeypatch.setattr(
            "rebrew.cross_import._annotations_by_va",
            lambda cfg: (
                {B_F1: ("STUB", ""), A_F1: ("EXACT", "f1.c")}
                if cfg.target_name == "DST"
                else {A_F1: ("EXACT", "f1.c")}
            ),
        )
        monkeypatch.setattr(
            "rebrew.cross_import.import_shared_function",
            lambda *a, **k: {
                "dst_va": "0x401040",
                "src_va": "0x401000",
                "score": 100.0,
                "action": "imported-shared",
                "status": "EXACT",
                "filepath": "../shared/f1.c",
                "message": "",
            },
        )

        from rebrew.main import app as umbrella

        runner = CliRunner()
        result = runner.invoke(
            umbrella, ["cross-import", "--from", "SRC", "--shared", "--target", "DST"]
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "src" / "shared" / "f1.c").is_file()
        assert not (tmp_path / "src" / "SRC" / "f1.c").exists()


class TestSharedSupersede:
    def _cfgs(self, tmp_path: Path) -> tuple[SimpleNamespace, SimpleNamespace]:
        rev = tmp_path / "src_SRC"
        rev.mkdir(parents=True)
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        dst_rev = tmp_path / "src_DST"
        dst_rev.mkdir(parents=True)
        cfg_src = SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=shared,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "a.exe",
            source_ext=".c",
            marker="SRC",
            posix_style=False,
        )
        cfg_dst = SimpleNamespace(
            root=tmp_path,
            target_name="DST",
            reversed_dir=dst_rev,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "b.exe",
            source_ext=".c",
            marker="DST",
            posix_style=False,
        )
        return cfg_src, cfg_dst

    def _ok_verify(self, monkeypatch) -> None:
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
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")

    def test_matched_shared_import_deletes_stub(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path)
        (cfg_src.shared_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        (cfg_dst.reversed_dir / "stub.c").write_text(
            "// FUNCTION: DST 0x401040\n// SIZE: 0\nint f1(void){ return 0; }\n"
        )
        self._ok_verify(monkeypatch)
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        assert res["action"] == "imported-shared"
        assert "superseded stub.c" in res["message"]
        assert not (cfg_dst.reversed_dir / "stub.c").exists()

    def test_unverified_shared_import_keeps_stub(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import CompareResult

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        (cfg_src.shared_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        (cfg_dst.reversed_dir / "stub.c").write_text(
            "// FUNCTION: DST 0x401040\n// SIZE: 0\nint f1(void){ return 0; }\n"
        )
        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda *a, **k: CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=5,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="NEAR",
            ),
        )
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        # The failed stack is rolled back: leaving it would give the VA two
        # claimants (lint E013) while the stub is the only matchable owner.
        assert res["action"] == "skipped-unverified"
        assert (cfg_dst.reversed_dir / "stub.c").is_file()
        assert "FUNCTION: DST" not in (cfg_src.shared_dir / "f1.c").read_text()

    def test_unverified_rollback_restores_cflags_and_status(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """The rollback covers the pre-verify metadata writes: a withdrawn
        claim restores the destination's own cflags override and leaves the
        stub's earned STATUS untouched."""
        from rebrew.compile import CompareResult
        from rebrew.metadata import get_entry, load_metadata, update_field, update_source_status

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        (cfg_src.shared_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        (cfg_dst.reversed_dir / "stub.c").write_text(
            "// FUNCTION: DST 0x401040\n// SIZE: 0\nint f1(void){ return 0; }\n"
        )
        update_field(tmp_path, 0x401040, "cflags", "/G5", "DST")
        update_source_status(tmp_path, "EXACT", "DST", 0x401040)
        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda *a, **k: CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=5,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="NEAR",
            ),
        )
        # Real apply_status_updates: the rollback must make it a no-op.
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "/O2")
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        assert res["action"] == "skipped-unverified"
        assert get_entry(tmp_path, 0x401040, "DST").get("cflags") == "/G5"
        entry = load_metadata(tmp_path).get(("DST", 0x401040), {})
        assert entry.get("status") == "EXACT"

    def test_unverified_rollback_removes_new_cflags_override(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """With no prior override, the withdrawn claim's cflags write is
        retracted entirely — no stale field steers the stub's compiles."""
        from rebrew.compile import CompareResult
        from rebrew.metadata import get_entry

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        (cfg_src.shared_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        (cfg_dst.reversed_dir / "stub.c").write_text(
            "// FUNCTION: DST 0x401040\n// SIZE: 0\nint f1(void){ return 0; }\n"
        )
        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda *a, **k: CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=5,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="NEAR",
            ),
        )
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "/O2")
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        assert res["action"] == "skipped-unverified"
        assert get_entry(tmp_path, 0x401040, "DST").get("cflags") is None

    def test_same_file_stub_never_deleted(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path)
        (cfg_src.shared_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        self._ok_verify(monkeypatch)
        res = ci.import_shared_function(
            cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="../shared/f1.c"
        )
        assert res["action"] == "imported-shared"
        assert (cfg_src.shared_dir / "f1.c").is_file()


class TestSharedCflagsPortable:
    """Shared imports record no absolute source-dir include.

    The copy path needs ``/I<abs parent>`` (destination tree lacks the
    source headers); the shared file moves WITH its tree, and compile.py
    already adds src_parent — so an absolute include only bakes one
    machine's checkout path into the metadata (guild-rebrew
    GOLDTL.0x004c75e0 carried ``/I/home/.../server.dll/...``).
    """

    def test_shared_cflags_have_no_absolute_include(self, tmp_path: Path, monkeypatch) -> None:
        rev = tmp_path / "src_SRC"
        rev.mkdir(parents=True)
        sub = rev / "Units" / "vfs"
        sub.mkdir(parents=True)
        (sub / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// CFLAGS: /O1 /Gd\nint f1(void){ return 1; }\n"
        )
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        dst_rev = tmp_path / "src_DST"
        dst_rev.mkdir(parents=True)
        cfg_src = SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=shared,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "a.exe",
            source_ext=".c",
            marker="SRC",
            posix_style=False,
        )
        cfg_dst = SimpleNamespace(
            root=tmp_path,
            target_name="DST",
            reversed_dir=dst_rev,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "b.exe",
            source_ext=".c",
            marker="DST",
            posix_style=False,
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

        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "Units/vfs/f1.c", 11)
        assert res["action"] == "imported-shared"
        from rebrew.metadata import load_metadata

        cflags = load_metadata(cfg_dst.metadata_dir)[("DST", B_F1)]["cflags"]
        assert cflags == "/O1 /Gd"
        assert str(tmp_path) not in cflags


class TestSharedDryRunPath:
    def test_dry_run_reports_project_relative_path(self, tmp_path: Path) -> None:
        """Dry-run filepath must be project-portable (../shared/f.c), not an
        absolute checkout path leaking into CI logs and JSON consumers."""
        rev = tmp_path / "src" / "SRC"
        rev.mkdir(parents=True)
        shared = tmp_path / "src" / "shared"
        shared.mkdir(parents=True)
        (shared / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
        )
        cfg_src = SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=shared,
            marker="SRC",
        )
        dst_rev = tmp_path / "src" / "DST"
        dst_rev.mkdir(parents=True)
        cfg_dst = SimpleNamespace(
            root=tmp_path,
            target_name="DST",
            reversed_dir=dst_rev,
            metadata_dir=tmp_path,
            marker="DST",
        )
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dry_run=True)
        assert res["action"] == "would-import-shared"
        assert res["filepath"] == "../shared/f1.c"
        assert str(tmp_path) not in res["filepath"]


class TestUnifiedTreeMarkerMove:
    """Unified tree (``shared_dir`` == ``reversed_dir``): one file holds the
    source body AND the destination's own claim.

    The copy path must never write one extracted function over such a file —
    that deletes every co-resident function and duplicates the body.  The
    shared path must MOVE the destination marker onto the source block instead
    of the old idempotent no-op, which verified the stale body.
    """

    SRC_FILE = (
        "// FUNCTION: SRC 0x401000\n"
        "// SIZE: 11\n"
        "int f1(void){ return 1; }\n"
        "\n"
        "// FUNCTION: SRC 0x401010\n"
        "// SIZE: 11\n"
        "int f2(void){ return 2; }\n"
    )

    def _cfg(self, tmp_path: Path) -> SimpleNamespace:
        rev = tmp_path / "src"
        rev.mkdir(parents=True)
        return SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=rev,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "a.exe",
            source_ext=".c",
            marker="SRC",
            posix_style=False,
        )

    def _cfgs(self, tmp_path: Path) -> tuple[SimpleNamespace, SimpleNamespace]:
        """SRC and DST configs over ONE tree — the unified layout."""
        src = self._cfg(tmp_path)
        dst = SimpleNamespace(**{**vars(src), "target_name": "DST", "marker": "DST"})
        return src, dst

    def test_stack_marker_on_block_moves_onto_named_block(self) -> None:
        text = (
            "#include <stdio.h>\n"
            "// FUNCTION: SRC 0x401000\n"
            "// SIZE: 11\n"
            "int f1(void){ return 1; }\n"
            "\n"
            "// FUNCTION: SRC 0x401010\n"
            "// SIZE: 11\n"
            "int f2(void){ return 2; }\n"
        )
        out = ci.stack_marker_on_block(text, "DST", 0x401040, 11, "SRC", 0x401010)
        assert out is not None
        lines = out.splitlines()
        # The destination marker sits directly above the SECOND block's body.
        assert lines[lines.index("// FUNCTION: DST 0x401040") + 2] == "// FUNCTION: SRC 0x401010"
        assert lines[lines.index("// FUNCTION: DST 0x401040") + 4].startswith("int f2")
        assert out.count("FUNCTION: DST") == 1
        assert "#include <stdio.h>" in out

    def test_stack_marker_on_block_drops_superseded_claim(self) -> None:
        text = (
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
            "\n// FUNCTION: DST 0x401040\n// SIZE: 3\nint f1(void){ return 0; }\n"
        )
        out = ci.stack_marker_on_block(
            text, "DST", 0x401040, 11, "SRC", 0x401000, drop=("DST", 0x401040)
        )
        assert out is not None
        assert out.count("FUNCTION: DST") == 1
        assert "return 0" not in out  # the stale destination body is gone
        assert out.splitlines()[0] == "// FUNCTION: DST 0x401040"

    def test_stack_marker_on_block_absent_source(self) -> None:
        text = "// FUNCTION: SRC 0x401000\nint f1(void){ return 1; }\n"
        assert ci.stack_marker_on_block(text, "DST", 0x401040, 11, "SRC", 0x409999) is None

    def test_copy_refuses_when_source_body_is_in_destination_file(self, tmp_path: Path) -> None:
        src, dst = self._cfgs(tmp_path)
        (src.reversed_dir / "f1.c").write_text(self.SRC_FILE, encoding="utf-8")
        before = (src.reversed_dir / "f1.c").read_text(encoding="utf-8")

        res = ci.import_function(dst, src, 0x401040, 0x401000, "f1.c", 11, dry_run=True)
        assert res["action"] == "error"
        assert res["status"] == "TARGET_CONFLICT"
        assert "--shared" in res["message"]
        assert (src.reversed_dir / "f1.c").read_text(encoding="utf-8") == before

    def test_copy_refuses_destination_file_without_this_va(self, tmp_path: Path) -> None:
        src, dst = self._cfgs(tmp_path)
        (src.reversed_dir / "f1.c").write_text(self.SRC_FILE, encoding="utf-8")
        (src.reversed_dir / "other.c").write_text("int unrelated(void){ return 0; }\n")
        res = ci.import_function(
            dst, src, 0x401040, 0x401000, "f1.c", 11, dst_file="other.c", dry_run=True
        )
        assert res["status"] == "TARGET_CONFLICT"
        assert "overwrite" in res["message"]

    def test_copy_reports_source_without_the_marker(self, tmp_path: Path) -> None:
        """One bad annotation row must not abort a whole-inventory run."""
        src, dst = self._cfgs(tmp_path)
        (src.reversed_dir / "f1.c").write_text(self.SRC_FILE, encoding="utf-8")
        res = ci.import_function(dst, src, 0x401040, 0x409999, "f1.c", 11, dry_run=True)
        assert res["action"] == "error"
        assert res["status"] == "NO_MARKER"

    def test_shared_import_moves_marker_onto_same_file_body(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from rebrew.compile import CompareResult

        src, dst = self._cfgs(tmp_path)
        path = src.reversed_dir / "f1.c"
        path.write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
            "\n// FUNCTION: DST 0x401040\n// SIZE: 3\nint f1(void){ return 0; }\n",
            encoding="utf-8",
        )
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
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")

        res = ci.import_shared_function(dst, src, 0x401040, 0x401000, "f1.c", 11)
        assert res["action"] == "imported-shared"
        assert "moved the DST marker" in res["message"]
        text = path.read_text(encoding="utf-8")
        assert text.count("FUNCTION: DST") == 1
        assert "return 0" not in text
        assert "return 1" in text

    def test_shared_import_dry_run_announces_the_move(self, tmp_path: Path) -> None:
        src, dst = self._cfgs(tmp_path)
        (src.reversed_dir / "f1.c").write_text(
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
            "\n// FUNCTION: DST 0x401040\n// SIZE: 3\nint f1(void){ return 0; }\n",
            encoding="utf-8",
        )
        res = ci.import_shared_function(dst, src, 0x401040, 0x401000, "f1.c", 11, dry_run=True)
        assert res["action"] == "would-import-shared"
        assert "move the DST marker" in res["message"]

    def test_failed_move_is_reverted(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import CompareResult

        src, dst = self._cfgs(tmp_path)
        path = src.reversed_dir / "f1.c"
        original = (
            "// FUNCTION: SRC 0x401000\n// SIZE: 11\nint f1(void){ return 1; }\n"
            "\n// FUNCTION: DST 0x401040\n// SIZE: 3\nint f1(void){ return 0; }\n"
        )
        path.write_text(original, encoding="utf-8")
        monkeypatch.setattr(
            "rebrew.verify.verify_entry",
            lambda *a, **k: CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=50.0,
                delta=5,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="NEAR",
            ),
        )
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")

        res = ci.import_shared_function(dst, src, 0x401040, 0x401000, "f1.c", 11)
        assert res["action"] == "skipped-unverified"
        assert path.read_text(encoding="utf-8") == original


class TestCandidatesOnly:
    """The "what is already reversed elsewhere?" listing.

    A whole-inventory run prints one row per destination function (thousands of
    "no unambiguous match" rows) with a handful of findings.  ``--candidates-only``
    keeps the findings and counts the rest, so the answer is readable in both
    the table and JSON modes.
    """

    def _project(self, tmp_path: Path) -> Path:
        (tmp_path / "rebrew-project.toml").write_text(
            "[project]\nname = 'probe'\ndefault_target = 'DST'\n"
            "[compiler]\nprofile = 'msvc-6.0'\ncommand = 'CL.EXE'\n"
            "[targets.SRC]\nbinary = 'a.exe'\n"
            "[targets.DST]\nbinary = 'b.exe'\n",
            encoding="utf-8",
        )
        (tmp_path / "a.exe").write_bytes(_pe_a())
        (tmp_path / "b.exe").write_bytes(_pe_b())
        return tmp_path

    def _patch(self, monkeypatch) -> None:
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
            lambda cfg: {A_F1: ("EXACT", "Units/vfs/f1.c")},
        )

    def test_json_lists_findings_and_names_the_source_file(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import json as json_mod

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        self._patch(monkeypatch)
        monkeypatch.setattr(
            "rebrew.cross_import.import_function",
            lambda *a, **k: {
                "dst_va": "0x401040",
                "src_va": "0x401000",
                "score": 100.0,
                "action": "would-import",
                "status": "",
                "filepath": "Units/vfs/f1.c",
                "message": "",
            },
        )

        runner = CliRunner()
        result = runner.invoke(
            umbrella,
            ["cross-import", "--from", "SRC", "--json", "--dry-run", "--candidates-only"],
        )
        assert result.exit_code == 0, result.output
        payload = json_mod.loads(result.output)
        rows = {r["dst_va"]: r for r in payload["results"]}
        assert set(rows) == {"0x401040"}  # the matchless destination is hidden
        assert payload["skipped_count"] == 1
        assert rows["0x401040"]["src_file"] == "Units/vfs/f1.c"
        assert rows["0x401040"]["src_status"] == "EXACT"

    def test_without_the_flag_every_destination_is_listed(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import json as json_mod

        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        self._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        self._patch(monkeypatch)
        monkeypatch.setattr(
            "rebrew.cross_import.import_function",
            lambda *a, **k: {
                "dst_va": "0x401040",
                "src_va": "0x401000",
                "score": 100.0,
                "action": "would-import",
                "status": "",
                "filepath": "Units/vfs/f1.c",
                "message": "",
            },
        )

        runner = CliRunner()
        result = runner.invoke(umbrella, ["cross-import", "--from", "SRC", "--json", "--dry-run"])
        assert result.exit_code == 0, result.output
        payload = json_mod.loads(result.output)
        assert len(payload["results"]) == 2
        assert "skipped_count" not in payload


class TestVerifiedSymbolFollowsTheBlock:
    """The verified symbol is the one the SOURCE VA's block defines.

    ``_source_name`` returns the file's FIRST definition.  In a multi-function
    file that is a different function, so a marker moved onto a later block
    compiled the file, found the first function and compared ITS bytes
    (guild-rebrew: "Size 33B vs 235B" on ErrorModule.c — the import could never
    verify).
    """

    MULTI = (
        "// FUNCTION: SRC 0x401000\n"
        "// SIZE: 11\n"
        "int first(void){ return 1; }\n"
        "\n"
        "// FUNCTION: SRC 0x401010\n"
        "// SIZE: 13\n"
        "int second(void){ return 2; }\n"
    )

    def test_name_for_va_picks_the_blocks_definition(self) -> None:
        assert ci._name_for_va(self.MULTI, 0x401010) == "second"
        assert ci._name_for_va(self.MULTI, 0x401000) == "first"

    def test_name_for_va_unknown_va(self) -> None:
        assert ci._name_for_va(self.MULTI, 0x409999) is None

    def test_name_for_va_marker_only_block_borrows_below(self) -> None:
        """A marker prepended above another block owns no body of its own."""
        text = (
            "// FUNCTION: DST 0x401040\n// SIZE: 13\n"
            "// FUNCTION: SRC 0x401010\n// SIZE: 13\nint second(void){ return 2; }\n"
        )
        assert ci._name_for_va(text, 0x401040) == "second"

    def test_shared_import_verifies_the_blocks_symbol(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compile import CompareResult

        rev = tmp_path / "src"
        rev.mkdir()
        cfg_src = SimpleNamespace(
            root=tmp_path,
            target_name="SRC",
            reversed_dir=rev,
            shared_dir=rev,
            metadata_dir=tmp_path,
            target_binary=tmp_path / "a.exe",
            source_ext=".c",
            marker="SRC",
            posix_style=False,
        )
        cfg_dst = SimpleNamespace(**{**vars(cfg_src), "target_name": "DST", "marker": "DST"})
        (rev / "f.c").write_text(
            self.MULTI + "\n// FUNCTION: DST 0x401040\n// SIZE: 3\nint second(void){ return 0; }\n",
            encoding="utf-8",
        )
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
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")

        res = ci.import_shared_function(cfg_dst, cfg_src, 0x401040, 0x401010, "f.c", 13)
        assert res["action"] == "imported-shared"
        assert seen["entry"].symbol == "_second"
        assert seen["entry"].name == "second"
