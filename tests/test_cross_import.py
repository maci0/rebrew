"""Tests for rebrew.cross_import — cross-target function import.

Covers the pure matching core (structural signatures), the two-PE fixture
scenario (shared functions at different VAs, differing and absent functions),
the import mechanics (marker strip, identity row, file write, verify + STATUS), and
the CLI wiring.  The mingw-16.2.0 end-to-end test runs a real compile+verify
round-trip when the native toolchain is installed (it is on this host).
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from bin_util import make_pe
from source_util import SourceFixture, write_source, write_store_fixture

import rebrew.cross_import as ci
from rebrew.compiler.toolchain import TOOLCHAINS, image_present

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


def _dst_cfg(tmp_path: Path, rev: Path) -> Any:
    """Import-destination config over an already-created *rev* directory."""
    return SimpleNamespace(
        root=tmp_path,
        target_name="DST",
        reversed_dir=rev,
        metadata_dir=tmp_path,
        target_binary=tmp_path / "b.exe",
        source_ext=".c",
        marker="DST",
        posix_style=False,
    )


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
        from rebrew.formats.binary_loader import extract_raw_bytes

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


class TestAddressRewrite:
    def test_copy_replaces_stacked_targets(self) -> None:
        from rebrew.metadata.anchors import parse_address_anchors

        source = (
            "/* ADDRESS: A 0x401000 */\n/* ADDRESS: B 0x501000 */\nint common(void) { return 1; }\n"
        )
        copied = ci._rewrite_address(source, "DST", 0x601000, name="common")
        assert [(a.module, a.va, a.name) for a in parse_address_anchors(copied)] == [
            ("DST", 0x601000, "common")
        ]
        assert copied.endswith("int common(void) { return 1; }\n")
        assert ci._rewrite_address(copied, "DST", 0x601000, name="common") == copied

    def test_copy_adds_address_to_metadata_only_definition(self) -> None:
        source = "int f(void) { return 1; }\n"
        assert ci._rewrite_address(source, "DST", 0x1234, name="f") == (
            "/* ADDRESS: DST 0x00001234 */\n" + source
        )

    def test_ambiguous_definitions_are_rejected(self) -> None:
        with pytest.raises(ValueError, match="no declaration"):
            ci._rewrite_address("int a(void) {}\nint b(void) {}\n", "D", 1, name="missing")

    def test_copy_preserves_crlf(self) -> None:
        source = "/* ADDRESS: A 0x401000 */\r\nint f(void) {}\r\n"
        copied = ci._rewrite_address(source, "D", 2, name="f")
        assert copied == "/* ADDRESS: D 0x00000002 */\r\nint f(void) {}\r\n"


class TestExtractSingleFunction:
    def test_single_function_source_unchanged(self) -> None:
        src = SourceFixture(
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            {"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        assert ci._extract_function_text(src, "f1") == src

    def test_multi_function_keeps_only_matched_block(self) -> None:
        """Copying a whole multi-function SERVER file into GOLDTL leaked every
        co-resident marker (lint E012) and duplicated the other functions.
        The matched function must import alone with its preamble."""
        src = SourceFixture(
            '#include "h.h"\n/* ADDRESS: SERVER 0x401000 */\nint f1(void){ return 1; }\n/* ADDRESS: SERVER 0x401010 */\nint f2(void){ return 2; }\n',
            {"SERVER.0x401000": {"kind": "FUNCTION"}, "SERVER.0x401010": {"kind": "FUNCTION"}},
        )
        out = ci._extract_function_text(src, "f1")
        assert out is not None
        assert "f1" in out
        assert "f2" not in out
        assert out.count("ADDRESS:") == 1
        assert out.startswith('#include "h.h"')

    def test_multi_function_second_block(self) -> None:
        src = SourceFixture(
            "/* ADDRESS: SERVER 0x401000 */\nint f1(void){ return 1; }\n/* ADDRESS: SERVER 0x401010 */\nint f2(void){ return 2; }\n",
            {"SERVER.0x401000": {"kind": "FUNCTION"}, "SERVER.0x401010": {"kind": "FUNCTION"}},
        )
        out = ci._extract_function_text(src, "f2")
        assert out is not None
        assert "f2" in out and "f1" not in out
        assert out.count("ADDRESS:") == 1

    def test_unknown_va_returns_none(self) -> None:
        src = SourceFixture(
            "/* ADDRESS: SERVER 0x401000 */\nint f1(void){ return 1; }\n",
            {"SERVER.0x401000": {"kind": "FUNCTION"}},
        )
        assert ci._extract_function_text(src, "absent") is None

    def test_import_emits_only_matched_function(self, tmp_path: Path, monkeypatch) -> None:
        """End-to-end: a SERVER multi-function file imports ONLY f1 into GOLDTL
        as pure C. No foreign marker survives, and the co-resident body is not
        copied. SIZE and identity live on the destination row, recorded
        before verify."""
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
        write_source(
            rev_src / "shared.c",
            '#include "shared.h"\n/* ADDRESS: SERVER 0x401000 */\nint f1(void){ return 1; }\n/* ADDRESS: SERVER 0x401010 */\nint f2(void){ return 2; }\n',
            metadata_fields={
                "SERVER.0x401000": {"kind": "FUNCTION"},
                "SERVER.0x401010": {"kind": "FUNCTION"},
            },
            metadata_dir=tmp_path,
        )

        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import get_entry

        seen: dict[str, Any] = {}

        def fake_verify(entry, cfg, cache=None, **kw):
            seen["row"] = get_entry(tmp_path, 0x601000, "DST")
            return CompareResult(
                matched=True,
                status="RELOC",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="RELOC",
            )

        monkeypatch.setattr("rebrew.verify.verify_entry", fake_verify)
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)
        monkeypatch.setattr(ci_mod, "_source_flags", lambda *a, **k: "")

        res = ci_mod.import_function(cfg_dst, cfg_src, 0x601000, 0x401000, "shared.c", 11)
        assert res["action"] == "imported"
        text = (rev_dst / "shared.c").read_text(encoding="utf-8")
        assert text.startswith('#include "shared.h"')
        assert "int f1(void){ return 1; }" in text
        assert "int f2" not in text
        assert "FUNCTION:" not in text
        assert "SIZE:" not in text
        assert seen["row"]["kind"] == "FUNCTION"
        assert seen["row"]["name"] == "f1"
        assert seen["row"]["symbol"] == "_f1"
        assert seen["row"]["size"] == 11
        assert seen["row"]["file"] == "src_GOLDTL/shared.c"


class TestPaddedSignatures:
    def _cfg(self, tmp_path: Path, code: bytes) -> SimpleNamespace:
        binary = tmp_path / "padded.exe"
        binary.write_bytes(make_pe(code))
        return SimpleNamespace(target_binary=binary, arch="x86_32")

    @pytest.mark.parametrize("padding", [b"\x90" * 5, b"\xcc" * 5, b"\x90\xcc\x90"])
    def test_padding_does_not_lower_the_default_match_score(
        self, tmp_path: Path, padding: bytes
    ) -> None:
        code = F1 + padding
        cfg = self._cfg(tmp_path, code)
        body = ci.signature_for(cfg, F1, A_F1)
        padded = ci.signature_for(cfg, code, A_F1)
        assert padded == body
        assert ci.cross_match({B_F1: padded}, {A_F1: body}) == {B_F1: (A_F1, 100.0)}

    @pytest.mark.parametrize(
        "body",
        [
            bytes.fromhex("85 c0 75 03 31 c0 c3 b8 01 00 00 00 c3"),
            bytes.fromhex("85 c0 75 01 c3 90 c3"),
            bytes.fromhex("c2 90 90"),
        ],
    )
    def test_complete_body_keeps_later_blocks_and_return_operands(
        self, tmp_path: Path, body: bytes
    ) -> None:
        code = body + b"\x90" * 5
        sig = ci.signature_for(self._cfg(tmp_path, code), code, A_F1)
        assert sig is not None and sig["size"] == len(body)

    @pytest.mark.parametrize(
        "code",
        [
            bytes.fromhex("75 20 c3 90 90 90"),
            bytes.fromhex("85 c0 74 04 eb fa 90 90 c3 90 90"),
            bytes.fromhex("e9 20 00 00 00 90 90"),
            bytes.fromhex("cc 90 90"),
            bytes.fromhex("90 90 90"),
            bytes.fromhex("c3 00 90"),
        ],
    )
    def test_ambiguous_or_unterminated_extent_is_not_shortened(
        self, tmp_path: Path, code: bytes
    ) -> None:
        sig = ci.signature_for(self._cfg(tmp_path, code), code, A_F1)
        assert sig is not None and sig["size"] == len(code)

    def test_missing_binary_keeps_the_supplied_span(self, tmp_path: Path) -> None:
        cfg = SimpleNamespace(target_binary=tmp_path / "missing.exe")
        code = F1 + b"\x90" * 5
        sig = ci.signature_for(cfg, code, A_F1)
        assert sig is not None and sig["size"] == len(code)

    def test_x86_padding_rule_does_not_trim_other_architectures(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.load_binary", lambda *a: SimpleNamespace(arch="arm32")
        )
        code = F1 + b"\x90" * 5
        sig = ci.signature_for(self._cfg(tmp_path, code), code, A_F1)
        assert sig is not None and sig["size"] == len(code)


class TestOnlyVaGuard:
    def test_only_va_does_not_bypass_matched_status(self, monkeypatch) -> None:
        """``--va`` on an already matched destination function must not re-add
        it through the disassembler (that path skipped the status filter)."""
        cfg = SimpleNamespace()
        monkeypatch.setattr(ci, "annotations_by_va", lambda cfg: {0x401040: ("EXACT", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda cfg: {0x401040: {"canonical_size": 16}})
        monkeypatch.setattr(ci, "disasm_sizes", lambda cfg, vas: ({0x401040: 16}, []))
        monkeypatch.setattr(ci, "target_bytes_by_va", lambda cfg, vas: dict.fromkeys(vas, b"\xc3"))
        assert ci.unmatched_dest_bytes(cfg, only_va=0x401040) == {}

    def test_proven_is_importable_destination_not_donor(self, monkeypatch) -> None:
        """PROVEN bytes differ from the target: a PROVEN destination is still
        unmatched work and a PROVEN source is not a byte-exact donor."""
        cfg = SimpleNamespace()
        monkeypatch.setattr(ci, "annotations_by_va", lambda cfg: {0x401040: ("PROVEN", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda cfg: {0x401040: {"canonical_size": 16}})
        monkeypatch.setattr(ci, "target_bytes_by_va", lambda cfg, vas: dict.fromkeys(vas, b"\xc3"))
        assert set(ci.unmatched_dest_bytes(cfg, only_va=0x401040)) == {0x401040}
        assert ci.matched_source_bytes(cfg) == {}

    def test_only_va_sizeless_unmatched_still_matched(self, monkeypatch) -> None:
        """A NOT-matched VA without a registry size still gets the disasm size
        (the guard must only block the matched case)."""
        cfg = SimpleNamespace()
        monkeypatch.setattr(ci, "annotations_by_va", lambda cfg: {0x401040: ("STUB", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda cfg: {})
        monkeypatch.setattr(ci, "disasm_sizes", lambda cfg, vas: ({0x401040: 16}, []))
        monkeypatch.setattr(ci, "target_bytes_by_va", lambda cfg, vas: dict.fromkeys(vas, b"\xc3"))
        assert set(ci.unmatched_dest_bytes(cfg, only_va=0x401040)) == {0x401040}


class TestTargetBytes:
    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        """A missing binary is an error, not an empty catalog of bytes."""
        cfg = SimpleNamespace(target_binary=tmp_path / "gone.exe")
        with pytest.raises(FileNotFoundError):
            ci.target_bytes_by_va(cfg, {0x401000: 16})

    def test_no_vas_skips_binary_load(self, tmp_path: Path) -> None:
        cfg = SimpleNamespace(target_binary=tmp_path / "gone.exe")
        assert ci.target_bytes_by_va(cfg, {}) == {}


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
        write_source(
            cfg.reversed_dir / "f1.c",
            "/* ADDRESS: FIXT 0x00401040 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"FIXT.0x00401040": {"kind": "FUNCTION", "size": 11}},
        )
        write_store_fixture(
            tmp_path / "rebrew-functions.toml",
            'format = 2\n["FIXT.0x00401040"]\nstatus = "EXACT"\nsize = 11\n',
        )
        assert ci.annotations_by_va(cfg) == {0x401040: ("EXACT", "f1.c")}

    def test_source_symbol_comes_from_the_definition(self) -> None:
        """A leading prototype or ``extern`` must not name the import.

        The old first-line heuristic named the import after a symbol the
        object never defines: verification failed with
        ``EXTRACT_ERROR: Symbol '_LogMessageInternal' not found in .obj`` and
        the import landed with no usable status.
        """
        text = SourceFixture(
            "\nvoid __cdecl LogMessageInternal(char*, unsigned int, char*, int);\nextern int g_counter;\n/* ADDRESS: SRC 0x401000 */\nint __cdecl f1(int value)\n{\n    return value + g_counter;\n}\n",
            {"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        assert ci._symbol_for_va(text, "SRC", 0x401000, "stem") == ("f1", "_f1")

    def test_source_name_falls_back_to_the_stem(self) -> None:
        """No definition under the marker: the fallback names the import."""
        text = SourceFixture("// no code here\n", {"SRC.0x401000": {"kind": "FUNCTION"}})
        assert ci._symbol_for_va(text, "SRC", 0x401000, "f2") == ("f2", "_f2")

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
        write_source(
            sub / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "cflags": "/O1 /Gd"}},
        )

        from rebrew.compiler.compile import CompareResult

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

        from rebrew.metadata.functions import load_metadata

        assert load_metadata(cfg_dst.metadata_dir)[("DST", B_F1)]["cflags"] == f"/O1 /Gd /I{sub}"

    def test_import_writes_file_and_verifies(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        write_source(
            cfg_src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            cfg_dst.reversed_dir / "f1.c",
            "/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            encoding="utf-8",
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION", "size": 0}},
        )

        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import get_entry

        seen: dict[str, Any] = {}

        def fake_verify(entry, cfg, cache=None, **kw):
            seen["entry"] = entry
            seen["row"] = get_entry(tmp_path, B_F1, "DST")
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
        assert text.splitlines()[-1] == "int f1(void){ return 1; }"
        assert "FUNCTION:" not in text
        assert "SIZE:" not in text
        assert seen["entry"].va == B_F1
        assert seen["entry"].size == 11
        assert seen["row"]["kind"] == "FUNCTION"
        assert seen["row"]["name"] == "f1"
        assert seen["row"]["symbol"] == "_f1"
        assert seen["row"]["size"] == 11
        assert seen["row"]["file"] == "src_DST/f1.c"
        assert applied and applied[0][0][0][1] == "EXACT"

    def test_import_verifies_with_the_symbol_map(self, tmp_path: Path, monkeypatch) -> None:
        """Import verification gets the destination's symbol map, as `rebrew test`
        and `verify` do: without it smart_reloc_compare cannot mask a typed
        relocation, and every body that touches a global or calls a function
        reads NEAR_MATCHING (guild-rebrew: 518 GOLD twins of GOLDTL bodies)."""
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        write_source(
            cfg_src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        from rebrew.compiler.compile import CompareResult

        seen: dict[str, Any] = {}

        def fake_verify(entry, cfg, cache=None, **kw):
            seen.update(kw)
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
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda fixes, cfg: None)
        symbols = {"_g": 0x500000}
        ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, name_to_va=symbols)
        assert seen["name_to_va"] is symbols

    def test_legacy_encoded_source_is_read_and_preserved(self, tmp_path: Path, monkeypatch) -> None:
        """A cp1252 source (0xE9 in a comment) must not crash the import, and
        the destination keeps the detected encoding instead of being re-encoded
        as UTF-8."""
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        body = b"/* ADDRESS: SRC 0x401000 */\n// caf\xe9\nint f1(void){ return 1; }\n"
        (cfg_src.reversed_dir / "f1.c").write_bytes(body)

        from rebrew.compiler.compile import CompareResult

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
        write_source(
            cfg_src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION"}},
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
        write_source(
            cfg_src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        # The destination has an UNRELATED f1.c for a different VA.
        write_source(
            cfg_dst.reversed_dir / "f1.c",
            "/* ADDRESS: DST 0x999000 */\nint other(void){ return 9; }\n",
            encoding="utf-8",
            metadata_fields={"DST.0x999000": {"kind": "FUNCTION"}},
        )

        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["status"] == "TARGET_CONFLICT"
        # The destination file is untouched.
        text = (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
        assert (
            SourceFixture("/* ADDRESS: DST 0x999000 */", {"DST.0x999000": {"kind": "FUNCTION"}})
            in text
        )
        assert "other" in text

    def test_destination_own_file_overwritten(self, tmp_path: Path, monkeypatch) -> None:
        """The destination's OWN annotation file (same VA) is overwritten as
        intended — that is the normal import target."""
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        write_source(
            cfg_src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        write_source(
            cfg_dst.reversed_dir / "f1.c",
            "/* ADDRESS: DST 0x401040 */\nint f1(void){ return 0; }\n",
            encoding="utf-8",
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION"}},
        )

        from rebrew.compiler.compile import CompareResult

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
        assert text.splitlines()[-1] == "int f1(void){ return 1; }"
        assert "FUNCTION:" not in text
        assert "return 0" not in text
        from rebrew.metadata.functions import get_entry

        row = get_entry(tmp_path, B_F1, "DST")
        assert row["kind"] == "FUNCTION"
        assert row["size"] == 11
        assert row["file"] == "src_DST/f1.c"

    def test_unmatched_copy_still_applies_status(self, tmp_path: Path, monkeypatch) -> None:
        """A copy that fails verify stays imported-unverified and still applies STATUS.

        Identity is recorded before verify. The written body is pure C.
        """
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        write_source(
            cfg_src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import get_entry

        applied: list[Any] = []

        def fake_verify(entry, cfg, cache=None, **kw):
            assert get_entry(tmp_path, B_F1, "DST")["kind"] == "FUNCTION"
            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=40.0,
                delta=4,
                obj_bytes=b"x",
                reloc_offsets=[],
                message="NEAR",
            )

        monkeypatch.setattr("rebrew.verify.verify_entry", fake_verify)
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda fixes, cfg: applied.append(fixes),
        )
        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["action"] == "imported-unverified"
        assert res["status"] == "NEAR_MATCHING"
        assert applied and applied[0][0][1] == "NEAR_MATCHING"
        text = (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8")
        assert text.splitlines()[-1] == "int f1(void){ return 1; }"
        assert "SIZE:" not in text

    def test_markerless_single_function_is_copied_whole(self, tmp_path: Path, monkeypatch) -> None:
        """One function row and no marker: the file is copied as pure C."""
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        body = "int f1(void){ return 1; }\n"
        src_path = cfg_src.reversed_dir / "f1.c"
        write_source(src_path, body, encoding="utf-8")
        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import get_entry, identity_file, record_function_identity

        record_function_identity(
            tmp_path,
            module="SRC",
            va=A_F1,
            file=identity_file(src_path, tmp_path),
            kind="FUNCTION",
            name="f1",
            symbol="_f1",
            size=11,
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
        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 13)
        assert res["action"] == "imported"
        assert (cfg_dst.reversed_dir / "f1.c").read_text(encoding="utf-8").endswith(body)
        row = get_entry(tmp_path, B_F1, "DST")
        assert row["kind"] == "FUNCTION"
        assert row["name"] == "f1"
        assert row["symbol"] == "_f1"
        assert row["size"] == 13

    def test_markerless_file_without_a_row_is_an_error(self, tmp_path: Path) -> None:
        cfg_src = self._cfg(tmp_path, "SRC", tmp_path / "a.exe")
        cfg_dst = self._cfg(tmp_path, "DST", tmp_path / "b.exe")
        (cfg_src.reversed_dir / "f1.c").write_text("int f1(void){ return 1; }\n", encoding="utf-8")
        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["action"] == "error"
        assert res["status"] == "NO_DEFINITION"
        assert res["message"] == "source f1.c has no definition for 0x401000"
        assert not (cfg_dst.reversed_dir / "f1.c").exists()


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
            marker=target,
            reversed_dir=rev,
            metadata_dir=tmp_path,
            target_binary=binary,
        )

    def test_disasm_sizes_ret_only(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        (tmp_path / "x.exe").write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "DST", tmp_path / "x.exe")
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.function_extent_from_disasm",
            lambda _p, _va, with_kind=False: (11, "ret") if with_kind else 11,
        )
        sizes, refused = ci.disasm_sizes(cfg, [A_F1, A_F2])
        assert sizes == {A_F1: 11, A_F2: 11}
        assert refused == []

    @pytest.mark.parametrize("kind", ["jmp", "padding", "ud2"])
    def test_disasm_sizes_refuses_nonreturn_and_none(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
    ) -> None:
        (tmp_path / "x.exe").write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "DST", tmp_path / "x.exe")

        def fake_extent(_p: Path, va: int, with_kind: bool = False):  # type: ignore[no-untyped-def]
            if va == A_F1:
                return (8, kind) if with_kind else 8
            return None

        monkeypatch.setattr("rebrew.formats.binary_loader.function_extent_from_disasm", fake_extent)
        sizes, refused = ci.disasm_sizes(cfg, [A_F1, A_F2])
        assert sizes == {}
        assert refused == [A_F1, A_F2]

    def test_unmatched_dest_bytes_sizeless_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pa = tmp_path / "a.exe"
        pa.write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "DST", pa)
        monkeypatch.setattr(ci, "annotations_by_va", lambda _c: {A_F1: ("STUB", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda _c: {A_F1: {"canonical_size": 0}})
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.function_extent_from_disasm",
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
        monkeypatch.setattr(ci, "annotations_by_va", lambda _c: {A_F1: ("STUB", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda _c: {A_F1: {"canonical_size": 0}})
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.function_extent_from_disasm",
            lambda _p, _va, with_kind=False: (len(F1), "ret") if with_kind else len(F1),
        )
        out = ci.unmatched_dest_bytes(cfg, only_va=A_F1)
        assert out[A_F1] == F1

    def test_matched_donor_uses_managed_body_extent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import update_field

        pa = tmp_path / "a.exe"
        pa.write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "SRC", pa)
        monkeypatch.setattr(ci, "annotations_by_va", lambda _c: {A_F1: ("EXACT", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda _c: {A_F1: {"canonical_size": len(F1) + 4}})
        update_field(cfg.metadata_dir, A_F1, "size", len(F1), module="SRC")
        assert ci.matched_source_bytes(cfg)[A_F1] == F1

    def test_donor_extent_is_target_scoped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.metadata.functions import update_field

        pa = tmp_path / "a.exe"
        pa.write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "SRC", pa)
        monkeypatch.setattr(ci, "annotations_by_va", lambda _c: {A_F1: ("EXACT", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda _c: {A_F1: {"canonical_size": len(F1)}})
        update_field(cfg.metadata_dir, A_F1, "size", 1, module="DST")
        assert ci.matched_source_bytes(cfg)[A_F1] == F1

    def test_matched_source_bytes_sizeless_matches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pa = tmp_path / "a.exe"
        pa.write_bytes(_pe_a())
        cfg = self._cfg(tmp_path, "SRC", pa)
        monkeypatch.setattr(ci, "annotations_by_va", lambda _c: {A_F1: ("EXACT", "f1.c")})
        monkeypatch.setattr(ci, "registry", lambda _c: {A_F1: {"canonical_size": 0}})
        monkeypatch.setattr(
            "rebrew.formats.binary_loader.function_extent_from_disasm",
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

        from rebrew.app.main import app as umbrella

        self._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(umbrella, ["source", "import-related", "--from", "DST"])
        assert result.exit_code != 0
        assert "--from must name a different target" in result.output

    def test_json_flow_with_mocked_import(self, tmp_path: Path, monkeypatch) -> None:
        import json as json_mod

        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

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
        monkeypatch.setattr("rebrew.cross_import.registry", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.cross_import.annotations_by_va",
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
            ["source", "import-related", "--from", "SRC", "--json", "--dry-run"],
        )
        assert result.exit_code == 0, result.output
        payload = json_mod.loads(result.output)
        assert payload["from"] == "SRC"
        assert payload["results"][0]["action"] == "imported"

    def test_limit_zero_imports_nothing(self, tmp_path: Path, monkeypatch) -> None:
        """--limit 0 must import zero functions; the old guard ran after the
        first import was already appended."""
        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

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
        monkeypatch.setattr("rebrew.cross_import.registry", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.cross_import.annotations_by_va",
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
            umbrella, ["source", "import-related", "--from", "SRC", "--json", "--limit", "0"]
        )
        assert result.exit_code == 0, result.output
        assert calls == []

    def test_sizeless_refusal_row(self, tmp_path: Path, monkeypatch) -> None:
        """A sizeless dest VA the disassembler cannot size gets the
        'sizeless, use --va' row instead of vanishing silently."""
        import json as json_mod

        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

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
        monkeypatch.setattr("rebrew.cross_import.registry", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.cross_import.annotations_by_va",
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
            ["source", "import-related", "--from", "SRC", "--json", "--dry-run"],
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
    """Real compile+verify round-trip through the mingw-16.2.0 docker image."""

    @pytest.mark.skipif(
        not image_present(TOOLCHAINS["mingw-16.2.0"].image or ""),
        reason="mingw-16.2.0 image not built (rebrew toolchain build mingw-16.2.0)",
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
        from rebrew.metadata.functions import update_source_status

        update_source_status(cfg_src.metadata_dir, "EXACT", "SRC", A_F1)
        write_source(
            cfg_src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            cfg_dst.reversed_dir / "f1.c",
            "/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            encoding="utf-8",
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION", "size": 0}},
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
        assert "FUNCTION:" not in text
        assert "SIZE:" not in text
        assert "int f1(void){ return 1; }" in text
        from rebrew.metadata.functions import get_entry

        row = get_entry(cfg_dst.metadata_dir, B_F1, "DST")
        assert row["kind"] == "FUNCTION"
        assert row["name"] == "f1"
        assert row["size"] == len(F1)


class TestSharedImport:
    """`--shared`: record a destination row for one file (ADR-010).

    ``_stack_marker`` does not insert a marker line.
    """

    def test_shared_import_records_destination_row(self, tmp_path: Path, monkeypatch) -> None:
        rev = tmp_path / "src_shared"
        rev.mkdir(parents=True)
        src_file = rev / "f1.c"
        write_source(
            src_file,
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
            metadata_dir=tmp_path,
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
        cfg_dst = _dst_cfg(tmp_path, dst_rev)

        from rebrew.compiler.compile import CompareResult

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
        assert text.splitlines()[-1] == "int f1(void){ return 1; }"
        assert "FUNCTION:" not in text
        assert not (dst_rev / "f1.c").exists()  # no copy: one file serves both
        from rebrew.metadata.functions import get_entry

        row = get_entry(tmp_path, B_F1, "DST")
        assert row["kind"] == "FUNCTION"
        assert row["name"] == "f1"
        assert row["symbol"] == "_f1"
        assert row["size"] == 11
        assert row["file"] == "src_shared/f1.c"
        src_row = get_entry(tmp_path, A_F1, "SRC")
        assert src_row["kind"] == "FUNCTION"
        assert src_row["file"] == "src_shared/f1.c"


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
        write_source(
            sub / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        res = ci.promote_to_shared(cfg, "Units/vfs/f1.c")
        assert res["action"] == "promoted"
        assert (cfg.shared_dir / "Units" / "vfs" / "f1.c").is_file()
        assert not (cfg.reversed_dir / "Units" / "vfs" / "f1.c").exists()

    def test_promote_retargets_the_row_file(self, tmp_path: Path) -> None:
        """A pure-C row's ``file`` follows the move. The marker does not."""
        cfg = self._cfg(tmp_path)
        cfg.metadata_dir = tmp_path
        src = cfg.reversed_dir / "f1.c"
        src.write_text("int f1(void){ return 1; }\n", encoding="utf-8")
        from rebrew.metadata.data import load_data_metadata, record_data_rows
        from rebrew.metadata.functions import get_entry, identity_file, record_function_identity

        record_function_identity(
            tmp_path,
            module="SRC",
            va=0x401000,
            file=identity_file(src, tmp_path),
            kind="FUNCTION",
            name="f1",
            symbol="_f1",
        )
        record_data_rows(
            tmp_path,
            [
                {
                    "module": "SRC",
                    "va": 0x402000,
                    "identity": {
                        "file": identity_file(src, tmp_path),
                        "kind": "DATA",
                        "name": "g_gap",
                    },
                }
            ],
        )
        res = ci.promote_to_shared(cfg, "f1.c")
        assert res["action"] == "promoted"
        moved = cfg.shared_dir / "f1.c"
        assert moved.is_file()
        assert "FUNCTION:" not in moved.read_text(encoding="utf-8")
        new_file = identity_file(moved, tmp_path)
        row = get_entry(tmp_path, 0x401000, "SRC")
        assert row["file"] == new_file
        assert row["kind"] == "FUNCTION"
        data = load_data_metadata(tmp_path)[("SRC", 0x402000)]
        assert data["file"] == new_file

    def test_promote_moves_across_filesystems(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """shared_dir on another mount: rename raises EXDEV, the move still lands."""
        cfg = self._cfg(tmp_path)
        (cfg.reversed_dir / "f1.c").write_text("x")

        def _exdev(src: Any, dst: Any, *args: Any, **kwargs: Any) -> None:
            raise OSError(errno.EXDEV, "Invalid cross-device link")

        monkeypatch.setattr(os, "rename", _exdev)
        res = ci.promote_to_shared(cfg, "f1.c")
        assert res["action"] == "promoted"
        assert (cfg.shared_dir / "f1.c").read_text() == "x"
        assert not (cfg.reversed_dir / "f1.c").exists()

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
        write_source(
            rev / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
            metadata_dir=tmp_path,
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
        cfg_dst = _dst_cfg(tmp_path, dst_rev)
        from rebrew.compiler.compile import CompareResult

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
        write_source(
            tmp_path / "src" / "SRC" / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
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
            "rebrew.cross_import.registry", lambda cfg: {B_F1: {"canonical_size": 11}}
        )
        monkeypatch.setattr(
            "rebrew.cross_import.annotations_by_va",
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

        from rebrew.app.main import app as umbrella

        runner = CliRunner()
        result = runner.invoke(
            umbrella, ["source", "import-related", "--from", "SRC", "--shared", "--target", "DST"]
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
        cfg_dst = _dst_cfg(tmp_path, dst_rev)
        return cfg_src, cfg_dst

    def _ok_verify(self, monkeypatch) -> None:
        from rebrew.compiler.compile import CompareResult

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
        write_source(
            cfg_src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            cfg_dst.reversed_dir / "stub.c",
            "/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION", "size": 0}},
        )
        self._ok_verify(monkeypatch)
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        assert res["action"] == "imported-shared"
        assert "superseded stub.c" in res["message"]
        assert not (cfg_dst.reversed_dir / "stub.c").exists()

    def test_unverified_shared_import_keeps_stub(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compiler.compile import CompareResult

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        write_source(
            cfg_src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            cfg_dst.reversed_dir / "stub.c",
            "/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION", "size": 0}},
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
        applied: list[Any] = []
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda *a, **k: applied.append(a),
        )
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        # A failed new claim is not recorded. The stub stays the only owner.
        assert res["action"] == "skipped-unverified"
        assert res["message"].endswith(
            "(destination already annotates this VA; claim not recorded)"
        )
        assert applied == []
        assert (cfg_dst.reversed_dir / "stub.c").is_file()
        assert "FUNCTION: DST" not in (cfg_src.shared_dir / "f1.c").read_text()

    @pytest.mark.parametrize(
        "owner",
        [
            "other_target",
            "managed_target",
            "inline_target",
            "other_function",
            "data",
            "data_declaration",
            "unmarked_function",
            "unmarked_global",
        ],
    )
    def test_shared_import_preserves_other_stub_owners(
        self, tmp_path: Path, monkeypatch, owner: str
    ) -> None:
        from rebrew.metadata.data import load_data_metadata, record_data_rows
        from rebrew.metadata.functions import load_metadata, record_function_identity, update_field

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        write_source(
            cfg_src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        stub = cfg_dst.reversed_dir / "stub.c"
        text = SourceFixture(
            "/* ADDRESS: DST 0x401040 */\n\n", {"DST.0x401040": {"kind": "FUNCTION", "size": 11}}
        )
        if owner in {"other_target", "managed_target", "inline_target"}:
            if owner != "managed_target":
                text += SourceFixture(
                    "/* ADDRESS: OTHER 0x501040 */\n", {"OTHER.0x501040": {"kind": "FUNCTION"}}
                )
            module, va, symbol = "OTHER", 0x501040, "_f1"
            if owner == "inline_target":
                module = ""
        elif owner == "other_function":
            module, va, symbol = "DST", B_F2, "_second"
        else:
            module, va, symbol = "", 0, ""
        text += "int f1(void){ return __LINE__; }\n"
        if owner in {"other_function", "unmarked_function"}:
            text += "int second(void){ return __LINE__; }\n"
        if owner in {"data", "unmarked_global"}:
            text += "int counter = 3;\n"
        if owner == "data_declaration":
            text += "extern int counter;\n"
        text += SourceFixture(
            "/* Example: ADDRESS: DST 0x401040\n*/\n", {"DST.0x401040": {"kind": "FUNCTION"}}
        )
        write_source(
            stub,
            text,
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION", "size": 11}},
        )
        if module:
            record_function_identity(
                tmp_path,
                module=module,
                va=va,
                file="src_DST/stub.c",
                kind="FUNCTION",
                name=symbol[1:],
                symbol=symbol,
                size=11,
            )
            update_field(tmp_path, va, "note", "preserve this owner", module)
        if owner in {"data", "data_declaration"}:
            record_data_rows(
                tmp_path,
                [
                    {
                        "module": "DST",
                        "va": 0x403000,
                        "identity": {
                            "file": "src_DST/stub.c",
                            "name": "counter",
                            "kind": "DATA",
                        },
                        "fields": {"size": 4, "type": "int"},
                    }
                ],
            )
        before_functions = load_metadata(tmp_path)
        before_data = load_data_metadata(tmp_path)
        self._ok_verify(monkeypatch)
        result = ci.import_shared_function(
            cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c"
        )
        assert result["action"] == "imported-shared"
        assert stub.exists(), "importing one identity must not delete other source owners"
        kept = stub.read_text()
        assert len(kept.splitlines()) == len(text.splitlines())
        assert "int f1(void){ return __LINE__; }" in kept
        assert "/* Example: ADDRESS: DST 0x401040\n*/" in kept
        assert not kept.startswith("// FUNCTION: DST")
        if owner in {"other_target", "inline_target"}:
            assert (
                SourceFixture(
                    "/* ADDRESS: OTHER 0x501040 */", {"OTHER.0x501040": {"kind": "FUNCTION"}}
                )
                in kept
            )
        for identity, row in before_functions.items():
            if identity != ("DST", B_F1):
                assert load_metadata(tmp_path)[identity] == row
        assert load_data_metadata(tmp_path) == before_data

    @pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
    def test_preserved_stub_keeps_legacy_encoding_and_line_endings(
        self, tmp_path: Path, monkeypatch, ending: bytes
    ) -> None:
        src, dst = self._cfgs(tmp_path)
        write_source(
            src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        stub = dst.reversed_dir / "stub.c"
        lines = [
            b"/* ADDRESS: DST 0x401040 */",
            b"/* ADDRESS: OTHER 0x501040 */",
            b"/* caf\xe9 */",
            b"int old(void){ return __LINE__; }",
        ]
        original = ending.join(lines) + ending
        stub.write_bytes(original)
        self._ok_verify(monkeypatch)
        result = ci.import_shared_function(dst, src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        assert result["action"] == "imported-shared"
        assert stub.read_bytes() == ending + ending.join(lines[1:]) + ending

    def test_shared_stub_is_retired_only_after_its_last_target_moves(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from rebrew.metadata.functions import get_entry, record_function_identity

        src, dst = self._cfgs(tmp_path)
        write_source(
            src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION"}},
        )
        stub = dst.reversed_dir / "stub.c"
        write_source(
            stub,
            "/* ADDRESS: DST 0x401040 */\n/* ADDRESS: OTHER 0x501040 */\nint old(void){ return 0; }\n",
            metadata_fields={
                "DST.0x401040": {"kind": "FUNCTION"},
                "OTHER.0x501040": {"kind": "FUNCTION"},
            },
        )
        for module, va in [("DST", B_F1), ("OTHER", 0x501040)]:
            record_function_identity(
                tmp_path,
                module=module,
                va=va,
                file="src_DST/stub.c",
                kind="FUNCTION",
                name="old",
                symbol="_old",
                size=11,
            )
        self._ok_verify(monkeypatch)
        first = ci.import_shared_function(dst, src, B_F1, A_F1, "f1.c", 11, dst_file="stub.c")
        assert first["action"] == "imported-shared" and stub.exists()
        other = SimpleNamespace(**{**vars(dst), "target_name": "OTHER", "marker": "OTHER"})
        last = ci.import_shared_function(other, src, 0x501040, A_F1, "f1.c", 11, dst_file="stub.c")
        assert last["action"] == "imported-shared" and not stub.exists()
        for module, va in [("DST", B_F1), ("OTHER", 0x501040)]:
            assert get_entry(tmp_path, va, module)["file"] == "src/shared/f1.c"

    def test_unverified_rollback_restores_cflags_and_status(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """The rollback covers the pre-verify metadata writes: a withdrawn
        claim restores the destination's own cflags override and leaves the
        stub's earned STATUS untouched."""
        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import (
            get_entry,
            load_metadata,
            update_field,
            update_source_status,
        )

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        write_source(
            cfg_src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            cfg_dst.reversed_dir / "stub.c",
            "/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION", "size": 0}},
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
        assert res["message"].endswith(
            "(destination already annotates this VA; claim not recorded)"
        )
        assert get_entry(tmp_path, 0x401040, "DST").get("cflags") == "/G5"
        entry = load_metadata(tmp_path).get(("DST", 0x401040), {})
        assert entry.get("status") == "EXACT"

    def test_unverified_import_does_not_create_new_cflags_override(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A rejected claim writes no flags or empty metadata table."""
        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import get_entry

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        write_source(
            cfg_src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            cfg_dst.reversed_dir / "stub.c",
            "/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            metadata_fields={"DST.0x401040": {"kind": "FUNCTION", "size": 0}},
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
        assert res["message"].endswith(
            "(destination already annotates this VA; claim not recorded)"
        )
        assert "cflags" not in get_entry(tmp_path, 0x401040, "DST")
        assert (tmp_path / "rebrew-functions.toml").is_file()

    def test_failed_reverify_of_stacked_claim_applies_status(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A destination marker already on the source block keeps the verify result.

        A failed re-verify still applies STATUS and does not roll the cflags
        write back. The file text is not rewritten.
        """
        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import get_entry, update_field

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        original = SourceFixture(
            "/* ADDRESS: SRC 0x401000 */\n\n/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 1; }\n",
            {
                "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
                "DST.0x401040": {"kind": "FUNCTION", "size": 11},
            },
        )
        write_source(
            cfg_src.shared_dir / "f1.c",
            original,
            encoding="utf-8",
            metadata_fields={
                "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
                "DST.0x401040": {"kind": "FUNCTION", "size": 11},
            },
        )
        update_field(tmp_path, B_F1, "cflags", "/G5", "DST")
        applied: list[Any] = []
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
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda fixes, cfg: applied.append(fixes),
        )
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "/O2")
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["action"] == "imported-unverified"
        assert "claim not recorded" not in res["message"]
        assert applied and applied[0][0][1] == "NEAR_MATCHING"
        assert get_entry(tmp_path, B_F1, "DST").get("cflags") == "/O2"
        assert (cfg_src.shared_dir / "f1.c").read_text(encoding="utf-8") == original

    def test_failed_reverify_of_toml_claim_applies_status(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """A destination row already naming this file is not a new claim.

        The inline file has only the source marker. The destination identity
        is already in the store, so a failed re-verify still applies STATUS
        and does not roll cflags back.
        """
        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.functions import (
            get_entry,
            identity_file,
            record_function_identity,
            update_field,
        )

        cfg_src, cfg_dst = self._cfgs(tmp_path)
        path = cfg_src.shared_dir / "f1.c"
        original = SourceFixture(
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            {"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        write_source(
            path,
            original,
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
        )
        record_function_identity(
            tmp_path,
            module="DST",
            va=B_F1,
            file=identity_file(path, tmp_path),
            kind="FUNCTION",
            name="f1",
            symbol="_f1",
            size=11,
        )
        update_field(tmp_path, B_F1, "cflags", "/G5", "DST")
        applied: list[Any] = []
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
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda fixes, cfg: applied.append(fixes),
        )
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "/O2")
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f1.c", 11)
        assert res["action"] == "imported-unverified"
        assert "claim not recorded" not in res["message"]
        assert applied and applied[0][0][1] == "NEAR_MATCHING"
        assert get_entry(tmp_path, B_F1, "DST").get("cflags") == "/O2"
        assert path.read_text(encoding="utf-8") == original

    def test_same_file_stub_never_deleted(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path)
        write_source(
            cfg_src.shared_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
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
    source headers); the shared file moves WITH its tree, and compiler/compile.py
    already adds src_parent — so an absolute include only bakes one
    machine's checkout path into the metadata (guild-rebrew
    GOLDTL.0x004c75e0 carried ``/I/home/.../server.dll/...``).
    """

    def test_shared_cflags_have_no_absolute_include(self, tmp_path: Path, monkeypatch) -> None:
        rev = tmp_path / "src_SRC"
        rev.mkdir(parents=True)
        sub = rev / "Units" / "vfs"
        sub.mkdir(parents=True)
        write_source(
            sub / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "cflags": "/O1 /Gd"}},
            metadata_dir=tmp_path,
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
        cfg_dst = _dst_cfg(tmp_path, dst_rev)
        from rebrew.compiler.compile import CompareResult

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
        from rebrew.metadata.functions import load_metadata

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
        write_source(
            shared / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11}},
            metadata_dir=tmp_path,
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
        assert res["message"] == "would record DST 0x401040"
        assert (tmp_path / "rebrew-functions.toml").is_file()


class TestUnifiedTreeMarkerMove:
    """Unified tree (``shared_dir`` == ``reversed_dir``): one file holds the
    source body AND the destination's own claim.

    The copy path must never write one extracted function over such a file.
    That deletes every co-resident function and duplicates the body. The
    shared path records the destination row for the source body. It does not
    insert a marker, and it does not drop a claim from the text.
    """

    SRC_FILE = SourceFixture(
        "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n\n/* ADDRESS: SRC 0x401010 */\n\nint f2(void){ return 2; }\n",
        {
            "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
            "SRC.0x401010": {"kind": "FUNCTION", "size": 11},
        },
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

    def test_place_shared_marker_leaves_text_unchanged(self) -> None:
        """A destination VA not yet claimed stays out of the file text.

        Regression: guild-rebrew plant.c got `GOLDTL 0x4bcbd0` stacked on the
        first function while the import verified the source function. The row
        is recorded by the caller. The text is not edited.
        """
        text = SourceFixture(
            "/* ADDRESS: DST 0x4bcb80 */\n/* ADDRESS: SRC 0x401000 */\nint f1(void){ return 1; }\n\n/* ADDRESS: SRC 0x401010 */\nint f2(void){ return 2; }\n",
            {
                "DST.0x4bcb80": {"kind": "FUNCTION"},
                "SRC.0x401000": {"kind": "FUNCTION"},
                "SRC.0x401010": {"kind": "FUNCTION"},
            },
        )
        out = ci._place_shared_marker(text, "DST", 0x4BCBD0, 11, "SRC", 0x401010, superseded=False)
        assert out == text

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
        assert res["status"] == "NO_DEFINITION"
        assert res["message"] == ("source f1.c has no definition for 0x409999")

    def test_shared_import_records_retarget_on_same_file(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compiler.compile import CompareResult

        src, dst = self._cfgs(tmp_path)
        path = src.reversed_dir / "f1.c"
        write_source(
            path,
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n\n/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            encoding="utf-8",
            metadata_fields={
                "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
                "DST.0x401040": {"kind": "FUNCTION", "size": 3},
            },
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
        assert "(retargeted DST 0x401040 onto the 0x401000 body)" in res["message"]
        text = path.read_text(encoding="utf-8")
        assert "FUNCTION:" not in text
        assert "return 1" in text
        assert "return 0" in text  # the other body is not dropped
        from rebrew.metadata.functions import get_entry

        row = get_entry(tmp_path, 0x401040, "DST")
        assert row["kind"] == "FUNCTION"
        assert row["name"] == "f1"
        assert row["size"] == 11

    def test_shared_import_dry_run_announces_the_retarget(self, tmp_path: Path) -> None:
        src, dst = self._cfgs(tmp_path)
        write_source(
            src.reversed_dir / "f1.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n\n/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            encoding="utf-8",
            metadata_fields={
                "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
                "DST.0x401040": {"kind": "FUNCTION", "size": 3},
            },
        )
        before = (src.reversed_dir / "f1.c").read_text(encoding="utf-8")
        res = ci.import_shared_function(dst, src, 0x401040, 0x401000, "f1.c", 11, dry_run=True)
        assert res["action"] == "would-import-shared"
        assert res["message"] == "would retarget DST 0x401040 onto the 0x401000 body"
        assert (src.reversed_dir / "f1.c").read_text(encoding="utf-8") == before
        assert (tmp_path / "rebrew-functions.toml").is_file()

    def test_failed_move_is_reverted(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compiler.compile import CompareResult

        src, dst = self._cfgs(tmp_path)
        path = src.reversed_dir / "f1.c"
        original = SourceFixture(
            "/* ADDRESS: SRC 0x401000 */\n\nint f1(void){ return 1; }\n\n/* ADDRESS: DST 0x401040 */\n\nint f1(void){ return 0; }\n",
            {
                "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
                "DST.0x401040": {"kind": "FUNCTION", "size": 3},
            },
        )
        write_source(
            path,
            original,
            encoding="utf-8",
            metadata_fields={
                "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
                "DST.0x401040": {"kind": "FUNCTION", "size": 3},
            },
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
        applied: list[Any] = []
        monkeypatch.setattr(
            "rebrew.verify.apply_status_updates",
            lambda *a, **k: applied.append(a),
        )
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")

        res = ci.import_shared_function(dst, src, 0x401040, 0x401000, "f1.c", 11)
        assert res["action"] == "skipped-unverified"
        assert res["message"].endswith("(claim not recorded)")
        assert "destination already annotates" not in res["message"]
        assert applied == []
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
        monkeypatch.setattr("rebrew.cross_import.registry", lambda cfg: {})
        monkeypatch.setattr(
            "rebrew.cross_import.annotations_by_va",
            lambda cfg: {A_F1: ("EXACT", "Units/vfs/f1.c")},
        )

    def test_json_lists_findings_and_names_the_source_file(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import json as json_mod

        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

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
            [
                "source",
                "import-related",
                "--from",
                "SRC",
                "--json",
                "--dry-run",
                "--candidates-only",
            ],
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

        from rebrew.app.main import app as umbrella

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
            umbrella, ["source", "import-related", "--from", "SRC", "--json", "--dry-run"]
        )
        assert result.exit_code == 0, result.output
        payload = json_mod.loads(result.output)
        assert len(payload["results"]) == 2
        assert "skipped_count" not in payload


class TestVerifiedSymbolFollowsTheBlock:
    """The verified symbol is the one the SOURCE VA's block defines.

    In a multi-function file the FIRST definition is a different function,
    so a marker moved onto a later block
    compiled the file, found the first function and compared ITS bytes
    (guild-rebrew: "Size 33B vs 235B" on ErrorModule.c — the import could never
    verify).
    """

    MULTI = SourceFixture(
        "/* ADDRESS: SRC 0x401000 */\n\nint first(void){ return 1; }\n\n/* ADDRESS: SRC 0x401010 */\n\nint second(void){ return 2; }\n",
        {
            "SRC.0x401000": {"kind": "FUNCTION", "size": 11},
            "SRC.0x401010": {"kind": "FUNCTION", "size": 13},
        },
    )

    def test_name_for_va_picks_the_blocks_definition(self) -> None:
        assert ci._symbol_for_va(self.MULTI, "SRC", 0x401010, "f") == ("second", "_second")
        assert ci._symbol_for_va(self.MULTI, "SRC", 0x401000, "f") == ("first", "_first")

    def test_name_for_va_unknown_va(self) -> None:
        assert ci._symbol_for_va(self.MULTI, "SRC", 0x409999, "f") == ("f", "_f")
        assert ci._symbol_for_va(self.MULTI, "DST", 0x401010, "f") == ("f", "_f")

    def test_name_for_va_marker_only_block_borrows_below(self) -> None:
        """A marker prepended above another block owns no body of its own."""
        text = SourceFixture(
            "/* ADDRESS: DST 0x401040 */\n\n/* ADDRESS: SRC 0x401010 */\n\nint second(void){ return 2; }\n",
            {
                "DST.0x401040": {"kind": "FUNCTION", "size": 13},
                "SRC.0x401010": {"kind": "FUNCTION", "size": 13},
            },
        )
        assert ci._symbol_for_va(text, "DST", 0x401040, "f") == ("second", "_second")

    def test_shared_import_verifies_the_blocks_symbol(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.compiler.compile import CompareResult

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
            self.MULTI + "\n/* ADDRESS: DST 0x401040 */\nint old_second(void){ return 0; }\n",
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


class TestImportSize:
    """The imported marker never claims less than the matched source body.

    A stale destination registry size (an old skeleton's ``// SIZE:``) made
    the import verify only a prefix and report EXACT MATCH; the next
    ``rebrew verify --full`` then flagged SIZE_MISMATCH (guild-rebrew round
    1412 — GOLD 0x00449d80 claimed 23 bytes, the body is 25).
    """

    def test_stale_destination_size_is_raised(self) -> None:
        assert ci.import_size(23, bytes(25)) == 25

    def test_equal_sizes_are_kept(self) -> None:
        assert ci.import_size(25, bytes(25)) == 25

    def test_larger_destination_size_is_kept(self) -> None:
        """A destination body longer than the source stays its own size."""
        assert ci.import_size(40, bytes(25)) == 40

    def test_missing_source_code_keeps_destination_size(self) -> None:
        assert ci.import_size(23, None) == 23
        assert ci.import_size(23, b"") == 23


#: A body tree-sitter cannot parse (MSVC inline asm): no ``function_definition``
#: node comes out of the file, so a name read from the syntax tree is lost.
_ASM_BODY = (
    "{\n\tint d;\n\t{\n\t\tchar* p;\n\t\t__asm {\n\t\t\tmov edi, p\n"
    "\t\t\tjle short L1\n\t\t\trep stosb\n\t\tL1:\n\t\t\tadd ecx, ebx\n\t\t}\n"
    "\t}\n\td = 0;\n\treturn d;\n}\n"
)


class TestVerifiedSymbolShapes:
    """The verified symbol is the definition's name, whatever surrounds it.

    guild-rebrew ``--shared`` runs failed with ``EXTRACT_ERROR: Symbol '_type'
    not found in .obj`` (also ``_x``, ``_x2``, ``_ZEXPORT``, ``_g_6a8774``): a
    macro-qualified definition named the macro, and a body tree-sitter cannot
    parse fell back to the file's first declaration line (a struct member or
    an ``extern``).
    """

    SHAPES = [
        pytest.param(
            "int ZEXPORT deflate(strm, flush)\n    z_streamp strm;\n    int flush;\n"
            "{\n    return flush;\n}\n",
            "_deflate",
            id="kr-macro-qualified",
        ),
        pytest.param(
            "typedef struct Deed {\n\tunsigned char type;\n\tint flags;\n} Deed;\n\n"
            "int __cdecl deed_init(Deed* d)\n" + _ASM_BODY,
            "_deed_init",
            id="struct-member-before-asm-body",
        ),
        pytest.param(
            "extern char g_6a8774[];\nextern int g_774a00;\n"
            "int __cdecl fill(char* e)\n" + _ASM_BODY,
            "_fill",
            id="externs-before-asm-body",
        ),
        pytest.param(
            "int __cdecl set_type(int type)\n" + _ASM_BODY,
            "_set_type",
            id="parameter-named-type",
        ),
        pytest.param(
            "int __stdcall two_args(int a, int b)\n{\n    return a + b;\n}\n",
            "_two_args@8",
            id="stdcall-decorated",
        ),
    ]

    def _cfgs(self, tmp_path: Path) -> tuple[SimpleNamespace, SimpleNamespace]:
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
        cfg_dst = SimpleNamespace(
            **{
                **vars(cfg_src),
                "target_name": "DST",
                "marker": "DST",
                "reversed_dir": tmp_path / "src_DST",
            }
        )
        cfg_dst.reversed_dir.mkdir()
        return cfg_src, cfg_dst

    def _capture_verify(self, monkeypatch) -> dict[str, Any]:
        from rebrew.compiler.compile import CompareResult

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
        return seen

    @pytest.mark.parametrize(("body", "symbol"), SHAPES)
    def test_shared_import_verifies_the_definition(
        self, tmp_path: Path, monkeypatch, body: str, symbol: str
    ) -> None:
        cfg_src, _cfg_dst = self._cfgs(tmp_path)
        cfg_dst = SimpleNamespace(**{**vars(_cfg_dst), "reversed_dir": cfg_src.reversed_dir})
        write_source(
            cfg_src.reversed_dir / "f.c",
            body,
            metadata_dir=tmp_path,
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11, "symbol": symbol}},
        )
        seen = self._capture_verify(monkeypatch)
        res = ci.import_shared_function(cfg_dst, cfg_src, B_F1, A_F1, "f.c", 11)
        assert res["action"] == "imported-shared"
        assert seen["entry"].symbol == symbol

    @pytest.mark.parametrize(("body", "symbol"), SHAPES)
    def test_copy_import_verifies_the_definition(
        self, tmp_path: Path, monkeypatch, body: str, symbol: str
    ) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path)
        write_source(
            cfg_src.reversed_dir / "f.c",
            body,
            metadata_dir=tmp_path,
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 11, "symbol": symbol}},
        )
        seen = self._capture_verify(monkeypatch)
        res = ci.import_function(cfg_dst, cfg_src, B_F1, A_F1, "f.c", 11)
        assert res["action"] == "imported"
        assert seen["entry"].symbol == symbol


#: Destination layout for the merged-entry tests: a 62-byte function at
#: 0x401000 (``pop esi; ret`` end), ``nop; nop`` to the 16-byte boundary, and
#: the next function the discoverer folded into the same inventory entry.
_MERGED_VA = 0x401000
_MERGED_BODY = 62
_MERGED_ENTRY = 100


def _merged_pe(tail: bytes = b"\x90\x90") -> bytes:
    body = b"\x56" + b"\x33\xc0" * 29 + b"\x40\x5e\xc3"
    assert len(body) == _MERGED_BODY
    return make_pe(body + tail + b"\x81\xec\xb0\x03\x00\x00" + b"\xc3" * 0x20)


class TestMergedInventoryEntry:
    """A destination entry that merges two functions still takes a true twin.

    guild-rebrew GOLD 0x5510f0: the inventory says 1056 bytes, the function is
    62 (``pop esi; ret``, ``nop; nop``, then a function the discoverer missed).
    The twin body compiles to exactly those 62 bytes, but verifying against
    the inventory size gave SIZE_MISMATCH and reverted the import (104 of 181
    GOLD twins in one run).
    """

    def _cfgs(self, tmp_path: Path, pe: bytes) -> tuple[SimpleNamespace, SimpleNamespace]:
        rev = tmp_path / "src"
        rev.mkdir()
        dst_bin = tmp_path / "b.exe"
        dst_bin.write_bytes(pe)
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
        cfg_dst = SimpleNamespace(
            **{**vars(cfg_src), "target_name": "DST", "marker": "DST", "target_binary": dst_bin}
        )
        write_source(
            rev / "f.c",
            "/* ADDRESS: SRC 0x401000 */\n\nint f(void){ return 1; }\n",
            encoding="utf-8",
            metadata_fields={"SRC.0x401000": {"kind": "FUNCTION", "size": 62}},
            metadata_dir=tmp_path,
        )
        return cfg_src, cfg_dst

    def _verify(
        self, monkeypatch, *, prefix_diffs: int = 0, obj_size: int = _MERGED_BODY
    ) -> list[int]:
        """Fake verify: SIZE_MISMATCH at the entry size, RELOC at the body size."""
        from rebrew.compiler.compile import CompareResult

        sizes: list[int] = []

        def fake_verify(entry, cfg, cache=None, **kw):
            sizes.append(entry.size)
            if entry.size == obj_size:
                return CompareResult(
                    matched=True,
                    status="RELOC",
                    match_percent=100.0,
                    delta=0,
                    obj_bytes=b"x" * obj_size,
                    reloc_offsets=[4],
                    message="RELOC-NORM MATCH (1 relocs)",
                )
            common = min(obj_size, entry.size)
            return CompareResult(
                matched=False,
                status="SIZE_MISMATCH",
                match_percent=50.0,
                delta=abs(entry.size - obj_size) + prefix_diffs,
                obj_bytes=b"x" * common,
                reloc_offsets=[4],
                message=f"SIZE_MISMATCH: Size {obj_size}B vs {entry.size}B",
                match_count=common - prefix_diffs,
                full_obj_size=obj_size,
                full_obj_bytes=b"x" * obj_size,
            )

        monkeypatch.setattr("rebrew.verify.verify_entry", fake_verify)
        monkeypatch.setattr("rebrew.verify.apply_status_updates", lambda *a, **k: None)
        monkeypatch.setattr("rebrew.cross_import._source_flags", lambda *a, **k: "")
        return sizes

    def _dst_sizes(self, cfg_dst: SimpleNamespace, path: Path) -> tuple[int, Any]:
        from rebrew.metadata.bindings import read_source_bindings
        from rebrew.metadata.functions import get_entry

        text = path.read_text(encoding="utf-8")
        assert "FUNCTION:" not in text
        assert "SIZE:" not in text
        seen = [
            a.size
            for a in read_source_bindings(
                path, target_name="DST", metadata_dir=cfg_dst.metadata_dir
            )
            if a.va == _MERGED_VA
        ]
        recorded = get_entry(cfg_dst.metadata_dir, _MERGED_VA, "DST").get("size")
        return seen[0], recorded

    def test_merged_entry_sized_to_the_body(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe())
        sizes = self._verify(monkeypatch)
        res = ci.import_shared_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert res["action"] == "imported-shared"
        assert res["status"] == "RELOC"
        assert "destination inventory entry merges functions" in res["message"]
        assert "62-byte body" in res["message"]
        assert sizes == [_MERGED_ENTRY, _MERGED_BODY]
        assert self._dst_sizes(cfg_dst, cfg_src.reversed_dir / "f.c") == (62, 62)

    def test_padded_signature_passes_default_gate_then_verifies_the_body(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe())
        code = ci.target_bytes_by_va(cfg_dst, {_MERGED_VA: 64})[_MERGED_VA]
        src_sig = ci.signature_for(cfg_dst, code[:_MERGED_BODY], A_F1)
        dst_sig = ci.signature_for(cfg_dst, code, _MERGED_VA)
        assert src_sig is not None and dst_sig is not None
        assert ci.cross_match({_MERGED_VA: dst_sig}, {A_F1: src_sig}) == {_MERGED_VA: (A_F1, 100.0)}
        sizes = self._verify(monkeypatch)
        res = ci.import_shared_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", 64)
        assert res["action"] == "imported-shared" and res["status"] == "RELOC"
        assert sizes == [64, _MERGED_BODY]
        assert self._dst_sizes(cfg_dst, cfg_src.reversed_dir / "f.c") == (62, 62)

    def test_int3_padding_accepted(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe(b"\xcc\xcc"))
        self._verify(monkeypatch)
        res = ci.import_shared_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert res["action"] == "imported-shared"

    @pytest.mark.parametrize("shared", [True, False])
    def test_body_retry_records_its_own_comparison_inputs(
        self, tmp_path: Path, monkeypatch, shared: bool
    ) -> None:
        import hashlib

        import rebrew.verify as verify
        from rebrew.formats.binary_loader import extract_raw_bytes
        from rebrew.metadata.functions import get_entry

        src, dst = self._cfgs(tmp_path, _merged_pe())
        apply_updates = verify.apply_status_updates
        self._verify(monkeypatch)
        original_verify = verify.verify_entry

        def measured(entry, cfg, **kw):
            result = original_verify(entry, cfg, **kw)
            reference = extract_raw_bytes(cfg.target_binary, entry.va, entry.size)
            entry.comparison_inputs = {
                "reference_size": str(entry.size),
                "reference_hash": hashlib.sha256(reference).hexdigest(),
                "input_hash": hashlib.sha256(reference).hexdigest(),
            }
            return result

        monkeypatch.setattr(verify, "verify_entry", measured)
        monkeypatch.setattr(verify, "apply_status_updates", apply_updates)
        if shared:
            result = ci.import_shared_function(dst, src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        else:
            dst.reversed_dir = tmp_path / "destination"
            dst.reversed_dir.mkdir()
            result = ci.import_function(dst, src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert result["status"] == "RELOC"
        row = get_entry(tmp_path, _MERGED_VA, "DST")
        assert row["size"] == _MERGED_BODY
        assert row["verification"]["reference_size"] == str(_MERGED_BODY)
        reference = extract_raw_bytes(dst.target_binary, _MERGED_VA, _MERGED_BODY)
        assert row["verification"]["reference_hash"] == hashlib.sha256(reference).hexdigest()

    @pytest.mark.parametrize("shared", [True, False])
    def test_verified_import_replaces_wrong_identity_name(
        self, tmp_path: Path, monkeypatch, shared: bool
    ) -> None:
        from rebrew.metadata.functions import get_entry, record_function_identity

        src, dst = self._cfgs(tmp_path, _merged_pe())
        identity_file = "src/f.c"
        if not shared:
            dst.reversed_dir = tmp_path / "destination"
            dst.reversed_dir.mkdir()
            write_source(
                dst.reversed_dir / "f.c",
                "/* ADDRESS: DST 0x401000 */\nint other(void){return 0;}\n",
                metadata_fields={"DST.0x401000": {"kind": "FUNCTION"}},
            )
            identity_file = "destination/f.c"
        record_function_identity(
            tmp_path,
            module="DST",
            va=_MERGED_VA,
            file=identity_file,
            kind="FUNCTION",
            name="other",
            symbol="_other",
            size=_MERGED_ENTRY,
        )
        self._verify(monkeypatch)
        importer = ci.import_shared_function if shared else ci.import_function
        result = importer(dst, src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY, dst_file="f.c")
        assert result["status"] == "RELOC"
        row = get_entry(tmp_path, _MERGED_VA, "DST")
        assert row["name"] == "f"
        assert row["symbol"] == "_f"

    def test_shared_import_uses_selected_function_flags(self, tmp_path: Path, monkeypatch) -> None:
        import rebrew.verify as verify
        from rebrew.metadata.functions import record_function_identity

        src, dst = self._cfgs(tmp_path, _merged_pe())
        path = src.reversed_dir / "f.c"
        path.write_text("int first(void){return 0;}\nint selected(void){return 1;}\n")
        for module, va, name, flags in [
            ("SRC", A_F1, "first", "/O1 /DFIRST"),
            ("SRC", A_F2, "selected", "/O2 /DSELECTED"),
            ("OTHER", A_F2, "selected", "/O1 /DFOREIGN"),
        ]:
            record_function_identity(
                tmp_path,
                module=module,
                va=va,
                file="src/f.c",
                kind="FUNCTION",
                name=name,
                symbol="_" + name,
                size=62,
                cflags=flags,
            )
        # Keep the real flag resolver; only compilation is substituted.
        from rebrew.compiler.compile import CompareResult

        observed = []

        def measured(entry, cfg, **kw):
            observed.append(entry.cflags)
            return CompareResult(
                matched=True,
                status="EXACT",
                match_percent=100.0,
                delta=0,
                obj_bytes=b"x" * entry.size,
                reloc_offsets=[],
                message="EXACT MATCH",
            )

        monkeypatch.setattr(verify, "verify_entry", measured)
        result = ci.import_shared_function(dst, src, _MERGED_VA, A_F2, "f.c", _MERGED_BODY)
        assert result["status"] == "EXACT"
        assert observed == ["/O2 /DSELECTED"]

    def test_failed_body_retry_keeps_original_comparison_inputs(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import rebrew.verify as verify
        from rebrew.compiler.compile import CompareResult
        from rebrew.metadata.bindings import SourceBinding

        _src, dst = self._cfgs(tmp_path, _merged_pe())
        self._verify(monkeypatch)
        first_verify = verify.verify_entry

        def measured(entry, cfg, **kw):
            entry.comparison_inputs = {"reference_size": str(entry.size)}
            if entry.size == _MERGED_BODY:
                return CompareResult(
                    matched=False,
                    status="NEAR_MATCHING",
                    match_percent=90.0,
                    delta=1,
                    obj_bytes=b"x" * entry.size,
                    reloc_offsets=[],
                    message="NEAR",
                )
            return first_verify(entry, cfg, **kw)

        monkeypatch.setattr(verify, "verify_entry", measured)
        entry = SourceBinding(
            va=_MERGED_VA,
            name="f",
            symbol="_f",
            size=_MERGED_ENTRY,
            filepath="f.c",
            kind="FUNCTION",
            module="DST",
        )
        result, body = ci._verify_import(entry, dst, cache=None, name_to_va=None)
        assert not result.matched and body is None
        assert entry.size == _MERGED_ENTRY
        assert entry.comparison_inputs == {"reference_size": str(_MERGED_ENTRY)}

    def test_failed_import_keeps_existing_identity_name(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.metadata.functions import get_entry, record_function_identity

        src, dst = self._cfgs(tmp_path, _merged_pe())
        record_function_identity(
            tmp_path,
            module="DST",
            va=_MERGED_VA,
            file="src/f.c",
            kind="FUNCTION",
            name="other",
            symbol="_other",
            size=_MERGED_ENTRY,
        )
        self._verify(monkeypatch, prefix_diffs=1)
        result = ci.import_shared_function(
            dst, src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY, dst_file="f.c"
        )
        assert result["status"] != "RELOC"
        row = get_entry(tmp_path, _MERGED_VA, "DST")
        assert row["name"] == "other" and row["symbol"] == "_other"

    def test_inherited_flags_remove_stale_destination_override(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from rebrew.metadata.functions import get_entry, record_function_identity

        src, dst = self._cfgs(tmp_path, _merged_pe())
        dst.cflags = "/O2 /Gd"
        record_function_identity(
            tmp_path,
            module="DST",
            va=_MERGED_VA,
            file="src/f.c",
            kind="FUNCTION",
            name="f",
            symbol="_f",
            size=_MERGED_ENTRY,
            cflags="/O1 /DOLD",
        )
        self._verify(monkeypatch)
        monkeypatch.setattr(ci, "_source_flags", lambda *a, **k: "/O2 /Gd")
        result = ci.import_shared_function(
            dst, src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY, dst_file="f.c"
        )
        assert result["status"] == "RELOC"
        assert "cflags" not in get_entry(tmp_path, _MERGED_VA, "DST")

    def test_failed_managed_retarget_preserves_entire_prior_record(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        import rebrew.verify as verify
        from rebrew.metadata.functions import (
            get_entry,
            record_function_identity,
            update_field,
            update_statuses_batch,
        )

        src, dst = self._cfgs(tmp_path, _merged_pe())
        record_function_identity(
            tmp_path,
            module="DST",
            va=_MERGED_VA,
            file="src/f.c",
            kind="FUNCTION",
            name="other",
            symbol="_other",
            size=_MERGED_ENTRY,
            cflags="/O1 /DOLD",
        )
        update_field(tmp_path, _MERGED_VA, "note", "keep prior evidence", "DST")
        update_statuses_batch(
            tmp_path, [{"module": "DST", "va": _MERGED_VA, "new_status": "RELOC"}]
        )
        prior = get_entry(tmp_path, _MERGED_VA, "DST")
        source = (src.reversed_dir / "f.c").read_bytes()
        preview = ci.import_shared_function(
            dst, src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY, dst_file="f.c", dry_run=True
        )
        assert preview["message"].startswith("would retarget DST")
        assert get_entry(tmp_path, _MERGED_VA, "DST") == prior
        apply_updates = verify.apply_status_updates
        self._verify(monkeypatch, prefix_diffs=1)
        monkeypatch.setattr(verify, "apply_status_updates", apply_updates)
        monkeypatch.setattr(ci, "_source_flags", lambda *a, **k: "/O2 /Gd")
        result = ci.import_shared_function(
            dst, src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY, dst_file="f.c"
        )
        assert result["action"] == "skipped-unverified"
        assert get_entry(tmp_path, _MERGED_VA, "DST") == prior
        assert (src.reversed_dir / "f.c").read_bytes() == source

    def test_aligned_body_needs_no_padding(self, tmp_path: Path, monkeypatch) -> None:
        """A body ending on the boundary: the next function starts right there."""
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe(b"\x55\x8b"))
        self._verify(monkeypatch, obj_size=64)
        res = ci.import_shared_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert res["action"] == "imported-shared"
        assert self._dst_sizes(cfg_dst, cfg_src.reversed_dir / "f.c") == (64, 64)

    def test_code_after_the_body_rejected(self, tmp_path: Path, monkeypatch) -> None:
        """No padding at the boundary: the entry's tail may be this function's code."""
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe(b"\x55\x8b"))
        sizes = self._verify(monkeypatch)
        res = ci.import_shared_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert res["action"] == "skipped-unverified"
        assert res["status"] == "SIZE_MISMATCH"
        assert "(claim not recorded)" in res["message"]
        assert "destination already annotates" not in res["message"]
        assert sizes == [_MERGED_ENTRY]
        assert "DST" not in (cfg_src.reversed_dir / "f.c").read_text(encoding="utf-8")

    def test_prefix_diffs_rejected(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe())
        sizes = self._verify(monkeypatch, prefix_diffs=1)
        res = ci.import_shared_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert res["action"] == "skipped-unverified"
        assert sizes == [_MERGED_ENTRY]

    def test_longer_body_rejected(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe())
        sizes = self._verify(monkeypatch, obj_size=_MERGED_ENTRY + 16)
        res = ci.import_shared_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert res["action"] == "skipped-unverified"
        assert sizes == [_MERGED_ENTRY]

    def test_copy_import_sized_to_the_body(self, tmp_path: Path, monkeypatch) -> None:
        cfg_src, cfg_dst = self._cfgs(tmp_path, _merged_pe())
        cfg_dst.reversed_dir = tmp_path / "src_DST"
        cfg_dst.reversed_dir.mkdir()
        sizes = self._verify(monkeypatch)
        res = ci.import_function(cfg_dst, cfg_src, _MERGED_VA, A_F1, "f.c", _MERGED_ENTRY)
        assert res["action"] == "imported"
        assert "62-byte body" in res["message"]
        assert sizes == [_MERGED_ENTRY, _MERGED_BODY]
        assert self._dst_sizes(cfg_dst, cfg_dst.reversed_dir / "f.c") == (62, 62)


class TestSourceVA:
    """An evidenced donor disambiguates twins without bypassing matching."""

    def _setup(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        TestCLI()._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        from rebrew.config import load_config

        source = load_config(tmp_path, target="SRC").reversed_dir
        source.mkdir(parents=True, exist_ok=True)
        for name, va in [("f1.c", A_F1), ("f2.c", A_F2)]:
            write_source(
                source / name,
                f"/* ADDRESS: SRC 0x{va:x} */\nint f(void) {{ return 0; }}\n",
                metadata_fields={f"SRC.0x{va:x}": {"kind": "FUNCTION"}},
            )
        monkeypatch.setattr(ci, "matched_source_bytes", lambda cfg: {A_F1: F1, A_F2: F1})
        monkeypatch.setattr(ci, "unmatched_dest_bytes", lambda cfg, only_va=None: {B_F1: F1})
        monkeypatch.setattr(ci, "registry", lambda cfg: {})
        monkeypatch.setattr(ci, "sizeless_dest_vas", lambda cfg: ({}, []))
        monkeypatch.setattr(
            ci,
            "annotations_by_va",
            lambda cfg: {A_F1: ("EXACT", "f1.c"), A_F2: ("RELOC", "f2.c")},
        )

        def preview(*args: Any, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["dry_run"] is True
            return {
                "dst_va": f"0x{args[2]:08x}",
                "src_va": f"0x{args[3]:08x}",
                "score": None,
                "action": "would-import",
                "status": "",
                "filepath": args[4],
                "message": "",
            }

        monkeypatch.setattr(ci, "import_function", preview)
        monkeypatch.setattr(ci, "import_shared_function", preview)

    @pytest.mark.parametrize("shared", [False, True])
    @pytest.mark.parametrize("donor", [A_F1, A_F2])
    def test_selects_evidenced_twin_at_default_gap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shared: bool, donor: int
    ) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

        self._setup(tmp_path, monkeypatch)
        args = ["source", "import-related", "--from", "SRC", "--dry-run", "--json"]
        if shared:
            args.append("--shared")
        runner = CliRunner()
        ambiguous = runner.invoke(umbrella, args)
        assert ambiguous.exit_code == 0, ambiguous.output
        assert json.loads(ambiguous.output)["results"][0]["action"] == "skipped"
        selected = runner.invoke(umbrella, [*args, "--source-va", hex(donor)])
        assert selected.exit_code == 0, selected.output
        row = json.loads(selected.output)["results"][0]
        assert row["src_va"] == f"0x{donor:08x}"
        assert row["score"] == 100.0
        assert row["action"] == "would-import"
        assert row["src_file"] == ("f1.c" if donor == A_F1 else "f2.c")

    @pytest.mark.parametrize("source_va", ["bad-address", "0x409999"])
    def test_invalid_or_unmatched_donor_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_va: str
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(
            umbrella,
            [
                "source",
                "import-related",
                "--from",
                "SRC",
                "--source-va",
                source_va,
                "--dry-run",
                "--json",
            ],
        )
        assert result.exit_code == 2, result.output
        assert "error" in result.output

    def test_explicit_donor_still_obeys_score_threshold(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import json

        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

        self._setup(tmp_path, monkeypatch)
        result = CliRunner().invoke(
            umbrella,
            [
                "source",
                "import-related",
                "--from",
                "SRC",
                "--source-va",
                hex(A_F1),
                "--min-score",
                "101",
                "--dry-run",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["results"][0]["action"] == "skipped"
