"""Unit tests for rebrew.xrefs — the cross-reference explorer CLI.

Builds the same synthetic PE as ``test_analysis`` (direct call, ``push
imm32``, and an IAT call whose slot VA is learned from a probe build) and
drives the CLI through ``CliRunner``.

Standalone typer apps are invoked as groups, so options (``--json``,
``--kind``) are passed *before* the positional arguments — the same
convention as ``test_imports.py``.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe  # noqa: E402

from rebrew.xrefs import app  # noqa: E402

TEXT_VA = 0x401000
IMAGE_BASE = 0x400000


def _build_code() -> tuple[bytes, dict[str, int]]:
    """Assemble the probe code; return ``(code_bytes, symbols)``.

    Layout (VAs are relative to ``TEXT_VA``), each reference target patched
    after the layout is known:
      0x000  e8 rel32      call <lea insn>     (direct call)
      0x005  68 imm32      push <hello>        ("Hello World")
      0x00a  b8 imm32      mov eax, <game>     ("Game Boy")
      0x00f  ff 15 imm32   call [iat_slot]     (IAT call, fixed by caller)
      0x015  8d 05 imm32   lea eax, [<wide>]   ("Wide" utf16)
      0x01b  8b 05 imm32   mov eax, [<wide>]   (data read)
      0x021  83 25 imm32 00 and [<hello>+4], 0 (generic mem)
      0x028  c3            ret
      <blob> "Hello World\\0" "Game Boys\\0" "\\0" "W\\0i\\0d\\0e\\0\\0\\0"
    """
    refs: dict[str, int] = {}

    def emit(raw: bytes, name: str | None = None) -> None:
        if name is not None:
            refs[name] = TEXT_VA + len(pre)
        pre.extend(raw)

    pre = bytearray()
    emit(b"\xe8" + b"\x00\x00\x00\x00", "call")  # rel patched below
    emit(b"\x68" + b"\x00\x00\x00\x00", "push")
    emit(b"\xb8" + b"\x00\x00\x00\x00", "mov")
    emit(b"\xff\x15" + b"\x00\x00\x00\x00", "iat_call")
    emit(b"\x8d\x05" + b"\x00\x00\x00\x00", "lea")
    emit(b"\x8b\x05" + b"\x00\x00\x00\x00", "mov_mem")
    emit(b"\x83\x25" + b"\x00\x00\x00\x00" + b"\x00", "and_mem")
    emit(b"\xc3")

    blob_start = TEXT_VA + len(pre)
    hello = blob_start
    game = blob_start + 12
    wide = blob_start + 23
    blob = b"Hello World\x00" + b"Game Boys\x00" + b"\x00" + b"W\x00i\x00d\x00e\x00\x00\x00"

    def patch(at: int, value: int, imm_off: int = 1) -> None:
        pre[at + imm_off : at + imm_off + 4] = struct.pack("<I", value)

    # 1-byte opcodes: imm starts at +1.  Two-byte opcodes (opcode+modrm):
    # imm starts at +2.
    patch(refs["call"] - TEXT_VA, refs["lea"] - (refs["call"] + 5), imm_off=1)
    patch(refs["push"] - TEXT_VA, hello, imm_off=1)
    patch(refs["mov"] - TEXT_VA, game, imm_off=1)
    patch(refs["lea"] - TEXT_VA, wide, imm_off=2)
    patch(refs["mov_mem"] - TEXT_VA, wide, imm_off=2)
    patch(refs["and_mem"] - TEXT_VA, hello, imm_off=2)

    syms = {
        **refs,
        "hello": hello,
        "game": game,
        "wide": wide,
    }
    return bytes(pre) + blob, syms


def _resolve_iat_slot(pe_bytes: bytes) -> int:
    """Find the IAT slot VA for ``HeapCreate`` in a built probe PE."""
    import lief

    pe = lief.PE.parse(bytes(pe_bytes))
    for imp in pe.imports:
        for entry in imp.entries:
            if entry.name == "HeapCreate":
                return IMAGE_BASE + entry.iat_address
    raise AssertionError("HeapCreate import not found")


def _make_binary(tmp_path: Path) -> tuple[Path, dict[str, int]]:
    """Build the probe PE on disk; return ``(path, symbols)``."""
    code, syms = _build_code()
    proto = make_pe(code, imports=[("KERNEL32.dll", ["HeapCreate"])])
    slot = _resolve_iat_slot(proto)
    code2 = bytearray(code)
    code2[0x0F + 2 : 0x0F + 6] = struct.pack("<I", slot)
    final = make_pe(bytes(code2), imports=[("KERNEL32.dll", ["HeapCreate"])])
    path = tmp_path / "probe.exe"
    path.write_bytes(final)
    return path, {**syms, "iat_slot": slot}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestXrefsCli:
    def test_direct_call_xref(self, tmp_path: Path) -> None:
        path, syms = _make_binary(tmp_path)
        call_dst = syms["call"] + 5 + 0x10
        result = CliRunner().invoke(app, ["--json", str(path), f"0x{call_dst:X}"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["target"] == call_dst
        assert payload["import_name"] is None
        assert payload["count"] == 1
        ref = payload["refs"][0]
        assert ref["kind"] == "call"
        assert ref["from_va"] == syms["call"]
        assert ref["instruction"].startswith("call ")

    def test_push_xref(self, tmp_path: Path) -> None:
        path, syms = _make_binary(tmp_path)
        result = CliRunner().invoke(app, ["--json", str(path), f"0x{syms['hello']:X}"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        pushes = [r for r in payload["refs"] if r["kind"] == "push"]
        assert len(pushes) == 1
        assert pushes[0]["from_va"] == syms["push"]
        assert pushes[0]["instruction"].startswith("push ")
        # Terminal table lists the referencing instructions with hex from_va.
        terminal = CliRunner().invoke(app, [str(path), f"0x{syms['hello']:X}"])
        assert terminal.exit_code == 0
        assert "0x00401005" in terminal.output  # the push instruction's own VA
        assert "and_mem" in terminal.output

    def test_iat_call_resolves_import(self, tmp_path: Path) -> None:
        path, syms = _make_binary(tmp_path)
        result = CliRunner().invoke(app, ["--json", str(path), f"0x{syms['iat_slot']:X}"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["import_name"] == "HeapCreate"
        assert payload["count"] == 1
        assert payload["refs"][0]["kind"] == "iat_call"
        assert payload["refs"][0]["from_va"] == syms["iat_call"]
        # The import note is prominent in terminal mode too.
        terminal = CliRunner().invoke(app, [str(path), f"0x{syms['iat_slot']:X}"])
        assert terminal.exit_code == 0
        assert "target is import: HeapCreate" in terminal.output

    def test_kind_filter(self, tmp_path: Path) -> None:
        path, syms = _make_binary(tmp_path)
        filtered = CliRunner().invoke(
            app, ["--kind", "push", "--json", str(path), f"0x{syms['hello']:X}"]
        )
        assert filtered.exit_code == 0
        payload = json.loads(filtered.output)
        assert {r["kind"] for r in payload["refs"]} == {"push"}
        # Repeatable: both kinds pass through together.
        both = CliRunner().invoke(
            app,
            ["--kind", "push", "--kind", "and_mem", "--json", str(path), f"0x{syms['hello']:X}"],
        )
        assert both.exit_code == 0
        assert {r["kind"] for r in json.loads(both.output)["refs"]} == {"push", "and_mem"}
        # A kind with no hits filters everything out (still exit 0).
        none = CliRunner().invoke(app, ["--kind", "mov", str(path), f"0x{syms['hello']:X}"])
        assert none.exit_code == 0
        assert "no references to" in none.output
        # Without a filter both kinds pointing at hello are reported.
        unfiltered = CliRunner().invoke(app, ["--json", str(path), f"0x{syms['hello']:X}"])
        assert unfiltered.exit_code == 0
        kinds = {r["kind"] for r in json.loads(unfiltered.output)["refs"]}
        assert kinds == {"push", "and_mem"}

    def test_empty_result_exits_ok(self, tmp_path: Path) -> None:
        path, _ = _make_binary(tmp_path)
        target = IMAGE_BASE + 0x9000  # outside the binary: never referenced
        result = CliRunner().invoke(app, [str(path), f"0x{target:X}"])
        assert result.exit_code == 0
        assert "no references to" in result.output
        result = CliRunner().invoke(app, ["--json", str(path), f"0x{target:X}"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["count"] == 0
        assert payload["refs"] == []
        assert payload["import_name"] is None

    def test_json_shape(self, tmp_path: Path) -> None:
        path, syms = _make_binary(tmp_path)
        call_dst = syms["call"] + 5 + 0x10
        result = CliRunner().invoke(app, ["--json", str(path), f"0x{call_dst:X}"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert set(payload) == {"target", "import_name", "count", "refs"}
        assert isinstance(payload["target"], int)
        assert isinstance(payload["count"], int)
        assert set(payload["refs"][0]) == {"kind", "from_va", "instruction"}
        assert isinstance(payload["refs"][0]["from_va"], int)
        assert isinstance(payload["refs"][0]["instruction"], str)

    def test_cli_invocation(self, tmp_path: Path) -> None:
        path, _ = _make_binary(tmp_path)
        result = CliRunner().invoke(app, [str(path), "0x401000"])
        assert result.exit_code == 0
        assert "no references to 0x00401000" in result.output

    def test_bad_va_exits_error(self, tmp_path: Path) -> None:
        path, _ = _make_binary(tmp_path)
        result = CliRunner().invoke(app, [str(path), "not-an-address"])
        assert result.exit_code != 0
        assert "Invalid hex VA" in result.output
