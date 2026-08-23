"""Tests for rebrew describe — per-function recon dossier.

Builds a synthetic PE (via ``bin_util.make_pe``) whose .text contains a probe
function with a direct call, a string push, a string mov, and an IAT call,
plus a caller function that calls the probe.  The temp rebrew project carries
annotations and a function list so the dossier can resolve names.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import append_pe_section, make_pe

from rebrew.analysis import section_range
from rebrew.binary_loader import load_binary
from rebrew.describe import app

IMAGE_BASE = 0x400000
TEXT_VA = 0x1000
PROBE_VA = IMAGE_BASE + TEXT_VA  # 0x00401000

_TOML = """\
[project]
default_target = "game"

[targets.game]
binary = "game.exe"
marker = "GAME"
reversed_dir = "src"
function_list = "src/functions.txt"

[compiler]
profile = "msvc6"
command = "cl"
cflags = "/O2"
"""

_PROBE_C = """\
// FUNCTION: GAME 0x00401000
// STATUS: EXACT
// SIZE: 22
int my_func(void) { return 1; }

// FUNCTION: GAME 0x00401034
// STATUS: STUB
// SIZE: 4
int helper_fn(void) { return 0; }
"""

_FUNCTIONS_TXT = """\
0x00401000 22 my_func
0x00401016 8 caller_fn
0x00401034 4 helper_fn
"""


def _build_code() -> tuple[bytes, dict[str, int]]:
    """Assemble the probe .text: probe fn, caller fn, string blob, callee stub.

    Layout (offsets relative to PROBE_VA), reference targets patched once the
    layout is known:
      0x000  e8 rel32     call <stub>         (direct call)
      0x005  68 imm32     push <hello>        (string)
      0x00a  b8 imm32     mov eax, <game>     (string)
      0x00f  ff 15 imm32  call [iat_slot]     (IAT call; slot patched by caller)
      0x015  c3           ret                 — probe body ends (size 0x16)
      0x016  90           nop
      0x017  e8 rel32     call <probe>        (caller → probe)
      0x01c  90           nop
      0x01d  c3           ret                 — caller ends (size 0x08)
      0x01e  "Hello World\\0" "Game Boys\\0"  — 22-byte string blob
      0x034  c3 x4                            — helper_fn stub
    """
    refs: dict[str, int] = {}

    def emit(raw: bytes, name: str | None = None) -> None:
        if name is not None:
            refs[name] = PROBE_VA + len(pre)
        pre.extend(raw)

    pre = bytearray()
    emit(b"\xe8\x00\x00\x00\x00", "call")
    emit(b"\x68\x00\x00\x00\x00", "push")
    emit(b"\xb8\x00\x00\x00\x00", "mov")
    emit(b"\xff\x15\x00\x00\x00\x00", "iat_call")
    emit(b"\xc3")
    emit(b"\x90", "caller")
    emit(b"\xe8\x00\x00\x00\x00", "caller_call")
    emit(b"\x90")
    emit(b"\xc3")
    blob_start = PROBE_VA + len(pre)
    hello = blob_start
    game = blob_start + 12
    emit(b"Hello World\x00" + b"Game Boys\x00")
    stub = PROBE_VA + len(pre)
    emit(b"\xc3" * 4)

    def patch(at: int, value: int) -> None:
        pre[at + 1 : at + 5] = struct.pack("<I", value & 0xFFFFFFFF)

    patch(refs["call"] - PROBE_VA, stub - (refs["call"] + 5))
    patch(refs["push"] - PROBE_VA, hello)
    patch(refs["mov"] - PROBE_VA, game)
    patch(refs["caller_call"] - PROBE_VA, PROBE_VA - (refs["caller_call"] + 5))

    syms = {
        "probe": PROBE_VA,
        "caller": refs["caller"],
        "caller_call": refs["caller_call"],
        "iat_call": refs["iat_call"],
        "hello": hello,
        "game": game,
        "stub": stub,
    }
    return bytes(pre), syms


def _resolve_iat_slot(pe_bytes: bytes) -> int:
    """Find the IAT slot VA for ``HeapCreate`` in a built probe PE."""
    import lief

    pe = lief.PE.parse(bytes(pe_bytes))
    for imp in pe.imports:
        for entry in imp.entries:
            if entry.name == "HeapCreate":
                return IMAGE_BASE + int(entry.iat_address)
    raise AssertionError("HeapCreate import not found")


def _make_project(
    tmp_path: Path,
    *,
    source: str = _PROBE_C,
    functions: str = _FUNCTIONS_TXT,
) -> None:
    """Write a minimal rebrew project (toml + sources + function list)."""
    (tmp_path / "rebrew-project.toml").write_text(_TOML, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    (src / "game.c").write_text(source, encoding="utf-8")
    (src / "functions.txt").write_text(functions, encoding="utf-8")


def _make_binary(tmp_path: Path) -> int:
    """Write game.exe with the probe code; return the IAT slot VA."""
    code, syms = _build_code()
    proto = make_pe(code, imports=[("KERNEL32.dll", ["HeapCreate"])])
    slot = _resolve_iat_slot(proto)
    code2 = bytearray(code)
    off = syms["iat_call"] - PROBE_VA
    code2[off + 2 : off + 6] = struct.pack("<I", slot)
    path = tmp_path / "game.exe"
    path.write_bytes(make_pe(bytes(code2), imports=[("KERNEL32.dll", ["HeapCreate"])]))
    return slot


class TestDescribeCli:
    """End-to-end ``rebrew describe`` over a synthetic project."""

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> Any:
        """Build the project + binary and run ``rebrew describe`` from tmp_path."""
        _make_project(tmp_path)
        _make_binary(tmp_path)
        monkeypatch.chdir(tmp_path)
        return CliRunner().invoke(app, list(args))

    def test_known_function_dossier(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Callers/callees/strings/imports all appear for the annotated probe."""
        result = self._invoke(tmp_path, monkeypatch, "--json", f"0x{PROBE_VA:x}")
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["va"] == PROBE_VA
        assert data["name"] == "my_func"
        assert data["status"] == "EXACT"
        assert data["size"] == 22
        assert data["cflags"] is None
        assert data["callers"] == [{"from_va": 0x401017, "name": "caller_fn"}]
        assert {"to_va": 0x401034, "name": "helper_fn", "kind": "call"} in data["callees"]
        iat = data["imports"][0]
        assert {"to_va": iat["slot"], "name": "HeapCreate", "kind": "iat_call"} in data["callees"]
        assert {"va": 0x40101E, "text": "Hello World"} in data["strings"]
        assert {"va": 0x40102A, "text": "Game Boys"} in data["strings"]
        assert data["globals"] == []
        assert iat == {"slot": iat["slot"], "name": "HeapCreate"}

    def test_unannotated_fallback_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A VA without a source annotation falls back to fcn_%08x / unknown size."""
        result = self._invoke(tmp_path, monkeypatch, "--json", "0x401016")
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["name"] == "fcn_00401016"
        assert data["status"] is None
        assert data["size"] is None
        # The dossier still resolves the caller's callee via annotations.
        assert {"to_va": PROBE_VA, "name": "my_func", "kind": "call"} in data["callees"]

    def test_unannotated_terminal_unknown_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Terminal output reports 'unknown' size for an unannotated function."""
        result = self._invoke(tmp_path, monkeypatch, "0x401016")
        assert result.exit_code == 0, result.output
        assert "fcn_00401016" in result.output
        assert "unknown" in result.output

    def test_va_outside_binary_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A VA outside the binary image exits non-zero with an error."""
        result = self._invoke(tmp_path, monkeypatch, "--json", "0x99999999")
        assert result.exit_code != 0
        assert "outside" in result.output

    def test_json_shape(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--json emits exactly the documented dossier keys and types."""
        result = self._invoke(tmp_path, monkeypatch, "--json", f"0x{PROBE_VA:x}")
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert set(data.keys()) == {
            "va",
            "name",
            "status",
            "size",
            "cflags",
            "pattern",
            "convention",
            "callers",
            "callees",
            "strings",
            "globals",
            "imports",
        }
        assert isinstance(data["va"], int)
        assert isinstance(data["name"], str)
        assert data["status"] is None or isinstance(data["status"], str)
        assert data["size"] is None or isinstance(data["size"], int)
        assert data["cflags"] is None or isinstance(data["cflags"], str)
        for entry in data["callers"]:
            assert set(entry.keys()) == {"from_va", "name"}
            assert isinstance(entry["from_va"], int)
        for entry in data["callees"]:
            assert set(entry.keys()) == {"to_va", "name", "kind"}
        for entry in data["strings"]:
            assert set(entry.keys()) == {"va", "text"}
        for entry in data["globals"]:
            assert set(entry.keys()) == {"va", "kind"}
        for entry in data["imports"]:
            assert set(entry.keys()) == {"slot", "name"}

    def test_terminal_output(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Rich terminal output shows identity and every section."""
        result = self._invoke(tmp_path, monkeypatch, f"0x{PROBE_VA:x}")
        assert result.exit_code == 0, result.output
        assert "my_func" in result.output
        assert "EXACT" in result.output
        assert "22 bytes" in result.output
        assert "caller_fn" in result.output
        assert "helper_fn" in result.output
        assert "HeapCreate" in result.output
        assert "Hello World" in result.output

    def test_explicit_target_option(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--target selects the same target as the project default."""
        result = self._invoke(
            tmp_path, monkeypatch, "--json", "--target", "game", f"0x{PROBE_VA:x}"
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["name"] == "my_func"

    def test_globals_section(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """A mov [global] ref into .data is reported in the globals section."""
        # Empty source tree — the probe has no annotation (fallback sizing).
        _make_project(tmp_path, source="", functions="")
        code = b"\x8b\x05\x00\x00\x00\x00\xc3"  # mov eax, [global]; ret
        # Pad to the file alignment so LIEF does not warn about unreadable
        # section padding (CliRunner mixes stderr into result.output).
        data = b"\x11\x22\x33\x44" + b"\x00" * 508
        proto_path = tmp_path / "proto.exe"
        proto_path.write_bytes(append_pe_section(make_pe(code), ".data", data))
        dstart, _ = section_range(load_binary(proto_path), ".data")
        final = append_pe_section(
            make_pe(b"\x8b\x05" + struct.pack("<I", dstart) + b"\xc3"),
            ".data",
            data,
        )
        (tmp_path / "game.exe").write_bytes(final)

        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--json", f"0x{PROBE_VA:x}"])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert data["name"] == "fcn_00401000"
        assert {"va": dstart, "kind": "mov_mem"} in data["globals"]

    def test_strings_paths_agree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_compute_strings with the dossier's all_refs (single-scan path)
        returns the same rows as the standalone string_refs path — the
        double-disassembly elimination must be behavior-preserving."""
        _make_project(tmp_path)
        _make_binary(tmp_path)
        from rebrew.analysis import scan_references
        from rebrew.binary_loader import load_binary
        from rebrew.describe import _compute_strings

        info = load_binary(tmp_path / "game.exe")
        all_refs = scan_references(info)
        start, end = PROBE_VA, PROBE_VA + 22
        via_all_refs = _compute_strings(info, start, end, all_refs)
        standalone = _compute_strings(info, start, end)
        assert via_all_refs == standalone
