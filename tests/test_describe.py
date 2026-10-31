"""Tests for rebrew binary function — per-function recon dossier.

Builds a synthetic PE (via ``bin_util.make_pe``) whose .text contains a probe
function with a direct call, a string push, a string mov, and an IAT call,
plus a caller function that calls the probe.  The temp rebrew project carries
annotations and a function list so the dossier can resolve names.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from bin_util import append_pe_section, make_pe
from cli_json import cli_payload
from source_util import SourceFixture, write_source
from typer.testing import CliRunner

from rebrew.analysis import section_range
from rebrew.describe import app
from rebrew.formats.binary_loader import load_binary

IMAGE_BASE = 0x400000
TEXT_VA = 0x1000
PROBE_VA = IMAGE_BASE + TEXT_VA  # 0x00401000

_TOML = """\
[project]
default_target = "game"

[targets.game]
binary = "game.exe"
module = "GAME"
reversed_dir = "src"
[compiler]
profile = "msvc-6.0"
command = "cl"
cflags = "/O2"
"""

_PROBE_C = SourceFixture(
    "/* ADDRESS: GAME 0x00401000 */\n\nint my_func(void) { return 1; }\n\n/* ADDRESS: GAME 0x00401034 */\n\nint helper_fn(void) { return 0; }\n",
    {
        "GAME.0x00401000": {"kind": "FUNCTION", "size": 22},
        "GAME.0x00401034": {"kind": "FUNCTION", "size": 4},
    },
)

_PROBE_META = (
    'format = 3\n["GAME.0x00401000"]\nstatus = "EXACT"\n\n["GAME.0x00401034"]\nstatus = "STUB"\n'
)

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
    write_source(tmp_path / "rebrew-project.toml", _TOML, encoding="utf-8")
    src = tmp_path / "src"
    src.mkdir()
    write_source(src / "game.c", source, encoding="utf-8")
    import contextlib as _contextlib
    import json as _json

    entries = []
    for _line in functions.splitlines():
        _parts = _line.split()
        if len(_parts) >= 3:
            with _contextlib.suppress(ValueError):
                entries.append(
                    {"va": int(_parts[0], 16), "size": int(_parts[1]), "name": _parts[2]}
                )
    (src / "function_structure.json").write_text(_json.dumps(entries), encoding="utf-8")
    if source == _PROBE_C:
        # Volatile STATUS lives in rebrew-functions.toml at the metadata
        # root (the parent of reversed_dir).
        from rebrew.metadata.functions import update_source_status

        update_source_status(tmp_path, "EXACT", "GAME", PROBE_VA, force=True)


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
    """End-to-end ``rebrew binary function`` over a synthetic project."""

    def _invoke(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> Any:
        """Build the project + binary and run ``rebrew binary function`` from tmp_path."""
        _make_project(tmp_path)
        _make_binary(tmp_path)
        monkeypatch.chdir(tmp_path)
        return CliRunner().invoke(app, list(args))

    def test_known_function_dossier(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Callers/callees/strings/imports all appear for the annotated probe."""
        result = self._invoke(tmp_path, monkeypatch, "--json", f"0x{PROBE_VA:x}")
        assert result.exit_code == 0, result.output
        data = cli_payload(result)
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

    def test_unannotated_inventory_extent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An unannotated VA retains its fallback name and known inventory extent."""
        result = self._invoke(tmp_path, monkeypatch, "--json", "0x401016")
        assert result.exit_code == 0, result.output
        data = cli_payload(result)
        assert data["name"] == "fcn_00401016"
        assert data["status"] is None
        assert data["size"] == 8
        # The dossier still resolves the caller's callee via annotations.
        assert {"to_va": PROBE_VA, "name": "my_func", "kind": "call"} in data["callees"]

    def test_unannotated_terminal_inventory_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Terminal output reports the known size for an unannotated function."""
        result = self._invoke(tmp_path, monkeypatch, "0x401016")
        assert result.exit_code == 0, result.output
        assert "fcn_00401016" in result.output
        assert "8 bytes" in result.output

    def test_native_only_metadata_names_without_source_claim(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Native names and notes survive before a source provider exists."""
        from rebrew.metadata.functions import record_function_rows, update_source_status

        _make_project(tmp_path, source="")
        _make_binary(tmp_path)
        record_function_rows(
            tmp_path,
            [
                {
                    "module": module,
                    "va": va,
                    "identity": {"name": name},
                    "fields": {"size": size, "note": "Reviewed native role only"},
                }
                for module, va, name, size in [
                    ("OTHER", PROBE_VA, "wrong_target", 1),
                    ("GAME", PROBE_VA, "native_probe", 22),
                    ("GAME", 0x401016, "native_caller", 8),
                    ("GAME", 0x401034, "native_helper", 4),
                ]
            ],
        )
        update_source_status(tmp_path, "EXACT", "GAME", PROBE_VA, force=True)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--json", f"0x{PROBE_VA:x}"])
        assert result.exit_code == 0, result.output
        data = cli_payload(result)
        assert data["name"] == "native_probe"
        assert data["size"] == 22
        assert data["status"] is None
        assert data["cflags"] is None
        assert data["callers"] == [{"from_va": 0x401017, "name": "native_caller"}]
        assert {"to_va": 0x401034, "name": "native_helper", "kind": "call"} in data["callees"]
        result = CliRunner().invoke(app, [f"0x{PROBE_VA:x}"])
        assert result.exit_code == 0, result.output
        assert "native_probe" in result.output
        assert "Reviewed native role only" in result.output

    @pytest.mark.parametrize("binding", ["absent", "unsized", "sized"])
    def test_inventory_extent_keeps_late_branch_without_neighbor_refs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, binding: str
    ) -> None:
        """Known extents include a branch after an early ret and exclude the neighbor."""
        source: str = ""
        if binding != "absent":
            fields: dict[str, Any] = {"kind": "FUNCTION"}
            if binding == "sized":
                fields["size"] = 11
            source = SourceFixture(
                "/* ADDRESS: GAME 0x00401000 */\nint probe(void) { return 0; }\n",
                {"GAME.0x00401000": fields},
            )
        # A complete source extent outranks a shorter discovery hint.
        inventory_size = 5 if binding == "sized" else 11
        functions = (
            f"0x00401000 {inventory_size} probe\n"
            "0x0040100b 6 neighbor\n"
            "0x00401011 1 late_helper\n"
            "0x00401012 1 neighbor_helper\n"
        )
        _make_project(tmp_path, source=source, functions=functions)
        # test eax,eax; jne late; ret; late: call late_helper; ret;
        # neighbor: call neighbor_helper; ret; late_helper: ret; neighbor_helper: ret.
        code = (
            b"\x85\xc0\x75\x01\xc3\xe8"
            + struct.pack("<i", 7)
            + b"\xc3\xe8"
            + struct.pack("<i", 2)
            + b"\xc3\xc3\xc3"
        )
        (tmp_path / "game.exe").write_bytes(make_pe(code))
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--json", f"0x{PROBE_VA:x}"])
        assert result.exit_code == 0, result.output
        data = cli_payload(result)
        assert data["size"] == 11
        assert {"to_va": PROBE_VA + 17, "name": "late_helper", "kind": "call"} in data["callees"]
        assert not any(callee["to_va"] == PROBE_VA + 18 for callee in data["callees"])

    def test_va_outside_binary_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A VA outside the binary image exits non-zero with an error."""
        result = self._invoke(tmp_path, monkeypatch, "--json", "0x99999999")
        assert result.exit_code != 0
        assert "outside" in result.output

    def test_internal_jump_is_not_a_callee(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Keep real recursion and an external tail call, excluding the local goto."""
        _make_project(
            tmp_path,
            source="",
            functions="0x00401000 13 probe\n0x0040100d 1 tail_helper\n",
        )
        # call probe; jmp local; ret; local: jmp tail_helper; tail_helper: ret.
        code = b"\xe8" + struct.pack("<i", -5) + b"\xeb\x01\xc3\xe9\x00\x00\x00\x00\xc3"
        (tmp_path / "game.exe").write_bytes(make_pe(code))
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["--json", f"0x{PROBE_VA:x}"])
        assert result.exit_code == 0, result.output
        data = cli_payload(result)
        assert data["size"] == 13
        assert data["callees"] == [
            {"to_va": PROBE_VA, "name": "probe", "kind": "call"},
            {"to_va": PROBE_VA + 13, "name": "tail_helper", "kind": "jmp"},
        ]

    def test_json_shape(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--json emits exactly the documented dossier keys and types."""
        result = self._invoke(tmp_path, monkeypatch, "--json", f"0x{PROBE_VA:x}")
        assert result.exit_code == 0, result.output
        data = cli_payload(result)
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
        # The loops below only run on a populated list, so pin the fixture's
        # cardinality first: an empty dossier would skip every shape check.
        assert data["callers"] == [{"from_va": 0x401017, "name": "caller_fn"}]
        assert {"to_va": 0x401034, "name": "helper_fn", "kind": "call"} in data["callees"]
        assert {"va": 0x40101E, "text": "Hello World"} in data["strings"]
        assert [i["name"] for i in data["imports"]] == ["HeapCreate"]
        assert data["globals"] == []
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
        assert cli_payload(result)["name"] == "my_func"

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
        data = cli_payload(result)
        assert data["name"] == "fcn_00401000"
        assert {"va": dstart, "kind": "mov_mem"} in data["globals"]

    def test_strings_paths_agree(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """_compute_strings with the dossier's all_refs (single-scan path)
        returns the same rows as the standalone string_refs path — the
        double-disassembly elimination must be behavior-preserving."""
        _make_project(tmp_path)
        _make_binary(tmp_path)
        from rebrew.analysis import scan_references
        from rebrew.describe import _compute_strings
        from rebrew.formats.binary_loader import load_binary

        info = load_binary(tmp_path / "game.exe")
        all_refs = scan_references(info)
        start, end = PROBE_VA, PROBE_VA + 22
        via_all_refs = _compute_strings(info, start, end, all_refs)
        standalone = _compute_strings(info, start, end)
        assert via_all_refs == standalone


class _RangeScans(list[tuple[int, int, str]]):
    """Function-range list that counts each full walk."""

    def __init__(self, items: list[tuple[int, int, str]]) -> None:
        super().__init__(items)
        self.scans = 0

    def __iter__(self) -> Iterator[tuple[int, int, str]]:
        self.scans += 1
        return super().__iter__()


class TestContainingNameSmallestRange:
    def test_overlapping_ranges_pick_the_smallest(self) -> None:
        """An oversized outer SIZE overlaps the next function; the resolver
        promises the SMALLEST containing range, not the earliest-starting one."""
        from rebrew.describe import _containing_name

        ranges = [(0x1000, 0x1200, "outer"), (0x1040, 0x1080, "inner")]
        assert _containing_name(0x1050, {}, ranges) == "inner"
        assert _containing_name(0x1150, {}, ranges) == "outer"
        # The shorter range is still the one that contains the site when it
        # is listed first, and equal lengths keep the earlier entry.
        listed_first = [(0x1040, 0x1080, "inner"), (0x1000, 0x1200, "outer")]
        assert _containing_name(0x1050, {}, listed_first) == "inner"
        assert _containing_name(0x1150, {}, listed_first) == "outer"
        same_length = [(0x1000, 0x1100, "first"), (0x1040, 0x1140, "second")]
        assert _containing_name(0x1080, {}, same_length) == "first"
        assert _containing_name(0x1120, {}, same_length) == "second"
        assert _containing_name(0x1000, {0x1000: "exact"}, ranges) == "exact"
        assert _containing_name(0x0900, {}, ranges) == "fcn_00000900"


class TestDossierRangeScan:
    def test_one_dossier_scans_function_ranges_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Caller and callee names walk the function ranges once per dossier.

        Each interior site used to walk the same list again. The resolved
        names stay the smallest enclosing range, with an exact start winning
        over every range.
        """
        import rebrew.describe as describe_mod
        from rebrew.analysis import Xref

        items = [
            (0x1800, 0x1900, "late"),
            (0x1000, 0x2000, "outer"),
            (0x1100, 0x1200, "inner"),
        ]
        names = {0x1000: "outer", 0x1100: "inner", 0x1800: "late"}
        ann = SimpleNamespace(
            name="probe",
            size=0x100,
            status="EXACT",
            cflags="",
            blocker="",
            note="",
        )
        cfg = SimpleNamespace(arch="")
        info = SimpleNamespace()

        def dossier(n_callers: int) -> tuple[int, dict[str, Any]]:
            ranges = _RangeScans(items)
            refs = [Xref("call", 0x1300 + i, 0x1000) for i in range(n_callers)]
            refs.append(Xref("call", 0x1120, 0x1000))
            refs.extend(
                (
                    Xref("call", 0x1010, 0x1850),
                    Xref("call", 0x1020, 0x1110),
                )
            )
            monkeypatch.setattr(
                describe_mod,
                "_build_lookup",
                lambda _cfg: ({0x1000: ann}, names, ranges),
            )
            monkeypatch.setattr(describe_mod, "scan_references", lambda _info: refs)
            monkeypatch.setattr(describe_mod, "_import_table", lambda _cfg: {})
            built = describe_mod.build_dossier(cfg, info, 0x1000)
            return ranges.scans, built

        scans, built = dossier(4)
        assert scans == 1
        assert built["callers"] == [
            {"from_va": 0x1120, "name": "inner"},
            {"from_va": 0x1300, "name": "outer"},
            {"from_va": 0x1301, "name": "outer"},
            {"from_va": 0x1302, "name": "outer"},
            {"from_va": 0x1303, "name": "outer"},
        ]
        assert built["callees"] == [
            {"to_va": 0x1110, "name": "inner", "kind": "call"},
            {"to_va": 0x1850, "name": "late", "kind": "call"},
        ]
        wider, _again = dossier(40)
        assert wider == 1


class TestMalformedInventoryEntry:
    def test_malformed_inventory_entry_is_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A bad inventory entry truncates every dossier range, so it is warned.

        ``cached_function_list`` already warns when the file cannot be read, so
        an exception here means the inventory parsed but holds a malformed
        entry.  Dropping the rest of it at DEBUG left ranges silently ending
        at annotation boundaries with nothing to explain them.
        """
        import logging

        import rebrew.describe as describe_mod
        from rebrew.describe import _build_lookup

        monkeypatch.setattr(describe_mod, "_collect_annotations", lambda cfg: [])
        monkeypatch.setattr(
            describe_mod,
            "cached_function_list",
            lambda cfg: [
                {"va": 0x1000, "size": 0x20, "name": "good"},
                {"va": "not-an-address", "size": 0x10, "name": "bad"},
                {"va": 0x2000, "size": 0x20, "name": "never_reached"},
            ],
        )

        with caplog.at_level(logging.WARNING, logger="rebrew.describe"):
            names, _ranges = _build_lookup(None)[1:]

        assert "malformed" in caplog.text
        assert "never_reached" not in names
        # The entry before the bad one is kept, not discarded with the rest.
        assert names[0x1000] == "good"


class TestDecoratedLookupName:
    def test_decorated_symbol_uses_the_c_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An empty C name still names the function, not the decoration.

        ``lstrip("_")`` left ``hook@@12`` and ``@keeps@4`` in the dossier,
        and it turned ``__foo`` into ``foo``. A stored name wins. The
        range label is the same C name.
        """
        import rebrew.describe as describe_mod
        from rebrew.describe import _build_lookup
        from rebrew.metadata.bindings import SourceBinding

        anns = [
            SourceBinding(va=0x1000, size=0x10, name="", symbol="hook@@12"),
            SourceBinding(va=0x1100, size=0x10, name="", symbol="@keeps@4"),
            SourceBinding(va=0x1200, size=0x10, name="", symbol="_sleepish@4"),
            SourceBinding(va=0x1300, size=0x10, name="", symbol="__foo"),
            SourceBinding(va=0x1400, size=0x10, name="", symbol="_foo"),
            SourceBinding(va=0x1500, size=0x10, name="kept", symbol="hook@@12"),
        ]
        monkeypatch.setattr(describe_mod, "_collect_annotations", lambda cfg: anns)
        monkeypatch.setattr(describe_mod, "cached_function_list", lambda cfg: [])

        _annotations, names, ranges = _build_lookup(None)

        assert names[0x1000] == "hook"
        assert names[0x1100] == "keeps"
        assert names[0x1200] == "sleepish"
        assert names[0x1300] == "_foo"
        assert names[0x1400] == "foo"
        assert names[0x1500] == "kept"
        by_va = {start: label for start, _end, label in ranges}
        assert by_va[0x1000] == "hook"
        assert by_va[0x1100] == "keeps"
        assert by_va[0x1300] == "_foo"
