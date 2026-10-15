"""Tests for pdb_export.py: synthetic PDB written through `rebrew export pdb`."""

from __future__ import annotations

import re
import shutil
import struct
import uuid
from pathlib import Path

import lief
import pytest
from bin_util import make_pe
from cli_json import cli_payload
from hypothesis import given, settings
from hypothesis import strategies as st
from source_util import SourceFixture, write_source, write_store_fixture
from typer.testing import CliRunner

import rebrew.pdb_export as pdb_export
from rebrew.app.main import app
from rebrew.pdb_export import TypeTable, read_debug_identity
from rebrew.pdb_info import extract_pdb_info

runner = CliRunner()

needs_pdbutil = pytest.mark.skipif(
    shutil.which("llvm-pdbutil") is None, reason="llvm-pdbutil not on PATH"
)

GUID = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
GUID_TEXT = "{11223344-5566-7788-99AA-BBCCDDEEFF00}"
AGE = 7
RSDS = b"RSDS" + GUID.bytes_le + struct.pack("<I", AGE) + b"C:\\build\\mini.pdb\x00"
NB10_SIGNATURE = 0x3FFD22BC
NB10 = b"NB10" + struct.pack("<III", 0, NB10_SIGNATURE, 2) + b"D:\\rel\\old.pdb\x00"
CODE = b"\xc3" * 0x100

_SOURCES = {
    "foo.c": SourceFixture(
        "/* ADDRESS: SRV 0x401000 */\n\nint foo(void) { return 1; }\n",
        {"SRV.0x401000": {"kind": "FUNCTION", "size": 16}},
    ),
    "bar.c": SourceFixture(
        "/* ADDRESS: SRV 0x401020 */\nint bar(void) { return 2; }\n",
        {"SRV.0x401020": {"kind": "FUNCTION"}},
    ),
    "far.c": SourceFixture(
        "/* ADDRESS: SRV 0x500000 */\nint far_away(void) { return 3; }\n",
        {"SRV.0x500000": {"kind": "FUNCTION"}},
    ),
    "data.c": (
        SourceFixture(
            "/* ADDRESS: SRV 0x401080 */\nint g_counter;\n\n/* ADDRESS: SRV 0x401090 */\nchar g_name[16];\n",
            {"SRV.0x401080": {"kind": "GLOBAL"}, "SRV.0x401090": {"kind": "GLOBAL"}},
        )
    ),
}
_DATA_TOML = 'format = 2\n["SRV.0x4010a0"]\nname = "g_table"\ntype = "unsigned char[]"\nsize = 8\nsection = ".text"\n'


def _project(tmp_path: Path, codeview: bytes | None) -> Path:
    (tmp_path / "original").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "original" / "mini.exe").write_bytes(make_pe(CODE, codeview=codeview))
    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "S"\n\n[targets."S"]\n'
        'binary = "original/mini.exe"\nformat = "pe"\narch = "x86_32"\n'
        'marker = "SRV"\nreversed_dir = "src"\n',
        encoding="utf-8",
    )
    for name, text in _SOURCES.items():
        write_source(tmp_path / "src" / name, text, encoding="utf-8")
    write_store_fixture(tmp_path / "rebrew-data.toml", _DATA_TOML, encoding="utf-8")
    return tmp_path


def _export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *args: str) -> dict[str, object]:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["export", "pdb", *args, "--json"])
    assert result.exit_code == 0, result.output
    payload: dict[str, object] = cli_payload(result)
    return payload


def _dump(pdb: Path, *flags: str) -> str:
    import subprocess

    tool = shutil.which("llvm-pdbutil")
    assert tool is not None
    done = subprocess.run(
        [tool, "dump", *flags, str(pdb)], capture_output=True, text=True, check=True
    )
    return done.stdout


# ---------------------------------------------------------------------------
# Round trip through llvm-pdbutil and rebrew's own reader
# ---------------------------------------------------------------------------


@needs_pdbutil
class TestRoundTrip:
    def test_identity_names_and_addresses_round_trip(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, RSDS)
        payload = _export(tmp_path, monkeypatch)
        pdb = tmp_path / "mini.pdb"  # the name the RSDS record asks for
        assert payload["output"] == "mini.pdb"
        assert pdb.is_file()
        assert payload["identity"] == {
            "kind": "rsds",
            "guid": GUID_TEXT,
            "signature": 0,
            "age": AGE,
            "pdb_name": "mini.pdb",
        }
        assert (payload["functions"], payload["functions_with_size"]) == (2, 1)
        assert (payload["data"], payload["typed_data"]) == (3, 3)
        assert payload["outside_sections"] == ["_far_away@0x00500000"]

        summary = _dump(pdb, "-summary")
        assert f"GUID: {GUID_TEXT}" in summary
        assert re.search(rf"^\s*Age: {AGE}$", summary, re.M)

        publics = _dump(pdb, "-publics")
        assert re.search(r"`_foo`\n\s+flags = function, addr = 0001:0000", publics)
        assert re.search(r"`_bar`\n\s+flags = function, addr = 0001:0032", publics)
        assert re.search(r"`g_counter`\n\s+flags = none, addr = 0001:0128", publics)
        assert re.search(r"`g_table`\n\s+flags = none, addr = 0001:0160", publics)
        assert "far_away" not in publics

        symbols = _dump(pdb, "-symbols")
        proc = re.search(
            r"S_GPROC32 \[size = \d+\] `foo`\n\s+parent = 0, end = (\d+), "
            r"addr = 0001:0000, code size = 16",
            symbols,
        )
        assert proc is not None
        assert re.search(rf"^\s+{proc.group(1)} \| S_END", symbols, re.M)
        assert re.search(r"S_GDATA32 \[size = \d+\] `g_counter`\n\s+type = 0x0074 \(int\)", symbols)

        types = _dump(pdb, "-types")
        assert "size: 16, index type: 0x0022 (unsigned long), element type: 0x0070 (char)" in types
        assert "size: 8, index type: 0x0022 (unsigned long), element type: 0x0020" in types

        headers = _dump(pdb, "-section-headers")
        assert ".text name" in headers

    def test_rebrew_pdb_reader_sees_the_functions(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, RSDS)
        _export(tmp_path, monkeypatch, "--output", "original/mini.pdb")
        info = extract_pdb_info(tmp_path / "original" / "mini.exe")
        assert info is not None
        assert info.error == ""
        assert [fn["name"] for fn in info.functions] == ["foo"]

    def test_nb10_target_keeps_signature_and_age(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, NB10)
        payload = _export(tmp_path, monkeypatch)
        assert payload["output"] == "old.pdb"
        summary = _dump(tmp_path / "old.pdb", "-summary")
        assert f"Signature: {NB10_SIGNATURE}" in summary
        assert re.search(r"^\s*Age: 2$", summary, re.M)
        assert "GUID: {00000000-0000-0000-0000-000000000000}" in summary
        assert payload["warnings"]

    def test_pe_symbols_add_import_slots(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, RSDS)
        image = make_pe(CODE, imports=[("KERNEL32.dll", ["ExitProcess"])], codeview=RSDS)
        (tmp_path / "original" / "mini.exe").write_bytes(image)
        payload = _export(tmp_path, monkeypatch, "--pe-symbols")
        assert isinstance(payload["pe_symbols"], int)
        assert payload["pe_symbols"] > 0
        assert "__imp_kernel32_ExitProcess" in _dump(tmp_path / "mini.pdb", "-publics")

    def test_rerun_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _project(tmp_path, RSDS)
        _export(tmp_path, monkeypatch)
        first = (tmp_path / "mini.pdb").read_bytes()
        _export(tmp_path, monkeypatch)
        assert (tmp_path / "mini.pdb").read_bytes() == first


# ---------------------------------------------------------------------------
# Targets without a usable record, missing tool
# ---------------------------------------------------------------------------


class TestRefusals:
    def test_no_codeview_record_refuses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, None)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["export", "pdb", "--json"])
        assert result.exit_code != 0
        assert "--unmatched" in result.output
        assert not list(tmp_path.glob("*.pdb"))

    @needs_pdbutil
    def test_unmatched_writes_zero_identity(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, None)
        payload = _export(tmp_path, monkeypatch, "--unmatched")
        assert payload["output"] == "mini.pdb"
        assert "GUID: {00000000-0000-0000-0000-000000000000}" in _dump(
            tmp_path / "mini.pdb", "-summary"
        )

    def test_missing_pdbutil_fails_loud(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _project(tmp_path, RSDS)
        monkeypatch.setattr(pdb_export.shutil, "which", lambda _name: None)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["export", "pdb", "--json"])
        assert result.exit_code != 0
        assert "llvm-pdbutil not found on PATH" in result.output
        assert not (tmp_path / "mini.pdb").exists()


# ---------------------------------------------------------------------------
# Debug-record reader (untrusted PE input)
# ---------------------------------------------------------------------------


def _identity(image: bytes) -> pdb_export.DebugIdentity:
    pe = lief.PE.parse(list(image))
    assert pe is not None
    return read_debug_identity(pe, image)


class TestDebugIdentity:
    def test_rsds(self) -> None:
        identity = _identity(make_pe(CODE, codeview=RSDS))
        assert (identity.kind, identity.guid, identity.age) == ("rsds", GUID_TEXT, AGE)
        assert identity.pdb_name == "mini.pdb"

    def test_nb10(self) -> None:
        identity = _identity(make_pe(CODE, codeview=NB10))
        assert (identity.kind, identity.signature, identity.age) == ("nb10", NB10_SIGNATURE, 2)
        assert identity.pdb_name == "old.pdb"

    def test_no_debug_directory(self) -> None:
        assert _identity(make_pe(CODE)).kind == "none"

    def test_truncated_nb10_reads_as_none(self) -> None:
        assert _identity(make_pe(CODE, codeview=NB10[:10])).kind == "none"

    def test_path_without_file_name_has_no_pdb_name(self) -> None:
        record = b"RSDS" + GUID.bytes_le + struct.pack("<I", 1) + b"C:\\dir\\\x00"
        assert _identity(make_pe(CODE, codeview=record)).pdb_name == ""

    @settings(max_examples=200, deadline=None)
    @given(st.binary(max_size=64), st.sampled_from([b"RSDS", b"NB10", b""]))
    def test_arbitrary_record_never_raises(self, body: bytes, magic: bytes) -> None:
        identity = _identity(make_pe(CODE, codeview=magic + body))
        assert identity.kind in {"rsds", "nb10", "none"}
        assert "\\" not in identity.pdb_name and "/" not in identity.pdb_name


# ---------------------------------------------------------------------------
# C type spellings → CodeView
# ---------------------------------------------------------------------------


class TestTypeTable:
    @pytest.mark.parametrize(
        ("spelling", "index"),
        [
            ("int", 0x0074),
            ("const float", 0x0040),
            ("unsigned char", 0x0020),
            ("char *", 0x0470),
            ("void*", 0x0403),
            ("unsigned short int", 0x0021),
        ],
    )
    def test_simple_types(self, spelling: str, index: int) -> None:
        assert TypeTable(pointer_size=4).type_for(spelling, None) == index

    def test_pointer_to_pointer_is_a_record(self) -> None:
        table = TypeTable(pointer_size=4)
        assert table.type_for("char **", None) == 0x1000
        assert table.records == [
            {"Kind": "LF_POINTER", "Pointer": {"ReferentType": 0x0470, "Attrs": 0x800A}}
        ]

    def test_x64_pointers(self) -> None:
        table = TypeTable(pointer_size=8)
        assert table.type_for("int *", None) == 0x0674
        assert table.type_for("int *[2]", None) == 0x1000
        assert table.records[0]["Array"] == {
            "ElementType": 0x0674,
            "IndexType": 0x0023,
            "Size": 16,
            "Name": "",
        }

    def test_multi_dimensional_array(self) -> None:
        table = TypeTable(pointer_size=4)
        index = table.type_for("int[2][3]", None)
        assert [r["Array"]["Size"] for r in table.records] == [12, 24]
        assert table.records[1]["Array"]["ElementType"] == 0x1000
        assert index == 0x1001

    def test_unbounded_array_takes_the_known_size(self) -> None:
        table = TypeTable(pointer_size=4)
        assert table.type_for("int[]", 12) == 0x1000
        assert table.records[0]["Array"]["Size"] == 12
        assert TypeTable(pointer_size=4).type_for("int[]", 10) == 0
        assert TypeTable(pointer_size=4).type_for("int[]", None) == 0

    def test_records_are_shared(self) -> None:
        table = TypeTable(pointer_size=4)
        assert table.type_for("char[4]", None) == table.type_for("const char[4]", None)
        assert len(table.records) == 1

    @pytest.mark.parametrize(
        "spelling", ["struct Foo", "DWORD", "void", "int (*)(int)", "char (*)[4]", "Foo *"]
    )
    def test_unsupported_stays_untyped(self, spelling: str) -> None:
        assert TypeTable(pointer_size=4).type_for(spelling, None) == 0
