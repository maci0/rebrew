"""Tests for instruction_diff.py and ``rebrew test --json --instructions``.

The fixtures are real bytes of rebrew-test-projects' bench-rebrew (bench.exe,
msvc-6.0-sp6): each target slice from the binary and each rebuilt slice from
``rebrew test`` compiling the project's source.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cli_json import cli_payload

from rebrew.instruction_diff import MAX_BYTES, instruction_diff

# fcn_00401420 (129 bytes, RELOC): the rebuilt `call` carries a relocation at 6.
MEMOPS_VA = 0x401420
MEMOPS_TARGET = bytes.fromhex(
    "b800200000e8360200008b8424042000005533d233ed85c07e5d5356578bc5b90004000025ff00"
    "00008d7c24108ad88d7424108afb8bc3c1e010668bc3f3ab8bc5b9000400008dbc241010000025"
    "ff0f0000f3a50fbe8c04101000008b84241420000003d1453be87cb35f5e5b8bc25d81c4002000"
    "00c38bc25d81c400200000c3"
)
MEMOPS_REBUILT = bytes.fromhex(
    "b800200000e8000000008b8424042000005533d233ed85c07e5d5356578bc5b90004000025ff00"
    "00008d7c24108ad88d7424108afb8bc3c1e010668bc3f3ab8bc5b9000400008dbc241010000025"
    "ff0f0000f3a50fbe8c04101000008b84241420000003d1453be87cb35f5e5b8bc25d81c4002000"
    "00c38bc25d81c400200000c3"
)
MEMOPS_RELOCS = [6]

# fcn_004012b0 (121 bytes, SIZE_MISMATCH: the rebuild is 94 bytes): register
# allocation differs and the loop body is shorter.
INTOPS_VA = 0x4012B0
INTOPS_TARGET = bytes.fromhex(
    "56578b7c240cb90100000085ffbe02000000b803000000ba040000007e5253558bd80fafde2bda"
    "8d54520103cb8bf18be9d1fe33f083e50f8bde81e3ff0000002bdd03c38bd9c1fb0233d38be88d"
    "1c1233cb8bdac1fb032beb33c103f58bde83e37f03c38d1c802bd903d34f75b25d5b03c25f03c6"
    "5e03c1c3"
)
INTOPS_REBUILT = bytes.fromhex(
    "56578b7c240cb90100000085ffba02000000be03000000b8040000007e3753558bde0fafda2bd8"
    "8d44400103cb8bd18be9d1fa33d683e50f8bda81e3ff0000002bdd03f38bd9c1fb0233c38d1c00"
    "33cb4f75cd5d5b03c65f03c25e03c1c3"
)

X86 = {"cs_arch": "CS_ARCH_X86", "cs_mode": "CS_MODE_32"}


def _rows(diff: dict[str, Any]) -> list[tuple[Any, ...]]:
    return [
        (r["op"], r["left"], r["right"], *(("reloc",) if r.get("reloc") else ()))
        for r in diff["rows"]
    ]


class TestInstructionDiff:
    def test_relocated_call_is_equal_with_reloc(self) -> None:
        diff = instruction_diff(
            MEMOPS_TARGET, MEMOPS_REBUILT, va=MEMOPS_VA, reloc_offsets=MEMOPS_RELOCS, **X86
        )
        assert diff["max_bytes"] == MAX_BYTES
        assert diff["truncated"] is False
        assert len(diff["original"]) == len(diff["rebuilt"]) == 44
        assert _rows(diff) == [("equal", i, i, *(("reloc",) if i == 1 else ())) for i in range(44)]
        assert diff["original"][1] == {
            "offset": 5,
            "bytes": "e836020000",
            "mnemonic": "call",
            "operands": "0x401660",
            "spans": [{"start": 0, "end": 8, "kind": "immediate", "value": 2, "changed": True}],
        }
        assert diff["rebuilt"][1] == {
            "offset": 5,
            "bytes": "e800000000",
            "mnemonic": "call",
            "operands": "0x40142a",
            "spans": [{"start": 0, "end": 8, "kind": "immediate", "value": 3, "changed": True}],
        }
        # An exact row marks nothing changed and shares value ids across sides.
        assert diff["original"][0] == {
            "offset": 0,
            "bytes": "b800200000",
            "mnemonic": "mov",
            "operands": "eax, 0x2000",
            "spans": [
                {"start": 0, "end": 3, "kind": "register", "value": 0},
                {"start": 5, "end": 11, "kind": "immediate", "value": 1},
            ],
        }
        assert diff["rebuilt"][0] == diff["original"][0]

    def test_a_relocated_instruction_names_its_symbols(self) -> None:
        diff = instruction_diff(
            MEMOPS_TARGET,
            MEMOPS_REBUILT,
            va=MEMOPS_VA,
            reloc_offsets=MEMOPS_RELOCS,
            reloc_symbols={6: "__chkstk", 200: "_past_the_end", 7: ""},
            **X86,
        )
        assert diff["rebuilt"][1]["symbols"] == ["__chkstk"]
        assert "symbols" not in diff["original"][1]
        assert all("symbols" not in insn for insn in diff["rebuilt"][2:] + diff["rebuilt"][:1])
        assert _rows(diff)[1] == ("equal", 1, 1, "reloc")

    def test_without_relocations_the_call_is_replaced(self) -> None:
        diff = instruction_diff(MEMOPS_TARGET, MEMOPS_REBUILT, va=MEMOPS_VA, **X86)
        assert diff["rows"][1] == {"op": "replace", "left": 1, "right": 1}

    def test_an_invalid_relocation_is_replaced(self) -> None:
        diff = instruction_diff(
            MEMOPS_TARGET,
            MEMOPS_REBUILT,
            va=MEMOPS_VA,
            reloc_offsets=MEMOPS_RELOCS,
            invalid_reloc_offsets=MEMOPS_RELOCS,
            **X86,
        )
        assert diff["rows"][1] == {"op": "replace", "left": 1, "right": 1}

    def test_register_allocation_and_shorter_loop(self) -> None:
        diff = instruction_diff(INTOPS_TARGET, INTOPS_REBUILT, va=INTOPS_VA, **X86)
        assert (len(diff["original"]), len(diff["rebuilt"])) == (52, 40)
        replaced = {5, 6, 7, 8, 11, 12, 13, 14, 16, 18, 19, 21, 24, 27, 28}
        assert _rows(diff) == [
            *(("replace" if i in replaced else "equal", i, i) for i in range(29)),
            ("delete", 29, None),
            ("equal", 30, 29),
            *(("delete", i, None) for i in range(31, 42)),
            ("equal", 42, 30),
            ("replace", 43, 31),
            ("equal", 44, 32),
            ("equal", 45, 33),
            ("insert", None, 34),
            ("insert", None, 35),
            ("equal", 46, 36),
            ("delete", 47, None),
            ("delete", 48, None),
            ("equal", 49, 37),
            ("equal", 50, 38),
            ("equal", 51, 39),
        ]
        # mov esi, 2 against mov edx, 2: the register changed, the number did not,
        # and esi keeps one value id on both sides (rebuilt row 6 moves 3 into it).
        assert diff["original"][5] == {
            "offset": 13,
            "bytes": "be02000000",
            "mnemonic": "mov",
            "operands": "esi, 2",
            "spans": [
                {"start": 0, "end": 3, "kind": "register", "value": 0, "changed": True},
                {"start": 5, "end": 6, "kind": "immediate", "value": 6},
            ],
        }
        assert diff["rebuilt"][5]["spans"][0] == {
            "start": 0,
            "end": 3,
            "kind": "register",
            "value": 7,
            "changed": True,
        }
        assert diff["rebuilt"][6]["operands"] == "esi, 3"
        assert diff["rebuilt"][6]["spans"][0]["value"] == 0
        # Same branch target, different displacement: replaced, no operand changed.
        assert diff["original"][43]["operands"] == diff["rebuilt"][31]["operands"] == "0x4012d0"
        assert "changed" not in diff["original"][43]["spans"][0]

    def test_a_side_past_the_bound_is_cut_and_says_so(self) -> None:
        nops = b"\x90" * (MAX_BYTES + 1)
        diff = instruction_diff(nops, b"\xc3", va=0x1000, **X86)
        assert diff["truncated"] is True
        assert len(diff["original"]) == MAX_BYTES
        assert diff["original"][-1]["offset"] == MAX_BYTES - 1

    def test_an_undecodable_tail_is_one_db(self) -> None:
        diff = instruction_diff(b"\xc3\x0f", b"", va=0x1000, **X86)
        assert diff["original"][1] == {
            "offset": 1,
            "bytes": "0f",
            "mnemonic": "db",
            "operands": "0f",
            "spans": [],
        }
        assert diff["rebuilt"] == []
        assert _rows(diff) == [("delete", 0, None), ("delete", 1, None)]


class TestTestInstructionsOption:
    def _project(self, tmp_path: Path, monkeypatch: Any) -> Path:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "x"\n'
            '[targets.x]\nbinary = "x.exe"\n'
            '[compiler]\nprofile = "msvc-6.0"\n',
            encoding="utf-8",
        )
        (tmp_path / "x.exe").write_bytes(b"MZ")
        (tmp_path / "f.c").write_text("int f(int n) { return n; }\n", encoding="utf-8")
        blob = tmp_path / "target.bin"
        blob.write_bytes(MEMOPS_TARGET)
        return blob

    def test_json_result_carries_the_comparison(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella
        from rebrew.compiler.compile import CompareResult

        blob = self._project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: CompareResult(
                matched=True,
                status="RELOC",
                match_percent=100.0,
                delta=0,
                obj_bytes=MEMOPS_REBUILT,
                reloc_offsets=MEMOPS_RELOCS,
                reloc_symbols={6: "__chkstk"},
            ),
        )
        cli = CliRunner().invoke(
            umbrella,
            [
                "test",
                "f.c",
                "--va",
                "0x401420",
                "--symbol",
                "_f",
                "--target-bin",
                str(blob),
                "--no-promote",
                "--instructions",
                "--json",
            ],
        )
        assert cli.exit_code == 0, cli.output
        payload = cli_payload(cli)
        assert payload["status"] == "RELOC"
        diff = payload["instructions"]
        assert diff["rows"][1] == {"op": "equal", "left": 1, "right": 1, "reloc": True}
        assert diff["rebuilt"][1]["operands"] == "0x40142a"
        assert diff["rebuilt"][1]["symbols"] == ["__chkstk"]
        assert len(diff["rows"]) == 44

    def test_needs_json(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        cli = CliRunner().invoke(umbrella, ["test", "f.c", "--instructions"])
        assert cli.exit_code == 2
        assert "--instructions requires --json" in cli.output

    def test_refused_with_all(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        cli = CliRunner().invoke(umbrella, ["test", "--all", "--instructions", "--json"])
        assert cli.exit_code == 2
        assert "--instructions is single-function only" in cli.output


class TestVerifyInstructionsOption:
    """``rebrew verify --json --instructions`` adds the comparison to each row that is not EXACT."""

    def _project(self, tmp_path: Path, monkeypatch: Any) -> Path:
        import shutil

        from source_util import write_source

        root = tmp_path / "project"
        (root / "original").mkdir(parents=True)
        (root / "src" / "SERVER").mkdir(parents=True)
        shutil.copy(Path(__file__).parent / "fixtures" / "mini_pe.exe", root / "original" / "x.exe")
        (root / "rebrew-project.toml").write_text(
            '[project]\ndefault_target = "SERVER"\njobs = 1\n'
            '[targets."SERVER"]\nbinary = "original/x.exe"\nformat = "pe"\narch = "x86_32"\n'
            'reversed_dir = "src/SERVER"\nmodule = "SERVER"\n'
            '[compiler]\nprofile = "mingw-16.2.0"\ncflags = "-O2"\n',
            encoding="utf-8",
        )
        for va, name in ((0x401000, "f1"), (0x401010, "f2")):
            write_source(
                root / "src" / "SERVER" / f"{name}.c",
                f"/* ADDRESS: SERVER 0x{va:08x} */\nint {name}(void) {{ return 0; }}\n",
                encoding="utf-8",
                metadata_fields={f"SERVER.0x{va:08x}": {"kind": "FUNCTION", "size": 3}},
            )
        monkeypatch.chdir(root)
        return root

    def test_rows_that_are_not_exact_carry_the_comparison(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella
        from rebrew.compiler.compile import CompareResult

        self._project(tmp_path, monkeypatch)

        def compare(cfg: Any, source: Any, symbol: str, target: bytes, *a: Any, **k: Any) -> Any:
            if symbol.endswith("f1"):
                return CompareResult(
                    matched=True,
                    status="EXACT",
                    match_percent=100.0,
                    delta=0,
                    obj_bytes=target,
                    reloc_offsets=[],
                )
            rebuilt = b"\x90" + target[1:]
            return CompareResult(
                matched=False,
                status="NEAR_MATCHING",
                match_percent=66.7,
                delta=1,
                obj_bytes=rebuilt,
                reloc_offsets=[],
            )

        monkeypatch.setattr("rebrew.compiler.compile.compile_and_compare", compare)
        cli = CliRunner().invoke(
            umbrella, ["verify", "--no-cache", "--no-promote", "--instructions", "--json"]
        )
        assert cli.exit_code in {0, 1}, cli.output
        rows = {r["va"]: r for r in cli_payload(cli)["results"]}
        assert "instructions" not in rows["0x00401000"]
        diff = rows["0x00401010"]["instructions"]
        assert diff["rebuilt"][0]["mnemonic"] == "nop"
        assert diff["rows"][0]["op"] in {"replace", "insert"}

    def test_needs_json(self, tmp_path: Path, monkeypatch: Any) -> None:
        from typer.testing import CliRunner

        from rebrew.app.main import app as umbrella

        self._project(tmp_path, monkeypatch)
        cli = CliRunner().invoke(umbrella, ["verify", "--instructions"])
        assert cli.exit_code == 2
        assert "--instructions requires --json" in cli.output


class TestDirectCallWithoutInstructions:
    """A direct ``main`` call that leaves --instructions out reads it as off."""

    def test_test_main(self, tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
        import json

        import rebrew.test as testmod
        from rebrew.compiler.compile import CompareResult

        blob = TestTestInstructionsOption()._project(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "rebrew.test.compile_and_compare",
            lambda *a, **k: CompareResult(
                matched=True,
                status="RELOC",
                match_percent=100.0,
                delta=0,
                obj_bytes=MEMOPS_REBUILT,
                reloc_offsets=MEMOPS_RELOCS,
            ),
        )
        testmod.main(
            "f.c",
            va="0x401420",
            symbol="_f",
            target_bin=str(blob),
            size=None,
            cflags=None,
            toolchain=None,
            all_sources=False,
            batch_dir=None,
            origin=None,
            dry_run=False,
            jobs=None,
            no_promote=True,
            force_status=False,
            fix_sizes=False,
            linked=False,
            watch=False,
            context=None,
            json_output=True,
            target=None,
            all_targets=False,
            source_targets=False,
        )
        payload = json.loads(capsys.readouterr().out)
        assert payload["status"] == "RELOC" and "instructions" not in payload


#: SWITCH's (tests/test_ops.py) fields that name its own labels: field offset,
#: label offset.  An unlinked object leaves them zero.
SWITCH_LABELS = [(9, 0x30), (16, 0x24), (0x24, 0x14), (0x28, 0x1A), (0x2C, 0x20)]


def _switch_rebuild(tmp_path: Path, labels: list[tuple[int, int]]) -> tuple[Any, dict[str, Any]]:
    """SWITCH at ENTRY_VA compared with its unlinked object whose label
    relocations are *labels*: the compare result and its instruction diff."""
    from types import SimpleNamespace

    from bin_util import make_coff_obj, make_pe
    from test_ops import ENTRY_VA, SWITCH

    from rebrew.compiler.compile import _extract_and_compare
    from rebrew.instruction_diff import record_instructions

    unlinked = bytearray(SWITCH)
    for at, _ in labels:
        unlinked[at : at + 4] = bytes(4)
    obj = tmp_path / "f.obj"
    obj.write_bytes(
        make_coff_obj(
            bytes(unlinked),
            func_symbol="_f",
            label_relocs=[(at, 0x6, value) for at, value in labels],
        )
    )
    binary = tmp_path / "x.exe"
    binary.write_bytes(make_pe(SWITCH))
    target = SWITCH + bytes(2)  # the object pads its section to 4 bytes
    result = _extract_and_compare(
        str(obj), "_f", target, name_to_va={"_f": ENTRY_VA}, section_va=ENTRY_VA
    )
    cfg = SimpleNamespace(
        capstone_arch=X86["cs_arch"], capstone_mode=X86["cs_mode"], target_binary=binary
    )
    record_instructions(cfg, result, target, ENTRY_VA)
    assert result.instructions is not None
    return result, result.instructions


class TestJumpTables:
    def test_rebuilt_tables_resolve_through_their_label_relocations(self, tmp_path: Path) -> None:
        """An unlinked object's jump table holds zeros where its ``$L`` labels
        go; the comparison reads the labels from the relocations, so both
        sides list the table as the same data and every row is equal."""
        result, diff = _switch_rebuild(tmp_path, SWITCH_LABELS)
        assert result.status == "RELOC", result.message
        table = [(i["mnemonic"], i["operands"]) for i in diff["rebuilt"][12:15]]
        assert table == [("dd", "0x401014"), ("dd", "0x40101a"), ("dd", "0x401020")]
        assert diff["rebuilt"][12]["bytes"] == "00000000"
        assert [i["mnemonic"] for i in diff["original"]] == [i["mnemonic"] for i in diff["rebuilt"]]
        assert {r["op"] for r in diff["rows"]} == {"equal"}

    def test_rebuilt_operands_show_the_addresses_of_their_own_labels(self, tmp_path: Path) -> None:
        """An operand naming one of the function's labels showed 0, the unset
        field; it shows the address the target shows, and a row whose resolved
        bytes equal the target's is equal, not a relocation row.  The byte
        verdict does not change: it already counts relocated bytes as matching."""
        result, diff = _switch_rebuild(tmp_path, SWITCH_LABELS)
        assert result.status == "RELOC", result.message
        dispatch = [(i["operands"], i["bytes"]) for i in diff["rebuilt"][3:5]]
        assert dispatch == [
            ("cl, byte ptr [eax + 0x401030]", "8a8800000000"),
            ("dword ptr [ecx*4 + 0x401024]", "ff248d00000000"),
        ]
        assert [r for r in diff["rows"] if r.get("reloc")] == []
        assert not any(s.get("changed") for i in diff["rebuilt"] for s in i["spans"])

    def test_a_label_at_another_offset_is_a_changed_relocation_row(self, tmp_path: Path) -> None:
        """The dispatch names a label 4 bytes past the target's table: its
        operand shows that address, marked changed, on a relocation row."""
        labels = [(at, value + 4 if at == 16 else value) for at, value in SWITCH_LABELS]
        result, diff = _switch_rebuild(tmp_path, labels)
        assert result.status == "RELOC", result.message
        jmp = diff["rebuilt"][4]
        assert jmp["operands"] == "dword ptr [ecx*4 + 0x401028]"
        assert [r for r in diff["rows"] if r.get("reloc")] == [
            {"op": "equal", "left": 4, "right": 4, "reloc": True}
        ]
        changed = [jmp["operands"][s["start"] : s["end"]] for s in jmp["spans"] if s.get("changed")]
        assert changed == ["0x401028"]
