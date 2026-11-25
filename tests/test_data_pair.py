"""Cross-target data operand pairing (``rebrew data pair``)."""

import struct
lazy from pathlib import Path

import capstone
import pytest
from bin_util import append_pe_section, make_pe
from cli_json import cli_payload
from typer.testing import CliRunner

from rebrew.app.main import app
from rebrew.cast_rewrite import declare_externs
from rebrew.config import ProjectConfig
from rebrew.data_pair import OperandPair, pair_data_operands, plan_pairs
from rebrew.metadata.data import load_data_metadata, record_data_rows

X86 = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)


def _in_data(va: int) -> bool:
    return 0x500000 <= va < 0x700000


def _section(_va: int) -> str:
    return ".data"


@pytest.fixture
def targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, tuple[ProjectConfig, int, int]]:
    configs = {}
    for module, base in (("A", 0x400000), ("B", 0x500000)):
        directory = tmp_path / "src" / module
        directory.mkdir(parents=True)
        (directory / "rebrew-functions.toml").write_text("format = 3\n", encoding="utf-8")
        binary = tmp_path / f"{module}.exe"
        address = base + 0x2000
        code = b"\xa1" + struct.pack("<I", address) + b"\xc3"
        binary.write_bytes(append_pe_section(make_pe(code, image_base=base), ".data", bytes(4)))
        cfg = ProjectConfig(
            root=tmp_path,
            target_name=module,
            module=module,
            reversed_dir=directory,
            target_binary=binary,
        )
        assert cfg.metadata_dir == directory
        configs[module] = (cfg, base + 0x1000, address)
    monkeypatch.setattr(
        "rebrew.data_pair.require_config", lambda *, target, **kwargs: configs[target][0]
    )
    return configs


def _seed_data(cfg: ProjectConfig, address: int) -> None:
    record_data_rows(
        cfg.metadata_dir,
        [
            {
                "module": cfg.module,
                "va": address,
                "identity": {"name": "shared", "kind": "GLOBAL"},
                "fill": {"size": 4, "type": "int", "section": ".data"},
            }
        ],
    )


@pytest.mark.parametrize("existing", ["A", "B"])
def test_pair_writes_the_missing_row_to_its_target_store(targets, existing: str) -> None:
    other = "B" if existing == "A" else "A"
    known_cfg, _, known_va = targets[existing]
    missing_cfg, _, missing_va = targets[other]
    _seed_data(known_cfg, known_va)
    result = CliRunner().invoke(
        app,
        [
            "data",
            "pair",
            hex(targets["A"][1]),
            hex(targets["B"][1]),
            "--from",
            "A",
            "--target",
            "B",
            "--size",
            "6",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output or repr(result.exception)
    assert cli_payload(result)["created"] == 1
    assert set(load_data_metadata(known_cfg.metadata_dir)) == {(existing, known_va)}
    assert load_data_metadata(missing_cfg.metadata_dir)[other, missing_va]["name"] == "shared"


@pytest.mark.parametrize("failure", ["metadata", "source", None])
def test_pair_rewrite_and_rows_publish_together(
    targets, monkeypatch: pytest.MonkeyPatch, failure: str | None
) -> None:
    cfg_a, va_a, address_a = targets["A"]
    cfg_b, va_b, address_b = targets["B"]
    source = cfg_a.reversed_dir / "f.c"
    original = f"\r\nint f(void) {{ return *(int *)0x{address_a:x}; }}\r\n".encode()
    source.write_bytes(original)
    source.chmod(0o640)
    _seed_data(cfg_a, address_a)
    before = (cfg_a.metadata_dir / "rebrew-data.toml").read_bytes()

    def fail_after_recording(directory, rows):
        record_data_rows(directory, rows)
        raise OSError("forced metadata failure")

    def fail_to_publish(stage, path, content):
        raise OSError("forced source failure")

    if failure == "metadata":
        monkeypatch.setattr("rebrew.metadata.data.record_data_rows", fail_after_recording)
    elif failure == "source":
        monkeypatch.setattr("rebrew.metadata.coordinated.CoordinatedStage.publish", fail_to_publish)
    result = CliRunner().invoke(
        app,
        [
            "data",
            "pair",
            hex(va_a),
            hex(va_b),
            "--from",
            "A",
            "--target",
            "B",
            "--size",
            "6",
            "--rewrite",
            str(source),
            "--json",
        ],
    )
    assert (cfg_a.metadata_dir / "rebrew-data.toml").read_bytes() == before
    assert source.stat().st_mode & 0o777 == 0o640
    if failure is not None:
        assert isinstance(result.exception, OSError), result.output or repr(result.exception)
        assert source.read_bytes() == original
        assert not load_data_metadata(cfg_b.metadata_dir)
    else:
        assert result.exit_code == 0, result.output or repr(result.exception)
        assert b"*(int *)&shared" in source.read_bytes()
        assert load_data_metadata(cfg_b.metadata_dir)["B", address_b]["name"] == "shared"


class TestPairDataOperands:
    @pytest.mark.parametrize("opcode", ["e8", "e9"])
    def test_external_destinations_are_reported(self, opcode: str) -> None:
        a = bytes.fromhex(opcode + "fb1f0000")
        b = bytes.fromhex(opcode + "fb2f0000")
        pairs, calls = pair_data_operands(a, 0x1000, b, 0x2000, _in_data, _in_data, *X86)
        assert pairs == []
        assert calls == [OperandPair(0, 0x3000, 0x5000)]

    def test_changed_internal_branch_is_refused(self) -> None:
        with pytest.raises(ValueError, match="control flow"):
            pair_data_operands(
                bytes.fromhex("75009090"),
                0x1000,
                bytes.fromhex("75019090"),
                0x2000,
                _in_data,
                _in_data,
                *X86,
            )

    def test_absolute_loads_and_stores_pair_by_position(self) -> None:
        # mov eax, [A]; push eax; call rel32; mov dword [A], -1
        a = bytes.fromhex("a170516700 50 e800000000 c70570516700ffffffff".replace(" ", ""))
        b = bytes.fromhex("a1f8105f00 50 e800000000 c705f8105f00ffffffff".replace(" ", ""))
        pairs, calls = pair_data_operands(a, 0x402320, b, 0x401E50, _in_data, _in_data, *X86)
        assert pairs == [OperandPair(0, 0x675170, 0x5F10F8), OperandPair(11, 0x675170, 0x5F10F8)]
        assert calls == []

    def test_one_sided_data_address_is_refused(self) -> None:
        a = bytes.fromhex("a170516700")
        b = bytes.fromhex("a1f8105f00")
        with pytest.raises(ValueError, match="non-data"):
            pair_data_operands(a, 0x1000, b, 0x2000, _in_data, lambda va: False, *X86)

    def test_different_code_is_refused(self) -> None:
        a = bytes.fromhex("a170516700")
        b = bytes.fromhex("8b0df8105f00")
        with pytest.raises(ValueError, match="differ|different"):
            pair_data_operands(a, 0x1000, b, 0x2000, _in_data, _in_data, *X86)


class TestPlanPairs:
    def test_named_side_creates_the_missing_row(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x675170, 0x5F10F8)],
            {},
            {0x5F10F8: {"name": "g_675170", "size": 4, "type": "int", "kind": "GLOBAL"}},
            _section,
            _section,
        )
        assert plan == [
            {
                "offset": 0,
                "a": "0x00675170",
                "b": "0x005f10f8",
                "action": "create-a",
                "name": "g_675170",
                "size": 4,
                "type": "int",
                "kind": "GLOBAL",
                "section": ".data",
                "a_row": "0x00675170",
                "b_row": "0x005f10f8",
            }
        ]

    def test_interior_operand_creates_the_row_at_the_paired_start(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x675178, 0x5F1100)],
            {},
            {0x5F10F8: {"name": "g_table", "size": 16}},
            _section,
            _section,
        )
        assert (plan[0]["action"], plan[0]["a_row"]) == ("create-a", "0x00675170")

    def test_different_names_are_a_conflict(self) -> None:
        plan = plan_pairs(
            [OperandPair(0, 0x675170, 0x5F10F8)],
            {0x675170: {"name": "g_one", "size": 4}},
            {0x5F10F8: {"name": "g_two", "size": 4}},
            _section,
            _section,
        )
        assert plan[0]["action"] == "conflict"

    def test_unnamed_on_both_sides_is_reported(self) -> None:
        plan = plan_pairs([OperandPair(0, 0x675170, 0x5F10F8)], {}, {}, _section, _section)
        assert plan[0]["action"] == "unnamed"


class TestDeclareExterns:
    def test_empty_line_hosts_declarations_without_moving_lines(self) -> None:
        text = '\n#include "x.h"\n\nvoid f(void)\n{\n}\n'
        out, declared = declare_externs(text, ["g_675170"])
        assert declared == ["g_675170"]
        assert out.splitlines()[0] == "extern char g_675170[];"
        assert len(out.splitlines()) == len(text.splitlines())
