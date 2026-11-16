"""Tests for ``rebrew binary asm show --format cfg`` — one function's CFG from the CLI.

The payload is what a renderer consumes: per block its absolute VA, byte
size, instruction count and first/last instruction text; per edge the
absolute VAs it connects and a back-edge marker.  The fixtures are the same
shapes the ``cfg_ged`` unit tests use (straight line, if/else, loop with a
back edge), driven through the real CLI surface.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
lazy from pathlib import Path

import capstone
import pytest
import typer
from cli_json import cli_payload
from typer.testing import CliRunner, Result

import rebrew.asm as asm
import rebrew.cfg_ged as cfg_ged
import rebrew.formats.binary_loader as binary_loader

runner = CliRunner()

BASE_VA = 0x01001000

# cmp eax,1; je +7; mov eax,1; jmp +5 (onto the ret); mov eax,2; ret — 4 blocks, 4 edges
IFELSE = bytes.fromhex("83 f8 01 74 07 b8 01 00 00 00 eb 05 b8 02 00 00 00 c3")
# mov ecx,4; dec ecx; jne -3; ret — loop with a back edge
LOOP = bytes.fromhex("b9 04 00 00 00 49 75 fd c3")
# mov eax,1; add eax,1; ret — straight-line flow, 1 block
STRAIGHT = bytes.fromhex("b8 01 00 00 00 83 c0 01 c3")

#: zlib's ``adler32`` as MSVC 6 compiled it into guild-rebrew's server.dll
#: (0x10001000, 302 bytes; zlib license).  Seven conditional jumps, four of
#: them into the middle of a run of straight-line code, two of them loops.
ADLER32_VA = 0x10001000
ADLER32 = bytes.fromhex(
    "568b74240c578b7c240c8bcf81e1ffff0000c1ef1085f675085fb8010000005e"
    "c3538b5c241885db0f86f50000005581fbb01500008bc37205b8b01500002bd8"
    "83f8100f8ca70000008be8c1ed048bd5f7dac1e20403c233d28a1683c61003ca"
    "33d28a56f103f903ca33d28a56f203f903ca33d28a56f303f903ca33d28a56f4"
    "03f903ca33d28a56f503f903ca33d28a56f603f903ca33d28a56f703f903ca33"
    "d28a56f803f903ca33d28a56f903f903ca33d28a56fa03f903ca33d28a56fb03"
    "f903ca33d28a56fc03f903ca33d28a56fd03f903ca33d28a56fe03f903ca33d2"
    "8a56ff03f903ca03f94d0f8567ffffff85c0740c33d28a1603ca4603f94875f4"
    "8bc133d2b9f1ff0000f7f18bc7bff1ff00008bca33d2f7f785db8bfa0f870dff"
    "ffff5d8bc75bc1e0105f0bc15ec3"
)


def _app() -> typer.Typer:
    """The standalone command app (the wiring ``asm.show_entry`` uses)."""
    app = typer.Typer()
    app.command()(asm.show)
    return app


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    code: bytes,
    *,
    declared: int | None = None,
    walked: int | None = None,
    arch: str = "x86_32",
) -> SimpleNamespace:
    """Stub the CLI's config, byte reader and extent walker.

    *declared* is the function-list size (written to a real functions.txt),
    *walked* the disassembly walk's extent; both ``None`` means an extent the
    engine cannot resolve.  Returns the stub config so a direct call can
    share the same inputs as the CLI.
    """
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x90")
    if declared is not None:
        import json as _json

        (tmp_path / "function_structure.json").write_text(
            _json.dumps([{"va": BASE_VA, "size": declared, "name": "func"}]),
            encoding="utf-8",
        )
    cfg = SimpleNamespace(
        root=tmp_path,
        target_binary=binary,
        reversed_dir=tmp_path,
        arch=arch,
        capstone_mode=capstone.CS_MODE_32,
    )
    monkeypatch.setattr(asm, "require_config", lambda target=None, json_mode=False: cfg)
    monkeypatch.setattr(binary_loader, "extract_raw_bytes", lambda path, va, size: code)
    monkeypatch.setattr(binary_loader, "function_extent_from_disasm", lambda path, va: walked)
    return cfg


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    code: bytes,
    *extra: str,
    **patch_kwargs: Any,
) -> Result:
    """Invoke ``rebrew binary asm show <va> --format cfg`` against stubbed inputs."""
    _patch(monkeypatch, tmp_path, code, **patch_kwargs)
    return runner.invoke(_app(), [f"0x{BASE_VA:x}", "--format", "cfg", *extra])


def _payload(result: Result) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    return cli_payload(result)


class TestCfgJsonPayload:
    def test_ifelse_blocks_carry_absolute_vas_and_labels(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, IFELSE, "--size", "18", "--json"))
        assert payload["va"] == "0x01001000"
        assert payload["size"] == len(IFELSE)
        assert payload["block_total"] == 4
        assert payload["truncated"] is False
        assert payload["note"] is None
        blocks = payload["blocks"]
        assert [b["va"] for b in blocks] == [
            "0x01001000",
            "0x01001005",
            "0x0100100c",
            "0x01001011",
        ]
        assert blocks[0] == {
            "va": "0x01001000",
            "size": 5,
            "instruction_count": 2,
            "first": "cmp eax, 1",
            "last": "je 0x100100c",
        }
        assert blocks[2]["first"] == blocks[2]["last"] == "mov eax, 2"
        assert blocks[3]["first"] == "ret"
        assert [(e["from"], e["to"], e["back_edge"], e["kind"]) for e in payload["edges"]] == [
            ("0x01001000", "0x0100100c", False, "taken"),
            ("0x01001000", "0x01001005", False, "not_taken"),
            ("0x01001005", "0x01001011", False, "unconditional"),
            ("0x0100100c", "0x01001011", False, "unconditional"),
        ]

    def test_loop_edge_marked_back_edge(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, LOOP, "--size", "9", "--json"))
        assert [b["va"] for b in payload["blocks"]] == ["0x01001000", "0x01001005", "0x01001008"]
        assert payload["edges"] == [
            {"from": "0x01001000", "to": "0x01001005", "back_edge": False, "kind": "unconditional"},
            {"from": "0x01001005", "to": "0x01001005", "back_edge": True, "kind": "taken"},
            {"from": "0x01001005", "to": "0x01001008", "back_edge": False, "kind": "not_taken"},
        ]

    def test_jump_targets_start_blocks_on_adler32(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Every edge lands on the jump's own operand, not on the block around it.

        Production answered ``jbe 0x10001123`` with an edge to 0x10001122 (the
        ``pop ebp`` block holding the target), and ``ja 0x1000102f`` with one
        to 0x1000102e.
        """
        _patch(monkeypatch, tmp_path, ADLER32)
        result = runner.invoke(
            _app(), [f"0x{ADLER32_VA:x}", "--format", "cfg", "--size", "302", "--json"]
        )
        payload = _payload(result)
        assert [int(b["va"], 16) - ADLER32_VA for b in payload["blocks"]] == [
            0x00,
            0x19,
            0x21,
            0x2E,
            0x2F,
            0x39,
            0x3E,
            0x49,
            0x57,
            0xF0,
            0xF4,
            0x100,
            0x122,
            0x123,
        ]
        edges = [
            (
                int(e["from"], 16) - ADLER32_VA,
                int(e["to"], 16) - ADLER32_VA,
                e["kind"],
                e["back_edge"],
            )
            for e in payload["edges"]
        ]
        assert edges == [
            (0x00, 0x21, "taken", False),  # jne
            (0x00, 0x19, "not_taken", False),
            (0x21, 0x123, "taken", False),  # jbe
            (0x21, 0x2E, "not_taken", False),
            (0x2E, 0x2F, "unconditional", False),  # push ebp, then the outer loop head
            (0x2F, 0x3E, "taken", False),  # jb
            (0x2F, 0x39, "not_taken", False),
            (0x39, 0x3E, "unconditional", False),
            (0x3E, 0xF0, "taken", False),  # jl
            (0x3E, 0x49, "not_taken", False),
            (0x49, 0x57, "unconditional", False),
            (0x57, 0x57, "taken", True),  # jne: the 16-byte loop
            (0x57, 0xF0, "not_taken", False),
            (0xF0, 0x100, "taken", False),  # je
            (0xF0, 0xF4, "not_taken", False),
            (0xF4, 0xF4, "taken", True),  # jne: the 1-byte loop
            (0xF4, 0x100, "not_taken", False),
            (0x100, 0x2F, "taken", True),  # ja: the outer loop
            (0x100, 0x122, "not_taken", False),
            (0x122, 0x123, "unconditional", False),  # pop ebp, then the jbe target
        ]

    def test_straight_line_single_block_no_edges(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, STRAIGHT, "--size", "9", "--json"))
        assert [b["va"] for b in payload["blocks"]] == ["0x01001000"]
        assert payload["blocks"][0]["instruction_count"] == 3
        assert payload["blocks"][0]["first"] == "mov eax, 1"
        assert payload["blocks"][0]["last"] == "ret"
        assert payload["edges"] == []

    def test_extent_comes_from_the_function_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, IFELSE, "--json", declared=len(IFELSE)))
        assert payload["size"] == len(IFELSE)
        assert payload["block_total"] == 4


class TestCfgEmptyAnswers:
    def test_empty_bytes_answer_blocks_with_a_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, b"", "--size", "16", "--json"))
        assert payload["blocks"] == []
        assert payload["edges"] == []
        assert payload["size"] == 0
        assert payload["note"] == "no bytes readable at 0x01001000"

    def test_unresolved_extent_answers_blocks_with_a_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, IFELSE, "--json"))
        assert payload["blocks"] == []
        assert payload["edges"] == []
        assert payload["size"] == 0
        assert payload["note"] is not None
        assert "extent unresolved" in payload["note"]

    def test_undecodable_bytes_note_comes_from_the_segmenter(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, b"\xff\xff", "--size", "2", "--json"))
        assert payload["blocks"] == []
        assert payload["note"] == "no decodable instructions"


class TestCfgCap:
    def test_cap_states_true_count_and_truncation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(cfg_ged, "MAX_CFG_BLOCKS_PER_FUNCTION", 2)
        payload = _payload(_run(monkeypatch, tmp_path, IFELSE, "--size", "18", "--json"))
        assert payload["block_cap"] == 2
        assert payload["block_total"] == 4
        assert payload["block_count"] == 2
        assert payload["truncated"] is True
        assert len(payload["blocks"]) == 2
        kept = {b["va"] for b in payload["blocks"]}
        assert all(e["from"] in kept and e["to"] in kept for e in payload["edges"])


class TestCfgHumanRendering:
    def test_human_rendering_labels_blocks_and_back_edge(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch(monkeypatch, tmp_path, LOOP, declared=len(LOOP))
        result = runner.invoke(_app(), [f"0x{BASE_VA:x}", "--format", "cfg"])
        assert result.exit_code == 0, result.output
        assert "CFG for 0x01001000 (9 bytes, 3 blocks, 3 edges)" in result.output
        assert "B0  0x01001000" in result.output
        assert "dec ecx ... jne 0x1001005" in result.output
        assert "0x01001000 -> 0x01001005  unconditional\n" in result.output
        assert "0x01001005 -> 0x01001005  taken  back edge" in result.output
        assert "0x01001005 -> 0x01001008  not_taken\n" in result.output

    def test_human_rendering_keeps_operand_brackets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``[esp + 4]`` is Rich markup syntax: the rendering must not eat it."""
        code = bytes.fromhex("8b 44 24 04 c3")  # mov eax, [esp+4]; ret
        _patch(monkeypatch, tmp_path, code, declared=len(code))
        result = runner.invoke(_app(), [f"0x{BASE_VA:x}", "--format", "cfg"])
        assert result.exit_code == 0, result.output
        assert "[esp + 4]" in result.output


class TestCfgUsageErrors:
    def test_cfg_requires_a_va(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path, IFELSE)
        raw = tmp_path / "raw.bin"
        raw.write_bytes(b"")
        result = runner.invoke(_app(), ["--bin", str(raw), "--format", "cfg", "--json"])
        assert result.exit_code == 2
        assert "--format cfg requires a VA" in cli_payload(result)["error"]

    def test_cfg_rejects_non_x86_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _run(monkeypatch, tmp_path, IFELSE, "--size", "18", "--json", arch="arm32")
        assert result.exit_code == 2
        assert "x86 targets only" in cli_payload(result)["error"]

    def test_unknown_format_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path, IFELSE)
        result = runner.invoke(_app(), [f"0x{BASE_VA:x}", "--format", "bogus"])
        assert result.exit_code == 2


class TestBuildCfgPayload:
    """``build_cfg_payload()`` is the importable form of ``--format cfg --json``."""

    def test_matches_cli_with_an_explicit_size(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _patch(monkeypatch, tmp_path, IFELSE)
        payload = asm.build_cfg_payload(cfg, BASE_VA, len(IFELSE))
        cli = _payload(_run(monkeypatch, tmp_path, IFELSE, "--size", "18", "--json"))
        assert payload == cli
        assert payload["block_total"] == 4

    def test_resolves_the_size_from_the_function_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _patch(monkeypatch, tmp_path, IFELSE, declared=len(IFELSE))
        payload = asm.build_cfg_payload(cfg, BASE_VA)
        assert payload["size"] == len(IFELSE)
        assert payload["block_total"] == 4

    def test_unresolved_extent_answers_a_note(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = _patch(monkeypatch, tmp_path, IFELSE)
        payload = asm.build_cfg_payload(cfg, BASE_VA)
        assert payload["blocks"] == []
        assert "extent unresolved" in payload["note"]

    def test_reads_a_jump_table_past_the_extent_from_the_image(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """zlib's ``inflate`` with an extent that stops at its jump table: the
        CLI (and the ``rebrew.control_flow_graph`` op, through this payload)
        reads the table from the target PE and gives one ``switch`` edge per case."""
        from bin_util import make_pe
        from memory_cap import address_space_cap
        from test_cfg_ged import (
            INFLATE,
            INFLATE_CASES,
            INFLATE_JMP_VA,
            INFLATE_TABLE_VA,
            INFLATE_VA,
        )

        text_va = INFLATE_VA & ~0xFFF
        binary = tmp_path / "server.dll"
        binary.write_bytes(
            make_pe(
                b"\xcc" * (INFLATE_VA - text_va) + INFLATE,
                image_base=0x10000000,
                text_va=text_va - 0x10000000,
            )
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            target_binary=binary,
            reversed_dir=tmp_path,
            arch="x86_32",
            capstone_mode=capstone.CS_MODE_32,
        )
        monkeypatch.setattr(asm, "require_config", lambda target=None, json_mode=False: cfg)
        size = INFLATE_TABLE_VA - INFLATE_VA
        with address_space_cap():
            result = runner.invoke(
                _app(), [f"0x{INFLATE_VA:x}", "--format", "cfg", "--size", str(size), "--json"]
            )
        switch = [e for e in _payload(result)["edges"] if e["kind"] == "switch"]
        assert {e["from"] for e in switch} == {f"0x{INFLATE_JMP_VA:08x}"}
        assert [e["to"] for e in switch] == [f"0x{va:08x}" for va in INFLATE_CASES]
