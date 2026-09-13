"""Tests for ``rebrew asm --format cfg`` — one function's CFG from the CLI.

The payload is what a renderer consumes: per block its absolute VA, byte
size, instruction count and first/last instruction text; per edge the
absolute VAs it connects and a back-edge marker.  The fixtures are the same
shapes the ``cfg_ged`` unit tests use (straight line, if/else, loop with a
back edge), driven through the real CLI surface.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import capstone
import pytest
import typer
from typer.testing import CliRunner, Result

import rebrew.asm as asm
import rebrew.binary_loader as binary_loader
import rebrew.cfg_ged as cfg_ged

runner = CliRunner()

BASE_VA = 0x01001000

# cmp eax,1; je +7; mov eax,1; jmp +5; mov eax,2; ret — 3 blocks, 3 edges
IFELSE = bytes.fromhex("83 f8 01 74 07 b8 01 00 00 00 eb 05 b8 02 00 00 00 c3")
# mov ecx,4; dec ecx; jne -3; ret — loop with a back edge
LOOP = bytes.fromhex("b9 04 00 00 00 49 75 fd c3")
# mov eax,1; add eax,1; ret — straight-line flow, 1 block
STRAIGHT = bytes.fromhex("b8 01 00 00 00 83 c0 01 c3")


def _app() -> typer.Typer:
    """The standalone command app (the wiring ``asm.main_entry`` uses)."""
    app = typer.Typer()
    app.command()(asm.main)
    return app


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    code: bytes,
    *,
    declared: int | None = None,
    walked: int | None = None,
    arch: str = "x86_32",
) -> None:
    """Stub the CLI's config, byte reader and extent walker.

    *declared* is the function-list size (written to a real functions.txt),
    *walked* the disassembly walk's extent; both ``None`` means an extent the
    engine cannot resolve.
    """
    binary = tmp_path / "target.bin"
    binary.write_bytes(b"\x90")
    functions = tmp_path / "functions.txt"
    if declared is not None:
        functions.write_text(f"0x{BASE_VA:x} func {declared}\n", encoding="utf-8")
    cfg = SimpleNamespace(
        root=tmp_path,
        target_binary=binary,
        arch=arch,
        capstone_mode=capstone.CS_MODE_32,
        function_list=str(functions) if declared is not None else "",
    )
    monkeypatch.setattr(asm, "require_config", lambda target=None, json_mode=False: cfg)
    monkeypatch.setattr(binary_loader, "extract_raw_bytes", lambda path, va, size: code)
    monkeypatch.setattr(binary_loader, "function_extent_from_disasm", lambda path, va: walked)


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    code: bytes,
    *extra: str,
    **patch_kwargs: Any,
) -> Result:
    """Invoke ``rebrew asm <va> --format cfg`` against stubbed inputs."""
    _patch(monkeypatch, tmp_path, code, **patch_kwargs)
    return runner.invoke(_app(), [f"0x{BASE_VA:x}", "--format", "cfg", *extra])


def _payload(result: Result) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


class TestCfgJsonPayload:
    def test_ifelse_blocks_carry_absolute_vas_and_labels(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, IFELSE, "--size", "18", "--json"))
        assert payload["va"] == "0x01001000"
        assert payload["size"] == len(IFELSE)
        assert payload["block_total"] == 3
        assert payload["truncated"] is False
        assert payload["note"] is None
        blocks = payload["blocks"]
        assert [b["va"] for b in blocks] == ["0x01001000", "0x01001005", "0x0100100c"]
        assert blocks[0] == {
            "va": "0x01001000",
            "size": 5,
            "instruction_count": 2,
            "first": "cmp eax, 1",
            "last": "je 0x100100c",
        }
        assert blocks[2]["first"] == "mov eax, 2"
        assert blocks[2]["last"] == "ret"
        assert {(e["from"], e["to"], e["back_edge"]) for e in payload["edges"]} == {
            ("0x01001000", "0x0100100c", False),
            ("0x01001000", "0x01001005", False),
            ("0x01001005", "0x0100100c", False),
        }

    def test_loop_edge_marked_back_edge(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        payload = _payload(_run(monkeypatch, tmp_path, LOOP, "--size", "9", "--json"))
        assert [b["va"] for b in payload["blocks"]] == ["0x01001000", "0x01001008"]
        assert {"from": "0x01001000", "to": "0x01001000", "back_edge": True} in payload["edges"]
        assert {"from": "0x01001000", "to": "0x01001008", "back_edge": False} in payload["edges"]

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
        assert payload["block_total"] == 3


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
        assert payload["block_total"] == 3
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
        assert "CFG for 0x01001000 (9 bytes, 2 blocks, 2 edges)" in result.output
        assert "B0  0x01001000" in result.output
        assert "mov ecx, 4 ... jne 0x1001005" in result.output
        assert "0x01001000 -> 0x01001000  back edge" in result.output
        assert "0x01001000 -> 0x01001008" in result.output

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
        assert "--format cfg requires a VA" in json.loads(result.output)["error"]

    def test_cfg_rejects_non_x86_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = _run(monkeypatch, tmp_path, IFELSE, "--size", "18", "--json", arch="arm32")
        assert result.exit_code == 2
        assert "x86 targets only" in json.loads(result.output)["error"]

    def test_unknown_format_rejected(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _patch(monkeypatch, tmp_path, IFELSE)
        result = runner.invoke(_app(), [f"0x{BASE_VA:x}", "--format", "bogus"])
        assert result.exit_code == 2
