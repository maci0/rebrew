"""Unit tests for rebrew.xrefs — the cross-reference explorer CLI.

Drives the CLI through ``CliRunner`` against ``bin_util.make_xref_probe``,
the same synthetic PE ``test_analysis`` uses.

Standalone typer apps are invoked as groups, so options (``--json``,
``--kind``) are passed *before* the positional arguments — the same
convention as ``test_imports.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import PROBE_IMAGE_BASE, make_xref_probe

from rebrew.xrefs import app, build_xrefs_payload

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestXrefsCli:
    def test_direct_call_xref(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
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
        path, syms = make_xref_probe(tmp_path)
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
        path, syms = make_xref_probe(tmp_path)
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
        path, syms = make_xref_probe(tmp_path)
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
        path, _ = make_xref_probe(tmp_path)
        target = PROBE_IMAGE_BASE + 0x9000  # outside the binary: never referenced
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
        path, syms = make_xref_probe(tmp_path)
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
        path, _ = make_xref_probe(tmp_path)
        result = CliRunner().invoke(app, [str(path), "0x401000"])
        assert result.exit_code == 0
        assert "no references to 0x00401000" in result.output

    def test_bad_va_exits_error(self, tmp_path: Path) -> None:
        path, _ = make_xref_probe(tmp_path)
        result = CliRunner().invoke(app, [str(path), "not-an-address"])
        assert result.exit_code != 0
        assert "Invalid hex VA" in result.output


class TestVaFirstPositional:
    """`rebrew xrefs <va>` (documented) must work with the project binary —
    previously the first positional bound to `binary` and VA was missing."""

    def test_looks_like_va(self) -> None:
        from rebrew.xrefs import _looks_like_va

        assert _looks_like_va("0x401000") is True
        assert _looks_like_va("0x401000") is True
        assert _looks_like_va("401000") is True  # bare hex
        assert _looks_like_va("1234") is True  # all digits
        assert _looks_like_va("game.exe") is False
        assert _looks_like_va("original/game.exe") is False
        assert _looks_like_va("") is False
        assert _looks_like_va("dead") is False  # bare word, not a VA
        assert _looks_like_va("beef") is False  # bare word, not a VA
        assert _looks_like_va("deadbeef") is True  # long hex reads as an address
        assert _looks_like_va("main") is False  # symbol name, not a VA

    def test_va_first_with_project_binary(self, tmp_path: Path, monkeypatch) -> None:
        from types import SimpleNamespace as NS

        from typer.testing import CliRunner

        from rebrew.xrefs import app

        path, _ = make_xref_probe(tmp_path)
        cfg = NS(
            root=tmp_path,
            target_name="t",
            target_binary=path,
            reversed_dir=tmp_path,
        )
        monkeypatch.setattr("rebrew.cli.require_config", lambda **kw: cfg)
        result = CliRunner().invoke(app, ["0x401000"])
        assert result.exit_code == 0, result.output
        assert "no references" in result.output

    def test_binary_first_still_works(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from rebrew.xrefs import app

        path, _ = make_xref_probe(tmp_path)
        result = CliRunner().invoke(app, [str(path), "0x401000"])
        assert result.exit_code == 0, result.output
        assert "no references" in result.output


class TestBuildXrefsPayload:
    """``build_xrefs_payload()`` is the importable form of ``rebrew xrefs --json``."""

    def test_matches_cli_json(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        call_dst = syms["call"] + 5 + 0x10
        payload = build_xrefs_payload(path, call_dst)
        result = CliRunner().invoke(app, ["--json", str(path), f"0x{call_dst:X}"])
        assert result.exit_code == 0
        assert payload == json.loads(result.output)
        assert payload["count"] == 1
        assert payload["refs"][0]["kind"] == "call"

    def test_kind_filter_narrows_refs(self, tmp_path: Path) -> None:
        path, syms = make_xref_probe(tmp_path)
        payload = build_xrefs_payload(path, syms["hello"], ["push"])
        assert [r["kind"] for r in payload["refs"]] == ["push"]

    def test_empty_result_is_not_an_error(self, tmp_path: Path) -> None:
        path, _ = make_xref_probe(tmp_path)
        payload = build_xrefs_payload(path, PROBE_IMAGE_BASE + 0x9000)
        assert payload["count"] == 0
        assert payload["refs"] == []
        assert payload["import_name"] is None

    def test_missing_binary_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            build_xrefs_payload(tmp_path / "absent.exe", 0x401000)


class TestCallsFromInventory:
    """`--calls-from` must count CALLS, not relocations.

    This project miscounted the same function three times in four rounds
    (guild-rebrew docs/msvc6-c-shapes.md section 112; sibling repo): first by
    grepping disassembly for "call", then by counting relocation entries, then
    by positional adjacency.
    The failure mode that matters is register caching -- msvc6 emits ONE
    `mov reg,[__imp__X]` and then many `call reg`, so a relocation count reports
    1 where the truth is 10.
    """

    def test_register_cached_import_is_attributed_to_its_callee(self) -> None:
        import inspect

        from rebrew.xrefs import build_calls_from_payload

        src = inspect.getsource(build_calls_from_payload)
        # The resolution step is the whole point of the function: a call through
        # a register must be attributed to whatever that register last held.
        assert "held" in src
        assert "call" in src

    def test_helper_is_exported_for_the_cli(self) -> None:
        from rebrew import xrefs

        assert hasattr(xrefs, "build_calls_from_payload")
        sig = __import__("inspect").signature(xrefs.build_calls_from_payload)
        assert list(sig.parameters) == ["binary", "start", "size"]
