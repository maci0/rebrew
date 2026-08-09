"""Unit tests for rebrew.strings — the ``rebrew strings`` CLI tool.

Drives the Typer app via ``CliRunner`` against synthetic PEs built by
``bin_util.make_pe`` (a single ``.text`` section), whose code bytes embed
string blobs — and, for the xref test, a ``push imm32`` that references one.

The probe binary has no data-ish sections, so the default section scan finds
nothing: tests that need real extraction pass ``--section .text``.

Note on invocation order: these callback-style apps are click Groups, and
click groups parse options only up to the first positional token.  Like the
rest of the test suite (e.g. ``test_crt_match.py``), options are therefore
passed BEFORE the positional binary path.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))  # tests/ on path for bin_util
from bin_util import make_pe  # noqa: E402
from typer.testing import CliRunner  # noqa: E402

from rebrew.strings import app  # noqa: E402

TEXT_VA = 0x401000  # make_pe default: image_base 0x400000 + text_va 0x1000

runner = CliRunner()


def _write_probe(tmp_path: Path, code: bytes, name: str = "probe.exe") -> Path:
    """Write *code* as the .text payload of a synthetic PE; return its path."""
    path = tmp_path / name
    path.write_bytes(make_pe(code))
    return path


class TestExtractStrings:
    def test_ascii_extraction(self, tmp_path: Path) -> None:
        code = b"Hello World\x00" + b"Game Boy\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, ["--section", ".text", str(path)], env={"COLUMNS": "200"})
        assert result.exit_code == 0
        assert "Hello World" in result.output
        assert "Game Boy" in result.output
        assert f"0x{TEXT_VA:08x}" in result.output
        assert "ascii" in result.output

    def test_min_len_filters(self, tmp_path: Path) -> None:
        code = b"AB\x00" + b"LongEnoughString\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        short = runner.invoke(app, ["--json", "--min-len", "2", "--section", ".text", str(path)])
        assert short.exit_code == 0
        texts = [s["text"] for s in json.loads(short.stdout)["strings"]]
        assert texts == ["AB", "LongEnoughString"]
        long = runner.invoke(app, ["--json", "--min-len", "10", "--section", ".text", str(path)])
        assert [s["text"] for s in json.loads(long.stdout)["strings"]] == ["LongEnoughString"]

    def test_utf16_extraction(self, tmp_path: Path) -> None:
        code = b"H\x00i\x00\x00\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, ["--json", "--min-len", "2", "--section", ".text", str(path)])
        assert result.exit_code == 0
        strings = json.loads(result.stdout)["strings"]
        assert len(strings) == 1
        assert strings[0]["text"] == "Hi"
        assert strings[0]["kind"] == "utf16"
        assert strings[0]["size"] == 4


class TestFilter:
    def test_case_insensitive_regex(self, tmp_path: Path) -> None:
        code = b"Hello World\x00" + b"Goodbye Moon\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(
            app, ["--json", "--section", ".text", "--filter", "WORLD", str(path)]
        )
        assert result.exit_code == 0
        texts = [s["text"] for s in json.loads(result.stdout)["strings"]]
        assert texts == ["Hello World"]

    def test_no_match_yields_empty(self, tmp_path: Path) -> None:
        code = b"Hello World\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, ["--json", "--section", ".text", "--filter", "zzz", str(path)])
        assert json.loads(result.stdout)["count"] == 0


class TestSectionSelection:
    def test_no_data_sections_note(self, tmp_path: Path) -> None:
        """Probe has only .text: default scan finds nothing, exits OK."""
        code = b"Hello World\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, [str(path)], env={"COLUMNS": "200"})
        assert result.exit_code == 0
        assert "nothing to scan" in result.output

    def test_no_data_sections_json(self, tmp_path: Path) -> None:
        code = b"Hello World\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, ["--json", str(path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["count"] == 0
        assert data["strings"] == []

    def test_section_override_scans_text(self, tmp_path: Path) -> None:
        code = b"Hello World\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, ["--json", "--section", ".text", str(path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["count"] == 1
        assert data["strings"][0]["section"] == ".text"


class TestXrefs:
    def _probe(self, tmp_path: Path) -> Path:
        str_va = TEXT_VA + 6  # after `push imm32` (5 bytes) + `ret` (1 byte)
        code = b"\x68" + struct.pack("<I", str_va) + b"\xc3" + b"Referenced String\x00"
        return _write_probe(tmp_path, code)

    def test_table_lists_referencing_addresses(self, tmp_path: Path) -> None:
        path = self._probe(tmp_path)
        result = runner.invoke(
            app, ["--xref", "--section", ".text", str(path)], env={"COLUMNS": "200"}
        )
        assert result.exit_code == 0
        assert f"1: 0x{TEXT_VA:08x}" in result.output
        assert "Referenced String" in result.output

    def test_json_lists_all_xrefs(self, tmp_path: Path) -> None:
        path = self._probe(tmp_path)
        result = runner.invoke(app, ["--xref", "--json", "--section", ".text", str(path)])
        assert result.exit_code == 0
        strings = json.loads(result.stdout)["strings"]
        assert len(strings) == 1
        assert strings[0]["xrefs"] == [{"kind": "push", "from_va": TEXT_VA}]

    def test_no_xref_flag_leaves_xrefs_empty(self, tmp_path: Path) -> None:
        path = self._probe(tmp_path)
        result = runner.invoke(app, ["--json", "--section", ".text", str(path)])
        assert json.loads(result.stdout)["strings"][0]["xrefs"] == []


class TestJsonOutput:
    def test_envelope_shape(self, tmp_path: Path) -> None:
        code = b"Hello World\x00" + b"Game Boy\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, ["--json", "--section", ".text", str(path)])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert set(data) == {"binary", "count", "strings"}
        assert data["binary"] == str(path)
        assert data["count"] == 2
        assert data["strings"][0] == {
            "va": TEXT_VA,
            "section": ".text",
            "kind": "ascii",
            "size": 11,
            "text": "Hello World",
            "xrefs": [],
        }
        assert [s["text"] for s in data["strings"]] == ["Hello World", "Game Boy"]


class TestBinaryArgument:
    def test_positional_binary(self, tmp_path: Path) -> None:
        code = b"Hello World\x00" + b"\xc3"
        path = _write_probe(tmp_path, code)
        result = runner.invoke(app, ["--json", "--section", ".text", str(path)])
        assert result.exit_code == 0
        assert json.loads(result.stdout)["binary"] == str(path)


class TestErrors:
    def test_missing_binary(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.exe"
        result = runner.invoke(app, [str(missing)])
        assert result.exit_code == 1
        assert "binary not found" in result.output

    def test_missing_binary_json(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.exe"
        result = runner.invoke(app, ["--json", str(missing)])
        assert result.exit_code == 1
        data = json.loads(result.stdout)
        assert data["code"] == 1
        assert "binary not found" in data["error"]

    def test_invalid_filter_regex(self, tmp_path: Path) -> None:
        path = _write_probe(tmp_path, b"Hello World\x00" + b"\xc3")
        result = runner.invoke(app, ["--filter", "[", str(path)], env={"COLUMNS": "200"})
        assert result.exit_code == 2
        assert "invalid --filter regex" in result.output
