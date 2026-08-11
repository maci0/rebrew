"""Tests for rebrew analyze — the one-shot intelligence dossier."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from rebrew.analyze import build_dossier
from rebrew.main import app

FIXTURES = Path(__file__).parent / "fixtures"


def _cfg() -> SimpleNamespace:
    return SimpleNamespace(root=Path("/nonexistent"), target_binary=FIXTURES / "mini_pe.exe")


class TestBuildDossier:
    def test_pe_dossier_sections(self) -> None:
        d = build_dossier(_cfg(), FIXTURES / "mini_pe.exe")
        assert d["meta"]["format"] == "pe"
        assert d["meta"]["image_base"] == 0x400000
        assert d["meta"]["text_va"] == 0x401000
        names = [s["name"] for s in d["meta"]["sections"]]
        assert ".text" in names
        # Toolchain detection always produces a ToolchainInfo-shaped dict.
        assert set(d["toolchain"]) == {
            "family",
            "version_hint",
            "confidence",
            "detected_by",
            "flags",
            "evidence",
        }
        # The fixture imports exactly one API.
        assert d["imports"]["count"] == 1
        assert d["imports"]["entries"][0]["name"] == "GetTickCount"

    def test_near_match_section(self, tmp_path: Path) -> None:
        """The dossier's near_match section carries blockers + mutations."""
        (tmp_path / "rebrew-function.toml").write_text(
            '["T.0x10002000"]\n'
            'status = "NEAR_MATCHING"\n'
            'blocker = "NEAR_MATCHING — REGISTER (57% of delta) — try: mut_swap_register_keywords"\n',
            encoding="utf-8",
        )
        cfg = SimpleNamespace(
            root=tmp_path,
            target_binary=FIXTURES / "mini_pe.exe",
            metadata_dir=tmp_path,
        )
        d = build_dossier(cfg, FIXTURES / "mini_pe.exe")
        nm = d["near_match"]
        assert nm and nm[0]["va"] == "0x10002000"
        assert "mut_swap_register_keywords" in nm[0]["blocker"]

    def test_near_match_none_without_metadata(self) -> None:
        d = build_dossier(_cfg(), FIXTURES / "mini_pe.exe")
        assert d["near_match"] is None  # mock cfg has no metadata_dir
        assert d["imports"]["entries"][0]["dll"] == "KERNEL32.dll"
        # Strings / references / dispatch are lists or counts, never absent.
        assert isinstance(d["strings"]["count"], int)
        assert isinstance(d["references"]["total"], int)
        assert isinstance(d["dispatch_tables"], list)
        assert d["functions"] is None or isinstance(d["functions"], dict)
        # No flirt_sigs in this project → FLIRT section skipped (null).
        assert d["flirt"] is None

    def test_elf_dossier(self) -> None:
        d = build_dossier(_cfg(), FIXTURES / "mini.elf")
        assert d["meta"]["format"] == "elf"
        assert d["meta"]["image_base"] == 0x400000

    def test_strings_found_in_fixture(self) -> None:
        """mini_pe.exe has no printable strings, but the census still runs."""
        d = build_dossier(_cfg(), FIXTURES / "mini_pe.exe")
        assert d["strings"] == {"count": 0, "top": []}

    def test_missing_binary_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            build_dossier(_cfg(), FIXTURES / "nope.exe")


class TestAnalyzeCli:
    def test_json_purity_and_schema(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """The dossier CLI emits pure JSON with the expected top-level keys."""
        root = tmp_path / "proj"
        (root / "original").mkdir(parents=True)
        (root / "src" / "S").mkdir(parents=True)
        (root / "bin" / "S").mkdir(parents=True)
        (root / "original" / "mini_pe.exe").write_bytes((FIXTURES / "mini_pe.exe").read_bytes())
        (root / "rebrew-project.toml").write_text(
            """\
[project]
name = "p"
default_target = "S"
jobs = 1

[targets."S"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/S"
function_list = "src/S/functions.txt"
bin_dir = "bin/S"
marker = "S"

[compiler]
profile = "gcc-pe"
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
""",
            encoding="utf-8",
        )
        monkeypatch.chdir(root)
        result = CliRunner().invoke(app, ["analyze", "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)  # pure JSON, no preamble
        for key in (
            "binary",
            "meta",
            "toolchain",
            "strings",
            "imports",
            "references",
            "functions",
            "dispatch_tables",
            "flirt",
        ):
            assert key in payload

    def test_missing_binary_errors_as_json(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "proj"
        (root / "original").mkdir(parents=True)
        (root / "src" / "S").mkdir(parents=True)
        (root / "bin" / "S").mkdir(parents=True)
        (root / "rebrew-project.toml").write_text(
            """\
[project]
name = "p"
default_target = "S"
jobs = 1

[targets."S"]
binary = "original/missing.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/S"
function_list = "src/S/functions.txt"
bin_dir = "bin/S"
marker = "S"

[compiler]
profile = "gcc-pe"
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
""",
            encoding="utf-8",
        )
        monkeypatch.chdir(root)
        result = CliRunner().invoke(app, ["analyze", "--json"])
        assert result.exit_code == 1  # error_exit convention
        assert json.loads(result.stdout)["error"]

    def test_standalone_mode_without_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """analyze <binary> works outside a project — binary-driven dossier.

        The whole point of the dossier is intelligence on an *unknown*
        binary; requiring a project first would force setup before
        analysis.  Project-scoped sections (flirt/library/near_match)
        degrade to null/[] instead of aborting.
        """
        monkeypatch.chdir(tmp_path)  # no rebrew-project.toml anywhere
        binary = FIXTURES / "mini_pe.exe"
        result = CliRunner().invoke(app, ["analyze", str(binary), "--json"])
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)  # pure JSON
        assert payload["binary"].endswith("mini_pe.exe")
        assert payload["meta"]["format"] == "pe"
        assert payload["flirt"] is None  # no project sig dir
        assert payload["library"] == []  # no project library headers
        assert "warning:" not in result.stderr  # project backends degrade silently

    def test_standalone_output_report(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Standalone --output writes a Markdown report without warnings."""
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "report.md"
        result = CliRunner().invoke(
            app, ["analyze", str(FIXTURES / "mini_pe.exe"), "--output", str(out)]
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        assert "# Rebrew Analysis" in out.read_text(encoding="utf-8")
        assert "warning:" not in result.stderr

    def test_standalone_requires_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No project + no binary -> a clear error, not a crash."""
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(app, ["analyze", "--json"])
        assert result.exit_code == 1
        assert "no binary given" in json.loads(result.stdout)["error"]


class TestAnalyzeV2:
    """analyze v2: --output Markdown report and --function drill."""

    def _project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        root = tmp_path / "proj"
        (root / "original").mkdir(parents=True)
        (root / "src" / "S").mkdir(parents=True)
        (root / "bin" / "S").mkdir(parents=True)
        (root / "original" / "mini_pe.exe").write_bytes((FIXTURES / "mini_pe.exe").read_bytes())
        (root / "rebrew-project.toml").write_text(
            """\
[project]
name = "p"
default_target = "S"
jobs = 1

[targets."S"]
binary = "original/mini_pe.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/S"
function_list = "src/S/functions.txt"
bin_dir = "bin/S"
marker = "S"

[compiler]
profile = "gcc-pe"
command = "i686-w64-mingw32-gcc"
includes = ""
libs = ""
cflags = "-O2"
base_cflags = ""
timeout = 60
""",
            encoding="utf-8",
        )
        monkeypatch.chdir(root)
        return root

    def test_output_writes_markdown(self, tmp_path: Path, monkeypatch) -> None:
        root = self._project(tmp_path, monkeypatch)
        report = root / "report.md"
        result = CliRunner().invoke(app, ["analyze", "--output", str(report)])
        assert result.exit_code == 0, result.output
        text = report.read_text(encoding="utf-8")
        assert text.startswith("# Rebrew Analysis")
        for heading in ("## Sections", "## Toolchain", "## Strings", "## Imports"):
            assert heading in text
        assert ".text" in text

    def test_function_drill_in_report(self, tmp_path: Path, monkeypatch) -> None:
        root = self._project(tmp_path, monkeypatch)
        report = root / "report.md"
        result = CliRunner().invoke(
            app, ["analyze", "--function", "0x401000", "--output", str(report)]
        )
        assert result.exit_code == 0, result.output
        text = report.read_text(encoding="utf-8")
        assert "## Function drill" in text
        assert "0x00401000" in text
        assert "### Callers" in text

    def test_output_conflicts_with_json(self, tmp_path: Path, monkeypatch) -> None:
        root = self._project(tmp_path, monkeypatch)
        result = CliRunner().invoke(app, ["analyze", "--json", "--output", str(root / "r.md")])
        assert result.exit_code == 1
        assert "cannot be combined" in result.output


class TestDispatchTablesShape:
    """Corpus regression: analyze must not assume DispatchTable internals."""

    def test_collect_dispatch_uses_real_fields(self, monkeypatch) -> None:
        from types import SimpleNamespace

        from rebrew.analyze import _collect_dispatch
        from rebrew.data import DispatchEntry, DispatchTable

        tables = [
            DispatchTable(
                va=0x5000,
                section=".rdata",
                entries=[
                    DispatchEntry(target_va=0x401000, name="f1"),
                    DispatchEntry(target_va=0x402000),  # unresolved
                ],
            )
        ]
        monkeypatch.setattr("rebrew.data.find_dispatch_tables", lambda *a, **k: tables)
        out = _collect_dispatch(SimpleNamespace(data=b"", sections={}))
        assert out == [{"va": "0x00005000", "section": ".rdata", "entries": 2, "resolved": 1}]


class TestLibrarySection:
    """J10: the dossier carries a library-glue view."""

    def test_dossier_includes_library(self, tmp_path: Path, monkeypatch) -> None:
        from rebrew.analyze import build_dossier

        monkeypatch.setattr(
            "rebrew.identify_library.collect_candidates",
            lambda cfg: [
                type(
                    "C",
                    (),
                    {
                        "va": 0x40DCE0,
                        "name": "DirectDrawCreate",
                        "module": "DDRAW",
                        "kind": "import",
                        "confidence": 0.3,
                    },
                )()
            ],
        )
        d = build_dossier(_cfg(), FIXTURES / "mini_pe.exe")
        assert d["library"] == [
            {
                "va": "0x0040dce0",
                "name": "DirectDrawCreate",
                "module": "DDRAW",
                "kind": "import",
                "confidence": 0.3,
            }
        ]


class TestFarCalls:
    """_collect_far_calls catalogs distinct lcall targets for NE binaries."""

    def test_ne_far_call_catalog(self, tmp_path: Path) -> None:
        from test_ne_loader import _build_ne

        from rebrew.analyze import _collect_far_calls

        # Code: marker + push bp; mov bp,sp; lcall 1:2 twice; pop bp; ret
        code = bytes.fromhex("55 8b ec 9a 02 00 01 00 9a 02 00 01 00 5d c3")
        raw = _build_ne(segments=[(b"\x01\x00" + code, 0x01)], autodata=1)
        p = tmp_path / "app.ne"
        p.write_bytes(raw)
        out = _collect_far_calls(p)
        assert out is not None
        # One distinct target, counted twice, mapped to segment 1 (selector
        # <= the segment count follows Borland's index convention).
        assert len(out) == 1
        assert out[0]["selector"] == "0x0001"
        assert out[0]["count"] == 2
        assert out[0]["segment"] == 1

    def test_pe_returns_none(self, tmp_path: Path) -> None:
        from rebrew.analyze import _collect_far_calls

        p = tmp_path / "app.exe"
        p.write_bytes(b"MZ" + b"\x00" * 0x40 + b"\x00" * 0x40 + b"PE\x00\x00")
        assert _collect_far_calls(p) is None
