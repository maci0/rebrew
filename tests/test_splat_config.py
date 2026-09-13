"""Tests for splat_config.py: reading a splat config and `rebrew import-splat`.

The fixture under ``fixtures/splat_config/`` is a hand-written splat config for
a minimal PE built here (``_build_pe``), so these tests exercise the real path:
parse the YAML, plan against a real project directory, and write through the
same writers the project's other tools use.
"""

from __future__ import annotations

import shutil
import struct
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import rebrew.splat_config as splat_config
from rebrew.splat_config import (
    UNKNOWN_OPTION_REASON,
    ImportPlan,
    load_symbols,
    parse_splat_config,
    parse_yaml_subset,
)

runner = CliRunner()

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "splat_config"
SYMBOL_FILES = ("symbol_addrs.txt", "undefined_funcs_auto.txt", "undefined_syms_auto.txt")

IMAGE_BASE = 0x400000
FILE_ALIGN = 0x200
SEC_ALIGN = 0x1000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
BSS_RVA = 0x3000
BSS_SIZE = 0x100
#: Spans the fixture config's segments declare (rom 0x200..0x400, 0x400..0x600).
SEGMENT_SPAN = 0x200

TEXT_BYTES = bytes([0x55, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3]) + b"\x90" * 9
DATA_BYTES = b"fixture data\x00\x00\x00\x00"

PROJECT_TOML = """\
[project]
name = "fixture"
default_target = "fixture.exe"

[targets."fixture.exe"]
binary = "original/fixture.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/fixture.exe"
function_list = "src/fixture.exe/functions.txt"
bin_dir = "bin/fixture.exe"
source_ext = ".c"
marker = "FIXTURE"

[compiler]
profile = "msvc-6.0"
# A non-empty host command keeps config loading off the toolchain registry
# (an image-backed profile with an empty command resolves through it).
command = "wine CL.EXE"
runner = "wine"
"""

#: A config with only the fields the parser requires, for the error paths.
MINIMAL_YAML = """\
options:
  basename: fixture.exe
  target_path: "fixture.exe"
  platform: win32
  compiler: MSVC6
  symbol_addrs_path: symbol_addrs.txt
segments:
  - name: text
    type: code
    start: 0x200
    vram: 0x00401000
    subsegments:
      - [0x200, text, main_text]
  - [0x400]
"""


def _section_header(
    name: bytes, vsize: int, vaddr: int, rsize: int, rptr: int, chars: int
) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI", name.ljust(8, b"\x00")[:8], vsize, vaddr, rsize, rptr, 0, 0, 0, 0, chars
    )


def _build_pe() -> bytes:
    """A minimal PE32 with .text/.data/.bss at the VAs the fixture config claims."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 3, 0, 0, 0, 0xE0, 0x010F)
    size_of_image = BSS_RVA + BSS_SIZE
    opt = struct.pack("<H", 0x10B)
    opt += struct.pack("<BB", 6, 0)
    opt += struct.pack("<I", SEGMENT_SPAN)  # SizeOfCode
    opt += struct.pack("<I", SEGMENT_SPAN)  # SizeOfInitializedData
    opt += struct.pack("<I", BSS_SIZE)  # SizeOfUninitializedData
    opt += struct.pack("<I", TEXT_RVA)  # AddressOfEntryPoint
    opt += struct.pack("<I", TEXT_RVA)  # BaseOfCode
    opt += struct.pack("<I", DATA_RVA)  # BaseOfData
    opt += struct.pack("<I", IMAGE_BASE)
    opt += struct.pack("<I", SEC_ALIGN)
    opt += struct.pack("<I", FILE_ALIGN)
    opt += struct.pack("<HH", 4, 0)
    opt += struct.pack("<HH", 0, 0)
    opt += struct.pack("<HH", 4, 0)
    opt += struct.pack("<I", 0)  # Win32VersionValue
    opt += struct.pack("<I", size_of_image)
    opt += struct.pack("<I", FILE_ALIGN)  # SizeOfHeaders
    opt += struct.pack("<I", 0)  # CheckSum
    opt += struct.pack("<H", 3)  # Subsystem (console)
    opt += struct.pack("<H", 0)
    opt += struct.pack("<I", 0x100000)
    opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<I", 0x100000)
    opt += struct.pack("<I", 0x1000)
    opt += struct.pack("<I", 0)  # LoaderFlags
    opt += struct.pack("<I", 16)  # NumberOfRvaAndSizes
    opt += b"\x00" * (16 * 8)  # data directories
    assert len(opt) == 0xE0

    sections = b""
    sections += _section_header(
        b".text", len(TEXT_BYTES), TEXT_RVA, SEGMENT_SPAN, FILE_ALIGN, 0x60000020
    )
    sections += _section_header(
        b".data", len(DATA_BYTES), DATA_RVA, SEGMENT_SPAN, FILE_ALIGN * 2, 0xC0000040
    )
    sections += _section_header(b".bss", BSS_SIZE, BSS_RVA, 0, 0, 0xC0000080)

    header = bytes(dos) + b"PE\x00\x00" + coff + opt + sections
    header = header.ljust(FILE_ALIGN, b"\x00")
    text = TEXT_BYTES.ljust(SEGMENT_SPAN, b"\x00")
    data = DATA_BYTES.ljust(SEGMENT_SPAN, b"\x00")
    return header + text + data


def _stage_splat(tmp_path: Path) -> Path:
    """Write the committed fixture plus its PE into *tmp_path*, return the YAML."""
    cfg_dir = tmp_path / "splat"
    cfg_dir.mkdir()
    for name in SYMBOL_FILES:
        shutil.copy2(FIXTURE_DIR / name, cfg_dir / name)
    yaml_path = cfg_dir / "win32_app.yaml"
    yaml_path.write_text((FIXTURE_DIR / "win32_app.yaml").read_text(encoding="utf-8"))
    (cfg_dir / "fixture.exe").write_bytes(_build_pe())
    return yaml_path


def _write_minimal_config(tmp_path: Path, **replacements: str) -> Path:
    """MINIMAL_YAML written into *tmp_path*, with ``old`` -> ``new`` substitutions."""
    cfg_dir = tmp_path / "minimal"
    cfg_dir.mkdir(exist_ok=True)
    text = MINIMAL_YAML
    for old, new in replacements.items():
        assert old in text, f"MINIMAL_YAML has no {old!r}"
        text = text.replace(old, new)
    yaml_path = cfg_dir / "minimal.yaml"
    yaml_path.write_text(text, encoding="utf-8")
    return yaml_path


def _invoke(args: list[str]) -> Any:
    """Invoke the command the way ``main_entry`` publishes it as a script.

    ``splat_config.main`` is registered as a plain command on a fresh app, the
    same shape the standalone ``rebrew-import-splat`` entry point uses, so the
    tests exercise the CLI function without composing the umbrella app (and
    without depending on the toolchain registry that the umbrella's other
    components resolve at import time).
    """
    import typer

    standalone = typer.Typer()
    standalone.command()(splat_config.main)
    return runner.invoke(standalone, args)


def _make_project(root: Path) -> None:
    """A minimal project with the fixture PE already in ``original/``."""
    (root / "src" / "fixture.exe").mkdir(parents=True, exist_ok=True)
    (root / "original").mkdir(parents=True, exist_ok=True)
    (root / "original" / "fixture.exe").write_bytes(_build_pe())
    (root / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")


class TestYamlSubset:
    def test_block_mapping_sequence_and_flow(self) -> None:
        doc = parse_yaml_subset(
            "# leading comment\n"
            "options:\n"
            "  basename: 'quoted value'\n"
            "  flag: True\n"
            "  order: ['.text', \".data\"]\n"
            "  ptr: 0x00401000\n"
            "segments:\n"
            "  - name: text\n"
            "    type: code\n"
            "    start: 0x200\n"
            "    subsegments:\n"
            "      - [0x200, text, main_text]\n"
            "  - { name: bss, type: bss, bss_size: 0x100 }\n"
            "  - [0x600]\n"
        )
        assert doc["options"]["basename"] == "quoted value"
        assert doc["options"]["flag"] is True
        assert doc["options"]["order"] == [".text", ".data"]
        assert doc["options"]["ptr"] == 0x00401000
        seg = doc["segments"]
        assert seg[0]["name"] == "text"
        assert seg[0]["subsegments"] == [[0x200, "text", "main_text"]]
        assert seg[1] == {"name": "bss", "type": "bss", "bss_size": 0x100}
        assert seg[2] == [0x600]

    @pytest.mark.parametrize(
        ("text", "needle"),
        [
            ("options:\n\tbasename: x\n", "tab indentation"),
            ("options:\n  note: |\n    text\n", "block scalar"),
            ("options:\n  x: &anchor 1\n", "anchors"),
            ("options:\n  x: 1\n  x: 2\n", "duplicate key"),
            ("options:\n  x: [1, 2\n", "unterminated flow sequence"),
            ("---\n...\n", "multiple documents"),
        ],
    )
    def test_refuses_constructs_outside_the_subset(self, text: str, needle: str) -> None:
        with pytest.raises(ValueError) as exc:
            parse_yaml_subset(text)
        assert needle in str(exc.value)

    def test_refusal_names_the_line(self) -> None:
        with pytest.raises(ValueError) as exc:
            parse_yaml_subset("options:\n  x: 1\n  y:\n\tz: 2\n")
        assert "line 4" in str(exc.value)


class TestParseSplatConfig:
    def test_reads_the_fixture_surface(self, tmp_path: Path) -> None:
        cfg = parse_splat_config(_stage_splat(tmp_path))
        assert cfg.platform == "win32"
        assert cfg.compiler == "MSVC6"
        assert cfg.basename == "fixture.exe"
        assert cfg.target_path == tmp_path / "splat" / "fixture.exe"
        assert cfg.rom_end == 0x600
        assert [s.name for s in cfg.segments] == ["header", "text", "data", "bss"]
        text = cfg.segments[1]
        assert (text.kind, text.rom_start, text.rom_end, text.vram) == (
            "code",
            0x200,
            0x400,
            0x00401000,
        )
        assert text.rom_size == 0x200
        assert text.subsegments[0].kind == "text"
        assert cfg.segments[3].bss_size == 0x100
        assert [p.name for p in cfg.symbol_addrs_paths] == ["symbol_addrs.txt"]
        assert cfg.undefined_funcs_auto_path is not None
        assert cfg.undefined_syms_auto_path is not None

    def test_reports_ignored_keys_with_reasons(self, tmp_path: Path) -> None:
        cfg = parse_splat_config(_stage_splat(tmp_path))
        ignored = {item.key: item.reason for item in cfg.ignored}
        assert "GNU ld directive" in ignored["options.subalign"]
        assert "linker script" in ignored["options.ld_script_path"]
        assert "section order" in ignored["options.section_order"]
        assert ignored["options.unknown_knob"] == UNKNOWN_OPTION_REASON
        assert "sha1" in ignored

    def test_reports_unknown_segment_key_and_subsegment_type(self, tmp_path: Path) -> None:
        yaml_path = _stage_splat(tmp_path)
        yaml_path.write_text(
            yaml_path.read_text(encoding="utf-8")
            .replace("    vram: 0x00401000\n", "    vram: 0x00401000\n    align: 16\n")
            .replace("[0x200, text, main_text]", "[0x200, vtx, main_text]"),
            encoding="utf-8",
        )
        cfg = parse_splat_config(yaml_path)
        ignored = {item.key: item.reason for item in cfg.ignored}
        assert "segments[].align" in ignored
        assert "subsegment type 'vtx'" in ignored

    def test_refuses_an_unsupported_platform(self, tmp_path: Path) -> None:
        yaml_path = _write_minimal_config(tmp_path, **{"platform: win32": "platform: n64"})
        with pytest.raises(ValueError) as exc:
            parse_splat_config(yaml_path)
        assert "platform 'n64'" in str(exc.value)

    def test_requires_target_path(self, tmp_path: Path) -> None:
        yaml_path = _write_minimal_config(tmp_path, **{'  target_path: "fixture.exe"\n': ""})
        with pytest.raises(ValueError) as exc:
            parse_splat_config(yaml_path)
        assert "target_path" in str(exc.value)

    def test_requires_compiler_and_segments(self, tmp_path: Path) -> None:
        yaml_path = _write_minimal_config(tmp_path, **{"  compiler: MSVC6\n": ""})
        with pytest.raises(ValueError) as exc:
            parse_splat_config(yaml_path)
        assert "compiler" in str(exc.value)


class TestSymbols:
    def test_reads_defined_and_undefined_rows(self, tmp_path: Path) -> None:
        cfg = parse_splat_config(_stage_splat(tmp_path))
        symbols = load_symbols(cfg)
        by_name = {row.name: row for row in symbols.defined}
        assert by_name["entrypoint"].kind == "func"
        assert by_name["entrypoint"].size == 0x13
        assert by_name["g_table"].kind == "u32"
        assert by_name["g_table"].size == 0x10
        assert by_name["imp_KERNEL32_dll_GetTickCount"].detail == "import from KERNEL32.dll"
        assert [row.name for row in symbols.undefined] == ["_printf", "g_outside_image"]
        assert symbols.missing == ()
        # The shared reader drops ``//`` lines, so the fixture's three comment
        # lines (including its forwarded-export note) show up as a count.
        assert symbols.note_lines == 3

    def test_missing_symbol_file_is_reported(self, tmp_path: Path) -> None:
        yaml_path = _stage_splat(tmp_path)
        (yaml_path.parent / "undefined_funcs_auto.txt").unlink()
        cfg = parse_splat_config(yaml_path)
        symbols = load_symbols(cfg)
        assert [p.name for p in symbols.missing] == ["undefined_funcs_auto.txt"]


class TestPlan:
    def _plan(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ImportPlan:
        yaml_path = _stage_splat(tmp_path)
        project = tmp_path / "project"
        _make_project(project)
        monkeypatch.chdir(project)
        return splat_config.build_plan(parse_splat_config(yaml_path))

    def test_classifies_every_symbol_row(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        plan = self._plan(tmp_path, monkeypatch)
        by_va = {a.va: a for a in plan.annotations}
        assert by_va[0x00401000].kind == "FUNCTION"
        assert by_va[0x00401000].path == "entrypoint.c"
        assert by_va[0x00401020].kind == "LIBRARY"
        assert by_va[0x00401020].module == "OTHER"
        assert by_va[0x00401020].path == "library_other.h"
        assert by_va[0x00402000].kind == "DATA"
        assert by_va[0x00402000].section == ".data"
        assert by_va[0x00402010].marker == (
            "// DATA: FIXTURE 0x00402010\nextern unsigned int imp_KERNEL32_dll_GetTickCount;"
        )
        # The undefined_* function lands inside .text: the config says that code
        # is a library's, so it is a LIBRARY entry with the inferred module.
        assert by_va[0x00401030].kind == "LIBRARY"
        assert by_va[0x00401030].module == "MSVCRT"

        reasons = dict(plan.skipped)
        assert "no rebrew annotation" in reasons["odd_label"]
        assert "outside every code segment" in reasons["outside_segments"]
        assert "lies outside the image" in reasons["g_outside_image"]

    def test_layout_sections_come_from_the_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        plan = self._plan(tmp_path, monkeypatch)
        sections = {s.name: s for s in plan.sections}
        assert set(sections) == {".text", ".data"}
        assert sections[".text"].va == TEXT_RVA
        assert sections[".text"].raw == SEGMENT_SPAN
        assert sections[".text"].raw_ptr == FILE_ALIGN
        assert sections[".data"].va == DATA_RVA

    def test_target_metadata(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        plan = self._plan(tmp_path, monkeypatch)
        assert plan.target == "fixture.exe"
        assert plan.marker == "FIXTURE"
        assert plan.profile == "msvc-6.0"
        assert (plan.format, plan.arch) == ("pe", "x86_32")
        assert plan.image_base == IMAGE_BASE
        assert plan.copy_binary is True
        assert plan.binary_dest == "original/fixture.exe"

    def test_plan_notes_an_unmapped_splat_compiler(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        yaml_path = _stage_splat(tmp_path)
        yaml_path.write_text(
            yaml_path.read_text(encoding="utf-8").replace("compiler: MSVC6", "compiler: MSVC14"),
            encoding="utf-8",
        )
        project = tmp_path / "project"
        _make_project(project)
        monkeypatch.chdir(project)
        plan = splat_config.build_plan(parse_splat_config(yaml_path))
        assert plan.profile == "msvc-6.0"  # the project's profile, unchanged
        assert any("no rebrew profile" in note for note in plan.notes)


class TestRegistration:
    def test_registered_in_the_umbrella_manifest(self) -> None:
        """The command is mounted by ``main.py``'s component list.

        A text check (the way ``test_docs_hygiene`` pins the pyproject
        manifest): importing ``rebrew.main`` composes the whole component
        graph, which a unit test should not depend on.  The mount itself is
        exercised by running ``rebrew import-splat`` for real.
        """
        source = (Path(__file__).parent.parent / "src" / "rebrew" / "main.py").read_text(
            encoding="utf-8"
        )
        assert 'name="import-splat"' in source
        assert 'module="rebrew.splat_config"' in source

    def test_pyproject_publishes_a_standalone_script(self) -> None:
        toml = (Path(__file__).parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        assert 'rebrew-import-splat = "rebrew.splat_config:main_entry"' in toml


class TestApply:
    def _project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
        yaml_path = _stage_splat(tmp_path)
        project = tmp_path / "project"
        _make_project(project)
        monkeypatch.chdir(project)
        return project, yaml_path

    def test_dry_run_writes_nothing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project, yaml_path = self._project(tmp_path, monkeypatch)
        before = sorted(p.name for p in project.rglob("*"))
        result = _invoke([str(yaml_path)])
        assert result.exit_code == 0, result.output
        assert "dry run" in result.output
        assert "// FUNCTION: FIXTURE 0x00401000" in result.output
        assert sorted(p.name for p in project.rglob("*")) == before

    def test_write_creates_the_annotations(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project, yaml_path = self._project(tmp_path, monkeypatch)
        result = _invoke([str(yaml_path), "--write"])
        assert result.exit_code == 0, result.output

        reversed_dir = project / "src" / "fixture.exe"
        function = (reversed_dir / "entrypoint.c").read_text(encoding="utf-8")
        assert function.startswith("// FUNCTION: FIXTURE 0x00401000\n")
        assert "entrypoint(void)" in function

        library = (reversed_dir / "library_other.h").read_text(encoding="utf-8")
        assert "// LIBRARY: OTHER 0x00401020" in library
        assert "// imp_OTHER_dll_FarProc" in library

        crt = (reversed_dir / "library_msvcrt.h").read_text(encoding="utf-8")
        assert "// LIBRARY: MSVCRT 0x00401030" in crt

        data = (reversed_dir / "data_g_table.c").read_text(encoding="utf-8")
        assert data.startswith("// DATA: FIXTURE 0x00402000\n")
        assert "extern unsigned int g_table[4];" in data

        assert (project / "original" / "fixture.exe").is_file()
        config = (project / "rebrew-project.toml").read_text(encoding="utf-8")
        assert '[targets."fixture.exe".compiler]' in config
        assert 'source = "splat:win32_app.yaml"' in config
        assert '{name = ".text", va = 4096, vs = 19, raw = 512, ptr = 512' in config

        functions = (project / "src" / "rebrew-functions.toml").read_text(encoding="utf-8")
        assert 'status = "STUB"' in functions
        assert "size = 19" in functions
        assert "seeded from a splat config" in functions

        data_meta = (project / "src" / "rebrew-data.toml").read_text(encoding="utf-8")
        assert 'section = ".data"' in data_meta
        assert "size = 16" in data_meta

    def test_write_copies_the_binary_into_the_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project, yaml_path = self._project(tmp_path, monkeypatch)
        (project / "original" / "fixture.exe").unlink()
        result = _invoke([str(yaml_path), "--write"])
        assert result.exit_code == 0, result.output
        assert (project / "original" / "fixture.exe").read_bytes() == _build_pe()

    def test_rerun_is_idempotent(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        project, yaml_path = self._project(tmp_path, monkeypatch)
        assert _invoke([str(yaml_path), "--write"]).exit_code == 0
        reversed_dir = project / "src" / "fixture.exe"
        before = {p: p.stat().st_mtime_ns for p in reversed_dir.iterdir()}
        result = _invoke([str(yaml_path), "--write", "--json"])
        assert result.exit_code == 0, result.output
        assert {p: p.stat().st_mtime_ns for p in reversed_dir.iterdir()} == before

    def test_conflict_is_refused_and_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project, yaml_path = self._project(tmp_path, monkeypatch)
        foreign = project / "src" / "fixture.exe" / "entrypoint.c"
        foreign.write_text("// FUNCTION: FIXTURE 0xdeadbeef\nint other(void) { return 0; }\n")
        before = foreign.read_text(encoding="utf-8")

        result = _invoke([str(yaml_path), "--write"])
        assert result.exit_code == 1
        assert "entrypoint.c already exists and does not annotate 0x00401000" in result.output
        assert foreign.read_text(encoding="utf-8") == before
        assert not (project / "src" / "fixture.exe" / "data_g_table.c").exists()

        forced = _invoke([str(yaml_path), "--write", "--force"])
        assert forced.exit_code == 0, forced.output
        assert foreign.read_text(encoding="utf-8").startswith("// FUNCTION: FIXTURE 0x00401000")

    def test_json_payload_lists_the_plan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, yaml_path = self._project(tmp_path, monkeypatch)
        result = _invoke([str(yaml_path), "--json"])
        assert result.exit_code == 0, result.output
        import json

        payload = json.loads(result.output)
        assert payload["dry_run"] is True
        assert payload["project"]["profile"] == "msvc-6.0"
        assert [s["name"] for s in payload["layout"]["sections"]] == [".text", ".data"]
        kinds = {a["kind"] for a in payload["annotations"]}
        assert kinds == {"FUNCTION", "LIBRARY", "DATA"}
        assert payload["ignored_keys"]
        assert payload["conflicts"] == []

    def test_requires_a_project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        yaml_path = _stage_splat(tmp_path)
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.chdir(empty)
        result = _invoke([str(yaml_path), "--write"])
        assert result.exit_code == 2
        assert "rebrew-project.toml" in result.output
