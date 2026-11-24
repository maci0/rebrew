"""Cross-process tests for persisted LIEF section and directory facts."""

import json
import os
import subprocess
import sys
lazy from pathlib import Path

import pytest
from bin_util import make_pe

_WORKER = """\
from dataclasses import asdict
import importlib.metadata
import json
from pathlib import Path
import sys

import rebrew
from rebrew.formats.binary_loader import cache_pe_layouts, load_binary

path, override = sys.argv[1:]
fmt = "auto"
if override == "lief":
    installed_version = importlib.metadata.version
    importlib.metadata.version = (
        lambda name: "999.0" if name == "lief" else installed_version(name)
    )
elif override == "rebrew":
    rebrew.__version__ = "999.0"
elif override == "format":
    fmt = "pe"
elif override == "extractor":
    # A development install keeps its release number when the extractor changes.
    from rebrew.formats import binary_loader

    edited = Path(path).with_name("binary_loader.py")
    edited.write_bytes(Path(binary_loader.__file__).read_bytes() + b"\\n# edited\\n")
    binary_loader.__file__ = str(edited)
with cache_pe_layouts():
    info = asdict(load_binary(Path(path), fmt))
info = {name: value for name, value in info.items() if not name.startswith("_")}
print(json.dumps(["lief" in sys.modules, info], default=str))
"""


def _load(tmp_path: Path, binary: Path, override: str = "") -> tuple[bool, dict[str, object]]:
    script = tmp_path / "read_pe.py"
    script.write_text(_WORKER, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(script), str(binary), override],
        env={**os.environ, "XDG_CACHE_HOME": str(tmp_path / "cache")},
        check=True,
        capture_output=True,
        text=True,
    )
    imported, info = json.loads(proc.stdout)
    assert isinstance(imported, bool) and isinstance(info, dict)
    return imported, info


def _write_binary(path: Path, *, text_va: int = 0x1000) -> Path:
    path.write_bytes(
        make_pe(
            b"\xc3",
            text_va=text_va,
            imports=[("USER32.dll", ["MessageBoxA"])],
            section_name="CODE",
            pe32_plus=True,
        )
    )
    return path


class TestPeLayoutCache:
    def test_cross_process_hit_preserves_pe_facts_without_importing_lief(
        self, tmp_path: Path
    ) -> None:
        binary = _write_binary(tmp_path / "fixture.exe")
        imported, before = _load(tmp_path, binary)
        assert imported
        assert before["pointer_size"] == 8
        assert before["data_directories"]
        sections = before["sections"]
        assert isinstance(sections, dict) and sections.keys() == {"CODE", ".text"}
        assert _load(tmp_path, binary) == (False, before)

    @pytest.mark.parametrize("change", ["edit", "preserve-mtime", "replace"])
    def test_changed_content_reparses(self, tmp_path: Path, change: str) -> None:
        binary = _write_binary(tmp_path / "fixture.exe")
        before = binary.stat()
        assert _load(tmp_path, binary)[0]

        if change == "replace":
            _write_binary(tmp_path / "replacement.exe", text_va=0x3000).replace(binary)
        else:
            _write_binary(binary, text_va=0x3000)
        if change != "edit":
            os.utime(binary, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert binary.stat().st_mtime_ns == before.st_mtime_ns
        assert binary.stat().st_size == before.st_size
        if change == "preserve-mtime":
            assert binary.stat().st_ino == before.st_ino

        imported, info = _load(tmp_path, binary)
        assert imported
        assert info["text_va"] == 0x403000

    @pytest.mark.parametrize("override", ["lief", "rebrew", "extractor", "format"])
    def test_changed_parser_identity_reparses(self, tmp_path: Path, override: str) -> None:
        binary = _write_binary(tmp_path / "fixture.exe")
        imported, before = _load(tmp_path, binary)
        assert imported
        assert _load(tmp_path, binary, override) == (True, before)

    @pytest.mark.parametrize("damage", ["truncate", "valid-json-change"])
    def test_damaged_entry_reparses(self, tmp_path: Path, damage: str) -> None:
        binary = _write_binary(tmp_path / "fixture.exe")
        imported, before = _load(tmp_path, binary)
        assert imported
        (entry,) = (tmp_path / "cache" / "rebrew" / "pe-layout").iterdir()
        data = entry.read_bytes()
        if damage == "truncate":
            entry.write_bytes(data[:-1])
        else:
            assert b"4198400" in data
            entry.write_bytes(data.replace(b"4198400", b"4198401"))
        assert _load(tmp_path, binary) == (True, before)
        assert _load(tmp_path, binary) == (False, before)
