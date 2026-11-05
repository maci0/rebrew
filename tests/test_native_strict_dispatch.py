"""Strict standalone analysis must distinguish unavailable context and failed scans."""

import shutil
import subprocess
from pathlib import Path

import pytest

from rebrew.analyze import _collect_dispatch, build_dossier, standalone_config
from rebrew.formats.binary_loader import load_binary


def test_real_elf_strict_dispatch() -> None:
    binary = Path("/bin/true")
    if not binary.is_file():
        pytest.skip("system ELF unavailable")
    cfg = standalone_config(binary)
    assert cfg.dll_exports == {}
    dossier = build_dossier(cfg, binary, strict_dispatch=True)
    assert dossier["dispatch_name_context"] == "unavailable"
    assert dossier["dispatch_scan_status"] == "partial"
    assert isinstance(dossier["dispatch_tables"], list)


def test_empty_scan_and_failures_are_distinct(monkeypatch: pytest.MonkeyPatch) -> None:
    from rebrew import catalog, data_scan

    binary = Path("/bin/true")
    if not binary.is_file():
        pytest.skip("system ELF unavailable")
    cfg, info = standalone_config(binary), load_binary(binary)
    monkeypatch.setattr(data_scan, "find_dispatch_tables", lambda *a, **kw: [])
    assert _collect_dispatch(info, cfg, strict=True) == []

    def fail(*args, **kwargs):
        raise ValueError("unavailable")

    monkeypatch.setattr(data_scan, "find_dispatch_tables", fail)
    with pytest.raises(ValueError, match="unavailable"):
        _collect_dispatch(info, cfg, strict=True)
    assert _collect_dispatch(info, cfg) == []
    monkeypatch.setattr(catalog, "cached_function_list", fail)
    with pytest.raises(ValueError, match="unavailable"):
        _collect_dispatch(info, cfg, strict=True)


def test_pe64_uses_input_pointer_width(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    compiler = shutil.which("x86_64-w64-mingw32-gcc")
    if not compiler:
        pytest.skip("PE64 compiler unavailable")
    source, binary = tmp_path / "target.c", tmp_path / "target.exe"
    source.write_text("int main(void) { return 0; }\n")
    subprocess.run([compiler, str(source), "-o", str(binary)], check=True, capture_output=True)
    info = load_binary(binary)
    assert info.format == "pe" and info.pointer_size == 8
    from rebrew import data_scan

    scan = data_scan.find_dispatch_tables
    seen = []

    def wrapped(*args, **kwargs):
        seen.append((kwargs["ptr_size"], kwargs["info"].pointer_size))
        return scan(*args, **kwargs)

    monkeypatch.setattr(data_scan, "find_dispatch_tables", wrapped)
    assert isinstance(_collect_dispatch(info, standalone_config(binary), strict=True), list)
    assert seen == [(None, 8)]


def test_unscanned_and_invalid_sections_are_not_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    from rebrew import data_scan

    def section(name: str, va: int, offset: int, size: int) -> SimpleNamespace:
        return SimpleNamespace(name=name, va=va, size=size, file_offset=offset, raw_size=size)

    pointers = (0x1000).to_bytes(8, "little") * 3
    text = section(".text", 0x1000, 0, 8)
    data = section(".data", 0x2000, 8, len(pointers))
    rodata = section(".rodata", 0x2000, 8, len(pointers))
    info = SimpleNamespace(
        data=b"\0" * 8 + pointers,
        sections={".text": text, ".data": data},
        format="pe",
        arch="x86_64",
        endian="little",
        pointer_size=8,
    )
    monkeypatch.setattr(data_scan, "build_dispatch_known_functions", lambda *args, **kwargs: {})
    cfg = SimpleNamespace(reversed_dir=Path("/nonexistent"))
    assert len(_collect_dispatch(info, cfg, strict=True)) == 1
    info.sections = {".text": text, ".rodata": rodata}
    assert _collect_dispatch(info, cfg, strict=True) == []  # marked partial by build_dossier
    info.sections = {".text": text, ".data": data}
    info.data = info.data[:-1]
    with pytest.raises(ValueError, match="section bounds"):
        _collect_dispatch(info, cfg, strict=True)
    info.sections = {".data": data}
    with pytest.raises(ValueError, match="no code section"):
        _collect_dispatch(info, cfg, strict=True)
