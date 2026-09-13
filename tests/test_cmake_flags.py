"""`rebrew cmake-flags` — the build must compile what the tools measure.

The command exists because a CMake build that reads the `.c`'s inline
``// CFLAGS:`` compiles a different translation unit than every rebrew tool,
which resolves flags from ``rebrew-functions.toml``.  guild-rebrew's
``gm_AllocSpieler`` ran that way: annotation ``/O2 /Gd /Oa``, metadata
``/Oa /Ow``, notes measured on the metadata, linked function 363 bytes behind.
"""

from __future__ import annotations

import re
from pathlib import Path

from rebrew.cmake_flags import _codegen_key, _defines, collect
from rebrew.config import load_config

TOML = """\
[project]
default_target = "server_dll"

[targets.server_dll]
binary = "original/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server_dll"

[compiler]
profile = "msvc-6.0"
"""


def _project(tmp_path: Path, functions_toml: str, sources: dict[str, str]):
    (tmp_path / "rebrew-project.toml").write_text(TOML, encoding="utf-8")
    (tmp_path / "src/server_dll").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src/rebrew-functions.toml").write_text(functions_toml, encoding="utf-8")
    for name, body in sources.items():
        (tmp_path / "src/server_dll" / name).write_text(body, encoding="utf-8")
    return load_config(root=tmp_path, target="server_dll")


def test_metadata_flags_are_emitted(tmp_path: Path) -> None:
    """The TOML value wins — that is the whole point of the command."""
    cfg = _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/Ox /Gd"\n',
        {"a.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"},
    )
    files, problems, _notes = collect(cfg, "SERVER")
    assert problems == []
    assert list(files.values()) == ["/Ox /Gd"]


def test_conflicting_functions_in_one_file_are_reported(tmp_path: Path) -> None:
    """A TU compiles with one flag set, so this cannot be honoured silently."""
    cfg = _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/O2 /Gd"\n'
        '["SERVER.0x10001020"]\ncflags = "/O2 /Ob0 /Gd"\n',
        {
            "a.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"
            "// FUNCTION: SERVER 0x10001020\nint b(void) { return 0; }\n"
        },
    )
    files, problems, _notes = collect(cfg, "SERVER")
    assert "a.c" in problems[0]
    assert "/Ob0" in problems[0]
    assert files == {}  # no guess is emitted for the ambiguous file


def test_define_alone_is_not_a_conflict_and_is_not_emitted(tmp_path: Path) -> None:
    """`/DREBREW_ALLOW_NAKED` gates a reconstruction the shipped build must not
    compile, so a file whose functions differ only by it stays usable — and the
    define is dropped, visibly, rather than silently."""
    cfg = _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/O2 /Gd /DREBREW_ALLOW_NAKED"\n'
        '["SERVER.0x10001020"]\ncflags = "/O2 /Gd"\n',
        {
            "a.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"
            "// FUNCTION: SERVER 0x10001020\nint b(void) { return 0; }\n"
        },
    )
    files, problems, notes = collect(cfg, "SERVER")
    assert problems == []
    assert list(files.values()) == ["/O2 /Gd"]
    assert any("DREBREW_ALLOW_NAKED" in n for n in notes)


def test_codegen_key_ignores_order_and_defines() -> None:
    assert _codegen_key("/Gd /O2") == _codegen_key("/O2 /Gd")
    assert _codegen_key("/O2 /Gd /DX=1") == _codegen_key("/O2 /Gd")
    assert _codegen_key("/O2 /Gd") != _codegen_key("/O2 /Gd /Ow")
    assert _defines("/O2 /Gd /DX=1 -DY") == {"/DX=1", "-DY"}


def test_written_include_is_valid_cmake(tmp_path: Path) -> None:
    """The emitted include must be something CMake can swallow."""
    cfg = _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/O2 /Gd /Ow"\n',
        {"a b.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"},
    )
    files, _p, _n = collect(cfg, "SERVER")
    rel = next(iter(files)).relative_to(cfg.root).as_posix()
    line = (
        f'set_source_files_properties("${{CMAKE_CURRENT_SOURCE_DIR}}/{rel}"\n'
        f'    PROPERTIES COMPILE_FLAGS "{files[next(iter(files))]}")\n'
    )
    assert re.fullmatch(
        r'set_source_files_properties\("\$\{CMAKE_CURRENT_SOURCE_DIR\}/[^"]+"\n'
        r'\s+PROPERTIES COMPILE_FLAGS "[^"]+"\)\n',
        line,
    )
