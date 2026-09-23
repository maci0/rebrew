"""`rebrew cmake-flags` — the build must compile what the tools measure.

The command exists because a CMake build that reads the `.c`'s inline
``// CFLAGS:`` compiles a different translation unit than every rebrew tool,
which resolves flags from ``rebrew-functions.toml``.  guild-rebrew's
``gm_AllocSpieler`` ran that way: annotation ``/O2 /Gd /Oa``, metadata
``/Oa /Ow``, notes measured on the metadata, linked function 363 bytes behind.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.cli import EXIT_ERROR
from rebrew.cmake_flags import _defines, app, collect
from rebrew.config import load_config
from rebrew.lint_cflags import _codegen_cflags_key

TOML = """\
[project]
default_target = "server_dll"

[targets.server_dll]
binary = "original/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server_dll"
marker = "SERVER"

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
    assert _codegen_cflags_key("/Gd /O2") == _codegen_cflags_key("/O2 /Gd")
    assert _codegen_cflags_key("/O2 /Gd /DX=1") == _codegen_cflags_key("/O2 /Gd")
    assert _codegen_cflags_key("/O2 /Gd") != _codegen_cflags_key("/O2 /Gd /Ow")
    assert _defines("/O2 /Gd /DX=1 -DY") == {"/DX=1", "-DY"}


def test_data_marker_does_not_count_as_a_function(tmp_path: Path) -> None:
    """A generated `// DATA:` blob in the same file carries no compile flags.

    Treating it as a function made the file look self-contradictory (default
    flags vs the function's `/Oy-`) and the command refused to emit anything --
    which broke the configure step of the build that consumes it.
    """
    cfg = _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/O2 /Gd /Oy-"\n',
        {
            "a.c": "// DATA: SERVER 0x10002000\nchar blob[4] = {0};\n"
            "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"
        },
    )
    files, problems, _notes = collect(cfg, "SERVER")
    assert problems == []
    assert list(files.values()) == ["/O2 /Gd /Oy-"]


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


def test_cli_json_dry_run_stdout_is_pure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``--json --dry-run`` must emit only JSON on stdout (no CMake include text)."""
    _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/Ox /Gd"\n',
        {"a.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"},
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["--json", "--dry-run"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["written"] is None
    assert payload["problems"] == []
    assert "set_source_files_properties" not in result.stdout
    assert any(str(p).endswith("a.c") for p in payload["files"])


def test_cli_conflicting_flags_exit_error_with_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Conflicting per-file flags exit EXIT_ERROR and still emit a JSON envelope."""
    _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/O2 /Gd"\n'
        '["SERVER.0x10001020"]\ncflags = "/O2 /Ob0 /Gd"\n',
        {
            "a.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"
            "// FUNCTION: SERVER 0x10001020\nint b(void) { return 0; }\n"
        },
    )
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["--json", "-o", str(tmp_path / "out.cmake")])
    assert result.exit_code == EXIT_ERROR, result.output
    payload = json.loads(result.stdout)
    assert payload["written"] is None
    assert payload["problems"]
    assert not (tmp_path / "out.cmake").exists()

    # Conflicts must fail under --dry-run too (preview is not a free pass).
    dry = CliRunner().invoke(app, ["--json", "--dry-run"])
    assert dry.exit_code == EXIT_ERROR
    assert json.loads(dry.stdout)["problems"]


def test_toolchain_pin_is_reported_because_the_build_cannot_honour_it(
    tmp_path: Path,
) -> None:
    """A per-function toolchain changes `rebrew test`, never the linked bytes.

    Regression: `collect` resolved the effective toolchain and threw it away
    (`_tc, flags = resolve_compile_overrides(...)`), emitting only flags.  The
    CMake build's compiler is fixed by the toolchain file, so a pin let the
    metadata claim one compiler while the deliverable was built by another —
    the same divergence class this module's docstring describes for CFLAGS,
    and the reason a round-188 service-pack sweep could not be acted on.
    """
    cfg = _project(
        tmp_path,
        '["SERVER.0x10001000"]\ntoolchain = "msvc-6.0"\n',
        {"a.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n"},
    )
    _files, problems, notes = collect(cfg, "SERVER")
    assert problems == []
    joined = " ".join(notes)
    assert "msvc-6.0" in joined, notes
    assert "never the linked bytes" in joined, notes


def test_sources_file_unannotated_appears_in_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--sources-file`` entries without annotations must still show in ``--json``."""
    _project(
        tmp_path,
        '["SERVER.0x10001000"]\ncflags = "/Ox /Gd"\n',
        {
            "a.c": "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n",
            "extra.c": "int extra(void) { return 1; }\n",
        },
    )
    listed = tmp_path / "sources.txt"
    listed.write_text("src/server_dll/a.c\nsrc/server_dll/extra.c\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["--json", "--dry-run", "--sources-file", str(listed)])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert "src/server_dll/a.c" in payload["files"]
    assert "src/server_dll/extra.c" in payload["files"]
    assert payload["files"]["src/server_dll/a.c"] == "/Ox /Gd"


def test_shared_sources_are_collected(tmp_path: Path) -> None:
    """A shared file's marker for this target decides its CMake flags — the
    old reversed_dir-only rglob left every shared TU flagless in the build."""
    (tmp_path / "rebrew-project.toml").write_text(
        TOML.replace(
            'default_target = "server_dll"',
            'default_target = "server_dll"\nshared_dir = "src/shared"',
        ),
        encoding="utf-8",
    )
    (tmp_path / "src/server_dll").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src/shared").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src/rebrew-functions.toml").write_text(
        '["SERVER.0x10001000"]\ncflags = "/Ox /Gd"\n', encoding="utf-8"
    )
    (tmp_path / "src/shared" / "common.c").write_text(
        "// FUNCTION: SERVER 0x10001000\nint a(void) { return 0; }\n",
        encoding="utf-8",
    )
    cfg = load_config(root=tmp_path, target="server_dll")
    files, problems, _notes = collect(cfg, "SERVER")
    assert problems == []
    assert any(Path(p).name == "common.c" and flags == "/Ox /Gd" for p, flags in files.items()), (
        files
    )
