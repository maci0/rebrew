"""`rebrew build cmake-sources` — the build must link what the target owns.

A glob over a shared tree over-includes: every target's TUs compile and
link into every binary (duplicate symbols at best, foreign bytes at
worst).  Marker-selected lists include exactly the files carrying the
target's FUNCTION/LIBRARY/STUB block, plus unannotated helpers.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.cmake_sources import app, collect
from rebrew.config import ProjectConfig, load_config

TOML = """\
[project]
default_target = "server_dll"

[targets.server_dll]
binary = "original/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server_dll"
marker = "SERVER"

[targets.client_exe]
binary = "original/client.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/shared"
marker = "CLIENT"

[compiler]
profile = "msvc-6.0"
"""


def _project(tmp_path: Path, sources: dict[str, str]) -> ProjectConfig:
    (tmp_path / "rebrew-project.toml").write_text(TOML, encoding="utf-8")
    (tmp_path / "src/server_dll").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src/shared").mkdir(parents=True, exist_ok=True)
    for name, body in sources.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    return load_config(root=tmp_path, target="server_dll")


def test_stacked_file_belongs_to_both_targets(tmp_path: Path) -> None:
    """One stacked file serves every target whose marker it carries."""
    _project(
        tmp_path,
        {
            "src/shared/common.c": (
                "// FUNCTION: SERVER 0x10001000\n// SIZE: 8\n"
                "// FUNCTION: CLIENT 0x20001000\n// SIZE: 8\n"
                "int common(void){return 0;}\n"
            ),
        },
    )
    from rebrew.config import load_config as _load

    for target, count in (("server_dll", 1), ("client_exe", 1)):
        cfg = _load(root=tmp_path, target=target)
        own, foreign = collect(cfg, cfg.marker)
        assert len(own) == count, (target, own, foreign)


def test_foreign_only_file_excluded(tmp_path: Path) -> None:
    """A TU with no block for this target must not link into it."""
    cfg = _project(
        tmp_path,
        {
            "src/shared/only_client.c": (
                "// FUNCTION: CLIENT 0x20002000\n// SIZE: 8\nint oc(void){return 1;}\n"
            ),
            "src/shared/common.c": (
                "// FUNCTION: SERVER 0x10001000\n// SIZE: 8\nint s(void){return 0;}\n"
            ),
        },
    )
    own, foreign = collect(cfg, "SERVER")
    assert [p.name for p in own] == ["common.c"]
    assert [p.name for p in foreign] == ["only_client.c"]


def test_unannotated_helper_included(tmp_path: Path) -> None:
    """Helpers with no FUNCTION block belong to every target (as before)."""
    cfg = _project(
        tmp_path,
        {
            "src/shared/help.c": "int help(void){return 0;}\n",
        },
    )
    own, foreign = collect(cfg, "SERVER")
    assert [p.name for p in own] == ["help.c"]
    assert foreign == []


def test_emitted_include_sets_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The written file is a valid `set(VAR ...)` include."""
    _project(
        tmp_path,
        {
            "src/shared/a.c": "// FUNCTION: SERVER 0x10001000\nint a(void){return 0;}\n",
        },
    )
    monkeypatch.chdir(tmp_path)
    out = CliRunner().invoke(app, ["--var", "MYSRC", "--dry-run"])
    assert out.exit_code == 0, out.output
    assert "set(MYSRC" in out.stdout
    assert "src/shared/a.c" in out.stdout


def test_json_reports_excluded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--json names the excluded files so drops are auditable."""
    _project(
        tmp_path,
        {
            "src/shared/only_client.c": (
                "// FUNCTION: CLIENT 0x20002000\nint oc(void){return 1;}\n"
            ),
        },
    )
    monkeypatch.chdir(tmp_path)
    out = CliRunner().invoke(app, ["--json", "--dry-run"])
    assert out.exit_code == 0, out.output
    payload = json.loads(out.stdout)
    assert payload["files"] == []
    assert payload["excluded"] == ["src/shared/only_client.c"]


def test_config_change_regenerates_library_order(tmp_path: Path) -> None:
    """An ordinary build re-reads configuration instead of retaining stale libs."""
    cmake = shutil.which("cmake")
    if cmake is None:
        pytest.skip("CMake is required for the regeneration check")
    _project(tmp_path, {})
    config = tmp_path / "rebrew-project.toml"
    libraries = '[targets.server_dll.external_libs]\nKERNEL32 = "KERNEL32.lib"\n'
    config.write_text(TOML + libraries)
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.15)\nproject(regenerate NONE)\n"
        f'execute_process(COMMAND "{Path(sys.executable).as_posix()}" -m rebrew.cmake_sources '
        '-o "${CMAKE_BINARY_DIR}/sources.cmake" '
        'WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" RESULT_VARIABLE rc)\n'
        'if(NOT rc EQUAL 0)\nmessage(FATAL_ERROR "cmake-sources failed")\nendif()\n'
        'include("${CMAKE_BINARY_DIR}/sources.cmake")\n'
        'file(WRITE "${CMAKE_BINARY_DIR}/libs.txt" "${REBREW_EXTERNAL_LIBS}")\n'
    )
    build = tmp_path / "build"
    subprocess.run([cmake, "-S", str(tmp_path), "-B", str(build)], check=True, capture_output=True)
    assert (build / "libs.txt").read_text() == "KERNEL32.lib"
    config.write_text(TOML + libraries.replace("KERNEL32", "USER32"))
    subprocess.run([cmake, "--build", str(build)], check=True, capture_output=True)
    assert (build / "libs.txt").read_text() == "USER32.lib"


@pytest.mark.parametrize("metadata_in_src", [False, True])
def test_migrated_library_sources_keep_target_scope(tmp_path: Path, metadata_in_src: bool) -> None:
    """Project-root bindings select their owners rather than the unannotated fallback."""
    from rebrew.metadata import record_function_identity, save_metadata

    _project(
        tmp_path,
        {
            "src/shared/client_lib.c": "int client_lib(void) { return 1; }\n",
            "src/shared/server_lib.c": "int server_lib(void) { return 2; }\n",
            "src/shared/common_lib.c": "int common_lib(void) { return 3; }\n",
            "src/server_dll/client_lib.c": "int helper(void) { return 4; }\n",
        },
    )
    config = tmp_path / "rebrew-project.toml"
    config.write_text(
        config.read_text().replace(
            'default_target = "server_dll"', 'default_target = "server_dll"\nshared_dir = "src"'
        )
    )
    metadata = tmp_path / "src" if metadata_in_src else tmp_path
    save_metadata(metadata, {})
    for module, va, name in [
        ("CLIENT", 0x20001000, "client_lib"),
        ("SERVER", 0x10001000, "server_lib"),
        ("SERVER", 0x10002000, "common_lib"),
        ("CLIENT", 0x20002000, "common_lib"),
    ]:
        record_function_identity(
            metadata,
            module=module,
            va=va,
            file=f"src/shared/{name}.c",
            marker_type="LIBRARY",
            name=name,
            symbol="_" + name,
        )
    for target, expected in [
        (
            "server_dll",
            {"src/shared/server_lib.c", "src/shared/common_lib.c", "src/server_dll/client_lib.c"},
        ),
        (
            "client_exe",
            {"src/shared/client_lib.c", "src/shared/common_lib.c", "src/server_dll/client_lib.c"},
        ),
    ]:
        cfg = load_config(root=tmp_path, target=target)
        assert cfg.metadata_dir == metadata
        own, foreign = collect(cfg, cfg.marker)
        assert {f.relative_to(tmp_path).as_posix() for f in own} == expected
        assert {f.relative_to(tmp_path).as_posix() for f in foreign} == {
            "src/shared/client_lib.c" if target == "server_dll" else "src/shared/server_lib.c"
        }
