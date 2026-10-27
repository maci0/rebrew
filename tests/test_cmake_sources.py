"""`rebrew build cmake-sources` — the build must link what the target owns.

A glob over a shared tree over-includes: every target's TUs compile and
link into every binary (duplicate symbols at best, foreign bytes at
worst). Canonical identities and file-purpose metadata select target
translation units, with unbound helpers shared across targets.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cli_json import cli_payload
from source_util import SourceFixture, write_source
from typer.testing import CliRunner

from rebrew.cmake_sources import app
from rebrew.config import ProjectConfig, load_config
from rebrew.source_selection import collect_target_sources

TOML = """\
[project]
default_target = "server_dll"

[targets.server_dll]
binary = "original/server.dll"
format = "pe"
arch = "x86_32"
reversed_dir = "src/server_dll"
module = "SERVER"

[targets.client_exe]
binary = "original/client.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src/shared"
module = "CLIENT"

[compiler]
profile = "msvc-6.0"
"""


def _project(tmp_path: Path, sources: dict[str, str]) -> ProjectConfig:
    write_source(tmp_path / "rebrew-project.toml", TOML, encoding="utf-8")
    (tmp_path / "src/server_dll").mkdir(parents=True, exist_ok=True)
    (tmp_path / "src/shared").mkdir(parents=True, exist_ok=True)
    for name, body in sources.items():
        write_source(tmp_path / name, body, encoding="utf-8")
    return load_config(root=tmp_path, target="server_dll")


def test_leftover_anchor_of_another_target_stays_foreign(tmp_path: Path) -> None:
    """A file whose only anchor names another target must not join this build.

    Its claim was retired or rebound elsewhere, so the anchor resolves to no
    live row. Treating it as an unbound helper pulls that target's closures
    into this binary.
    """
    cfg = _project(
        tmp_path,
        {
            "src/shared/GOLDTL.leftover.c": (
                "/* ADDRESS: CLIENT 0x401000 */\nint __cdecl fcn_00401000(void) { return 1; }\n"
            ),
        },
    )
    own, foreign = collect_target_sources(cfg, "SERVER")
    leftover = tmp_path / "src/shared/GOLDTL.leftover.c"
    assert leftover not in own
    assert leftover in foreign


def test_stacked_file_belongs_to_both_targets(tmp_path: Path) -> None:
    """One stacked file serves every target whose marker it carries."""
    _project(
        tmp_path,
        {
            "src/shared/common.c": (
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\n/* ADDRESS: CLIENT 0x20001000 */\n\nint common(void){return 0;}\n",
                    {
                        "SERVER.0x10001000": {"kind": "FUNCTION", "size": 8},
                        "CLIENT.0x20001000": {"kind": "FUNCTION", "size": 8},
                    },
                )
            ),
        },
    )
    from rebrew.config import load_config as _load

    for target, count in (("server_dll", 1), ("client_exe", 1)):
        cfg = _load(root=tmp_path, target=target)
        own, foreign = collect_target_sources(cfg, cfg.module)
        assert len(own) == count, (target, own, foreign)


def test_foreign_only_file_excluded(tmp_path: Path) -> None:
    """A TU with no block for this target must not link into it."""
    cfg = _project(
        tmp_path,
        {
            "src/shared/only_client.c": (
                SourceFixture(
                    "/* ADDRESS: CLIENT 0x20002000 */\n\nint oc(void){return 1;}\n",
                    {"CLIENT.0x20002000": {"kind": "FUNCTION", "size": 8}},
                )
            ),
            "src/shared/common.c": (
                SourceFixture(
                    "/* ADDRESS: SERVER 0x10001000 */\n\nint s(void){return 0;}\n",
                    {"SERVER.0x10001000": {"kind": "FUNCTION", "size": 8}},
                )
            ),
        },
    )
    own, foreign = collect_target_sources(cfg, "SERVER")
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
    own, foreign = collect_target_sources(cfg, "SERVER")
    assert [p.name for p in own] == ["help.c"]
    assert foreign == []


def test_emitted_include_sets_variable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The written file is a valid `set(VAR ...)` include."""
    _project(
        tmp_path,
        {
            "src/shared/a.c": SourceFixture(
                "/* ADDRESS: SERVER 0x10001000 */\nint a(void){return 0;}\n",
                {"SERVER.0x10001000": {"kind": "FUNCTION"}},
            ),
        },
    )
    monkeypatch.chdir(tmp_path)
    out = CliRunner().invoke(app, ["--var", "MYSRC", "--dry-run"])
    assert out.exit_code == 0, out.output
    assert "set(MYSRC" in out.stdout
    assert "src/shared/a.c" in out.stdout
    for name in ("rebrew-functions.toml", "rebrew-data.toml"):
        assert f'"${{CMAKE_CURRENT_SOURCE_DIR}}/{name}"' in out.stdout


def test_json_reports_excluded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """--json names the excluded files so drops are auditable."""
    _project(
        tmp_path,
        {
            "src/shared/only_client.c": (
                SourceFixture(
                    "/* ADDRESS: CLIENT 0x20002000 */\nint oc(void){return 1;}\n",
                    {"CLIENT.0x20002000": {"kind": "FUNCTION"}},
                )
            ),
        },
    )
    monkeypatch.chdir(tmp_path)
    out = CliRunner().invoke(app, ["--json", "--dry-run"])
    assert out.exit_code == 0, out.output
    payload = cli_payload(out)
    assert payload["files"] == []
    assert payload["excluded"] == ["src/shared/only_client.c"]


@pytest.mark.parametrize("archive", ["vendor/runtime.lib", r"vendor\runtime.lib"])
def test_relative_archive_reaches_cmake_as_a_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, archive: str
) -> None:
    """Relative archive items otherwise become -lvendor/runtime.lib or .lib.lib."""
    cmake = shutil.which("cmake")
    compiler = shutil.which("cc")
    if not cmake or not compiler:
        pytest.skip("CMake and a C compiler are required")
    cfg = _project(tmp_path, {"src/server_dll/main.c": "int main(void) { return 0; }\n"})
    cfg.external_libs = {"RUNTIME": archive, "SYSTEM": "KERNEL32.lib"}
    monkeypatch.setattr("rebrew.cmake_sources.require_config", lambda **_kw: cfg)
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "sources.cmake"
    result = CliRunner().invoke(app, ["--output", str(output), "--json"])
    assert result.exit_code == 0, result.output
    assert cli_payload(result)["external_libs"] == [archive, "KERNEL32.lib"]
    (tmp_path / "vendor").mkdir()
    library = tmp_path / "vendor/runtime.lib"
    library.touch()
    (tmp_path / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.19)\nproject(archive_path C)\n"
        "include(sources.cmake)\nadd_executable(example ${REBREW_SOURCES})\n"
        "target_link_libraries(example PRIVATE ${REBREW_EXTERNAL_LIBS})\n"
    )
    subprocess.run(
        [
            cmake,
            "-S",
            str(tmp_path),
            "-B",
            str(tmp_path / "build"),
            "-G",
            "Unix Makefiles",
            f"-DCMAKE_C_COMPILER={compiler}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    command = (tmp_path / "build/CMakeFiles/example.dir/link.txt").read_text()
    assert str(library) in command
    assert "-lvendor" not in command and "runtime.lib.lib" not in command


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
    from rebrew.metadata.functions import record_function_identity, save_metadata

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
            kind="LIBRARY",
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
        own, foreign = collect_target_sources(cfg, cfg.module)
        assert {f.relative_to(tmp_path).as_posix() for f in own} == expected
        assert {f.relative_to(tmp_path).as_posix() for f in foreign} == {
            "src/shared/client_lib.c" if target == "server_dll" else "src/shared/server_lib.c"
        }


@pytest.mark.parametrize("purpose_module", [None, "SERVER", "CLIENT"])
def test_shared_helper_outside_metadata_root(tmp_path: Path, purpose_module: str | None) -> None:
    """Unbound shared helpers need not be descendants of the metadata directory."""
    from rebrew.metadata.functions import record_function_identity

    source = tmp_path / "src" / "game"
    source.mkdir(parents=True)
    shared = tmp_path / "shared"
    shared.mkdir()
    helper = shared / "helper.c"
    helper.write_text("int helper(void) { return 1; }\n")
    owner = source / "owner.c"
    owner.write_text("int owner(void) { return 2; }\n")
    record_function_identity(
        source.parent,
        module="SERVER",
        va=0x401000,
        file="game/owner.c",
        kind="FUNCTION",
        name="owner",
        symbol="_owner",
        size=8,
    )
    cfg = ProjectConfig(root=tmp_path, reversed_dir=source, shared_dir=shared, module="SERVER")
    assert cfg.metadata_dir == source.parent
    own, foreign = collect_target_sources(cfg, "SERVER")
    assert helper in own and helper not in foreign
