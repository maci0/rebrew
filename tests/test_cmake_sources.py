"""`rebrew cmake-sources` — the build must link what the target owns.

A glob over a shared tree over-includes: every target's TUs compile and
link into every binary (duplicate symbols at best, foreign bytes at
worst).  Marker-selected lists include exactly the files carrying the
target's FUNCTION/LIBRARY/STUB block, plus unannotated helpers.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rebrew.cmake_sources import app, collect
from rebrew.config import load_config

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


def _project(tmp_path: Path, sources: dict[str, str]):
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
