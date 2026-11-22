"""A withdrawn toolchain is listed with its reason, never offered, and never run."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cli_json import cli_payload
from typer.testing import CliRunner

from rebrew.app.main import app

WITHDRAWN = "msvc-9.0-sp1"


def test_the_registry_withdraws_the_itanium_compiler() -> None:
    from rebrew.compiler.toolchain import TOOLCHAINS

    assert "Itanium" in TOOLCHAINS[WITHDRAWN].withdrawn
    assert not TOOLCHAINS["msvc-9.0"].withdrawn


def test_toolchain_list_shows_the_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("rebrew.compiler.toolchain.docker_available", lambda: False)
    monkeypatch.setattr("rebrew.toolchain_cli.docker_available", lambda: False)
    result = CliRunner().invoke(app, ["toolchain", "list", "--json"])
    assert result.exit_code == 0, result.output
    rows = {row["name"]: row for row in cli_payload(result)["toolchains"]}
    assert "Itanium" in rows[WITHDRAWN]["withdrawn"]
    assert rows["msvc-9.0"]["withdrawn"] is None


@pytest.mark.parametrize("command", ["build", "pull", "vendor"])
def test_no_command_assembles_a_withdrawn_toolchain(command: str) -> None:
    result = CliRunner().invoke(app, ["toolchain", command, WITHDRAWN, "--json"])
    assert result.exit_code != 0
    assert "withdrawn" in result.output and "Itanium" in result.output


def test_init_does_not_offer_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["init", "--toolchain", WITHDRAWN, "--json"])
    assert result.exit_code != 0
    assert "withdrawn" in result.output and "Itanium" in result.output
    assert not (tmp_path / "rebrew-project.toml").exists()


def test_a_toolchain_sweep_leaves_it_out() -> None:
    from rebrew.match_sweep import _vendored_msvc_toolchains

    names = [name for name, _cl, _inc in _vendored_msvc_toolchains(SimpleNamespace())]
    assert WITHDRAWN not in names and "msvc-9.0" in names
    assert _vendored_msvc_toolchains(SimpleNamespace(compiler_profile=WITHDRAWN), only="9.0") == [
        ("msvc-9.0", "", "")
    ]


def test_doctor_names_the_reason_not_a_build() -> None:
    from rebrew.doctor import _FAIL, check_toolchain_backed

    result = check_toolchain_backed(SimpleNamespace(compiler_profile=WITHDRAWN, root=Path(".")))
    assert result.status == _FAIL
    assert "Itanium" in result.message
    assert "build" not in result.fix and "vendor" not in result.fix


def test_a_project_naming_it_loads_and_its_compile_is_refused_unrun(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stored evidence names the profile, so the project loads; the compile says why it cannot run."""
    from rebrew.compiler.compile import compile_to_obj
    from rebrew.compiler.toolchain import COMPILER_WITHDRAWN, CompilerNotOffered
    from rebrew.config import load_config

    (tmp_path / "rebrew-project.toml").write_text(
        '[project]\ndefault_target = "main"\n[targets.main]\nbinary = "original/main.exe"\n'
        f'[compiler]\nprofile = "{WITHDRAWN}"\n',
        encoding="utf-8",
    )
    monkeypatch.delenv("REBREW_RECOMPILE_URL", raising=False)
    cfg = load_config(tmp_path)
    assert cfg.compiler_profile == WITHDRAWN

    def ran(*args: Any, **kwargs: Any) -> None:
        pytest.fail("a withdrawn compiler was run")

    monkeypatch.setattr("rebrew.compiler.compile.run_toolchain", ran)
    source = tmp_path / "f.c"
    source.write_text("int f(void) { return 0; }\n", encoding="utf-8")
    errors: list[Any] = []
    obj, message = compile_to_obj(cfg, source, "", tmp_path, backend_errors=errors)
    assert obj is None and "Itanium" in message
    assert isinstance(errors[0], CompilerNotOffered)
    assert errors[0].error_code == COMPILER_WITHDRAWN
    assert json.loads(json.dumps(errors[0].to_dict()))["error_code"] == COMPILER_WITHDRAWN
