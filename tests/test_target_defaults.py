"""Target selection contract: default target, --target override, --all-targets.

Every project-scoped command must select the project's ``default_target``
when no ``--target`` is given (``rebrew.config.load_config``'s rule), accept
``--target <name>`` to override, and batch tools accept ``--all-targets`` to
sweep every configured target.  Commands whose inputs are explicit paths or
which are project-global by design are listed in :data:`TARGETLESS_EXEMPT`
with the reason — a NEW command missing ``--target`` fails
``test_every_command_exposes_target`` until it complies or joins the exempt
list on purpose.
"""

from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

from rebrew.cli import all_targets_run, iter_target_configs, run_for_each_target
from rebrew.config import load_config

# Commands that legitimately take no --target, keyed (component, command).
# Rationale lives on the tuple — keep it next to the exemption.
TARGETLESS_EXEMPT: set[tuple[str, str]] = {
    # explicit-path binary tools: the binary/layout/CSV is the argument
    ("postlink", "main"),
    ("pdb-info", "main"),
    ("unpack-lzexe", "main"),
    ("gen-flirt-pat", "main"),
    ("discover-functions", "main"),
    ("order-sources", "main"),
    ("resource", "compare"),
    ("resource", "extract"),
    # generators driven by explicit input/output paths
    ("gen-stubs", "main"),
    ("gen-link-stubs", "main"),
    # toolchain image management (not project-scoped)
    ("cmake-toolchain", "main"),
    ("toolchain", "list"),
    ("toolchain", "status"),
    ("toolchain", "pull"),
    ("toolchain", "vendor"),
    ("toolchain", "smoke"),
    ("toolchain", "build"),
    ("toolchain", "check-updates"),
    ("toolchain", "update"),
    # project-global services / self-describing
    ("skills", "list"),
    ("skills", "show"),
    ("library", "show"),
    ("library", "list"),
    ("library", "set"),
    ("library", "rm"),
    ("cache", "main"),
    ("dashboard", "main"),
    # build-check validates the one generated CMake build (server_dll)
    ("build-check", "main"),
    # cfg edits the project file itself; some subcommands take the target
    # NAME as their subject (add-target/remove-target)
    ("cfg", "list-targets"),
    ("cfg", "raw"),
    ("cfg", "path"),
    ("cfg", "add-target"),
    ("cfg", "remove-target"),
    ("cfg", "set"),
}

PROJECT_TOML = """\
[project]
name = "t"
default_target = "alpha"

[targets.alpha]
binary = "bin/a.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
marker = "ALPHA"

[targets.beta]
binary = "bin/b.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
marker = "BETA"

[compiler]
profile = "gcc-14.2.0"
command = "gcc"
includes = ""
libs = ""
"""


def _project(tmp_path: Path) -> Path:
    (tmp_path / "rebrew-project.toml").write_text(PROJECT_TOML, encoding="utf-8")
    (tmp_path / "src").mkdir(exist_ok=True)
    return tmp_path


def _command_functions() -> list[tuple[str, str, Any]]:
    """``(component, command, fn)`` for every registered command function."""
    from rebrew.builtins import BUILTIN_COMPONENTS

    out: list[tuple[str, str, Any]] = []
    for comp in BUILTIN_COMPONENTS:
        module = importlib.import_module(comp.module)
        if comp.is_group:
            app = getattr(module, "app", None)
            for sub in getattr(app, "registered_commands", []) or []:
                if sub.callback is not None:
                    out.append((comp.name, sub.name or "?", sub.callback))
        else:
            fn = getattr(module, "main", None)
            if fn is not None:
                out.append((comp.name, "main", fn))
    return out


class TestTargetOptionContract:
    def test_every_command_exposes_target(self) -> None:
        """New commands must take --target (or join TARGETLESS_EXEMPT)."""
        missing = []
        for comp_name, cmd_name, fn in _command_functions():
            if (comp_name, cmd_name) in TARGETLESS_EXEMPT:
                continue
            params = inspect.signature(fn).parameters
            if "target" not in params and "target_name" not in params:
                missing.append((comp_name, cmd_name))
        assert not missing, (
            f"commands missing --target: {missing} — add a `target: str | None = "
            "TargetOption` parameter (defaults to project.default_target) or "
            "list the command in TARGETLESS_EXEMPT with a reason"
        )

    def test_batch_tools_declare_all_targets(self) -> None:
        """The batch tools carry the --all-targets escape hatch."""
        from rebrew import lint, status, todo, verify
        from rebrew import test as testmod

        for mod in (verify, testmod, lint, status, todo):
            assert "all_targets" in inspect.signature(mod.main).parameters, mod.__name__


class TestTargetResolution:
    def test_no_target_picks_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _project(tmp_path)
        monkeypatch.chdir(tmp_path)
        assert load_config().target_name == "alpha"
        assert load_config(target="beta").target_name == "beta"

    def test_iter_target_configs_expands(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        cfg = load_config(root=root)
        names = [c.target_name for c in iter_target_configs(cfg)]
        assert names == ["alpha", "beta"]


class TestRunForEachTarget:
    def test_sweeps_all_targets(self) -> None:
        seen: list[str] = []

        code = run_for_each_target(["alpha", "beta"], lambda n: seen.append(n), json_mode=False)
        assert seen == ["alpha", "beta"]
        assert code == 0

    def test_worst_exit_code_wins(self) -> None:
        codes = {"alpha": 0, "beta": 2}

        def run(n: str) -> None:
            if codes[n]:
                raise typer.Exit(code=codes[n])

        assert run_for_each_target(["alpha", "beta"], run, json_mode=False) == 2

    def test_one_bad_target_does_not_stop_the_sweep(self) -> None:
        seen: list[str] = []

        def run(n: str) -> None:
            seen.append(n)
            if n == "alpha":
                raise RuntimeError("boom")

        code = run_for_each_target(["alpha", "beta"], run, json_mode=False)
        assert seen == ["alpha", "beta"]
        assert code == 2  # infrastructure error, sweep still finished

    def test_json_nested_envelope(self, capsys: pytest.CaptureFixture[str]) -> None:
        from rebrew.cli import json_print

        run_for_each_target(
            ["alpha", "beta"],
            lambda n: json_print({"target": n}),
            json_mode=True,
        )
        doc = json.loads(capsys.readouterr().out)
        assert set(doc["targets"]) == {"alpha", "beta"}
        assert doc["targets"]["alpha"] == {"target": "alpha"}

    def test_all_targets_run_rejects_target_combo(self) -> None:
        with pytest.raises(typer.Exit) as exc:
            all_targets_run(
                target="alpha",
                all_targets=True,
                json_mode=False,
                run_one=lambda n: None,
            )
        assert exc.value.exit_code == 2

    def test_all_targets_run_defers_single_target(self) -> None:
        assert (
            all_targets_run(
                target=None,
                all_targets=False,
                json_mode=False,
                run_one=lambda n: None,
            )
            is False
        )


class TestStatusAllTargetsCli:
    def test_sweep_renders_every_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.status import app as status_app

        _project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(status_app, ["--all-targets"])
        assert result.exit_code == 0
        assert "=== Target alpha ===" in result.output
        assert "=== Target beta ===" in result.output

    def test_json_envelope_per_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.status import app as status_app

        _project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(status_app, ["--all-targets", "--json"])
        assert result.exit_code == 0
        doc = json.loads(result.stdout)
        assert set(doc["targets"]) == {"alpha", "beta"}
        for target_doc in doc["targets"].values():
            assert "functions" in target_doc
            assert target_doc["target"] in ("alpha", "beta")

    def test_mutual_exclusion_with_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rebrew.status import app as status_app

        _project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(status_app, ["--all-targets", "--target", "alpha"])
        assert result.exit_code == 2
        assert "mutually exclusive" in result.output


class TestVerifyPlacementDefaults:
    def test_default_built_follows_active_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--built defaults to build/<target>, not one hardcoded binary."""
        from rebrew.verify_placement import app as vp_app

        root = _project(tmp_path)
        (root / "src" / "rebrew-data.toml").write_text("", encoding="utf-8")
        monkeypatch.chdir(root)
        result = CliRunner().invoke(vp_app, [])
        # Missing binary error must name the DEFAULT target's build path.
        assert result.exit_code == 2
        assert "build/alpha" in result.output
