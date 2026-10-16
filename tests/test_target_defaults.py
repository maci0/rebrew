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
from cli_json import cli_payload
from source_util import write_store_fixture
from typer.testing import CliRunner

from rebrew.cli import all_targets_run, run_for_each_target
from rebrew.config import load_config

# Commands that legitimately take no --target, keyed (component, command).
# Rationale lives on the tuple — keep it next to the exemption.
TARGETLESS_EXEMPT: set[tuple[str, str]] = {
    ("build", "postlink"),
    ("binary", "pdb show"),
    ("binary", "unpack-lzexe"),
    ("library", "signatures"),
    ("binary", "functions"),
    ("build", "order-sources"),
    ("binary", "resource compare"),
    ("binary", "resource extract"),
    ("build", "symbol-stubs"),
    ("build", "link-stubs"),
    ("build", "cmake-toolchain"),
    ("build", "driver"),
    ("toolchain", "list"),
    ("toolchain", "status"),
    ("toolchain", "pull"),
    ("toolchain", "vendor"),
    ("toolchain", "smoke"),
    ("toolchain", "build"),
    ("toolchain", "check-updates"),
    ("toolchain", "update"),
    ("skills", "list"),
    ("skills", "show"),
    # schema prints the CLI document and never reads a project.
    ("schema", "main"),
    ("library", "show"),
    ("library", "list"),
    ("library", "set"),
    ("library", "remove"),
    # Compile-cache inventory and clearing operate across targets at a project root.
    ("cache", "stats"),
    ("cache", "clear"),
    ("coverage", "serve"),
    ("build", "check"),
    ("cfg", "target list"),
    ("cfg", "raw"),
    ("cfg", "path"),
    ("cfg", "target add"),
    ("cfg", "target remove"),
    ("cfg", "set"),
    ("binary", "pdb import-cflags"),
    ("dev", "refactor"),
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
module = "ALPHA"

[targets.beta]
binary = "bin/b.exe"
format = "pe"
arch = "x86_32"
reversed_dir = "src"
module = "BETA"

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
    from rebrew.app.builtins import BUILTIN_COMPONENTS

    out: list[tuple[str, str, Any]] = []
    for comp in BUILTIN_COMPONENTS:
        module = importlib.import_module(comp.module)
        if comp.is_group:
            app = getattr(module, "app", None)
            for sub in getattr(app, "registered_commands", []) or []:
                if sub.callback is not None:
                    name = sub.name or sub.callback.__name__.replace("_", "-")
                    out.append((comp.name, name, sub.callback))
        else:
            fn = getattr(module, comp.attr or "main", None)
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

    def test_all_targets_lists_every_target(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        assert load_config(root=root).all_targets == ["alpha", "beta"]


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
        doc = cli_payload(result)
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
        write_store_fixture(root / "rebrew-data.toml", "", encoding="utf-8")
        monkeypatch.chdir(root)
        result = CliRunner().invoke(vp_app, [])
        # Missing binary error must name the DEFAULT target's build path.
        assert result.exit_code == 2
        assert "build/alpha" in result.output


class TestSourceTargetScope:
    def test_bound_skipped_and_invalid_targets_are_distinct(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rebrew.cli import source_targets_run

        root = _project(tmp_path)
        config = root / "rebrew-project.toml"
        config.write_text(config.read_text() + '\n[targets.broken]\narch = "unknown"\n')
        source = root / "src" / "f.c"
        source.write_text("/* ADDRESS: BETA 0x401000 */\nint f(void) { return 0; }\n")
        monkeypatch.chdir(root)
        seen: list[str] = []
        from rebrew.cli import json_print

        def run(name: str) -> None:
            seen.append(name)
            json_print({"ran": name})

        with pytest.raises(typer.Exit) as caught:
            source_targets_run(
                str(source),
                enabled=True,
                target=None,
                all_targets=False,
                json_mode=True,
                run_one=run,
            )
        assert caught.value.exit_code == 2
        assert seen == ["beta"]
        targets = json.loads(capsys.readouterr().out)["targets"]
        assert "skipped" in targets["alpha"]
        assert targets["beta"] == {"ran": "beta"}
        assert "error" in targets["broken"]

    def test_entirely_unbound_scope_is_not_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        from rebrew.cli import source_targets_run

        root = _project(tmp_path)
        source = root / "src" / "f.c"
        source.write_text("int f(void) { return 0; }\n")
        monkeypatch.chdir(root)
        with pytest.raises(typer.Exit) as caught:
            source_targets_run(
                str(source),
                enabled=True,
                target=None,
                all_targets=False,
                json_mode=True,
                run_one=lambda _: pytest.fail("unbound compile"),
            )
        assert caught.value.exit_code == 1
        assert all(
            "skipped" in row for row in json.loads(capsys.readouterr().out)["targets"].values()
        )

    def test_exact_paths_do_not_bind_sibling_basenames(self, tmp_path: Path) -> None:
        from rebrew.metadata.bindings import function_rows_for_file
        from rebrew.metadata.data import data_rows_for_path, set_data_field
        from rebrew.metadata.functions import stored_file_matches

        source = tmp_path / "other" / "f.c"
        assert not stored_file_matches("f.c", "other/f.c")
        entries = {("ALPHA", 0x401000): {"file": "f.c", "name": "f"}}
        assert function_rows_for_file(source, tmp_path, entries) == []
        set_data_field(tmp_path, 0x402000, "file", "f.c", "ALPHA")
        assert data_rows_for_path(tmp_path, source) == []

    @pytest.mark.parametrize("fragment", ["", "not JSON"])
    def test_failed_json_target_has_explicit_error(
        self, fragment: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def run(_: str) -> None:
            if fragment:
                print(fragment)
            raise RuntimeError("compile broke")

        assert run_for_each_target(["alpha"], run, json_mode=True) == 2
        assert "error" in json.loads(capsys.readouterr().out)["targets"]["alpha"]

    def test_all_targets_root_does_not_load_invalid_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path)
        config = root / "rebrew-project.toml"
        config.write_text(
            config.read_text().replace('default_target = "alpha"', 'default_target = "absent"')
        )
        monkeypatch.chdir(tmp_path.parent)
        seen: list[str] = []
        assert all_targets_run(
            target=None, all_targets=True, json_mode=False, run_one=seen.append, root=root
        )
        assert seen == ["alpha", "beta"]

    @pytest.mark.parametrize(
        "module, args",
        [
            ("rebrew.test", ["--source-targets", "--va", "0x401000"]),
            ("rebrew.test", ["--source-targets", "--size", "0"]),
            ("rebrew.verify", ["--source-targets", "--data"]),
            ("rebrew.verify", ["--all-targets", "--link-map", "one.map"]),
            ("rebrew.data", ["list", "--all-targets", "--link-map", "one.map"]),
        ],
    )
    def test_pinned_overrides_rejected_before_config(self, module: str, args: list[str]) -> None:
        result = CliRunner().invoke(importlib.import_module(module).app, [*args, "--json"])
        assert result.exit_code == 2
        assert "mutually exclusive" in cli_payload(result)["error"]


class TestTargetCompilerIsolation:
    def test_invalid_sibling_compiler_only_fails_its_target(self, tmp_path: Path) -> None:
        root = _project(tmp_path)
        path = root / "rebrew-project.toml"
        path.write_text(
            path.read_text().replace("[targets.beta]", '[targets.beta]\ncompiler = "invalid"')
        )
        assert load_config(root=root, target="alpha").target_name == "alpha"
        with pytest.raises(ValueError, match="targets.beta.compiler"):
            load_config(root=root, target="beta")
