"""CLI surface contract (AGENTS.md conventions), enforced across every command.

Shared options are identical everywhere: `--json` help is exactly
"Output results as JSON", `--dry-run` help exactly "Preview changes
without writing", and the `--target` option describes selecting a
`rebrew-project.toml` target.  `main_entry` carries one docstring.  New
commands inherit all of this from `TargetOption`/`AllTargetsOption` and
`rebrew.cli.run_standalone` — a drift here is a grep-level regression.
`--va` help belongs to one of three semantic families (disambiguation,
direct VA selection, kept-distinct scoping), enumerated literally in
`VA_HELP_ALLOWED`.  A group's help is a landing page with no place else to
show a workflow, so every group app carries an `epilog` with an
`Examples:` section.

The rules bind *options* only: positionals (e.g. a function reference as
a C file, symbol, or hex VA) are a different concept and legitimately
precede the options in the signature.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import re
from pathlib import Path
from typing import Any

from typer.models import OptionInfo

from rebrew.builtins import BUILTIN_COMPONENTS

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = ROOT / "src" / "rebrew"

CANONICAL_MAIN_ENTRY_DOC = "Run the Typer CLI application."
JSON_HELP = "Output results as JSON"
DRY_RUN_HELP = "Preview changes without writing"
TARGET_HELP_PREFIX = "Target name"
VA_HELP_ALLOWED = frozenset(
    {
        # Class A: pick which function inside a file/function reference.
        "Disambiguate VA in a multi-function file (hex)",
        # Class B: direct VA selection, default from the file's annotation.
        "Target VA in hex (default: from annotation)",
        # Class C: kept distinct — bulk/artifact scoping, not target selection.
        "VA in hex (e.g. 0x10009310)",
        "Check a single function VA (hex) instead of the whole .text",
        "Check a single VA (hex) instead of every reversed function.",
        "Restrict to one destination VA (hex, e.g. 0x401000)",
        "Extract a single function by VA (hex) into its own file",
    }
)


def _command_functions():
    """``(component, command, fn)`` for every registered command function."""
    from rebrew.main import _EXTRA_COMPONENTS

    out = []
    for comp in (*BUILTIN_COMPONENTS, *_EXTRA_COMPONENTS):
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


def _options(fn) -> dict[str, OptionInfo]:
    return {
        name: p.default
        for name, p in inspect.signature(fn).parameters.items()
        if isinstance(p.default, OptionInfo)
    }


class TestSharedOptionHelp:
    def test_json_help_is_uniform(self) -> None:
        bad = []
        for comp, cmd, fn in _command_functions():
            opt = _options(fn).get("json_output")
            if opt is not None and (opt.help or "") != JSON_HELP:
                bad.append((comp, cmd, opt.help))
        assert not bad, f"--json help drifted from {JSON_HELP!r}: {bad}"

    def test_dry_run_help_is_uniform(self) -> None:
        bad = []
        for comp, cmd, fn in _command_functions():
            opt = _options(fn).get("dry_run")
            if opt is not None and (opt.help or "") != DRY_RUN_HELP:
                bad.append((comp, cmd, opt.help))
        assert not bad, f"--dry-run help drifted from {DRY_RUN_HELP!r}: {bad}"

    def test_target_help_names_the_concept(self) -> None:
        bad = []
        for comp, cmd, fn in _command_functions():
            opt = _options(fn).get("target") or _options(fn).get("target_name")
            if opt is not None and not (opt.help or "").startswith(TARGET_HELP_PREFIX):
                bad.append((comp, cmd, opt.help))
        assert not bad, f"--target help must start with {TARGET_HELP_PREFIX!r}: {bad}"

    def test_json_precedes_target_option_in_signature(self) -> None:
        """Convention: --json before --target, both trailing options."""
        bad = []
        for comp, cmd, fn in _command_functions():
            opts = _options(fn)
            if "json_output" not in opts:
                continue
            target_key = next((k for k in ("target", "target_name") if k in opts), None)
            if target_key is None:
                continue
            names = list(inspect.signature(fn).parameters)
            if names.index("json_output") > names.index(target_key):
                bad.append((comp, cmd))
        assert not bad, f"--json must precede --target in the signature: {bad}"

    def test_va_help_is_canonical(self) -> None:
        bad = []
        for comp, cmd, fn in _command_functions():
            for name in ("va", "va_override"):
                opt = _options(fn).get(name)
                if opt is not None and (opt.help or "") not in VA_HELP_ALLOWED:
                    bad.append((comp, cmd, name, opt.help))
        assert not bad, f"--va help must be one of the canonical set: {bad}"


class TestEntryPointDocstrings:
    def test_main_entry_docstring_is_uniform(self) -> None:
        bad = []
        for comp in BUILTIN_COMPONENTS:
            module = importlib.import_module(comp.module)
            fn = getattr(module, "main_entry", None)
            if fn is None:
                continue
            doc = (fn.__doc__ or "").strip()
            if doc != CANONICAL_MAIN_ENTRY_DOC:
                bad.append((comp.name, doc))
        assert not bad, f"main_entry docstring must be exactly {CANONICAL_MAIN_ENTRY_DOC!r}: {bad}"

    def test_standalone_app_is_runnable(self) -> None:
        """`python -m <module>` resolves a command and keeps the exit contract."""
        import typer

        bad = []
        for comp in BUILTIN_COMPONENTS:
            module = importlib.import_module(comp.module)
            app = getattr(module, "app", None)
            if app is None:
                continue
            if getattr(module, "main_entry", None) is None:
                bad.append((comp.name, "no main_entry"))
                continue
            try:
                typer.main.get_command(app)
            except RuntimeError as exc:
                bad.append((comp.name, str(exc)))
        assert not bad, f"standalone app not runnable: {bad}"


class TestVersionFlag:
    def test_every_command_offers_version(self) -> None:
        """`--version` works on each tool, not just the `rebrew` group.

        Every tool also ships as its own console script (`rebrew-diff`,
        `rebrew-test`, ...). Asking one of those for its version used to
        return click's ``No such option: --version`` with exit 2.
        """
        import typer

        from rebrew.cli import add_version_option

        bad = []
        for comp in BUILTIN_COMPONENTS:
            app = getattr(importlib.import_module(comp.module), "app", None)
            if app is None:
                continue
            cmd = add_version_option(typer.main.get_command(app))
            names = {opt for param in cmd.params for opt in param.opts}
            if "--version" not in names:
                bad.append(comp.name)
        assert not bad, f"command without --version: {bad}"

    def test_umbrella_subcommand_reports_version(self) -> None:
        from typer.testing import CliRunner

        from rebrew import __version__
        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["diff", "--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_umbrella_short_version_flag_matches_subcommands(self) -> None:
        """`rebrew -V` answers the version, like `rebrew diff -V` does.

        The group declares its own ``--version`` option, so the shared
        ``add_version_option`` injection skips it; before this was pinned the
        group carried the long form only and every subcommand answered
        ``-V``, so the one spelling a script learned from a subcommand
        exited 2 on the group.
        """
        from typer.testing import CliRunner

        from rebrew import __version__
        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["-V"])
        assert result.exit_code == 0, result.output
        assert __version__ in result.stdout

    def test_version_is_eager_over_a_missing_argument(self) -> None:
        """`rebrew diff --version` reports the version, not a usage error.

        ``diff`` requires SOURCE; an eager flag answers before the parser
        reaches the missing argument, so a script probing the install never
        sees a spurious exit 2.
        """
        from typer.testing import CliRunner

        from rebrew import __version__
        from rebrew.main import app as umbrella

        result = CliRunner().invoke(umbrella, ["diff", "--version"])
        assert result.exit_code == 0, result.output
        assert "Missing argument" not in result.output
        assert __version__ in result.stdout


class TestGroupHelpEpilog:
    def test_every_group_help_shows_examples(self) -> None:
        """A group's `--help` is a landing page: it names the common invocations.

        Single-command tools carry their examples in the command help; a group
        has no such place, so the epilog is the only place a reader learns the
        workflow.  An unset `epilog` leaves the group help as a bare command
        list.
        """
        from typer.models import DefaultPlaceholder

        bad = []
        for comp in BUILTIN_COMPONENTS:
            if not comp.is_group:
                continue
            app = getattr(importlib.import_module(comp.module), "app", None)
            if app is None:
                continue
            epilog = getattr(app.info, "epilog", None)
            if epilog is None or isinstance(epilog, DefaultPlaceholder):
                bad.append(comp.name)
                continue
            if "Examples:" not in epilog:
                bad.append(f"{comp.name} (epilog without an Examples section)")
        assert not bad, f"group help without usage examples: {bad}"


class TestGroupWithoutSubcommand:
    def test_group_without_subcommand_is_usage_error_on_stderr(self) -> None:
        """A bare group invocation exits 2 with nothing on stdout, like any usage error."""
        from typer.testing import CliRunner

        from rebrew.main import app as umbrella

        bad = []
        for comp in BUILTIN_COMPONENTS:
            if not comp.is_group:
                continue
            app = getattr(importlib.import_module(comp.module), "app", None)
            if app is None or app.registered_callback is not None:
                continue  # a group callback may run a default action
            result = CliRunner().invoke(umbrella, [comp.name])
            if result.exit_code != 2 or result.stdout:
                bad.append((comp.name, result.exit_code, result.stdout[:80]))
        assert not bad, f"bare group must exit 2 with empty stdout: {bad}"


class TestScriptDispatch:
    """Every ``[project.scripts]`` target dispatches through the exit contract.

    ``run_standalone`` / ``run_cli`` turn SIGPIPE and Ctrl-C into 141/130 and
    a usage error into 2.  A bare ``app()`` skips all three, so the entry
    attribute's body is checked rather than its name: most targets name
    ``main_entry``, but the umbrella and the CMake bridges do not.
    """

    @staticmethod
    def _targets() -> list[tuple[str, Any]]:
        toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        out = []
        for script, module, attr in re.findall(r'^([\w-]+) = "([\w.]+):(\w+)"$', toml, re.M):
            out.append((script, getattr(importlib.import_module(module), attr)))
        return out

    def test_every_script_dispatches_through_the_exit_contract(self) -> None:
        targets = self._targets()
        assert targets, "no [project.scripts] entries found — the regex is stale"
        bad = []
        for script, fn in targets:
            body = inspect.getsource(fn)
            if "run_standalone(" not in body and "run_cli(" not in body:
                bad.append(f"{script}: {fn.__name__} does not call run_standalone/run_cli")
        assert not bad, (
            "script entry point bypasses the 141/130/2 exit contract:\n  " + "\n  ".join(bad)
        )

    def test_load_config_is_not_imported_from_cli(self) -> None:
        """``load_config`` is private to ``rebrew.config`` (AGENTS.md, CLI conventions).

        ``rebrew.cli`` imports it to serve ``require_config()``, which leaves
        the name importable from the wrong module; nothing should take it.
        """
        offenders = []
        for path in sorted(PACKAGE_ROOT.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module == "rebrew.cli":
                    names = [a.name for a in node.names if a.name == "load_config"]
                    if names:
                        offenders.append(f"{path.relative_to(ROOT)}")
        assert not offenders, f"import load_config from rebrew.config, not rebrew.cli: {offenders}"
