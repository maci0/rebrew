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

import pytest
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
            fn = getattr(module, comp.attr or "main", None)
            if fn is not None:
                out.append((comp.name, "main", fn))
    return out


def _options(fn) -> dict[str, OptionInfo]:
    return {
        name: p.default
        for name, p in inspect.signature(fn).parameters.items()
        if isinstance(p.default, OptionInfo)
    }


def _extra_components():
    from rebrew.main import _EXTRA_COMPONENTS

    return _EXTRA_COMPONENTS


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

    def test_output_keeps_its_short_form(self) -> None:
        """``--output`` is the one path-valued option every command spells ``-o``."""
        bad = []
        for comp, cmd, fn in _command_functions():
            for name, opt in _options(fn).items():
                if "--output" not in (opt.param_decls or []):
                    continue
                if "-o" not in (opt.param_decls or []):
                    bad.append((comp, cmd, name))
        assert not bad, f"--output must keep its -o short form: {bad}"

    def test_root_help_is_uniform(self) -> None:
        """``--root`` is the shared :data:`rebrew.cli.RootOption`, so one help string.

        It used to be declared per command and drifted: ``verify``/``catalog``
        documented the walk-up default they actually had, ``build-db`` and
        ``dashboard`` said "Project root directory" and silently resolved the
        current directory instead.  One constant keeps the help and the
        behaviour tied to the same object.
        """
        from rebrew.cli import RootOption

        bad = []
        for comp, cmd, fn in _command_functions():
            for name, opt in _options(fn).items():
                if "--root" not in (opt.param_decls or []):
                    continue
                if (opt.help or "") != (RootOption.help or ""):
                    bad.append((comp, cmd, name, opt.help))
        assert not bad, f"--root must use the shared RootOption help: {bad}"

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

        Shared options work after the subcommand name and during direct
        module execution, in addition to the root callback's options.
        """
        import typer

        from rebrew.cli import add_global_options

        bad = []
        for comp in BUILTIN_COMPONENTS:
            app = getattr(importlib.import_module(comp.module), "app", None)
            if app is None:
                continue
            cmd = add_global_options(typer.main.get_command(app))
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
        ``add_global_options`` injection skips it; before this was pinned the
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


class TestVerbosityFlags:
    def test_every_command_offers_verbosity_flags(self) -> None:
        """`-v` / `-q` work after the subcommand, not only before it.

        The umbrella advertises both, but click parses a group's own options
        only ahead of the subcommand name, so `rebrew diff -v` and the flat
        `rebrew-diff -v` used to exit 2 with "No such option: --verbose".
        """
        import typer

        from rebrew.cli import add_global_options

        missing: dict[str, list[str]] = {}
        for comp in BUILTIN_COMPONENTS:
            app = getattr(importlib.import_module(comp.module), "app", None)
            if app is None:
                continue
            cmd = add_global_options(typer.main.get_command(app))
            names = {opt for param in cmd.params for opt in param.opts}
            absent = [f for f in ("--verbose", "-v", "--quiet", "-q") if f not in names]
            if absent:
                missing[comp.name] = absent
        assert not missing, f"commands missing verbosity flags: {missing}"

    def test_command_declared_flag_wins_over_injection(self) -> None:
        """`lint --quiet` stays "errors only"; the injector adds only --verbose.

        The shared injection skips a spelling the command already declares, so
        rebrew's own meaning for it survives the global options.
        """
        import typer

        from rebrew.cli import add_global_options
        from rebrew.lint import app as lint_app

        cmd = add_global_options(typer.main.get_command(lint_app))
        params = {param.name: param for param in cmd.params}
        assert params["quiet"].help == "Only show errors, suppress warnings"
        assert params["verbose"].help == "Increase output verbosity."

    def test_subcommand_quiet_reaches_the_log_level(self) -> None:
        """`rebrew diff -q` parses and pins logs at warning.

        The injected callbacks share one recorded state with the umbrella's
        own, so the flag lands wherever it is written.
        """
        import logging

        from typer.testing import CliRunner

        from rebrew import cli
        from rebrew.main import app as umbrella

        cli.reset_verbosity()
        result = CliRunner().invoke(umbrella, ["diff", "-q", "nosuch.c"])
        assert "No such option" not in result.output
        assert cli.effective_log_level() == logging.WARNING

    def test_group_verbose_survives_subcommand_default(self) -> None:
        """`rebrew -vv diff` is not reset by the subcommand's own copy.

        Both spellings record into one state, so the copy that was not
        written on the command line cannot lower the level the group set.
        """
        import logging

        from typer.testing import CliRunner

        from rebrew import cli
        from rebrew.main import app as umbrella

        cli.reset_verbosity()
        CliRunner().invoke(umbrella, ["-vv", "diff", "nosuch.c"])
        assert cli.effective_log_level() == logging.DEBUG, cli.effective_log_level()


class TestHelpMarkupEscaping:
    """Bracketed text in help survives rendering: Rich eats an unescaped tag.

    Every app sets ``rich_markup_mode="rich"``, so Rich parses each
    ``[token]`` in a help string or epilog as a markup tag and silently drops
    it.  A TOML table name is the recurring case: ``[link]`` rendered as
    "values from  in rebrew-project.toml".  Escape it (``\\[link]``) or
    reword it.  The candidates come from Rich's own tag pattern and the
    verdict from ``Style.parse``, so the rule tracks Rich rather than a
    hand-kept list of style names.
    """

    @staticmethod
    def _eaten(text: str) -> list[str]:
        """Bracketed tokens in *text* that Rich consumes as markup, not as text.

        ``[<raw-size>:raw_end]`` is left alone: it does not match Rich's tag
        pattern, so it already reaches the reader verbatim.
        """
        from rich import errors
        from rich.markup import RE_TAGS, render
        from rich.style import Style

        eaten = []
        as_is = render(text, style="", emoji=False).plain
        for match in RE_TAGS.finditer(text):
            tag = match.group(0)
            if tag.startswith("\\"):
                continue  # already escaped: the reader sees the literal brackets
            body = tag[1:-1]
            if body.startswith("/") or "=" in body:  # a closing tag or a real [link=url]
                continue
            try:
                Style.parse(body)
            except errors.StyleSyntaxError:
                pass
            else:
                continue  # a style Rich applies, not text a reader needs to see
            # Escaping the one tag is the reference rendering: where the two
            # differ, the tag was markup and the reader never saw its text.
            escaped = render(text.replace(tag, "\\" + tag)).plain
            if as_is != escaped:
                eaten.append(tag)
        return eaten

    def test_option_help_keeps_its_bracketed_text(self) -> None:
        bad = []
        for comp, cmd, fn in _command_functions():
            for name, opt in _options(fn).items():
                for token in self._eaten(str(opt.help or "")):
                    bad.append(f"{comp} {cmd} --{name.replace('_', '-')}: {token}")
        assert not bad, "escape or reword these help strings:\n  " + "\n  ".join(bad)

    def test_app_help_and_epilog_keep_their_bracketed_text(self) -> None:
        bad = []
        for comp in (*BUILTIN_COMPONENTS, *_extra_components()):
            app = getattr(importlib.import_module(comp.module), "app", None)
            if app is None:
                continue
            for field in ("help", "epilog"):
                value = getattr(app.info, field, None)
                if not isinstance(value, str):
                    continue
                for token in self._eaten(value):
                    bad.append(f"{comp.name} {field}: {token}")
        assert not bad, "escape or reword these help strings:\n  " + "\n  ".join(bad)


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

    def test_every_command_help_shows_examples(self) -> None:
        """Every single-command tool's `--help` closes with an Examples block.

        The epilog is the only place a reader learns how the tool is actually
        invoked; a tool whose `_EPILOG` is defined but never wired into
        `typer.Typer(epilog=...)` prints the option list and nothing else.
        """
        from typer.models import DefaultPlaceholder

        bad = []
        for comp in BUILTIN_COMPONENTS:
            if comp.is_group:
                continue
            app = getattr(importlib.import_module(comp.module), "app", None)
            if app is None:
                continue
            epilog = getattr(app.info, "epilog", None)
            if epilog is None or isinstance(epilog, DefaultPlaceholder):
                bad.append(comp.name)
                continue
            if "Examples:" not in epilog and "Example:" not in epilog:
                bad.append(f"{comp.name} (epilog without an Examples section)")
        assert not bad, f"command help without usage examples: {bad}"


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


class TestRowCountOptions:
    """A "how many rows" option rejects a negative value with exit 2.

    These options end in a Python slice, where ``-5`` silently keeps every
    row but the last five and still exits 0, so a script storing the report
    never learns that it is a tail.  ``0`` stays legal: several commands
    spell it "no cap".  The list is spelled out so a new such option is
    added here rather than shipped unvalidated.
    """

    #: (component, callback parameter name, flag)
    COUNT_OPTIONS = (
        ("todo", "count", "--count"),
        ("similar", "top", "--top"),
        ("binary-similarity", "low", "--low"),
        ("verify-placement", "limit", "--limit"),
        ("text-audit", "limit", "--limit"),
        ("analyze", "top_strings", "--top-strings"),
        ("recover-structs", "limit", "--limit"),
        ("graph", "depth", "--depth"),
    )

    def test_negative_row_count_exits_2(self) -> None:
        import typer

        from rebrew.cli import EXIT_ERROR, require_non_negative

        with pytest.raises(typer.Exit) as exc_info:
            require_non_negative(-1, "--count")
        assert exc_info.value.exit_code == EXIT_ERROR
        assert require_non_negative(0, "--count") == 0

    def test_every_count_option_is_validated(self) -> None:
        modules = {comp.name: comp.module for comp in BUILTIN_COMPONENTS}
        bad = []
        for comp, param, flag in self.COUNT_OPTIONS:
            module = modules.get(comp)
            assert module is not None, f"{comp} is not a registered component"
            fn = importlib.import_module(module).main
            info = _options(fn).get(param)
            if info is None or flag not in info.param_decls:
                bad.append((comp, param, flag))
                continue
            body = inspect.getsource(fn)
            if "require_non_negative" not in body:
                bad.append((comp, param, "not validated by require_non_negative"))
        assert not bad, f"row-count option without a non-negative check: {bad}"


class TestScriptDispatch:
    """Every ``[project.scripts]`` target dispatches through the exit contract.

    ``run_standalone`` / ``run_cli`` turn SIGPIPE and Ctrl-C into 141/130 and
    a usage error into 2.  A bare ``app()`` skips all three, so the entry
    attribute's body is checked rather than its name; all commands now
    dispatch through the umbrella.
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
