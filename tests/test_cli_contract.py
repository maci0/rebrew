"""CLI surface contract (AGENTS.md conventions), enforced across every command.

Shared options are identical everywhere: `--json` help is exactly
"Output results as JSON", `--dry-run` help exactly "Preview changes
without writing", and the `--target` option describes selecting a
`rebrew-project.toml` target.  `main_entry` carries one docstring.  New
commands inherit all of this from `TargetOption`/`AllTargetsOption` and
`rebrew.cli.run_standalone` — a drift here is a grep-level regression.

The rules bind *options* only: positionals (e.g. a function reference as
a C file, symbol, or hex VA) are a different concept and legitimately
precede the options in the signature.
"""

from __future__ import annotations

import importlib
import inspect

from typer.models import OptionInfo

from rebrew.builtins import BUILTIN_COMPONENTS

CANONICAL_MAIN_ENTRY_DOC = "Run the Typer CLI application."
JSON_HELP = "Output results as JSON"
DRY_RUN_HELP = "Preview changes without writing"
TARGET_HELP_PREFIX = "Target name"


def _command_functions():
    """``(component, command, fn)`` for every registered command function."""
    out = []
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
            target_key = next(
                (k for k in ("target", "target_name") if k in opts), None
            )
            if target_key is None:
                continue
            names = list(inspect.signature(fn).parameters)
            if names.index("json_output") > names.index(target_key):
                bad.append((comp, cmd))
        assert not bad, f"--json must precede --target in the signature: {bad}"


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
        assert not bad, (
            f"main_entry docstring must be exactly {CANONICAL_MAIN_ENTRY_DOC!r}: {bad}"
        )
