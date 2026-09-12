"""Docs hygiene meta-tests.

Pins the docs to the code so drift is caught in CI:

- every lint code emitted by ``src/rebrew/lint.py`` is documented in
  ``docs/ANNOTATIONS.md`` (the linter reference tables);
- every component in the packaged CLI manifest has a dedicated section in
  ``docs/CLI.md`` and is covered by a bundled agent skill.
"""

from __future__ import annotations

import re
from pathlib import Path

from rebrew.builtins import BUILTIN_COMPONENTS
from rebrew.plugin import Panel

ROOT = Path(__file__).resolve().parent.parent


def test_every_lint_code_documented() -> None:
    src = (ROOT / "src" / "rebrew" / "lint.py").read_text(encoding="utf-8")
    codes = set(re.findall(r'result\.(?:warning|error)\(\s*[^,]+,\s*"([EW]\d{3})"', src))
    assert codes, "no lint codes found — the regex may be stale"
    doc = (ROOT / "docs" / "ANNOTATIONS.md").read_text(encoding="utf-8")
    missing = sorted(c for c in codes if c not in doc)
    assert not missing, (
        f"lint code(s) {missing} emitted by lint.py but not documented in "
        "docs/ANNOTATIONS.md — add them to the linter reference tables"
    )


def test_every_builtin_component_has_valid_panel() -> None:
    """Every packaged component names a panel Rich can render under.

    A component with an unknown (or empty) panel would render outside every
    help panel, hiding the command; the panel is declared next to the tool so
    the two cannot drift the way a separate name-keyed table allowed.
    """
    assert BUILTIN_COMPONENTS, "no built-in components found — the manifest is empty"
    bad = sorted(c.name for c in BUILTIN_COMPONENTS if c.panel not in Panel.ALL)
    assert not bad, f"components with an invalid help panel: {bad}"


def test_every_cli_command_documented() -> None:
    names = {c.name for c in BUILTIN_COMPONENTS}
    assert names, "no CLI commands found — the manifest is empty"
    cli = (ROOT / "docs" / "CLI.md").read_text(encoding="utf-8")
    missing = sorted(
        n for n in names if f"### `rebrew {n}`" not in cli and f"## `rebrew {n}`" not in cli
    )
    assert not missing, (
        f"CLI command(s) {missing} registered in the manifest but without a section in docs/CLI.md"
    )


#: Commands intentionally absent from the agent skills — meta/niche tooling
#: agents never drive (PE resource compare, skill discovery itself).  Every
#: other command must be named in a SKILL.md; the advanced/manual tools are
#: listed in the workflow skill's "Advanced commands" section.
_SKILL_OUT_OF_SCOPE = {"resource", "skills"}


def test_every_cli_command_covered_by_agent_skills() -> None:
    """Every workflow command appears in at least one bundled agent skill."""
    names = {c.name for c in BUILTIN_COMPONENTS}
    skills_dir = ROOT / "src" / "rebrew" / "agent-skills"
    skills_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in skills_dir.rglob("SKILL.md")
    )
    missing = sorted(n for n in names if n not in skills_text and n not in _SKILL_OUT_OF_SCOPE)
    assert not missing, (
        f"commands {missing} are not mentioned in any agent-skills SKILL.md — "
        "add them to the relevant workflow skill or document the carve-out"
    )


def test_every_script_main_has_callback_decorator() -> None:
    """Every [project.scripts] main_entry must sit on a @app.callback main.

    A plain ``def main`` in a command module yields "RuntimeError: Could
    not get a command for this Typer instance" when invoked as a
    standalone script (discover.py and pdb_info.py regressed exactly this
    way). The umbrella command registration masks the gap; the standalone
    entry points expose it.
    """
    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    mods = re.findall(r'^rebrew-[\w-]+ = "rebrew\.(\w+):main_entry"$', toml, re.M)
    assert mods, "no [project.scripts] entries found"
    for mod in mods:
        src = (ROOT / "src" / "rebrew" / f"{mod}.py").read_text(encoding="utf-8")
        # Single-command modules need @app.callback on main(); multi-command
        # apps register @app.command subcommands and run app() directly.
        assert "@app.callback" in src or "@app.command" in src, (
            f"{mod}.py wires no callback and no subcommands — the standalone "
            "rebrew-{mod} script fails at runtime"
        )


def test_every_project_script_resolves() -> None:
    """Every ``[project.scripts]`` entry resolves to a live module attribute.

    The scripts are the standalone entry points (``rebrew-<cmd>``); a
    deleted module, a renamed entry point, or a stale ``main_entry`` would
    make the script fail at runtime while the umbrella still works — the
    same drift class the callback-decorator test catches, at the attribute
    level (cli-review F3).
    """
    import importlib

    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    entries = re.findall(r'^rebrew-[\w-]+ = "rebrew\.([\w.]+):([\w]+)"$', toml, re.M)
    assert entries, "no [project.scripts] entries found"
    for mod_path, attr in entries:
        mod = importlib.import_module(f"rebrew.{mod_path}")
        assert hasattr(mod, attr), (
            f"rebrew-{mod_path} script points at rebrew.{mod_path}:{attr} "
            "which does not exist — update pyproject.toml"
        )


def test_every_component_module_resolves() -> None:
    """Every ``BUILTIN_COMPONENTS`` module imports and exposes its entry point.

    A single-command component must expose a ``main`` callback and a Typer
    ``app``; a group component must expose a Typer ``app`` for ``add_typer``.
    """
    import importlib

    for component in BUILTIN_COMPONENTS:
        mod = importlib.import_module(component.module)
        if component.is_group:
            assert hasattr(mod, "app"), (
                f"group component {component.name!r} module {component.module} has no app"
            )
        else:
            assert hasattr(mod, "main") and hasattr(mod, "app"), (
                f"component {component.name!r} module {component.module} has neither "
                "a main callback nor an app"
            )
