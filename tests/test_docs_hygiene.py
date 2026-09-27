"""Docs hygiene meta-tests.

Pins the docs to the code so drift is caught in CI:

- every lint code emitted by ``src/rebrew/lint.py`` is documented in
  ``docs/ANNOTATIONS.md`` (the linter reference tables);
- every component in the packaged CLI manifest has a dedicated section in
  ``docs/CLI.md`` and is covered by a bundled agent skill;
- the decision and requirement sets (``docs/adr/``, ``docs/prd/``) keep
  their index, lifecycle status, and cross-links intact;
- every package whose ``AGENTS.md`` declares an ``Externals`` allowlist imports
  only the packages on it.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from rebrew.builtins import BUILTIN_COMPONENTS
from rebrew.plugin import Panel

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = ROOT / "src" / "rebrew"

#: ``Externals (the only ... one may import): `a`, `b.sub`, and `c`.``
_EXTERNALS_RE = re.compile(r"^Externals \(the only [^\n]*?\): (.+)$", re.M)


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
#: other command must be named in a SKILL.md or a progressive-disclosure
#: reference under agent-skills/ (e.g. workflow references/advanced-commands.md).
_SKILL_OUT_OF_SCOPE = {"resource", "skills"}


def test_every_cli_command_covered_by_agent_skills() -> None:
    """Every workflow command appears in at least one bundled agent skill."""
    names = {c.name for c in BUILTIN_COMPONENTS}
    skills_dir = ROOT / "src" / "rebrew" / "agent-skills"
    skills_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in skills_dir.rglob("*.md")
    )
    missing = sorted(n for n in names if n not in skills_text and n not in _SKILL_OUT_OF_SCOPE)
    assert not missing, (
        f"commands {missing} are not mentioned in any agent-skills markdown — "
        "add them to the relevant skill/reference or document the carve-out"
    )


def test_skill_local_reference_paths_exist() -> None:
    """Backticked ``references/*.md`` paths must resolve inside that skill tree.

    Progressive-disclosure splits are useless if SKILL.md points at a missing
    file (e.g. a trim that forgot to add the reference). Cross-skill pointers
    must not use a local ``references/…`` backtick — name the sibling skill.
    """
    skills_dir = ROOT / "src" / "rebrew" / "agent-skills"
    missing: list[str] = []
    for skill_dir in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
        for md in skill_dir.rglob("*.md"):
            text = md.read_text(encoding="utf-8")
            for match in re.finditer(r"`(references/[\w./-]+\.md)`", text):
                rel = match.group(1)
                if not (skill_dir / rel).is_file():
                    missing.append(f"{md.relative_to(ROOT)} -> {rel}")
    assert missing == [], "skill markdown points at missing local references:\n  " + "\n  ".join(
        missing
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
    mods = re.findall(r'^rebrew-[\w-]+ = "rebrew\.([\w.]+):main_entry"$', toml, re.M)
    assert mods, "no [project.scripts] entries found"
    for mod in mods:
        mod_file = mod.replace(".", "/")
        src = (ROOT / "src" / "rebrew" / f"{mod_file}.py").read_text(encoding="utf-8")
        # Single-command modules need @app.callback on main(); multi-command
        # apps register @app.command subcommands and run app() directly.
        assert "@app.callback" in src or "@app.command" in src, (
            f"{mod_file}.py wires no callback and no subcommands — the standalone "
            f"rebrew-{mod.split('.')[-1]} script fails at runtime"
        )


def test_every_project_script_resolves() -> None:
    """Every ``[project.scripts]`` entry resolves to a live module attribute.

    The scripts are the standalone entry points (``rebrew-<cmd>``); a
    deleted module, a renamed entry point, or a stale ``main_entry`` would
    make the script fail at runtime while the umbrella still works — the
    same drift class the callback-decorator test catches, at the attribute
    level.
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


def test_option_help_survives_rich_markup() -> None:
    """Literal ``[section]`` spans in ``help=`` must render in ``--help``.

    Rich treats ``[link]`` / ``[compiler]`` as markup tags and silently drops
    them from help text unless escaped as ``\\[…]`` (see ``pdb-info
    --write-cflags``).  Pin the gen-layout options that previously vanished.
    """
    from typer.testing import CliRunner

    from rebrew.main import app

    result = CliRunner().invoke(app, ["gen-layout", "--help"])
    assert result.exit_code == 0, result.output
    assert "[link]" in result.stdout
    assert "[targets.<t>.layout]" in result.stdout

    match_result = CliRunner().invoke(app, ["match", "--help"])
    assert match_result.exit_code == 0, match_result.output
    assert "[llm]" in match_result.stdout


#: Status values the ADR convention in ``docs/adr/README.md`` defines.  A
#: record outside these is a decision whose lifecycle state a reader cannot
#: resolve, which is worse than no record.
_ADR_STATUS = r"(?:Accepted|Amended by|Superseded by)"

_ADR_REQUIRED_SECTIONS = ("## Context", "## Decision", "## Consequences")


def _adr_files() -> list[Path]:
    return sorted(p for p in (ROOT / "docs" / "adr").glob("[0-9]*.md"))


def _prd_files() -> list[Path]:
    d = ROOT / "docs" / "prd"
    return sorted(p for p in d.glob("[0-9]*.md") if not p.name.startswith("00-"))


def test_every_adr_has_lifecycle_fields() -> None:
    """Every ADR carries a Status from the convention and a dated header.

    An accepted record that is silently reversed by the code is worse than a
    missing one, because readers trust the status and build on it.
    """
    adrs = _adr_files()
    assert adrs, "no ADR files found — the glob may be stale"
    bad: list[str] = []
    for path in adrs:
        text = path.read_text(encoding="utf-8")
        if not re.search(rf"^- \*\*Status\*\*:.*{_ADR_STATUS}", text, re.M):
            bad.append(f"{path.name}: no Status ({_ADR_STATUS})")
        if not re.search(r"^- \*\*Date\*\*: *\d{4}-\d{2}", text, re.M):
            bad.append(f"{path.name}: no `YYYY-MM` Date line")
        missing = [s for s in _ADR_REQUIRED_SECTIONS if s not in text]
        if missing:
            bad.append(f"{path.name}: missing section(s) {missing}")
    assert not bad, "ADR lifecycle/structure problems:\n  " + "\n  ".join(bad)


def test_adr_index_lists_every_record() -> None:
    """The ADR index carries a row for each record in the directory, and back.

    An index that lags the directory is how a superseded record stays
    readable as current.
    """
    index = (ROOT / "docs" / "adr" / "README.md").read_text(encoding="utf-8")
    on_disk = {p.name[:3] for p in _adr_files()}
    listed = set(re.findall(r"^\| (\d{3}) \|", index, re.M))
    missing = sorted(on_disk - listed)
    stale = sorted(listed - on_disk)
    assert not missing and not stale, (
        f"docs/adr/README.md index drift — records on disk but unlisted: {missing}; "
        f"rows with no file: {stale}"
    )


def test_adr_cross_references_resolve() -> None:
    """Every ``NNN-short-title.md`` link in an ADR or its index names a real record."""
    adr_dir = ROOT / "docs" / "adr"
    targets = {p.name for p in _adr_files()}
    dangling: list[str] = []
    for path in [*_adr_files(), adr_dir / "README.md"]:
        for link in re.findall(r"\((\d{3}-[\w-]+\.md)\)", path.read_text(encoding="utf-8")):
            if link not in targets:
                dangling.append(f"{path.name} -> {link}")
    assert not dangling, "ADR links to a record that does not exist:\n  " + "\n  ".join(dangling)


def test_every_prd_is_listed_and_carries_status() -> None:
    """Each PRD is in the directory index and declares Status, Date, Owner.

    The PRDs are the record of what ships; a PRD missing from the index or
    missing a status is a requirement set nobody can date or trust.
    """
    prds = _prd_files()
    assert prds, "no PRD files found — the glob may be stale"
    index = (ROOT / "docs" / "prd" / "README.md").read_text(encoding="utf-8")
    unlisted = [p.name for p in prds if p.name not in index]
    assert not unlisted, f"PRD(s) absent from docs/prd/README.md: {unlisted}"
    bad = [
        f"{p.name}: missing {line}"
        for p in prds
        for line in ("- **Status**:", "- **Date**:", "- **Owner**:")
        if line not in p.read_text(encoding="utf-8")
    ]
    assert not bad, "PRD header problems:\n  " + "\n  ".join(bad)


def _external_allowlist(pkg: Path) -> set[str] | None:
    """The ``rebrew.*`` modules a package's ``AGENTS.md`` permits, or None.

    An entry may name a whole package (``utils``) or a single submodule
    (``binsync.export``); a submodule entry grants that module and nothing
    beneath its siblings. Every backticked name on the line counts as allowed,
    so trailing prose keeps its backticks off.
    """
    doc = pkg / "AGENTS.md"
    if not doc.is_file():
        return None
    match = _EXTERNALS_RE.search(doc.read_text(encoding="utf-8"))
    if match is None:
        return None
    return set(re.findall(r"`([a-z_][a-z_0-9]*(?:\.[a-z_][a-z_0-9]*)?)`", match.group(1)))


def _imported_modules(pkg: Path) -> set[str]:
    """Every ``rebrew.*`` module imported under ``pkg``, at any call depth.

    A deferred import is still a dependency: ``catalog`` may pull in
    ``binary_loader`` inside a function, and the allowlist says so.
    """
    found: set[str] = set()
    for path in sorted(pkg.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module == "rebrew":
                    # `from rebrew import compile` names rebrew.compile.
                    found.update(f"rebrew.{a.name}" for a in node.names)
                elif node.module and node.module.startswith("rebrew."):
                    found.add(node.module)
            elif isinstance(node, ast.Import):
                found.update(a.name for a in node.names if a.name.startswith("rebrew."))
    return found


def test_package_imports_stay_inside_their_allowlist() -> None:
    """Each package imports only what its ``AGENTS.md`` ``Externals`` line lists.

    The allowlist is the dependency direction between the subpackages: a leaf
    like ``workspace`` may reach for ``errors`` and ``utils`` and nothing else,
    which is what keeps a lower layer from importing an application one. Left
    unenforced the line is documentation in name only, and the first convenient
    import widens it silently.
    """
    violations: list[str] = []
    gated: list[str] = []
    for pkg in sorted(p for p in PACKAGE_ROOT.iterdir() if (p / "__init__.py").is_file()):
        allowlist = _external_allowlist(pkg)
        if allowlist is None:
            continue
        gated.append(pkg.name)
        for module in sorted(_imported_modules(pkg)):
            target = module.removeprefix("rebrew.")
            if target == pkg.name or target.startswith(f"{pkg.name}."):
                continue
            if not any(target == a or target.startswith(f"{a}.") for a in allowlist):
                violations.append(f"{pkg.name}: {target}")

    assert gated, "no package declares an Externals allowlist — the regex may be stale"
    assert not violations, (
        "import outside the package's declared Externals allowlist "
        "(add the dependency to its AGENTS.md, or drop the import):\n  "
        + "\n  ".join(violations)
    )
