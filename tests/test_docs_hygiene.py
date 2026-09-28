"""Docs hygiene meta-tests.

Pins the docs to the code so drift is caught in CI:

- every lint code emitted by ``src/rebrew/lint.py`` is documented in
  ``docs/ANNOTATIONS.md`` (the linter reference tables);
- every component in the packaged CLI manifest has a dedicated section in
  ``docs/CLI.md`` and is covered by a bundled agent skill;
- the decision and requirement sets (``docs/adr/``, ``docs/prd/``) keep
  their index, lifecycle status, and cross-links intact;
- every package whose ``AGENTS.md`` declares an ``Externals`` allowlist imports
  only the packages on it;
- no module imports another module's ``_name`` (the underscore rule, which
  the ``Externals`` allowlists above do not cover);
- every ``make <target>`` the ``AGENTS.md`` files name is a Makefile target, and
  the same for the docs that spell out the human contributor path;
- the architecture diagram's format pointer names a doc that exists;
- every repo path, ``rebrew <command>``, and make target a rule file cites
  resolves, in the repo's own ``AGENTS.md``, each subpackage's, and the
  ``AGENTS.md.template`` that ``rebrew init`` renders into a user project.
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

#: Rule files loaded into an agent session on every visit: the repo's own, each
#: subpackage's, and the template ``rebrew init`` renders into a user project.
#: The template is the one that drifts furthest from the CLI, because nothing
#: in this repo runs its command table.
RULE_FILES = (
    ROOT / "AGENTS.md",
    PACKAGE_ROOT / "AGENTS.md.template",
    *sorted(PACKAGE_ROOT.glob("*/AGENTS.md")),
)

#: The docs a human contributor follows from a clean clone to a merged change.
#: Every ``make <target>`` in these is a command to run, so a renamed target is
#: a command that fails before any work starts.  The rest of ``docs/`` is design
#: prose, where "make a bridge" is a sentence and not an invocation.
CONTRIBUTOR_DOCS = (
    ROOT / "README.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "docs" / "ADDING_A_COMMAND.md",
    ROOT / "docs" / "CI.md",
    ROOT / "docs" / "DEVELOPMENT.md",
)

#: Words that follow "make" in prose without naming a target.
_PROSE_AFTER_MAKE = frozenset(
    {"a", "an", "each", "it", "sure", "target", "targets", "that", "the", "this"}
)


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


def test_architecture_diagram_format_pointer_resolves() -> None:
    """The diagram's ``format: <doc>.md`` label must name a doc that exists.

    2.16.0 renamed ``docs/DB_FORMAT.md`` to ``docs/COVERAGE_DOCUMENT.md`` and
    the diagram kept the old name, so the one place a reader is told where the
    coverage-document format is written down pointed at a file the release
    deleted.  Only the format pointer is checked: the diagram also names docs
    in a sibling ``ai-decomp`` wiki, which no file here owns.
    """
    diagram = (ROOT / "docs" / "architecture.drawio").read_text(encoding="utf-8")
    missing = [
        name
        for name in re.findall(r"format: (\S+\.md)", diagram)
        if not (ROOT / "docs" / name).is_file()
    ]
    assert missing == [], f"architecture.drawio points at missing docs: {missing}"


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


def test_every_adr_header_is_exactly_status_and_date() -> None:
    """The preamble before ``## Context`` is the title plus Status and Date.

    The convention in ``docs/adr/README.md`` names those two fields, and every
    amendment explanation belongs inside the Status line.  A parallel field
    (``- **Amended by (detail)**:``) is how a record ends up with two status
    blocks that disagree, because only one of them is the convention's.
    """
    bad: list[str] = []
    for path in _adr_files():
        text = path.read_text(encoding="utf-8")
        preamble = text.split("## Context", 1)[0]
        fields = re.findall(r"^- \*\*([^*]+)\*\*:", preamble, re.M)
        if fields != ["Status", "Date"]:
            bad.append(f"{path.name}: header fields {fields} (expected ['Status', 'Date'])")
    assert not bad, "ADR header drift from the convention:\n  " + "\n  ".join(bad)


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
        "(add the dependency to its AGENTS.md, or drop the import):\n  " + "\n  ".join(violations)
    )


#: The one family the underscore rule exempts, so its modules may reach into
#: each other's privates.  The root rule scopes that exemption to the family
#: itself: the module above it does not inherit it.
_PRIVATE_IMPORT_EXEMPT = "rebrew.matcher.mutations"


def test_no_module_imports_another_modules_private_name() -> None:
    """No module reaches into a sibling's ``_name``; the exemption is narrow.

    An underscore marks a name its own module may change or drop, so a caller
    built on it couples to an implementation detail with no public interface
    to migrate through.  ``rebrew/matcher/mutator.py`` held three such edges
    into ``mutations/``; the accessors those three needed are public now.

    Walked across the whole package rather than per package, so a new
    subpackage is covered the day it lands.
    """
    violations: list[str] = []
    scanned = 0
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        module = "rebrew." + ".".join(path.relative_to(PACKAGE_ROOT).with_suffix("").parts)
        if module == "rebrew.__init__":
            continue
        scanned += 1
        if module.startswith(_PRIVATE_IMPORT_EXEMPT):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.startswith("rebrew")
            ):
                for alias in node.names:
                    if alias.name.startswith("_") and not alias.name.startswith("__"):
                        violations.append(
                            f"{path.relative_to(ROOT)}:{node.lineno} -> {node.module}.{alias.name}"
                        )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    tail = alias.name.rsplit(".", 1)[-1]
                    if alias.name.startswith("rebrew.") and tail.startswith("_"):
                        violations.append(f"{path.relative_to(ROOT)}:{node.lineno} -> {alias.name}")

    assert scanned > 100, f"scanned only {scanned} modules — the walk is broken"
    assert not violations, (
        "module-private name imported across a module boundary "
        "(promote it to a public name and list it in the owning module's __all__):\n  "
        + "\n  ".join(violations)
    )


def _unknown_make_targets(docs: tuple[Path, ...]) -> tuple[list[str], int]:
    """Make targets ``docs`` name that the Makefile does not define, and how
    many target references were seen (so a stale regex cannot pass silently)."""
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    defined = set(re.findall(r"^([a-zA-Z][a-zA-Z0-9_.-]*):", makefile, re.MULTILINE))
    unknown: list[str] = []
    named = 0
    for doc in docs:
        where = doc.relative_to(ROOT)
        for target in re.findall(r"make ([a-z][a-z0-9-]*)", doc.read_text(encoding="utf-8")):
            if target in _PROSE_AFTER_MAKE:
                continue
            named += 1
            if target not in defined:
                unknown.append(f"{where}: make {target}")
    return unknown, named


def test_rule_files_name_real_make_targets() -> None:
    """Every ``make <target>`` an ``AGENTS.md`` names is defined in the Makefile.

    The rule files are loaded into every session, so a target that was renamed
    or dropped sends the next agent to a command that fails before any work
    starts. ``T=`` and ``FLAGS=`` arguments are not part of the target name.
    """
    unknown, named = _unknown_make_targets(RULE_FILES)

    assert named, f"no make target found in {len(RULE_FILES)} rule files; the regex is stale"
    assert not unknown, (
        "rule file names a make target the Makefile does not define "
        "(rename the target or the reference):\n  " + "\n  ".join(unknown)
    )


def test_contributor_docs_name_real_make_targets() -> None:
    """Every ``make <target>`` the contributor path names is a real target.

    The same drift the rule-file check above covers, on the files a human
    follows from a clean clone: the command a renamed target leaves behind is
    the first one a new contributor runs, so it fails before any work starts.
    """
    unknown, named = _unknown_make_targets(CONTRIBUTOR_DOCS)

    assert named, f"no make target found in {len(CONTRIBUTOR_DOCS)} docs; the regex is stale"
    assert not unknown, (
        "contributor doc names a make target the Makefile does not define "
        "(rename the target or the reference):\n  " + "\n  ".join(unknown)
    )


#: Repo-relative file references a rule file may cite. Only trees this repo
#: owns are checked: ``rebrew-project.toml`` and friends are files of a user's
#: workspace, not of this package.
_PATH_PREFIXES = ("docs/", "tests/", "tools/", "src/")


def test_rule_files_cite_real_repo_paths() -> None:
    """Every repo-relative file a rule file cites exists.

    A moved or renamed doc is cited by every future session and resolves to
    nothing. Globs and placeholders (``tests/test_mutator*.py``,
    ``docs/adr/NNN-short-title.md``, ``src/<target>/function_structure.json``)
    name a pattern, not a file, and are exempt.
    """
    missing: list[str] = []
    cited = 0
    for doc in RULE_FILES:
        where = doc.relative_to(ROOT)
        text = doc.read_text(encoding="utf-8")
        for ref in re.findall(r"`([\w./-]+\.(?:md|py|toml|json|cmake))`", text):
            placeholder = any(c in ref for c in "*{}<>") or re.search(r"[A-Z]{2,}", ref)
            if not ref.startswith(_PATH_PREFIXES) or placeholder:
                continue
            cited += 1
            if not (ROOT / ref).exists():
                missing.append(f"{where}: {ref}")

    assert cited, "no repo path found in the rule files; the regex is stale"
    assert not missing, "rule file cites a path that does not exist:\n  " + "\n  ".join(missing)


def test_rule_files_name_real_cli_commands() -> None:
    """Every ``rebrew <command>`` a rule file names is registered.

    Rule files are where an agent learns the CLI, so a command renamed or
    dropped here sends it to a failing invocation. A second word is checked
    against that command's subcommands.
    """
    from rebrew.main import app

    groups = {
        g.name: g.typer_instance for g in app.registered_groups if g.name and g.typer_instance
    }
    top = {c.name for c in app.registered_commands if c.name} | set(groups)
    unknown: list[str] = []
    named = 0
    for doc in RULE_FILES:
        where = doc.relative_to(ROOT)
        text = doc.read_text(encoding="utf-8")
        for cmd, sub in re.findall(r"`rebrew ([a-z][a-z0-9-]*)(?: ([a-z][a-z0-9-]*))?", text):
            named += 1
            if cmd not in top:
                unknown.append(f"{where}: rebrew {cmd}")
            elif sub:
                group = groups[cmd]
                subs = {c.name for c in group.registered_commands if c.name}
                subs |= {g.name for g in group.registered_groups if g.name}
                # A callback-declared subcommand reports no name; its function
                # name is the command word.
                subs |= {
                    c.callback.__name__.replace("_", "-")
                    for c in group.registered_commands
                    if c.callback is not None
                }
                if sub not in subs:
                    unknown.append(f"{where}: rebrew {cmd} {sub}")

    assert named, f"no rebrew command found in {len(RULE_FILES)} rule files; the regex is stale"
    assert not unknown, (
        "rule file names a command the CLI does not register "
        "(rename the command or the reference):\n  " + "\n  ".join(unknown)
    )


class TestCellStateMarks:
    """``docs/COVERAGE_DOCUMENT.md`` names the marks the surfaces actually paint.

    The table once described a colour per cell state (Silver, Purple, Orange)
    that no renderer had: only a function STATUS is painted, from
    ``status_style.STATUS_HEX``.  Pin the hexes so the doc cannot drift back.
    """

    _TABLE_RE = re.compile(r"^\| `(?P<state>\w+)` .*?\| (?P<mark>[^|]+) \|$", re.M)

    def test_documented_marks_are_the_status_marks(self) -> None:
        from rebrew.status_style import STATUS_HEX

        doc = (ROOT / "docs" / "COVERAGE_DOCUMENT.md").read_text(encoding="utf-8")
        # The cell-state table only: the schema tables above it share its shape.
        table = doc[doc.index("#### Cell States") : doc.index("`other_count` is a catch-all")]
        rows = {m["state"]: m["mark"] for m in self._TABLE_RE.finditer(table)}
        assert "exact" in rows, "the cell-state table no longer parses"
        for state, status in (
            ("exact", "EXACT"),
            ("reloc", "RELOC"),
            ("near_matching", "NEAR_MATCHING"),
            ("proven", "PROVEN"),
            ("size_mismatch", "SIZE_MISMATCH"),
            ("stub", "STUB"),
            ("skip", "SKIP"),
            ("unknown", "UNKNOWN"),
            ("compile_error", "COMPILE_ERROR"),
            ("extract_error", "EXTRACT_ERROR"),
            ("missing_size", "MISSING_SIZE"),
            ("missing_file", "MISSING_FILE"),
            ("invalid_va", "INVALID_VA"),
        ):
            assert f"`{STATUS_HEX[status]}`" in rows[state], (state, rows[state])
        for state in ("none", "verified", "padding", "data", "thunk", "drift", "unchecked"):
            assert "count only" in rows[state], (state, rows[state])
