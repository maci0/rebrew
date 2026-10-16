"""validate_skill_commands.py – Validate that rebrew CLI flags referenced in SKILL.md files exist.

Parses each ``src/rebrew/agent-skills/*/SKILL.md`` and its ``references/*.md``,
collects every ``rebrew <subcommand>`` invocation from both ``bash`` code
blocks and inline code spans, and for each unique ``(subcommand, flags)``
combination renders ``rebrew <subcommand> --help`` on the composed command
tree (one build, no process per route) to confirm the subcommand resolves,
then checks every referenced long flag against that command's registered
option declarations.

The script does NOT invoke the actual commands — it only exercises ``--help``.

Exit codes:
    0 — all flags resolved
    1 — one or more flags missing or subcommand not found

Usage::

    uv run --frozen python tools/validate_skill_commands.py
    uv run --frozen python tools/validate_skill_commands.py --quiet
    uv run --frozen python tools/validate_skill_commands.py --docs
"""

from __future__ import annotations

import argparse
import re
import sys
from functools import cache
from pathlib import Path
from typing import cast

from typer._click.core import Command as TyperBaseCommand
from typer._click.core import Context as TyperContext
from typer.core import TyperGroup

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SKILLS_DIR = _REPO_ROOT / "src" / "rebrew" / "agent-skills"

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_BASH_BLOCK_RE = re.compile(r"```bash\n(.*?)```", re.DOTALL)
_INLINE_SPAN_RE = re.compile(r"`(rebrew [^`]+)`")
_CODE_SPAN_RE = re.compile(r"`([^`\n]+)`")
_MERMAID_BLOCK_RE = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)
#: Mermaid node labels, edge labels, and arrows: ``Pick[a<br/>rebrew todo --json]``
#: splits here so each fragment is a bare command with no diagram punctuation.
_MERMAID_SEP_RE = re.compile(r"[\[\]{}()|<>]+")
_MERMAID_CMD_RE = re.compile(r"rebrew [a-z][a-z0-9-]*[^\n]*")
_FLAG_RE = re.compile(r"(--[a-z][a-z0-9-]+)")

# Strip terminal styling from help-probe diagnostics.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Flags every Typer command carries regardless of what a skill writes, so
# citing one proves nothing.  ``--json`` and ``--target`` are deliberately NOT
# here: they are the two flags the skills cite most, and a blanket exemption
# meant the one pair a skill is most likely to get wrong went unchecked.  Both
# are validated like any other flag, so a skill citing ``--target`` on a
# command that does not surface it now fails the gate.
_SKIP_FLAGS: frozenset[str] = frozenset(
    {
        "--help",
        "--version",
    }
)


def _is_placeholder(word: str) -> bool:
    """True for ``<va>``-style placeholders and ``a/b`` slash alternations.

    Prose writes ``rebrew toolchain list/status/pull/build`` and ``rebrew
    diff/match/prove/test 0x<va>`` to name several commands at once; neither
    resolves as a single subcommand.
    """
    return any(c in word for c in "<>/{}[]*…") or word == "..."


@cache
def _command_tree() -> TyperBaseCommand:
    """Use the composed command tree to resolve arbitrarily nested routes."""
    import typer

    from rebrew.app.main import app

    return typer.main.get_command(app)


def _registered_flags(subcommand: str) -> set[str] | None:
    """Resolve a mounted command and return its declared long option names."""
    command = _command_tree()
    for name in subcommand.split():
        if not isinstance(command, TyperGroup):
            return None
        child = command.get_command(TyperContext(command), name)
        if child is None:
            return None
        command = child
    return {
        flag
        for param in command.params
        for flag in (*param.opts, *getattr(param, "secondary_opts", ()))
        if flag.startswith("--")
    }


def _parse_command(line: str) -> tuple[str, list[str]] | None:
    """Return ``(subcommand, flags)`` for one ``rebrew …`` invocation, or None.

    Resolve every nested operation (for example ``cfg target add``) before
    inspecting its flags; group help does not list leaf options.
    """
    line = line.split("#", maxsplit=1)[0].strip()
    if not line.startswith("rebrew "):
        return None
    tokens = line.split()
    if len(tokens) < 2 or _is_placeholder(tokens[1]):
        return None
    subcommand = tokens[1].strip("\"'")
    if not re.fullmatch(r"[a-z][a-z0-9-]*", subcommand):
        return None

    import typer

    command = _command_tree()
    path: list[str] = []
    for token in tokens[1:]:
        token = token.strip("\"'")
        if token.startswith("-") or _is_placeholder(token):
            break
        if not isinstance(command, TyperGroup):
            break
        context = typer._click.core.Context(command)
        child = command.get_command(context, token)
        path.append(token)
        if child is None:
            break  # retain an unknown route so its help probe reports the error
        command = child
    subcommand = " ".join(path) or subcommand

    return subcommand, [f for f in _FLAG_RE.findall(line) if f not in _SKIP_FLAGS]


def _extract_commands(skill_md: Path) -> list[tuple[str, list[str]]]:
    """Return list of (subcommand, [flags]) from *skill_md*.

    Covers ``bash`` code blocks, ``` `rebrew …` ``` spans in prose, and the
    command lines inside ```mermaid``` flowcharts.  Skills name commands in
    prose and in the diagram as often as in code blocks, and the diagram is
    what an agent reads first, so a block-only check leaves those unvalidated.
    """
    text = skill_md.read_text(encoding="utf-8")
    lines = [
        line for block in _BASH_BLOCK_RE.finditer(text) for line in block.group(1).splitlines()
    ]
    # Inline spans wrapping a line break are prose sentences, not invocations.
    lines += [m.group(1) for m in _INLINE_SPAN_RE.finditer(text) if "\n" not in m.group(1)]
    # Command tables often put options in the description cell rather than
    # inside the invocation. Validate those too, when the first cell names
    # exactly one command. Other cells may describe separate alternatives.
    for row in text.splitlines():
        if not row.lstrip().startswith("|"):
            continue
        cells = row.strip().strip("|").split("|")
        command_cell = cells[0].strip()
        invocation = re.fullmatch(r"`(rebrew [^`]+)`", command_cell)
        if invocation is None:
            continue
        descriptions = "|".join(cells[1:])
        spans = _CODE_SPAN_RE.findall(descriptions)
        if any(span.startswith("rebrew ") for span in spans):
            continue
        flags = [flag for span in spans if span.startswith("--") for flag in _FLAG_RE.findall(span)]
        if flags:
            lines.append(" ".join([invocation.group(1), *flags]))
    lines += [
        m.group(0).strip()
        for block in _MERMAID_BLOCK_RE.finditer(text)
        for fragment in _MERMAID_SEP_RE.split(block.group(1))
        for m in _MERMAID_CMD_RE.finditer(fragment)
    ]
    return [cmd for line in lines if (cmd := _parse_command(line)) is not None]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _run_help(subcommand: str) -> tuple[bool, str]:
    """Render ``rebrew <subcommand> --help`` and return (ok, output).

    Uses the composed command from :func:`_command_tree` (built once) instead of
    a process per route.  A wide terminal (COLUMNS=200) keeps Rich from
    truncating flag names.  *subcommand* may be a space-separated route like
    ``cfg target add``.
    """
    from click.core import Command
    from click.testing import CliRunner

    result = CliRunner().invoke(
        cast(Command, _command_tree()),
        [*subcommand.split(), "--help"],
        env={"COLUMNS": "200"},
    )
    output = _ANSI_RE.sub("", result.output or "")
    return result.exit_code == 0, output


def _probe_failure_message(skill_name: str, subcommand: str, output: str) -> str:
    """Return the error line for a ``--help`` probe that did not succeed.

    A probe that timed out or never spawned is not evidence the skill is
    stale; saying which it was stops the reader hunting for a renamed
    subcommand that was there all along.
    """
    if output.startswith("<"):
        return f"{skill_name}: rebrew {subcommand}: probe {output.strip('<>')}, not a skill defect"
    return f"{skill_name}: rebrew {subcommand} — subcommand not found"


def _current_docs() -> list[Path]:
    """Current guides/rules; dated release records and proposals are not CLI contracts."""
    docs = _REPO_ROOT / "docs"
    proposals = {"ROADMAP.md", "IDEAS-GUILD.md", "JEV.md"}
    return [
        *(p for p in sorted(docs.glob("*.md")) if p.name not in proposals),
        *(p for p in sorted((docs / "prd").glob("*.md")) if p.name[:2] not in {"00", "09"}),
        *(
            _REPO_ROOT / name
            for name in ("README.md", "AGENTS.md", "CONTRIBUTING.md", "SECURITY.md")
        ),
        *sorted((_REPO_ROOT / "src" / "rebrew").rglob("AGENTS.md")),
        _REPO_ROOT / "src" / "rebrew" / "AGENTS.md.template",
    ]


def validate(*, quiet: bool = False, docs: bool = False) -> bool:
    """Validate skill references, optionally including current guides and agent templates."""
    if not _SKILLS_DIR.is_dir():
        print(f"[SKIP] agent-skills dir not found: {_SKILLS_DIR}", file=sys.stderr)
        return True

    # Collect (skill_name, subcommand, flags) triples first, deduplicating per
    # skill, then render each unique subcommand's --help on the one composed
    # command tree.
    combos: list[tuple[str, str, tuple[str, ...]]] = []
    for skill_dir in sorted(_SKILLS_DIR.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_name = skill_dir.name
        # SKILL.md plus progressive-disclosure references/*.md
        md_files = [skill_dir / "SKILL.md", *sorted((skill_dir / "references").glob("*.md"))]
        seen: set[tuple[str, tuple[str, ...]]] = set()
        for md_path in md_files:
            if not md_path.is_file():
                continue
            for subcommand, flags in _extract_commands(md_path):
                key = (subcommand, tuple(sorted(flags)))
                if key in seen:
                    continue
                seen.add(key)
                combos.append((skill_name, subcommand, tuple(sorted(flags))))

    if docs:
        for path in _current_docs():
            for subcommand, doc_flags in sorted(
                {(sub, tuple(sorted(fs))) for sub, fs in _extract_commands(path)}
            ):
                combos.append((str(path.relative_to(_REPO_ROOT)), subcommand, doc_flags))

    unique_subs = sorted({c[1] for c in combos})
    help_cache = {sub: _run_help(sub) for sub in unique_subs}
    registered_flags = {sub: _registered_flags(sub) for sub in unique_subs if help_cache[sub][0]}

    errors: list[str] = []
    checked = 0
    for skill_name, subcommand, combo_flags in combos:
        checked += 1
        ok, output = help_cache[subcommand]

        if not ok:
            err = _probe_failure_message(skill_name, subcommand, output)
            errors.append(err)
            if not quiet:
                print(f"FAIL  {err}")
            continue

        available_flags = registered_flags[subcommand]
        if available_flags is None:
            err = f"{skill_name}: rebrew {subcommand} — command not registered"
            errors.append(err)
            if not quiet:
                print(f"FAIL  {err}")
            continue
        for flag in combo_flags:
            if flag not in available_flags:
                err = f"{skill_name}: rebrew {subcommand} {flag} — flag not registered"
                errors.append(err)
                if not quiet:
                    print(f"FAIL  {err}")

    if quiet:
        for error in errors:
            print(f"FAIL  {error}")
    print(
        f"\nChecked {checked} unique (subcommand, flags) combinations across "
        f"{_SKILLS_DIR.name}/{' and current docs/templates' if docs else ''}."
    )
    if errors:
        print(f"{len(errors)} failure(s).")
    else:
        print("All OK.")
    return len(errors) == 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate Rebrew command paths and flags in skills, guides, and agent templates."
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Only print failures and summary."
    )
    parser.add_argument(
        "--docs", action="store_true", help="Also check current guides and agent templates."
    )
    args = parser.parse_args()

    ok = validate(quiet=args.quiet, docs=args.docs)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
