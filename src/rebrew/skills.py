"""skills.py – Discover and display agent skills bundled with rebrew.

Enumerates the ``agent-skills/`` directory that ships with the package and
exposes two subcommands:

``rebrew skills list`` — table of skill name + first line of description.
``rebrew skills show NAME`` — pretty-print the full SKILL.md for NAME.

Community/user skills extend the packaged set through the
``REBREW_SKILLS_DIR`` environment variable: a directory of SKILL.md
directories, merged over the packaged tree (a user skill with the same name
as a packaged one wins — skills are docs, and the user's copy is the one
they want served).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import error_exit, json_print

console = Console(stderr=True)
_stdout_console = Console()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SKILLS_DIR = Path(__file__).parent / "agent-skills"

#: Env var naming a directory of user/community skills (one SKILL.md dir per
#: skill).  Unset → packaged skills only.
REBREW_SKILLS_DIR_ENV = "REBREW_SKILLS_DIR"

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def _parse_frontmatter(text: str) -> dict[str, str]:
    """Extract YAML-style frontmatter from a SKILL.md string.

    Only handles simple ``key: value`` lines (no nested YAML needed).
    """
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}
    result: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip()] = val.strip()
    return result


def _scan_skills_dir(skills_dir: Path) -> list[dict[str, Any]]:
    """All skills under one directory (keys: name, description, path)."""
    skills: list[dict[str, Any]] = []
    if not skills_dir.is_dir():
        return skills
    for skill_dir in sorted(skills_dir.iterdir()):
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            continue
        text = skill_md.read_text(encoding="utf-8")
        fm = _parse_frontmatter(text)
        name = fm.get("name") or skill_dir.name
        description = fm.get("description", "")
        first_line = description.split(".")[0].strip() if description else ""
        skills.append(
            {
                "name": name,
                "description": description,
                "first_line": first_line,
                "path": str(skill_md),
            }
        )
    return skills


def _user_skills_dir() -> Path | None:
    """The user/community skills dir from ``REBREW_SKILLS_DIR``, or None."""
    env = os.environ.get(REBREW_SKILLS_DIR_ENV)
    return Path(env) if env else None


def _list_skills() -> list[dict[str, Any]]:
    """Return a list of dicts with keys: name, description, path.

    Packaged skills first; a user skill (``REBREW_SKILLS_DIR``) with the
    same name overrides the packaged one."""
    skills: dict[str, dict[str, Any]] = {}
    for root in (r for r in (_SKILLS_DIR, _user_skills_dir()) if r is not None):
        for entry in _scan_skills_dir(root):
            skills[entry["name"]] = entry
    return [skills[name] for name in sorted(skills)]


def _find_skill(name: str) -> Path | None:
    """Return the SKILL.md path for the given skill name (by frontmatter name or dir name).

    User skills are searched first so they override packaged ones."""
    roots = [r for r in (_user_skills_dir(), _SKILLS_DIR) if r is not None]
    for root in roots:
        for skill_dir in sorted(root.iterdir()) if root.is_dir() else []:
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                continue
            # Match by directory name or frontmatter name
            if skill_dir.name == name:
                return skill_md
            text = skill_md.read_text(encoding="utf-8")
            fm = _parse_frontmatter(text)
            if fm.get("name") == name:
                return skill_md
    return None


# ---------------------------------------------------------------------------
# Typer app
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Discover and display agent skills bundled with rebrew.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew skills list · · · · · · · · · · List all available skills\n\n"
        "  rebrew skills show rebrew-workflow · · Show the rebrew-workflow skill guide\n\n"
        "  rebrew skills list --json · · · · · · Machine-readable skill list\n\n"
        "[dim]Skills live in src/rebrew/agent-skills/ (community skills merge "
        "in via $REBREW_SKILLS_DIR). "
        "Each directory contains a SKILL.md with YAML frontmatter.[/dim]"
    ),
)


@app.command("list")
def list_skills(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List all available agent skills with a short description."""
    skills = _list_skills()
    if json_output:
        json_print(
            {"skills": [{"name": s["name"], "description": s["description"]} for s in skills]}
        )
        return

    if not skills:
        console.print("[yellow]No skills found under agent-skills/.[/yellow]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Description")
    for s in skills:
        table.add_row(s["name"], s["first_line"] or s["description"][:80])
    _stdout_console.print(table)


@app.command("show")
def show_skill(
    name: str = typer.Argument(..., help="Skill name (e.g. 'rebrew-workflow')."),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Pretty-print the SKILL.md for the named skill."""
    skill_path = _find_skill(name)
    if skill_path is None:
        available = [s["name"] for s in _list_skills()]
        error_exit(
            f"Skill '{name}' not found. Available skills: {', '.join(available)}",
            json_mode=json_output,
        )

    text = skill_path.read_text(encoding="utf-8")

    if json_output:
        fm = _parse_frontmatter(text)
        json_print(
            {
                "name": fm.get("name", name),
                "description": fm.get("description", ""),
                "path": str(skill_path),
                "content": text,
            }
        )
        return

    try:
        from rich.markdown import Markdown

        _stdout_console.print(Markdown(text))
    except Exception:
        # Fallback: plain output
        print(text, end="")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
