"""Docs hygiene meta-tests.

Pins the docs to the code so drift is caught in CI:

- every lint code emitted by ``src/rebrew/lint.py`` is documented in
  ``docs/ANNOTATIONS.md`` (the linter reference tables);
- every registered CLI command has a dedicated section in ``docs/CLI.md``.
"""

from __future__ import annotations

import re
from pathlib import Path

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


def test_every_cli_command_documented() -> None:
    src = (ROOT / "src" / "rebrew" / "main.py").read_text(encoding="utf-8")
    # `\s*` after `(`: commands registered as multi-line tuples
    # (    \n    "analyze",\n    "rebrew.analyze", ...) were missed before —
    # analyze + 15 more slipped past the "every command documented" check.
    names = set(re.findall(r'\(\s*"([a-z-]+)",\s*"rebrew\.', src))
    assert names, "no CLI commands found — the regex may be stale"
    cli = (ROOT / "docs" / "CLI.md").read_text(encoding="utf-8")
    missing = sorted(
        n for n in names if f"### `rebrew {n}`" not in cli and f"## `rebrew {n}`" not in cli
    )
    assert not missing, (
        f"CLI command(s) {missing} registered in main.py but without a section in docs/CLI.md"
    )


#: Commands that are intentionally absent from the agent skills — they are
#: meta/niche tooling agents never drive (PE resource compare, skill
#: discovery itself).
_SKILL_OUT_OF_SCOPE = {"resource", "skills"}


def test_every_cli_command_covered_by_agent_skills() -> None:
    """Every workflow command appears in at least one bundled agent skill."""
    import re as _re

    src = (ROOT / "src" / "rebrew" / "main.py").read_text(encoding="utf-8")
    names = set(_re.findall(r'\("([a-z-]+)",\s*"rebrew\.', src))
    skills_dir = ROOT / "src" / "rebrew" / "agent-skills"
    skills_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in skills_dir.rglob("SKILL.md")
    )
    missing = sorted(n for n in names if n not in skills_text and n not in _SKILL_OUT_OF_SCOPE)
    assert not missing, (
        f"commands {missing} are not mentioned in any agent-skills SKILL.md — "
        "add them to the relevant workflow skill or document the carve-out"
    )
