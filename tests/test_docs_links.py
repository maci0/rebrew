"""Relative markdown link gate.

Every ``[label](target)`` link in the rule files and ``docs/`` that names a
repository file must resolve from the repository root.  A link into a
sibling checkout (``../guild-rebrew/...``) or an external URL is out of scope;
a link into this tree that no longer exists is drift, because it is how a
reader finds the evidence behind a claim.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_LINK = re.compile(r"(?<!!)\[([^\]\[]*)\]\(([^)\s]+)\)")
_CODE_SPAN = re.compile(r"`[^`]*`")

RULE_FILES = ("AGENTS.md", "CONTRIBUTING.md", "README.md")


def _doc_files() -> list[Path]:
    return [*sorted((ROOT / "docs").rglob("*.md")), *(ROOT / name for name in RULE_FILES)]


def _strip_code_spans(line: str) -> str:
    """Blank out inline code so a C array literal is not read as a link."""

    return _CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line)


def _repository_links(path: Path) -> list[tuple[int, str, Path]]:
    found: list[tuple[int, str, Path]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for label, target in _LINK.findall(_strip_code_spans(line)):
            bare = target.split("#", 1)[0]
            if not bare or bare.startswith(("http", "mailto:", "<")) or "://" in bare:
                continue
            resolved = (path.parent / bare).resolve()
            if ROOT not in resolved.parents:
                continue
            found.append((lineno, label or bare, resolved))
    return found


def test_relative_doc_links_resolve() -> None:
    broken = [
        f"{path.relative_to(ROOT)}:{lineno}: {label} -> {target}"
        for path in _doc_files()
        for lineno, label, target in _repository_links(path)
        if not target.exists()
    ]
    assert not broken, "markdown links into this repository do not resolve:\n" + "\n".join(broken)
