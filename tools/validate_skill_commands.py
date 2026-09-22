"""validate_skill_commands.py – Validate that rebrew CLI flags referenced in SKILL.md files exist.

Parses each ``src/rebrew/agent-skills/*/SKILL.md`` and its ``references/*.md``,
collects every ``rebrew <subcommand>`` invocation from both ``bash`` code
blocks and inline code spans, and for each unique ``(subcommand, flags)``
combination runs ``uv run rebrew <subcommand> --help`` to confirm the
subcommand resolves AND every long flag mentioned (``--flag``) appears in the
help output.

The script does NOT invoke the actual commands — it only exercises ``--help``.

Exit codes:
    0 — all flags resolved
    1 — one or more flags missing or subcommand not found

Usage::

    uv run python tools/validate_skill_commands.py
    uv run python tools/validate_skill_commands.py --quiet
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

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
_FLAG_RE = re.compile(r"(--[a-z][a-z0-9-]+)")

# typer colors the help whenever GITHUB_ACTIONS/FORCE_COLOR/PY_COLORS is set
# (its rich console then treats the pipe as a terminal), splitting an option
# name across escape sequences — ``-\x1b[1;36m-target`` never matches
# ``_FLAG_RE``.  Strip the styling before parsing the help text.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Flags that are generic/pass-through or tested elsewhere — skip to avoid
# false positives from injected placeholders like ``--target`` that some
# subcommands don't surface.
_SKIP_FLAGS: frozenset[str] = frozenset(
    {
        "--help",
        "--json",  # present on most commands but not all
        "--target",  # skip: optional on many commands
        "--version",
    }
)


def _multi_subcommands() -> frozenset[str]:
    """CLI groups whose top-level --help does not list subcommand flags.

    For these we validate ``<group> <subcommand>`` pairs instead.  Derived from
    the component registry so a newly added group is validated without editing
    this file — a hand-maintained list silently skipped ``binsync``/``library``/
    ``toolchain``/``resource`` after they were added.
    """
    from rebrew.builtins import BUILTIN_COMPONENTS

    return frozenset(c.name for c in BUILTIN_COMPONENTS if c.is_group)


#: Resolved once at import; see :func:`_multi_subcommands`.
_MULTI_SUBCOMMANDS: frozenset[str] = _multi_subcommands()


def _is_placeholder(token: str) -> bool:
    """True for ``<va>``-style placeholders and ``a/b`` slash alternations.

    Prose writes ``rebrew toolchain list/status/pull/build`` and ``rebrew
    diff/match/prove/test 0x<va>`` to name several commands at once; neither
    resolves as a single subcommand.
    """
    return any(c in token for c in "<>/")


def _parse_command(line: str) -> tuple[str, list[str]] | None:
    """Return ``(subcommand, flags)`` for one ``rebrew …`` invocation, or None.

    For multi-command groups (e.g. ``rebrew cfg add-target``), the subcommand
    is taken as ``cfg add-target`` so we invoke ``rebrew cfg add-target --help``
    instead of ``rebrew cfg --help`` (which would not list subcommand flags).
    """
    line = line.split("#", maxsplit=1)[0].strip()
    if not line.startswith("rebrew "):
        return None
    tokens = line.split()
    if len(tokens) < 2 or _is_placeholder(tokens[1]):
        return None
    subcommand = tokens[1]

    # For multi-command groups, absorb the subsubcommand if present
    if subcommand in _MULTI_SUBCOMMANDS and len(tokens) >= 3:
        second_sub = tokens[2]
        if not second_sub.startswith("-") and not _is_placeholder(second_sub):
            subcommand = f"{subcommand} {second_sub}"

    return subcommand, [f for f in _FLAG_RE.findall(line) if f not in _SKIP_FLAGS]


def _extract_commands(skill_md: Path) -> list[tuple[str, list[str]]]:
    """Return list of (subcommand, [flags]) from *skill_md*.

    Covers both ``bash`` code blocks and inline ``` `rebrew …` ``` spans in
    prose.  Skills name commands in prose as often as in code blocks, and a
    block-only check leaves those references unvalidated.
    """
    text = skill_md.read_text(encoding="utf-8")
    lines = [
        line for block in _BASH_BLOCK_RE.finditer(text) for line in block.group(1).splitlines()
    ]
    # Inline spans wrapping a line break are prose sentences, not invocations.
    lines += [m.group(1) for m in _INLINE_SPAN_RE.finditer(text) if "\n" not in m.group(1)]
    return [cmd for line in lines if (cmd := _parse_command(line)) is not None]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _rebrew_help_command() -> list[str]:
    """The rebrew CLI invocation for --help runs.

    Prefers the repo venv's console script (``.venv/bin/rebrew``) over
    ``uv run rebrew``: uv needs a writable cache dir under the user home,
    which is read-only in sandboxed environments (the help output would be
    an error instead of the flags).  Falls back to ``uv run rebrew`` when
    the venv script is not found (non-venv installs)."""
    # NOTE: no .resolve() on sys.executable — in venvs it is a symlink to
    # the uv-managed interpreter, and resolving would look next to the real
    # python (no rebrew script there).
    script = Path(sys.executable).parent / "rebrew"
    if script.exists():
        return [str(script)]
    return ["uv", "run", "rebrew"]


def _run_help(subcommand: str) -> tuple[bool, str]:
    """Run ``rebrew <subcommand> --help`` and return (ok, output).

    Runs with a wide terminal (COLUMNS=200) so Rich does not truncate flag names.
    *subcommand* may be a space-separated multi-word string like ``cfg add-target``.
    """
    import os

    env = {**os.environ, "COLUMNS": "200"}
    sub_tokens = subcommand.split()
    try:
        result = subprocess.run(
            _rebrew_help_command() + sub_tokens + ["--help"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=_REPO_ROOT,
            env=env,
        )
        combined = _ANSI_RE.sub("", result.stdout + result.stderr)
        return result.returncode == 0, combined
    except subprocess.TimeoutExpired:
        return False, "<timeout>"
    except FileNotFoundError:
        return False, "<uv not found>"


def validate(*, quiet: bool = False) -> bool:
    """Validate all agent-skills markdown command references.  Returns True if all pass."""
    if not _SKILLS_DIR.is_dir():
        print(f"[SKIP] agent-skills dir not found: {_SKILLS_DIR}", file=sys.stderr)
        return True

    # Collect (skill_name, subcommand, flags) triples first, deduplicating per
    # skill, then probe the UNIQUE subcommands' --help output IN PARALLEL —
    # each probe is an independent subprocess spawn (~1s); serialising ~30 of
    # them made the validation (and the two suite tests running it) take 30s+.
    from concurrent.futures import ThreadPoolExecutor

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

    unique_subs = sorted({c[1] for c in combos})
    with ThreadPoolExecutor(max_workers=8) as pool:
        help_cache: dict[str, tuple[bool, str]] = dict(
            zip(unique_subs, pool.map(_run_help, unique_subs), strict=True)
        )

    errors: list[str] = []
    checked = 0
    for skill_name, subcommand, combo_flags in combos:
        checked += 1
        ok, output = help_cache[subcommand]

        if not ok:
            err = f"{skill_name}: rebrew {subcommand} — subcommand not found / timeout"
            errors.append(err)
            if not quiet:
                print(f"FAIL  {err}")
            continue

        for flag in combo_flags:
            if flag not in output:
                err = f"{skill_name}: rebrew {subcommand} {flag} — flag not in --help output"
                errors.append(err)
                if not quiet:
                    print(f"FAIL  {err}")
            elif not quiet:
                pass  # verbose success suppressed by default

    if not quiet:
        print(
            f"\nChecked {checked} unique (subcommand, flags) combinations across {_SKILLS_DIR.name}/."
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
        description="Validate rebrew CLI flags referenced in agent SKILL.md files."
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Only print failures and summary."
    )
    args = parser.parse_args()

    ok = validate(quiet=args.quiet)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
