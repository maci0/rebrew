"""validate_skill_commands.py – Validate that rebrew CLI flags referenced in SKILL.md files exist.

Parses each ``src/rebrew/agent-skills/*/SKILL.md``, extracts every ``bash``
code block, finds lines that start with ``rebrew <subcommand>``, and for each
unique ``(subcommand, flags)`` combination runs ``uv run rebrew <subcommand>
--help`` to confirm the subcommand resolves AND every long flag mentioned
(``--flag``) appears in the help output.

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
_FLAG_RE = re.compile(r"(--[a-z][a-z0-9-]+)")

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


# Multi-command subcommands whose top-level --help does not list subcommand
# flags.  For these, we validate subcommand+subsubcommand pairs instead.
_MULTI_SUBCOMMANDS: frozenset[str] = frozenset({"cfg", "cache", "extract", "skills"})


def _extract_commands(skill_md: Path) -> list[tuple[str, list[str]]]:
    """Return list of (subcommand, [flags]) from bash blocks in *skill_md*.

    For multi-command groups (e.g. ``rebrew cfg add-target``), the subcommand
    is taken as ``cfg add-target`` so we invoke ``rebrew cfg add-target --help``
    instead of ``rebrew cfg --help`` (which would not list subcommand flags).
    """
    text = skill_md.read_text(encoding="utf-8")
    results: list[tuple[str, list[str]]] = []
    for block in _BASH_BLOCK_RE.finditer(text):
        for line in block.group(1).splitlines():
            # Strip inline comments
            line = line.split("#")[0].strip()
            if not line.startswith("rebrew "):
                continue
            tokens = line.split()
            if len(tokens) < 2:
                continue
            first_sub = tokens[1]
            # Skip lines that use placeholder-style subcommands (contain <…>)
            if "<" in first_sub or ">" in first_sub:
                continue

            # For multi-command groups, absorb the subsubcommand if present
            if first_sub in _MULTI_SUBCOMMANDS and len(tokens) >= 3:
                second_sub = tokens[2]
                # Skip if second token is a flag or placeholder
                if (
                    not second_sub.startswith("-")
                    and "<" not in second_sub
                    and ">" not in second_sub
                ):
                    subcommand = f"{first_sub} {second_sub}"
                else:
                    subcommand = first_sub
            else:
                subcommand = first_sub

            flags = [f for f in _FLAG_RE.findall(line) if f not in _SKIP_FLAGS]
            results.append((subcommand, flags))
    return results


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
        # rebrew --help exits 0; some subcommands exit non-zero on --help
        combined = result.stdout + result.stderr
        return True, combined
    except subprocess.TimeoutExpired:
        return False, "<timeout>"
    except FileNotFoundError:
        return False, "<uv not found>"


def validate(*, quiet: bool = False) -> bool:
    """Validate all SKILL.md command references.  Returns True if all pass."""
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
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            continue
        skill_name = skill_dir.name
        commands = _extract_commands(skill_md)

        seen: set[tuple[str, tuple[str, ...]]] = set()
        for subcommand, flags in commands:
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
