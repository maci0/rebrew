#!/usr/bin/env python3
"""Sync compiler flag definitions from decomp.me into rebrew.

Clones the decomp.me repo (sparse, depth-1), reads their flags.py,
and generates src/rebrew/flag_data.py using rebrew's own
FlagSet/Checkbox classes (same data structure as decomp.me).

Upstream is a branch, so a bare sync follows whatever decomp.me pushed since
the last one.  ``--ref`` names the ref to sync from (a tag or a commit) and the
resolved commit is printed on every run, so a re-sync of a known-good commit is
one flag away and the run says which upstream state it read.  The generated
header's ``Synced:`` line comes from SOURCE_DATE_EPOCH when that is set, so
re-syncing one upstream commit twice yields the same file.

Usage:
    uv run --frozen python tools/sync_decomp_flags.py            # writes flag_data.py
    uv run --frozen python tools/sync_decomp_flags.py --dry-run  # print to stdout
    uv run --frozen python tools/sync_decomp_flags.py --check    # fail if a sync would change it
    uv run --frozen python tools/sync_decomp_flags.py --ref <commit-or-tag>
"""

import argparse
import difflib
import importlib.util
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any

from rebrew.flags import Checkbox, FlagSet

REPO_URL = "https://github.com/decompme/decomp.me.git"
FLAGS_PATH = "backend/coreapp/flags.py"

# The generated header's one moving part: the day the sync ran.  A check run
# on another day would otherwise report drift on an unchanged upstream, so the
# comparison masks this line and nothing else.
_SYNCED_LINE_RE = re.compile(r"(?m)^Synced: \d{4}-\d{2}-\d{2}$")

# Flag IDs that only exist in MSVC 7.x+ (not available in MSVC 6.0)
MSVC7_ONLY_IDS = {"msvc_fp", "msvc_disable_buffer_security_checks"}

# rebrew-local axes that decomp.me does not model but MSVC6 codegen needs:
# /Oy (frame-pointer omission, with /Oy- to force keeping it) and
# /Op (floating-point consistency).  Appended after the synced entries.
LOCAL_MSVC_FLAGS = [
    FlagSet(id="msvc_fpo", flags=("/Oy", "/Oy-")),
    Checkbox(id="msvc_fp_consistency", flag="/Op"),
]

# Sweep tiers: which flag IDs to include at each effort level.
# quick:    core code-affecting axes (~fast)
# targeted: core + specific codegen-altering flags (/Oy, /Op)
# normal:   adds codegen, inline, callconv (~moderate)
# thorough: adds alignment + key toggles (~heavy)
# full:     all axes (use with sampling for large spaces)
MSVC_SWEEP_TIERS = {
    "quick": ["msvc_opt_level", "msvc_callconv", "msvc_codegen"],
    "targeted": [
        "msvc_opt_level",
        "msvc_callconv",
        "msvc_codegen",
        "msvc_fpo",
        "msvc_fp_consistency",
    ],
    "normal": [
        "msvc_opt_level",
        "msvc_codegen",
        "msvc_fp",
        "msvc_rtlib",
        "msvc_inline",
        "msvc_callconv",
    ],
    "thorough": [
        "msvc_opt_level",
        "msvc_codegen",
        "msvc_fp",
        "msvc_rtlib",
        "msvc_inline",
        "msvc_callconv",
        "msvc_alignment",
        "msvc_disable_stack_checking",
        "msvc_use_ehsc",
        "msvc_runtime_debug_checks",
    ],
    "full": None,  # None = all axes
}


def clone_decomp_me(tmp_dir: str, ref: str | None = None) -> Path:
    """Sparse-clone decomp.me into tmp_dir, return repo root.

    *ref* names the branch, tag, or commit to clone.  Without it the clone
    follows the remote's default branch, so a sync reads whatever upstream
    pushed last; a pinned *ref* makes the input to the generated file
    explicit.
    """
    repo_dir = Path(tmp_dir) / "decomp.me"
    command = ["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse"]
    if ref:
        command += ["--branch", ref]
    subprocess.run(
        [*command, REPO_URL, str(repo_dir)],
        capture_output=True,
        check=True,
    )
    subprocess.run(
        ["git", "sparse-checkout", "set", "backend/coreapp"],
        cwd=str(repo_dir),
        capture_output=True,
        check=True,
    )
    return repo_dir


def resolved_commit(repo_dir: Path) -> str:
    """Commit the clone actually resolved.

    Printed on every run so a sync records which upstream state produced the
    generated file; the flag axes it wrote are only as stable as that commit.
    """
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_dir),
        capture_output=True,
        check=True,
        text=True,
    )
    return result.stdout.strip()


def sync_date() -> str:
    """Date to stamp into the generated header.

    SOURCE_DATE_EPOCH wins, so re-syncing one upstream commit on two days
    writes the same file (reproducible-builds.org).  Without it the wall clock
    moves, and every re-run is a diff whether or not upstream changed.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), UTC).strftime("%Y-%m-%d")
    return datetime.now(UTC).strftime("%Y-%m-%d")


def load_flags_module(repo_dir: Path) -> ModuleType:
    """Import decomp.me's flags.py as a module."""
    flags_file = repo_dir / FLAGS_PATH
    if not flags_file.exists():
        raise FileNotFoundError(f"flags.py not found at {flags_file}")

    spec = importlib.util.spec_from_file_location("decomp_flags", str(flags_file))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load module from {flags_file}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def format_flags_list(var_name: str, flag_list: list[Any]) -> str:
    """Format a decomp.me Flags list as Python source using rebrew's classes."""
    lines = [f"{var_name}: Flags = ["]
    for item in flag_list:
        type_name = type(item).__name__
        if type_name == "FlagSet":
            # FlagSet.flags is typed tuple[str, ...] — decomp.me uses lists.
            flags_tuple = tuple(item.flags)
            if len(flags_tuple) <= 4:
                flags_repr = repr(flags_tuple)
                lines.append(f"    FlagSet(id={item.id!r}, flags={flags_repr}),")
            else:
                lines.append("    FlagSet(")
                lines.append(f"        id={item.id!r},")
                lines.append(f"        flags={flags_tuple!r},")
                lines.append("    ),")
        elif type_name == "Checkbox":
            lines.append(f"    Checkbox(id={item.id!r}, flag={item.flag!r}),")
        elif type_name == "LanguageFlagSet":
            # Convert LanguageFlagSet → FlagSet (we don't need language metadata)
            flag_strs = tuple(item.flags.keys())
            lines.append(f"    FlagSet(id={item.id!r}, flags={flag_strs!r}),")
    lines.append("]")
    return "\n".join(lines)


def count_combos(flag_list: list[Any], tier_ids: Sequence[str] | None = None) -> int:
    """Count flag combinations for a given tier."""
    total = 1
    for item in flag_list:
        if tier_ids is not None and item.id not in tier_ids:
            continue
        type_name = type(item).__name__
        if type_name == "FlagSet":
            total *= len(item.flags) + 1  # +1 for "none"
        elif type_name == "Checkbox":
            total *= 2
        elif type_name == "LanguageFlagSet":
            total *= len(item.flags) + 1
    return total


def generate_flag_data_py(msvc_flags: list[Any], msvc6_flags: list[Any], timestamp: str) -> str:
    """Generate the flag_data.py source code."""
    header = f'''\
"""Auto-generated compiler flag axes from decomp.me.

Source: {REPO_URL}
  File: {FLAGS_PATH}
Synced: {timestamp}

Do not edit manually — re-run tools/sync_decomp_flags.py to update.
"""

from rebrew.flags import Checkbox, Flags, FlagSet

'''
    body = format_flags_list("COMMON_MSVC_FLAGS", msvc_flags)
    body += "\n\n# MSVC 6.0 — excludes flags only available in 7.x+\n"
    body += format_flags_list("MSVC6_FLAGS", msvc6_flags)

    tiers_lines = []
    tiers_lines.append("")
    tiers_lines.append("")
    tiers_lines.append("# Flag IDs only available in MSVC 7.x+")
    tiers_lines.append(f"MSVC7_ONLY_IDS = {MSVC7_ONLY_IDS!r}")
    tiers_lines.append("")
    tiers_lines.append("# Sweep tiers — which flag IDs to include per effort level.")
    tiers_lines.append("# quick:    core code-affecting axes (~fast)")
    tiers_lines.append("# targeted: core + specific codegen-altering flags (/Oy, /Op)")
    tiers_lines.append("# normal:   adds codegen, inline, callconv (~moderate)")
    tiers_lines.append("# thorough: adds alignment + key toggles (~heavy)")
    tiers_lines.append("# full:     all axes (use with sampling for large spaces)")
    tiers_lines.append("MSVC_SWEEP_TIERS: dict[str, list[str] | None] = {")
    for tier_name, tier_ids in MSVC_SWEEP_TIERS.items():
        tiers_lines.append(f"    {tier_name!r}: {tier_ids!r},")
    tiers_lines.append("}")
    tiers_lines.append("")

    return header + body + "\n".join(tiers_lines)


#: Marker comment separating the auto-generated MSVC sections from the
#: hand-maintained flag families below (see flag_data.py).
_PRESERVED_TAIL_MARKER = "# --- Hand-maintained flag families below"


def splice_preserved_tail(generated: str, output_path: Path) -> str:
    """Re-append the hand-maintained tail of an existing flag_data.py.

    ``generate_flag_data_py`` rebuilds only the MSVC sections; the Watcom /
    Borland / MSVC152 / GCC flag families are written by hand below the
    marker comment and must survive a sync.  Returns *generated* with the
    existing tail (from the marker onward) re-attached, or *generated*
    unchanged when the file is absent or has no marker."""
    try:
        existing = output_path.read_text(encoding="utf-8")
    except OSError:
        return generated
    marker = existing.find(_PRESERVED_TAIL_MARKER)
    if marker < 0:
        return generated
    tail = existing[marker:]
    return generated.rstrip("\n") + "\n\n" + tail


def drifted_lines(committed: str, generated: str) -> list[str]:
    """Diff of a re-sync against the committed file, or ``[]`` when it is current.

    The ``Synced:`` header line is masked on both sides: it records the day a
    maintainer ran the sync, not what upstream said, and comparing it would
    report drift on an unchanged upstream every time the check runs on a
    different date.  Everything else is a real difference.
    """
    return list(
        difflib.unified_diff(
            _SYNCED_LINE_RE.sub("Synced: <date>", committed).splitlines(),
            _SYNCED_LINE_RE.sub("Synced: <date>", generated).splitlines(),
            fromfile="committed",
            tofile="regenerated",
            lineterm="",
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync flags from decomp.me")
    parser.add_argument("--dry-run", action="store_true", help="Print to stdout only")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 when a sync would change the output file (needs network)",
    )
    parser.add_argument(
        "--ref",
        default=None,
        help="Branch, tag, or commit to sync from (default: the remote's default branch)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file (default: src/rebrew/flag_data.py)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    output_path = (
        Path(args.output) if args.output else (project_root / "src" / "rebrew" / "flag_data.py")
    )

    source_desc = f"decomp.me@{args.ref}" if args.ref else "decomp.me (default branch)"
    print(f"Cloning {source_desc} (sparse, depth-1)...")
    with tempfile.TemporaryDirectory(prefix="decomp_sync_") as tmp_dir:
        repo_dir = clone_decomp_me(tmp_dir, args.ref)
        print(f"  → Cloned to {repo_dir} at {resolved_commit(repo_dir)}")

        print("Loading flags module...")
        mod = load_flags_module(repo_dir)

        msvc_flags = getattr(mod, "COMMON_MSVC_FLAGS", None)
        if msvc_flags is None:
            print("ERROR: COMMON_MSVC_FLAGS not found in flags.py")
            sys.exit(1)
        # Append the rebrew-local MSVC6 axes decomp.me does not model.
        msvc_flags = list(msvc_flags) + LOCAL_MSVC_FLAGS

        # Filter out 7.x-only flags for MSVC6
        msvc6_flags = [item for item in msvc_flags if item.id not in MSVC7_ONLY_IDS]

        print(f"  → MSVC:  {len(msvc_flags)} flag entries")
        print(f"  → MSVC6: {len(msvc6_flags)} flag entries (excluding {MSVC7_ONLY_IDS})")

        # Count combinations per tier
        for tier_name, tier_ids in MSVC_SWEEP_TIERS.items():
            total = count_combos(msvc_flags, tier_ids)
            n_axes = len(tier_ids) if tier_ids else len(msvc_flags)
            print(f"  → {tier_name}: {n_axes} axes, {total:,} combos")

        timestamp = sync_date()
        source = generate_flag_data_py(msvc_flags, msvc6_flags, timestamp)
        # Preserve the hand-maintained flag families (Watcom/Borland/MSVC152/
        # GCC …): everything from the marker comment to EOF survives a sync.
        source = splice_preserved_tail(source, output_path)

        if args.dry_run:
            print("\n--- Generated flag_data.py ---")
            print(source)
        elif args.check:
            if not output_path.is_file():
                print(f"ERROR: {output_path} does not exist; run a sync first")
                sys.exit(1)
            diff = drifted_lines(output_path.read_text(encoding="utf-8"), source)
            if diff:
                print(f"\nERROR: {output_path} is out of date with {source_desc}:")
                print("\n".join(diff))
                sys.exit(1)
            print(f"\n{output_path} matches {source_desc}")
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(source, encoding="utf-8")
            print(f"\nWrote {output_path}")


if __name__ == "__main__":
    main()
