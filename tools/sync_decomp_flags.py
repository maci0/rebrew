#!/usr/bin/env python3
"""Sync compiler flag definitions from decomp.me into rebrew.

Clones the decomp.me repo (sparse, depth-1), reads their flags.py,
and generates src/rebrew/matcher/flag_data.py using rebrew's own
FlagSet/Checkbox classes (same data structure as decomp.me).

Usage:
    python tools/sync_decomp_flags.py          # writes flag_data.py
    python tools/sync_decomp_flags.py --dry-run  # print to stdout
"""

import argparse
import importlib.util
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

REPO_URL = "https://github.com/decompme/decomp.me.git"
FLAGS_PATH = "backend/coreapp/flags.py"

# Flag IDs that only exist in MSVC 7.x+ (not available in MSVC 6.0)
MSVC7_ONLY_IDS = {"msvc_fp", "msvc_disable_buffer_security_checks"}

# Sweep tiers: which flag IDs to include at each effort level
MSVC_SWEEP_TIERS = {
    "quick": [
        "msvc_opt_level",
        "msvc_callconv",
        "msvc_codegen",
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


def clone_decomp_me(tmp_dir: str) -> Path:
    """Sparse-clone decomp.me into tmp_dir, return repo root."""
    repo_dir = Path(tmp_dir) / "decomp.me"
    subprocess.run(
        [
            "git", "clone", "--depth", "1",
            "--filter=blob:none", "--sparse",
            REPO_URL, str(repo_dir),
        ],
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


def load_flags_module(repo_dir: Path):
    """Import decomp.me's flags.py as a module."""
    flags_file = repo_dir / FLAGS_PATH
    if not flags_file.exists():
        raise FileNotFoundError(f"flags.py not found at {flags_file}")

    spec = importlib.util.spec_from_file_location("decomp_flags", str(flags_file))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def format_flags_list(var_name: str, flag_list) -> str:
    """Format a decomp.me Flags list as Python source using rebrew's classes."""
    lines = [f"{var_name}: Flags = ["]
    for item in flag_list:
        type_name = type(item).__name__
        if type_name == "FlagSet":
            if len(item.flags) <= 4:
                flags_repr = repr(item.flags)
                lines.append(f"    FlagSet(id={item.id!r}, flags={flags_repr}),")
            else:
                lines.append("    FlagSet(")
                lines.append(f"        id={item.id!r},")
                lines.append(f"        flags={item.flags!r},")
                lines.append("    ),")
        elif type_name == "Checkbox":
            lines.append(f"    Checkbox(id={item.id!r}, flag={item.flag!r}),")
        elif type_name == "LanguageFlagSet":
            # Convert LanguageFlagSet → FlagSet (we don't need language metadata)
            flag_strs = list(item.flags.keys())
            lines.append(f"    FlagSet(id={item.id!r}, flags={flag_strs!r}),")
    lines.append("]")
    return "\n".join(lines)


def count_combos(flag_list, tier_ids=None) -> int:
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


def generate_flag_data_py(msvc_flags, msvc6_flags, timestamp: str) -> str:
    """Generate the flag_data.py source code."""
    header = f'''\
"""Auto-generated compiler flag axes from decomp.me.

Source: {REPO_URL}
  File: {FLAGS_PATH}
Synced: {timestamp}

Do not edit manually — re-run tools/sync_decomp_flags.py to update.
"""

from rebrew.matcher.flags import Checkbox, Flags, FlagSet

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
    tiers_lines.append("# normal:   adds codegen, inline, callconv (~moderate)")
    tiers_lines.append("# thorough: adds alignment + key toggles (~heavy)")
    tiers_lines.append("# full:     all axes (use with sampling for large spaces)")
    tiers_lines.append("MSVC_SWEEP_TIERS = {")
    for tier_name, tier_ids in MSVC_SWEEP_TIERS.items():
        tiers_lines.append(f"    {tier_name!r}: {tier_ids!r},")
    tiers_lines.append("}")
    tiers_lines.append("")

    return header + body + "\n".join(tiers_lines)


def main():
    parser = argparse.ArgumentParser(description="Sync flags from decomp.me")
    parser.add_argument("--dry-run", action="store_true", help="Print to stdout only")
    parser.add_argument(
        "--output",
        default=None,
        help="Output file (default: src/rebrew/matcher/flag_data.py)",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    output_path = Path(args.output) if args.output else (
        project_root / "src" / "rebrew" / "matcher" / "flag_data.py"
    )

    print("Cloning decomp.me (sparse, depth-1)...")
    tmp_dir = tempfile.mkdtemp(prefix="decomp_sync_")
    try:
        repo_dir = clone_decomp_me(tmp_dir)
        print(f"  → Cloned to {repo_dir}")

        print("Loading flags module...")
        mod = load_flags_module(repo_dir)

        msvc_flags = getattr(mod, "COMMON_MSVC_FLAGS", None)
        if msvc_flags is None:
            print("ERROR: COMMON_MSVC_FLAGS not found in flags.py")
            sys.exit(1)

        # Filter out 7.x-only flags for MSVC6
        msvc6_flags = [
            item for item in msvc_flags
            if item.id not in MSVC7_ONLY_IDS
        ]

        print(f"  → MSVC:  {len(msvc_flags)} flag entries")
        print(f"  → MSVC6: {len(msvc6_flags)} flag entries (excluding {MSVC7_ONLY_IDS})")

        # Count combinations per tier
        for tier_name, tier_ids in MSVC_SWEEP_TIERS.items():
            total = count_combos(msvc_flags, tier_ids)
            n_axes = len(tier_ids) if tier_ids else len(msvc_flags)
            print(f"  → {tier_name}: {n_axes} axes, {total:,} combos")

        timestamp = datetime.now(UTC).strftime("%Y-%m-%d")
        source = generate_flag_data_py(msvc_flags, msvc6_flags, timestamp)

        if args.dry_run:
            print("\n--- Generated flag_data.py ---")
            print(source)
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(source)
            print(f"\nWrote {output_path}")

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
