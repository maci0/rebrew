"""naming.py - Shared function analysis and naming utilities.

Provides function classification (origin detection, difficulty estimation,
unmatchable detection), naming conventions (filename generation, sanitization),
and data loading helpers shared across multiple CLI tools.

Extracted from skeleton.py and next.py to eliminate circular dependencies.
"""

import bisect
import re
from pathlib import Path
from typing import Any

import capstone

from rebrew.annotation import DEFAULT_ORIGIN_PREFIXES, parse_c_file_multi
from rebrew.binary_loader import BinaryInfo, extract_bytes_at_va
from rebrew.config import ProjectConfig

# 8-tuple: (difficulty, size, va, name, origin, reason, neighbor_file, similarity)
UncoveredItem = tuple[int, int, int, str, str, str, str | None, float]

# ---------------------------------------------------------------------------
# Unmatchable function detection
# ---------------------------------------------------------------------------

# x86 IAT thunk: FF 25 xx xx xx xx  (jmp [addr])
_IAT_JMP = bytes([0xFF, 0x25])

# Single-byte ret: C3 or CC (int3 padding)
_RET = 0xC3
_INT3 = 0xCC
_NOP = 0x90

# SEH prologue using fs segment: 64 A1 00 00 00 00 (mov eax, fs:[0])
_SEH_FS = bytes([0x64, 0xA1, 0x00, 0x00, 0x00, 0x00])

# ASM CRT patterns
_ASM_BT = bytes([0x0F, 0xA3])
_ASM_BTS = bytes([0x0F, 0xAB])
_ASM_REPNE_SCASB = bytes([0xF2, 0xAE])
_ASM_REP_MOVS = (bytes([0xF3, 0xA4]), bytes([0xF3, 0xA5]))


def detect_unmatchable(
    va: int,
    size: int,
    binary_info: BinaryInfo | None,
    iat_thunks: set[int] | None = None,
    ignored_symbols: set[str] | None = None,
    name: str = "",
) -> str | None:
    """Check if a function is unmatchable from C source.

    Returns a reason string if unmatchable, or None if it appears normal.
    """
    # 1. Explicit IAT thunk list from config
    if iat_thunks and va in iat_thunks:
        return "IAT thunk (config)"

    # 2. Known ignored symbols (ASM builtins)
    if ignored_symbols and name in ignored_symbols:
        return f"ignored symbol: {name}"

    # 3. Byte-pattern detection (requires binary)
    if binary_info is None:
        return None

    raw = extract_bytes_at_va(binary_info, va, max(size, 8), padding_bytes=())
    if not raw:
        return None

    # 3a. Tiny functions: single ret or int3/nop padding
    if size <= 2:
        if raw[0] == _RET:
            return "single-byte RET stub"
        if raw[0] == _INT3:
            return "INT3 padding"
        if raw[0] == _NOP:
            return "NOP padding"

    # 3b. IAT jmp [addr] thunk (6 bytes: FF 25 xx xx xx xx)
    if size <= 8 and len(raw) >= 2 and raw[:2] == _IAT_JMP:
        return "IAT jmp [addr] thunk"

    # 3c. SEH handler manipulating fs:[0] directly (ASM-only patterns)
    if len(raw) >= 6 and raw[:6] == _SEH_FS:
        return "SEH handler (fs:[0] access)"

    # 3d. ASM-origin CRT patterns (via disassembly to avoid false positives in immediates)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    for insn in md.disasm(raw, va):
        mnem = insn.mnemonic
        if mnem in ("bt", "bts"):
            return "ASM-origin CRT (BT/BTS)"
        if mnem == "repne scasb":
            return "ASM-origin CRT (repne scasb)"
        if mnem in ("rep movsb", "rep movsw", "rep movsd"):
            return "ASM-origin CRT (rep movs)"

    return None


def ignored_symbols(cfg: ProjectConfig) -> set[str]:
    """Return the set of symbols to skip (ASM builtins, etc.).

    Reads from ``cfg.ignored_symbols`` (populated from ``rebrew-project.toml``).
    """
    syms = cfg.ignored_symbols
    return set(syms) if syms else set()


# ---------------------------------------------------------------------------
# Byte delta parsing
# ---------------------------------------------------------------------------

# Patterns for extracting byte delta from BLOCKER annotations
# Matches: "2B diff", "24B diff:", "1B diff:", "(2B diff)"
_DELTA_PATTERN_DIFF = re.compile(r"(\d+)\s*B?\s*(?:byte[s]?)?\s*diff", re.IGNORECASE)
# Matches: "XB vs YB" → delta = abs(X - Y)
_DELTA_PATTERN_VS = re.compile(r"(\d+)\s*B\s*vs\s*(\d+)\s*B", re.IGNORECASE)


def parse_byte_delta(blocker: str) -> int | None:
    """Extract byte delta from a BLOCKER annotation string.

    Tries several patterns seen in practice:
    - ``(2B diff)`` → 2
    - ``24B diff:`` → 24
    - ``229B vs 205B`` → 24 (abs difference)

    Returns None if no delta can be parsed.
    """
    if not blocker:
        return None

    # Try explicit "XB diff" pattern first
    m = _DELTA_PATTERN_DIFF.search(blocker)
    if m:
        return int(m.group(1))

    # Try "XB vs YB" pattern
    m = _DELTA_PATTERN_VS.search(blocker)
    if m:
        return abs(int(m.group(1)) - int(m.group(2)))

    return None


# ---------------------------------------------------------------------------
# Origin detection and difficulty estimation
# ---------------------------------------------------------------------------


def detect_origin(va: int, name: str, cfg: ProjectConfig) -> str:
    """Detect function origin based on VA, name, and config rules.

    Uses project-specific heuristics (zlib_vas, game_range_end) for known
    origins, then falls back to cfg.default_origin or the first configured origin.
    """
    zlib_vas = set(cfg.zlib_vas or [])
    if va in zlib_vas:
        return "ZLIB"
    game_range_end = cfg.game_range_end
    if game_range_end and va >= game_range_end:
        return "MSVCRT"
    if name.startswith(("__", "_crt")):
        return "MSVCRT"
    default = cfg.default_origin or ""
    if default:
        return default
    origins = cfg.origins or []
    return origins[0] if origins else "GAME"


def estimate_difficulty(
    size: int,
    name: str,
    origin: str,
    ignored: set[str] | None = None,
    cfg: ProjectConfig | None = None,
) -> tuple[int, str]:
    """Estimate difficulty (1-5) and reason."""
    if ignored and name in ignored:
        return 0, "ASM builtin / ignored symbol (skip)"

    lib_origins = cfg.library_origins if cfg else None
    if lib_origins is None:
        lib_origins = {"ZLIB", "MSVCRT"}
    if origin in lib_origins:
        if size < 100:
            return 2, f"small {origin} function, reference source available"
        return 3, f"{origin} function, check reference sources"

    # Primary origin (GAME or equivalent)
    if size < 80:
        return 1, "tiny function, likely simple getter/setter"
    if size < 150:
        return 2, "small function, straightforward logic"
    if size < 250:
        return 3, "medium function, may have branches/loops"
    if size < 400:
        return 4, "large function, complex control flow"
    return 5, "very large function, expect significant effort"


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_data(
    cfg: ProjectConfig,
) -> tuple[list[dict[str, Any]], dict[int, dict[str, str]], dict[int, str]]:
    """Load all project data.

    Returns (ghidra_funcs, existing, covered_vas) where:
    - ghidra_funcs: list of function dicts from ghidra_functions.json
    - existing: dict mapping VA -> {filename, status, origin, blocker, symbol}
    - covered_vas: dict mapping VA -> filename (for find_neighbor_file)
    """
    from rebrew.catalog import load_ghidra_functions
    from rebrew.cli import iter_sources, rel_display_path

    src_dir = Path(cfg.reversed_dir)
    ghidra_json = src_dir / "ghidra_functions.json"

    # Ghidra functions
    ghidra_funcs = load_ghidra_functions(ghidra_json)

    # Existing source files — use parse_c_file_multi to capture all VAs in
    # multi-function files (not just the first annotation).
    existing: dict[int, dict[str, str]] = {}
    covered_vas: dict[int, str] = {}
    for cfile in iter_sources(src_dir, cfg):
        entries = parse_c_file_multi(cfile, target_name=cfg.marker if cfg else None)
        rel_name = rel_display_path(cfile, src_dir)
        for entry in entries:
            if entry.marker_type in ("GLOBAL", "DATA"):
                continue
            if entry.va < 0x1000:
                continue
            existing[entry.va] = {
                "filename": rel_name,
                "status": entry.status,
                "origin": entry.origin,
                "blocker": entry.blocker,
                "blocker_delta": str(entry.blocker_delta)
                if entry.blocker_delta is not None
                else "",
                "symbol": entry.symbol,
            }
            covered_vas[entry.va] = rel_name

    return ghidra_funcs, existing, covered_vas


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


def group_uncovered(
    uncovered: list[UncoveredItem],
    max_gap: int = 0x1000,
) -> list[list[UncoveredItem]]:
    """Group uncovered functions by address proximity.

    Adjacent functions are grouped when the gap from the *end* of one function
    to the *start* of the next is within *max_gap* bytes.  This accounts for
    function body size, not just VA distance.  Groups are sorted by total size
    (smallest first — easiest batch to tackle).
    """
    if not uncovered:
        return []

    # Sort by VA (index 2) for contiguity detection
    by_va = sorted(uncovered, key=lambda x: x[2])

    groups: list[list[UncoveredItem]] = []
    current_group = [by_va[0]]

    for item in by_va[1:]:
        prev_va = current_group[-1][2]
        prev_size = current_group[-1][1]
        curr_va = item[2]

        # Gap from end of previous function to start of current
        gap = curr_va - (prev_va + prev_size)
        if gap <= max_gap:
            current_group.append(item)
        else:
            groups.append(current_group)
            current_group = [item]

    groups.append(current_group)

    # Sort groups by total size (smallest first)
    groups.sort(key=lambda g: sum(item[1] for item in g))

    return groups


# ---------------------------------------------------------------------------
# Naming conventions (from skeleton.py)
# ---------------------------------------------------------------------------

# Reverse mapping: origin → filename prefix (derived from annotation defaults)
_ORIGIN_TO_PREFIX: dict[str, str] = {v: k for k, v in DEFAULT_ORIGIN_PREFIXES.items()}


def load_existing_vas(src_dir: str | Path, cfg: ProjectConfig | None = None) -> dict[int, str]:
    """Load VAs already covered by source files. Returns {va: rel_path}.

    Supports multi-function files: a single source file may contain multiple
    annotation blocks, each registering a separate VA.

    Values are relative paths from *src_dir* (e.g. ``"game/pool_free.c"``
    for nested layouts, or ``"pool_free.c"`` for flat layouts).

    Args:
        src_dir: Directory containing reversed source files.
        cfg: Optional config for source extension (defaults to ``".c"``).
    """
    from rebrew.cli import iter_sources, rel_display_path

    src_path = Path(src_dir)
    existing: dict[int, str] = {}
    for cfile in iter_sources(src_path, cfg):
        rel_name = rel_display_path(cfile, src_path)
        entries = parse_c_file_multi(cfile, target_name=cfg.marker if cfg else None)
        for entry in entries:
            if entry.marker_type in ("GLOBAL", "DATA"):
                continue
            existing[entry.va] = rel_name
    return existing


def find_neighbor_file(
    va: int,
    existing_vas: dict[int, str],
    max_gap: int = 0x1000,
    _sorted_keys: list[int] | None = None,
) -> str | None:
    """Find an existing .c file containing a function near this VA.

    Searches for the closest covered VA within *max_gap* bytes. If found,
    returns the filename — suggesting the uncovered function should be
    appended to that file rather than getting its own skeleton.

    Args:
        va: The uncovered function's virtual address.
        existing_vas: Mapping of covered VA -> filename (from load_existing_vas).
        max_gap: Maximum address distance to consider (default 4KB).
        _sorted_keys: Optional pre-sorted list of VAs from *existing_vas*.
            Pass this when calling in a loop to avoid re-sorting on each call.
    """
    if not existing_vas:
        return None

    covered = _sorted_keys if _sorted_keys is not None else sorted(existing_vas)
    idx = bisect.bisect_left(covered, va)
    best_file = None
    best_gap = max_gap + 1

    # Check left neighbor
    if idx > 0:
        left_va = covered[idx - 1]
        gap = va - left_va
        if gap <= max_gap and gap < best_gap:
            best_gap = gap
            best_file = existing_vas[left_va]

    # Check right neighbor
    if idx < len(covered):
        right_va = covered[idx]
        gap = right_va - va
        if gap <= max_gap and gap < best_gap:
            best_gap = gap
            best_file = existing_vas[right_va]

    return best_file


def sanitize_name(ghidra_name: str) -> str:
    """Convert Ghidra name to a safe C filename prefix.

    Ensures:
    - No characters outside [a-zA-Z0-9_]
    - No leading digits (would be an invalid C identifier)
    - No consecutive underscores
    - Maximum 64 characters
    """
    # Strip FUN_ prefix
    name = ghidra_name
    if name.startswith("FUN_"):
        # Use the address as the name
        return "func_" + name[4:].lower()
    # Clean up special chars
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    # Collapse consecutive underscores
    name = re.sub(r"_+", "_", name)
    # Strip leading/trailing underscores
    name = name.strip("_")
    # Ensure no leading digit (invalid C identifier)
    if name and name[0].isdigit():
        name = "_" + name
    # Limit length
    if len(name) > 64:
        name = name[:64]
    return name or "unnamed"


def make_filename(
    va: int,
    ghidra_name: str,
    origin: str,
    custom_name: str | None = None,
    cfg: ProjectConfig | None = None,
) -> str:
    """Generate the .c filename following project naming conventions."""
    if custom_name:
        base = custom_name
    elif ghidra_name.startswith("FUN_"):
        base = "func_" + ghidra_name[4:].lower()
    else:
        base = sanitize_name(ghidra_name)

    # Apply origin prefix convention (config-driven or default)
    if cfg is not None and cfg.origin_prefixes:
        prefix = cfg.origin_prefixes.get(origin, "")
    else:
        prefix = _ORIGIN_TO_PREFIX.get(origin, "")

    # Don't double-prefix
    if prefix and not base.startswith(prefix) and not base.startswith("func_"):
        base = prefix + base

    ext = cfg.source_ext if cfg is not None else ".c"
    return base + ext
