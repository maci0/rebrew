"""lint.py - Annotation linter for rebrew decomp C files.

Check that all .c files in the reversed directory have proper reccmp-style annotations.
Supports --fix mode to auto-migrate from old format to new format.

Inspired by reccmp's decomplint tool.
"""

import contextlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from rebrew.annotation import (
    ALL_KNOWN_KEYS,
    BLOCK_FUNC_CAPTURE_RE,
    BLOCK_FUNC_RE,
    BLOCK_KV_RE,
    DEFAULT_ORIGIN_PREFIXES,
    DEFAULT_ORIGINS,
    JAVADOC_ADDR_RE,
    JAVADOC_KV_RE,
    NEW_FUNC_RE,
    NEW_KV_RE,
    OLD_RE,
    VALID_MARKERS,
    VALID_STATUSES,
    marker_for_origin,
    normalize_status,
    origin_from_filename,
)
from rebrew.cli import TargetOption, error_exit, get_config, json_print
from rebrew.config import ProjectConfig
from rebrew.utils import atomic_write_text

out_console = Console()

_HEADER_MARKER_RE = re.compile(r"//\s*(\w+):\s*(\S+)\s+(0x[0-9a-fA-F]+)")
_SIZE_ANNOTATION_RE = re.compile(r"//\s*SIZE\s+0x[0-9a-fA-F]+")
_MARKER_TYPE_RE = re.compile(r"//\s*(\w+):")


@dataclass
class LintResult:
    """Accumulated lint errors and warnings for a single source file.

    Why a custom linter? Standard C linters don't understand our `// STATUS:` and
    `// ORIGIN:` annotations. We need strict validation of these metadata fields
    to ensure the CI pipeline and other tools (like `rebrew test`) can parse them.
    """

    filepath: Path
    errors: list[tuple[int, str, str]] = field(default_factory=list)
    warnings: list[tuple[int, str, str]] = field(default_factory=list)
    context_prefix: str = ""

    def error(self, line: int, code: str, msg: str) -> None:
        """Record an error diagnostic at *line*."""
        self.errors.append((line, code, self.context_prefix + msg))

    def warning(self, line: int, code: str, msg: str) -> None:
        """Record a warning diagnostic at *line*."""
        self.warnings.append((line, code, self.context_prefix + msg))

    @property
    def passed(self) -> bool:
        """True if no errors were recorded."""
        return len(self.errors) == 0

    def display(self, quiet: bool = False) -> None:
        """Print errors (and optionally warnings) to the console."""
        rel = self.filepath.name
        for line, code, msg in self.errors:
            out_console.print(f"  [bold]{rel}[/bold]:{line}: [red]{code}[/red]: {msg}")
        if not quiet:
            for line, code, msg in self.warnings:
                out_console.print(f"  [bold]{rel}[/bold]:{line}: [yellow]{code}[/yellow]: {msg}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "file": str(self.filepath.name),
            "path": str(self.filepath),
            "errors": [{"line": ln, "code": c, "message": m} for ln, c, m in self.errors],
            "warnings": [{"line": ln, "code": c, "message": m} for ln, c, m in self.warnings],
            "passed": self.passed,
        }


def _parse_multi_headers(lines: list[str]) -> list[tuple[dict[str, str], dict[str, bool]]]:
    """Parse ALL annotation headers from the file.

    Returns a list of tuples: (found_keys, format_flags).
    """
    results = []

    current_keys = {}
    current_flags = {"has_new": False, "has_old": False, "has_block": False, "has_javadoc": False}
    in_block = False

    # Check for legacy formats in the first 20 lines (for compatibility with single-block legacy fixes)
    legacy_flags = {"has_new": False, "has_old": False, "has_block": False, "has_javadoc": False}
    legacy_keys = {}

    for line in lines[:20]:
        stripped = line.strip()
        if not stripped:
            continue
        if NEW_FUNC_RE.match(stripped):
            legacy_flags["has_new"] = True
        if OLD_RE.search(stripped):
            legacy_flags["has_old"] = True
        if BLOCK_FUNC_RE.match(stripped):
            legacy_flags["has_block"] = True
            bm = BLOCK_FUNC_CAPTURE_RE.match(stripped)
            if bm:
                legacy_keys["MARKER"] = bm.group("type")
                legacy_keys["MODULE"] = bm.group("module")
                legacy_keys["VA"] = bm.group("va")
        bm = BLOCK_KV_RE.match(stripped)
        if bm and legacy_flags["has_block"]:
            legacy_keys[bm.group("key").upper()] = bm.group("value").strip()
        if JAVADOC_ADDR_RE.match(stripped) or JAVADOC_KV_RE.match(stripped):
            legacy_flags["has_javadoc"] = True

    # If it is legacy format, just return the first block we found so `fix` can handle it
    if not legacy_flags["has_new"] and (
        legacy_flags["has_old"] or legacy_flags["has_block"] or legacy_flags["has_javadoc"]
    ):
        return [(legacy_keys, legacy_flags)]

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if NEW_FUNC_RE.match(stripped):
            if in_block:
                results.append((current_keys, current_flags))

            current_keys = {}
            current_flags = {
                "has_new": True,
                "has_old": False,
                "has_block": False,
                "has_javadoc": False,
            }
            in_block = True

            m = _HEADER_MARKER_RE.match(stripped)
            if m:
                current_keys["MARKER"] = m.group(1)
                current_keys["MODULE"] = m.group(2)
                current_keys["VA"] = m.group(3)
            continue

        m = NEW_KV_RE.match(stripped)
        if m and in_block:
            current_keys[m.group("key").upper()] = m.group("value").strip()
            continue

        # If we hit non-comment code while in_block, we could stop collecting keys for this block
        # But NEW_KV_RE already strictly requires `// ` or `/* ` prefix.

    if in_block:
        results.append((current_keys, current_flags))

    return results


def _parse_header(lines: list[str]) -> tuple[dict[str, str], dict[str, bool]]:
    """Parse annotation header from first 20 lines.

    Returns:
        (found_keys, format_flags) where format_flags has keys:
        has_new, has_old, has_block, has_javadoc
    """
    found_keys: dict[str, str] = {}
    flags = {"has_new": False, "has_old": False, "has_block": False, "has_javadoc": False}

    for _i, line in enumerate(lines[:20], 1):
        stripped = line.strip()
        if not stripped:
            continue

        if NEW_FUNC_RE.match(stripped):
            flags["has_new"] = True
            m = _HEADER_MARKER_RE.match(stripped)
            if m:
                found_keys["MARKER"] = m.group(1)
                found_keys["MODULE"] = m.group(2)
                found_keys["VA"] = m.group(3)
            continue

        m = NEW_KV_RE.match(stripped)
        if m and flags["has_new"]:
            found_keys[m.group("key").upper()] = m.group("value").strip()
            continue

        if BLOCK_FUNC_RE.match(stripped):
            flags["has_block"] = True
            bm = BLOCK_FUNC_CAPTURE_RE.match(stripped)
            if bm:
                found_keys["MARKER"] = bm.group("type")
                found_keys["MODULE"] = bm.group("module")
                found_keys["VA"] = bm.group("va")
            continue

        bm = BLOCK_KV_RE.match(stripped)
        if bm and flags["has_block"] and not flags["has_new"]:
            found_keys[bm.group("key").upper()] = bm.group("value").strip()
            continue

        jm = JAVADOC_ADDR_RE.search(stripped)
        if jm:
            flags["has_javadoc"] = True
            found_keys["VA"] = jm.group("va")
            continue

        jm = JAVADOC_KV_RE.match(stripped)
        if jm and flags["has_javadoc"]:
            key = jm.group("key").upper()
            val = jm.group("value").strip()
            if key == "ADDRESS":
                found_keys["VA"] = val
            elif key in (
                "STATUS",
                "ORIGIN",
                "SIZE",
                "CFLAGS",
                "SYMBOL",
                "SOURCE",
                "BLOCKER",
                "NOTE",
            ):
                found_keys[key] = val
            continue

        if OLD_RE.match(stripped):
            flags["has_old"] = True
            break

        if (
            not stripped.startswith("//")
            and not stripped.startswith("/*")
            and not stripped.startswith("*")
            and not stripped.startswith("*/")
        ):
            break

    return found_keys, flags


def _check_format_warnings(
    result: LintResult, found_keys: dict[str, str], flags: dict[str, bool]
) -> bool:
    """Check format-level warnings (W002, W012, W013). Returns True if validation should proceed."""
    has_new = flags["has_new"]
    has_old = flags["has_old"]
    has_block = flags["has_block"]
    has_javadoc = flags["has_javadoc"]

    if has_block and not has_new:
        result.warning(
            1,
            "W012",
            "Block-comment annotation format detected "
            "(/* FUNCTION: ... */ — run with --fix to migrate)",
        )
        flags["has_new"] = True

    if has_javadoc and not flags["has_new"]:
        result.warning(
            1,
            "W013",
            "Javadoc-style annotation format detected (@address — run with --fix to migrate)",
        )
        if "MARKER" not in found_keys:
            origin = found_keys.get("ORIGIN", "GAME")
            status = found_keys.get("STATUS", "RELOC")
            found_keys["MARKER"] = marker_for_origin(origin, status)
        flags["has_new"] = True

    if has_old and not flags["has_new"]:
        result.warning(1, "W002", "Old-format header detected (run with --fix to migrate)")
        return False

    if not flags["has_new"] and not has_old:
        result.error(1, "E001", "Missing FUNCTION/LIBRARY/STUB annotation")
        return False

    return True


def _check_E001_marker(result: LintResult, marker: str) -> None:
    if marker not in VALID_MARKERS:
        result.error(1, "E001", f"Invalid marker type: {marker}")


def _check_E002_va(result: LintResult, va_str: str) -> int | None:
    try:
        va_int = int(va_str, 16)
        if not (0x1000 <= va_int <= 0xFFFFFFFF):
            result.error(1, "E002", f"VA {va_str} is suspicious (outside 32-bit range)")
        return va_int
    except ValueError:
        result.error(1, "E002", f"Invalid VA format: {va_str}")
        return None


def _check_E013_duplicate_va(
    result: LintResult,
    va_int: int | None,
    va_str: str,
    filepath: Path,
    seen_vas: dict[int, str] | None,
) -> None:
    if va_int is not None and seen_vas is not None:
        if va_int in seen_vas:
            result.error(1, "E013", f"Duplicate VA {va_str} — also in {seen_vas[va_int]}")
        else:
            from rebrew.cli import rel_display_path

            seen_vas[va_int] = rel_display_path(filepath)


def _check_E003_E004_status(result: LintResult, found_keys: dict[str, str]) -> None:
    if "STATUS" not in found_keys:
        result.error(1, "E003", "Missing // STATUS: annotation")
    elif found_keys["STATUS"] not in VALID_STATUSES:
        if "\\n" in found_keys["STATUS"]:
            result.error(
                1,
                "E014",
                f"Corrupted STATUS value contains literal '\\n': {found_keys['STATUS']!r}",
            )
        else:
            result.error(1, "E004", f"Invalid STATUS: {found_keys['STATUS']}")


def _check_E005_E006_origin(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None = None
) -> None:
    if "ORIGIN" not in found_keys:
        result.error(1, "E005", "Missing // ORIGIN: annotation")
    else:
        valid = set(cfg.origins) if cfg and cfg.origins else DEFAULT_ORIGINS
        if valid and found_keys["ORIGIN"] not in valid:
            result.error(1, "E006", f"Invalid ORIGIN: {found_keys['ORIGIN']}")


def _check_E007_E008_size(result: LintResult, found_keys: dict[str, str]) -> None:
    if "SIZE" not in found_keys:
        result.error(1, "E007", "Missing // SIZE: annotation")
    else:
        try:
            sz = int(found_keys["SIZE"])
            if sz <= 0:
                result.error(1, "E008", f"Invalid SIZE: {found_keys['SIZE']}")
        except ValueError:
            result.error(1, "E008", f"Invalid SIZE: {found_keys['SIZE']}")


def _check_E009_cflags(result: LintResult, found_keys: dict[str, str]) -> None:
    if "CFLAGS" not in found_keys:
        result.error(1, "E009", "Missing // CFLAGS: annotation")
    elif not found_keys["CFLAGS"].strip():
        result.error(1, "E009", "Empty // CFLAGS: value")


def _check_E010_unknown_keys(result: LintResult, found_keys: dict[str, str]) -> None:
    for key in found_keys:
        if key not in ALL_KNOWN_KEYS and key != "MODULE":
            result.error(1, "E010", f"Unknown annotation key: {key}")


def _check_E015_marker_consistency(
    result: LintResult, marker: str, origin: str, status: str, cfg: ProjectConfig | None = None
) -> None:
    lib_origins = cfg.library_origins if cfg and cfg.library_origins is not None else None
    expected_marker = marker_for_origin(origin, status, lib_origins)
    if marker != expected_marker and marker in VALID_MARKERS and marker not in ("GLOBAL", "DATA"):
        result.error(
            1,
            "E015",
            f"Marker {marker} inconsistent with ORIGIN {origin} (expected {expected_marker})",
        )


def _check_E016_filename(result: LintResult, filepath: Path, symbol: str, marker: str) -> None:
    if symbol and marker not in ("GLOBAL", "DATA") and not filepath.stem.startswith("data_"):
        expected_stem = symbol.lstrip("_")
        if "@" in expected_stem:
            expected_stem = expected_stem.split("@")[0]
        actual_stem = filepath.stem
        if "@" in actual_stem:
            actual_stem = actual_stem.split("@")[0]
        if expected_stem and actual_stem != expected_stem:
            prefix_match = False
            for prefix in DEFAULT_ORIGIN_PREFIXES:
                if actual_stem.startswith(prefix):
                    unprefixed = actual_stem[len(prefix) :]
                    if unprefixed == expected_stem:
                        prefix_match = True
                        break
            if not prefix_match:
                result.error(
                    1,
                    "E016",
                    f"Filename '{filepath.name}' doesn't match SYMBOL "
                    f"'{symbol}' (expected '{expected_stem}{filepath.suffix}')",
                )


def _check_E017_contradictory(result: LintResult, status: str, marker: str) -> None:
    if status in ("MATCHING", "MATCHING_RELOC") and marker == "STUB":
        result.error(1, "E017", f"Contradictory: status is {status} but marker is STUB")


def _check_W001_symbol(result: LintResult, found_keys: dict[str, str]) -> None:
    if "SYMBOL" not in found_keys:
        result.warning(1, "W001", "Missing // SYMBOL: annotation (recommended)")


def _check_W005_blocker(result: LintResult, status: str, found_keys: dict[str, str]) -> None:
    if status == "STUB" and "BLOCKER" not in found_keys:
        result.warning(
            1,
            "W005",
            "STUB function missing // BLOCKER: annotation (explain why it doesn't match)",
        )


def _check_W006_source(
    result: LintResult, origin: str, found_keys: dict[str, str], cfg: ProjectConfig | None = None
) -> None:
    lib_origins = (
        cfg.library_origins if cfg and cfg.library_origins is not None else {"MSVCRT", "ZLIB"}
    )
    if origin in lib_origins and "SOURCE" not in found_keys:
        result.warning(
            1,
            "W006",
            f"{origin} function missing // SOURCE: annotation "
            "(reference file, e.g. SBHEAP.C:195 or deflate.c)",
        )


def _check_W014_origin_prefix(
    result: LintResult, filepath: Path, origin: str, cfg: ProjectConfig | None = None
) -> None:
    # Use config origin_prefixes if available (reversed: origin→prefix to prefix→origin)
    prefixes = None
    if cfg and cfg.origin_prefixes:
        prefixes = {v: k for k, v in cfg.origin_prefixes.items()}
    expected_origin = origin_from_filename(filepath.stem, prefixes)
    if expected_origin and origin and expected_origin != origin:
        result.warning(
            1,
            "W014",
            f"Filename prefix suggests ORIGIN '{expected_origin}' but annotation says '{origin}'",
        )


def _check_W015_va_case(result: LintResult, va_str: str) -> None:
    if va_str and va_str.startswith("0x"):
        hex_digits = va_str[2:]
        if hex_digits != hex_digits.lower() and hex_digits != hex_digits.upper():
            result.warning(
                1,
                "W015",
                f"VA '{va_str}' has mixed-case hex digits (prefer consistent case)",
            )


def _check_config_rules(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None, origin: str
) -> None:
    """Config-aware checks (W008, E012)."""
    if cfg is None:
        return

    # Note: W011 (origin not in configured origins) removed — E006 already checks
    # cfg.origins when available, so W011 would be a duplicate diagnostic.

    module = found_keys.get("MODULE", "")
    if module and hasattr(cfg, "marker") and cfg.marker and module != cfg.marker:
        result.error(
            1,
            "E012",
            f"Module '{module}' doesn't match configured marker '{cfg.marker}'",
        )

    if "CFLAGS" in found_keys:
        expected_cflags = None
        if (
            hasattr(cfg, "origin_compiler")
            and cfg.origin_compiler
            and origin in cfg.origin_compiler
            and "cflags" in cfg.origin_compiler[origin]
        ):
            expected_cflags = cfg.origin_compiler[origin]["cflags"]
        if (
            expected_cflags is None
            and hasattr(cfg, "cflags_presets")
            and cfg.cflags_presets
            and origin in cfg.cflags_presets
        ):
            expected_cflags = cfg.cflags_presets[origin]

        if expected_cflags is not None:
            actual_cflags = found_keys["CFLAGS"]
            if actual_cflags != expected_cflags:
                result.warning(
                    1,
                    "W008",
                    f"CFLAGS '{actual_cflags}' differ from {origin} preset '{expected_cflags}'",
                )


def _check_W016_section(result: LintResult, marker: str, found_keys: dict[str, str]) -> None:
    if marker in ("DATA", "GLOBAL") and "SECTION" not in found_keys:
        result.warning(
            1,
            "W016",
            f"{marker} annotation missing // SECTION: (.data, .rdata, .bss)",
        )


def _check_W017_note_rebrew(result: LintResult, found_keys: dict[str, str]) -> None:
    note = found_keys.get("NOTE", "")
    if note.startswith("[rebrew]"):
        result.warning(
            1,
            "W017",
            "NOTE starts with '[rebrew]' — this looks like auto-generated sync metadata, "
            "not a human note (likely from a bad pull)",
        )


def _check_body_rules(result: LintResult, lines: list[str], has_new: bool) -> None:
    """Check struct SIZE comments and code presence (W003, W007)."""
    has_code = False
    has_struct = False
    struct_has_size = False
    for line in lines[1:]:
        stripped = line.strip()
        if (
            stripped
            and not stripped.startswith("//")
            and not stripped.startswith("/*")
            and not stripped.startswith("*")
        ):
            has_code = True
        if "typedef struct" in stripped or "struct " in stripped:
            has_struct = True
        if _SIZE_ANNOTATION_RE.match(stripped):
            struct_has_size = True

    if not has_code and has_new:
        result.warning(1, "W003", "File has no function implementation")

    if has_struct and not struct_has_size:
        result.warning(
            1,
            "W007",
            "File defines struct(s) without // SIZE 0xNN annotation (reccmp recommendation)",
        )


def lint_file(
    filepath: Path,
    cfg: ProjectConfig | None = None,
    seen_vas: dict[int, str] | None = None,
) -> LintResult:
    """Lint a single C file.

    Args:
        filepath: Path to the .c file.
        cfg: Optional ProjectConfig for config-aware checks.
        seen_vas: Optional dict mapping VA → filename for duplicate detection.
                  Will be mutated (VAs from this file are added).
    """
    result = LintResult(filepath)

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        result.error(0, "E000", f"Cannot read file: {e}")
        return result

    lines = text.splitlines()
    if not lines:
        result.error(1, "E001", "Empty file, missing FUNCTION/LIBRARY/STUB annotation")
        return result

    all_headers = _parse_multi_headers(lines)
    if not all_headers:
        # Fallback to standard for totally broken files
        found_keys, flags = _parse_header(lines)
        all_headers = [(found_keys, flags)]

    for i, (found_keys, flags) in enumerate(all_headers):
        # We need a context string for errors in multi-block files to know WHICH block failed.
        mod = found_keys.get("MODULE", "")
        va_str = found_keys.get("VA", "")
        ctx = f"[{mod} {va_str}] " if mod and va_str else ""

        if len(all_headers) > 1:
            result.context_prefix = ctx
        else:
            result.context_prefix = ""

        if not _check_format_warnings(result, found_keys, flags):
            continue

        if flags["has_new"]:
            marker = found_keys.get("MARKER", "")
            _check_E001_marker(result, marker)

            va_int = _check_E002_va(result, va_str)

            # Use module + va to prevent duplicate within the same target.
            # `seen_vas` maps VA -> filepath. We just use the first block's VA for file-level dupe check,
            # otherwise a file with 2 different modules pointing to the same VA might complain.
            if i == 0 or (va_int and va_int not in (seen_vas or {})):
                _check_E013_duplicate_va(result, va_int, va_str, filepath, seen_vas)

            if marker not in ("GLOBAL", "DATA"):
                _check_E003_E004_status(result, found_keys)
                _check_E005_E006_origin(result, found_keys, cfg)
                _check_E009_cflags(result, found_keys)
                _check_W001_symbol(result, found_keys)
            _check_E007_E008_size(result, found_keys)

            origin = found_keys.get("ORIGIN", "GAME")
            status = found_keys.get("STATUS", "")

            _check_E015_marker_consistency(result, marker, origin, status, cfg)
            _check_W005_blocker(result, status, found_keys)
            _check_W006_source(result, origin, found_keys, cfg)
            _check_E010_unknown_keys(result, found_keys)
            _check_E017_contradictory(result, status, marker)
            _check_config_rules(result, found_keys, cfg, origin)

            # W014 and E016 shouldn't really complain for secondary blocks
            if i == 0:
                _check_E016_filename(result, filepath, found_keys.get("SYMBOL", ""), marker)
                _check_W014_origin_prefix(result, filepath, origin, cfg)

            _check_W015_va_case(result, va_str)
            _check_W016_section(result, marker, found_keys)
            _check_W017_note_rebrew(result, found_keys)

    result.context_prefix = ""
    _check_body_rules(result, lines, all_headers[0][1]["has_new"] if all_headers else False)

    return result


def fix_file(cfg: ProjectConfig, filepath: Path) -> bool:
    """Auto-migrate any legacy format to the canonical // KV format.

    Handles:
      - Old single-line: /* name @ 0xVA (NB) - /flags - STATUS [ORIGIN] */
      - Block-comment:   /* FUNCTION: SERVER 0xVA */ + /* KEY: value */
      - Javadoc:         @address 0xVA + @key value
    """
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    lines = text.splitlines(keepends=True)
    if not lines:
        return False

    first = lines[0].strip()

    # --- Try old single-line format ---
    m = OLD_RE.match(first)
    if m:
        name = m.group("name")
        va_str = m.group("va").lower()
        if not va_str.startswith("0x"):
            va_str = "0x" + va_str
        size = m.group("size")
        raw_cflags = m.group("cflags").strip()
        status = normalize_status(m.group("status"))
        origin = m.group("origin").strip().upper()
        marker = marker_for_origin(origin, status)
        cflags_parts = raw_cflags.split()
        lib_origins = cfg.library_origins if cfg.library_origins is not None else {"MSVCRT", "ZLIB"}
        if "/Gd" not in cflags_parts and origin not in lib_origins:
            cflags_parts.append("/Gd")
        cflags = " ".join(cflags_parts)
        symbol = "_" + name

        annotation = (
            f"// {marker}: {cfg.marker} {va_str}\n"
            f"// STATUS: {status}\n"
            f"// ORIGIN: {origin}\n"
            f"// SIZE: {size}\n"
            f"// CFLAGS: {cflags}\n"
            f"// SYMBOL: {symbol}\n"
        )
        new_text = annotation + "".join(lines[1:])
        atomic_write_text(filepath, new_text, encoding="utf-8")
        return True

    # --- Try block-comment format: /* FUNCTION: SERVER 0x... */ ---
    bm = BLOCK_FUNC_CAPTURE_RE.match(first)
    if bm:
        found_keys: dict[str, str] = {
            "MARKER": bm.group("type"),
            "MODULE": bm.group("module"),
            "VA": bm.group("va").lower(),
        }
        header_end = 1
        for idx, line in enumerate(lines[1:], 1):
            stripped = line.strip()
            km = BLOCK_KV_RE.match(stripped)
            if km:
                found_keys[km.group("key").upper()] = km.group("value").strip()
                header_end = idx + 1
            elif not stripped or stripped.startswith("//"):
                # Skip blank lines or // comments mixed in
                if not stripped:
                    header_end = idx + 1
                continue
            else:
                break

        marker = found_keys.get("MARKER", "FUNCTION")
        module = found_keys.get("MODULE", cfg.marker)
        va_str = found_keys.get("VA", "0x0")
        status = found_keys.get("STATUS", "RELOC")
        origin = found_keys.get("ORIGIN", "GAME")
        size = found_keys.get("SIZE", "0")
        cflags = found_keys.get("CFLAGS", "")
        symbol = found_keys.get("SYMBOL", "")

        annotation = (
            f"// {marker}: {module} {va_str}\n"
            f"// STATUS: {status}\n"
            f"// ORIGIN: {origin}\n"
            f"// SIZE: {size}\n"
            f"// CFLAGS: {cflags}\n"
        )
        if symbol:
            annotation += f"// SYMBOL: {symbol}\n"
        for extra_key in ("BLOCKER", "SOURCE", "NOTE", "SKIP"):
            if extra_key in found_keys:
                annotation += f"// {extra_key}: {found_keys[extra_key]}\n"

        new_text = annotation + "".join(lines[header_end:])
        atomic_write_text(filepath, new_text, encoding="utf-8")
        return True

    # --- Try javadoc format: /** ... @address 0x... */ ---
    if first.startswith(("/**", "/*")):
        found_keys_jd: dict[str, str] = {}
        header_end = 0
        in_javadoc = True
        for idx, line in enumerate(lines):
            stripped = line.strip()
            jm = JAVADOC_ADDR_RE.search(stripped)
            if jm:
                found_keys_jd["VA"] = jm.group("va").lower()
            jm2 = JAVADOC_KV_RE.match(stripped.lstrip("* "))
            if jm2:
                key = jm2.group("key").upper()
                val = jm2.group("value").strip()
                if key not in ("BRIEF",):
                    found_keys_jd[key] = val
            if "*/" in stripped:
                header_end = idx + 1
                in_javadoc = False
                break

        if not in_javadoc and "VA" in found_keys_jd:
            # Successfully parsed javadoc
            va_str = found_keys_jd.get("VA", "0x0")
            # Resolve VA from ADDRESS if present
            if "ADDRESS" in found_keys_jd:
                va_str = found_keys_jd["ADDRESS"].lower()
            origin = found_keys_jd.get("ORIGIN", "GAME").upper()
            status = found_keys_jd.get("STATUS", "RELOC").upper()
            marker = marker_for_origin(origin, status)
            size = found_keys_jd.get("SIZE", "0")
            cflags = found_keys_jd.get("CFLAGS", "")
            symbol = found_keys_jd.get("SYMBOL", "")

            annotation = (
                f"// {marker}: {cfg.marker} {va_str}\n"
                f"// STATUS: {status}\n"
                f"// ORIGIN: {origin}\n"
                f"// SIZE: {size}\n"
                f"// CFLAGS: {cflags}\n"
            )
            if symbol:
                annotation += f"// SYMBOL: {symbol}\n"

            new_text = annotation + "".join(lines[header_end:])
            atomic_write_text(filepath, new_text, encoding="utf-8")
            return True

    return False


def _print_summary(results: list[LintResult]) -> None:
    """Print a breakdown table by status and origin."""
    from collections import Counter

    status_counts: Counter[str] = Counter()
    origin_counts: Counter[str] = Counter()
    marker_counts: Counter[str] = Counter()

    for r in results:
        # Re-parse to get fields (lightweight — only header lines)
        try:
            text = r.filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines()[:20]:
            stripped = line.strip()
            m = NEW_KV_RE.match(stripped)
            if m:
                key = m.group("key").upper()
                val = m.group("value").strip()
                if key == "STATUS":
                    status_counts[val] += 1
                elif key == "ORIGIN":
                    origin_counts[val] += 1
            elif NEW_FUNC_RE.match(stripped):
                m2 = _MARKER_TYPE_RE.match(stripped)
                if m2:
                    marker_counts[m2.group(1)] += 1

    out_console.print()
    table = Table(title="Summary", show_lines=False, pad_edge=False)
    table.add_column("Category", style="bold")
    table.add_column("Value")
    table.add_column("Count", justify="right")

    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        table.add_row("STATUS", status, str(count))
    for origin, count in sorted(origin_counts.items(), key=lambda x: -x[1]):
        table.add_row("ORIGIN", origin, str(count))
    for marker, count in sorted(marker_counts.items(), key=lambda x: -x[1]):
        table.add_row("MARKER", marker, str(count))

    out_console.print(table)


app = typer.Typer(
    help="Lint annotation standards for decomp C source files.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew lint                                  Lint all .c files in reversed_dir

rebrew lint --fix                            Auto-migrate old-format annotations

rebrew lint --quiet                          Errors only, suppress warnings

rebrew lint --json                           Machine-readable JSON output

rebrew lint --summary                        Show status/origin breakdown table

rebrew lint --files src/game/foo.c           Lint specific files only

[bold]Error codes:[/bold]

E001   Missing FUNCTION/LIBRARY/STUB annotation

E002   Invalid VA format or range

E003   Missing STATUS annotation

E013   Duplicate VA across files

E016   Filename doesn't match SYMBOL

W001   Missing SYMBOL (recommended)

W005   STUB without BLOCKER explanation

W016   DATA/GLOBAL missing SECTION annotation

W017   NOTE contains [rebrew] sync metadata

[dim]Checks for reccmp-style annotations in the first 20 lines of each .c file.
Supports old-format, block-comment, and javadoc annotation styles (--fix migrates them).[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(False, help="Auto-migrate old-format headers to new annotations"),
    quiet: bool = typer.Option(False, help="Only show errors, suppress warnings"),
    files: list[Path] = typer.Option(None, help="Check specific files instead of all *.c"),
    target: str | None = TargetOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    summary: bool = typer.Option(False, "--summary", help="Print status/origin breakdown"),
) -> None:
    """Lint annotation standards in decomp C source files."""
    cfg = None
    with contextlib.suppress(FileNotFoundError, KeyError, ValueError):
        cfg = get_config(target=target)

    reversed_dir = cfg.reversed_dir if cfg else None

    from rebrew.cli import iter_sources

    ext = cfg.source_ext if cfg else ".c"
    if files:
        c_files = [f for f in files if f.suffix == ext]
    elif reversed_dir:
        c_files = iter_sources(reversed_dir, cfg)
    else:
        c_files = sorted(Path.cwd().rglob(f"*{ext}"))

    if fix:
        if cfg is None:
            error_exit("--fix requires a valid rebrew-project.toml config")
        fixed = 0
        already_ok = 0
        for cfile in c_files:
            result = lint_file(cfile, cfg=cfg)
            needs_fix = any(code in ("W002", "W012", "W013") for _, code, _ in result.warnings)
            if needs_fix:
                if fix_file(cfg, cfile):
                    fixed += 1
                else:
                    print(f"  Could not fix: {cfile.name}")
            else:
                already_ok += 1
        print(f"Fixed {fixed} files, {already_ok} already compliant")
        return

    # Cross-file duplicate VA tracking
    seen_vas: dict[int, str] = {}

    total = 0
    passed = 0
    error_count = 0
    warning_count = 0
    all_results: list[LintResult] = []

    for cfile in c_files:
        total += 1
        result = lint_file(cfile, cfg=cfg, seen_vas=seen_vas)
        all_results.append(result)
        if result.passed:
            passed += 1
        if not json_output and (not result.passed or (not quiet and result.warnings)):
            result.display(quiet=quiet)
        error_count += len(result.errors)
        warning_count += len(result.warnings)

    if json_output:
        output = {
            "total": total,
            "passed": passed,
            "errors": error_count,
            "warnings": warning_count,
            "files": [r.to_dict() for r in all_results if not r.passed or r.warnings],
        }
        json_print(output)
    else:
        pass_style = "green" if error_count == 0 else "red"
        err_style = "red" if error_count > 0 else ""
        result_text = Text()
        result_text.append(f"\nChecked {total} files: ")
        result_text.append(f"{passed} passed", style=pass_style)
        result_text.append(", ")
        result_text.append(f"{error_count} errors", style=err_style)
        result_text.append(f", {warning_count} warnings")
        out_console.print(result_text)

        if summary:
            _print_summary(all_results)

    if error_count > 0:
        raise typer.Exit(code=1)


def main_entry() -> None:
    """Package entry point for ``rebrew-lint``."""
    app()


if __name__ == "__main__":
    main_entry()
