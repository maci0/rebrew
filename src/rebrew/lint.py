"""lint.py - Annotation linter for rebrew decomp C files.

Check that all .c files in the reversed directory have proper reccmp-style annotations.
Supports --fix mode to auto-migrate from old format to new format.

Inspired by reccmp's decomplint tool.
"""

import contextlib
import re
from collections import Counter
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
    JAVADOC_ADDR_RE,
    JAVADOC_KV_RE,
    METADATA_KEYS,
    NEW_FUNC_CAPTURE_RE,
    NEW_FUNC_RE,
    NEW_KV_RE,
    OLD_RE,
    VALID_MARKERS,
    VALID_STATUSES,
    marker_for_module,
    normalize_status,
)
from rebrew.cli import TargetOption, error_exit, get_config, json_print
from rebrew.config import ProjectConfig
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

_HEADER_MARKER_RE = re.compile(r"//\s*(\w+):\s*(\S+)\s+(0x[0-9a-fA-F]+)")
_SIZE_ANNOTATION_RE = re.compile(r"//\s*SIZE\s+0x[0-9a-fA-F]+")
_MARKER_TYPE_RE = re.compile(r"//\s*(\w+):")


@dataclass
class LintResult:
    """Accumulated lint errors and warnings for a single source file.

    Why a custom linter? Standard C linters don't understand our `// STATUS:` and
    other rebrew annotations. We need strict validation of these metadata fields
    to ensure the CI pipeline and other tools (like `rebrew test`) can parse them.
    """

    filepath: Path
    errors: list[tuple[int, str, str]] = field(default_factory=list)
    warnings: list[tuple[int, str, str]] = field(default_factory=list)
    context_prefix: str = ""
    marker_line: int = 1
    # Counters collected during lint for --summary (avoids re-reading files).
    _status_counts: Counter[str] = field(default_factory=Counter)
    _marker_counts: Counter[str] = field(default_factory=Counter)

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
            console.print(f"  [bold]{rel}[/bold]:{line}: [red]{code}[/red]: {msg}")
        if not quiet:
            for line, code, msg in self.warnings:
                console.print(f"  [bold]{rel}[/bold]:{line}: [yellow]{code}[/yellow]: {msg}")

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

    current_keys: dict[str, str] = {}
    current_flags = {"has_new": False, "has_old": False, "has_block": False, "has_javadoc": False}
    in_block = False

    # Check for legacy formats in the first 20 lines (for compatibility with single-block legacy fixes)
    legacy_flags = {"has_new": False, "has_old": False, "has_block": False, "has_javadoc": False}
    legacy_keys: dict[str, str] = {}

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
        if JAVADOC_ADDR_RE.search(stripped) or JAVADOC_KV_RE.search(stripped):
            legacy_flags["has_javadoc"] = True

    # If it is legacy format, just return the first block we found so `fix` can handle it
    if not legacy_flags["has_new"] and (
        legacy_flags["has_old"] or legacy_flags["has_block"] or legacy_flags["has_javadoc"]
    ):
        return [(legacy_keys, legacy_flags)]

    pending_kv: dict[str, str] = {}
    seen_code_after_marker: bool = False

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        if NEW_FUNC_RE.match(stripped):
            if in_block:
                results.append((current_keys, current_flags))

            current_keys = dict(pending_kv)
            pending_kv = {}
            current_flags = {
                "has_new": True,
                "has_old": False,
                "has_block": False,
                "has_javadoc": False,
            }
            in_block = True
            seen_code_after_marker = False
            current_keys["_LINE"] = str(line_idx + 1)

            m = _HEADER_MARKER_RE.match(stripped)
            if m:
                current_keys["MARKER"] = m.group(1)
                current_keys["MODULE"] = m.group(2)
                current_keys["VA"] = m.group(3)
            continue

        m = NEW_KV_RE.match(stripped)
        if m:
            if in_block and not seen_code_after_marker:
                current_keys[m.group("key").upper()] = m.group("value").strip()
            else:
                pending_kv[m.group("key").upper()] = m.group("value").strip()
            continue

        if in_block:
            seen_code_after_marker = True

    if in_block:
        results.append((current_keys, current_flags))

    return results


# _parse_header was removed — _parse_multi_headers handles all cases,
# including legacy formats and broken files, in a single code path.


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
            result.marker_line,
            "W013",
            "Javadoc-style annotation format detected (@address — run with --fix to migrate)",
        )
        if "MARKER" not in found_keys:
            module = found_keys.get("MODULE", "")
            status = found_keys.get("STATUS", "RELOC")
            found_keys["MARKER"] = marker_for_module(module, status)
        flags["has_new"] = True

    if has_old and not flags["has_new"]:
        result.warning(
            result.marker_line, "W002", "Old-format header detected (run with --fix to migrate)"
        )
        return False

    if not flags["has_new"] and not has_old:
        result.error(result.marker_line, "E001", "Missing FUNCTION/LIBRARY/STUB annotation")
        return False

    return True


def _check_E001_marker(result: LintResult, marker: str) -> None:
    if marker not in VALID_MARKERS:
        result.error(result.marker_line, "E001", f"Invalid marker type: {marker}")


def _check_E002_va(result: LintResult, va_str: str) -> int | None:
    try:
        va_int = int(va_str, 16)
        if not (0x1000 <= va_int <= 0xFFFFFFFF):
            result.error(
                result.marker_line, "E002", f"VA {va_str} is suspicious (outside 32-bit range)"
            )
        return va_int
    except ValueError:
        result.error(result.marker_line, "E002", f"Invalid VA format: {va_str}")
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
            result.error(
                result.marker_line, "E013", f"Duplicate VA {va_str} — also in {seen_vas[va_int]}"
            )
        else:
            from rebrew.cli import rel_display_path

            seen_vas[va_int] = rel_display_path(filepath)


def _check_E003_E004_status(result: LintResult, found_keys: dict[str, str]) -> None:
    # STATUS is a special key: it is in REQUIRED_KEYS (not METADATA_KEYS), yet
    # it can be supplied from either the inline annotation OR the rebrew-function.toml
    # metadata.  The metadata overlay in lint_file() injects STATUS into found_keys
    # before this check runs, so E003 only fires when STATUS is absent from both.
    if "STATUS" not in found_keys:
        result.error(result.marker_line, "E003", "Missing // STATUS: annotation")
    elif found_keys["STATUS"] not in VALID_STATUSES:
        if "\\n" in found_keys["STATUS"]:
            result.error(
                result.marker_line,
                "E014",
                f"Corrupted STATUS value contains literal '\\n': {found_keys['STATUS']!r}",
            )
        else:
            result.error(result.marker_line, "E004", f"Invalid STATUS: {found_keys['STATUS']}")


def _check_W018_cflags(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    has_annotation = "CFLAGS" in found_keys and found_keys["CFLAGS"].strip()
    if has_annotation:
        return
    # Only warn if the target config also has no default cflags
    has_config_default = bool(getattr(cfg, "base_cflags", "") if cfg else "")
    if not has_config_default:
        result.warning(
            result.marker_line, "W018", "Missing // CFLAGS: and no default cflags in project config"
        )


def _check_W010_unknown_keys(result: LintResult, found_keys: dict[str, str]) -> None:
    for key in found_keys:
        if key not in ALL_KNOWN_KEYS and key not in ("MODULE", "_LINE"):
            result.warning(result.marker_line, "W010", f"Unknown annotation key: {key}")


def _check_E015_marker_consistency(
    result: LintResult, marker: str, module: str, status: str, cfg: ProjectConfig | None = None
) -> None:
    lib_modules = cfg.library_modules if cfg and cfg.library_modules is not None else set()
    expected_marker = marker_for_module(module, status, lib_modules)
    if marker != expected_marker and marker in VALID_MARKERS and marker not in ("GLOBAL", "DATA"):
        result.error(
            result.marker_line,
            "E015",
            f"Marker {marker} inconsistent with module {module!r} (expected {expected_marker})",
        )


def _check_E017_contradictory(result: LintResult, status: str, marker: str) -> None:
    if status == "MATCHING" and marker == "STUB":
        result.error(
            result.marker_line, "E017", f"Contradictory: status is {status} but marker is STUB"
        )


def _check_W005_blocker(result: LintResult, status: str, found_keys: dict[str, str]) -> None:
    # BLOCKER lives in rebrew-function.toml metadata; the metadata overlay already injects it
    # into found_keys before this check runs, so this fires only when absent from both.
    if status == "STUB" and "BLOCKER" not in found_keys:
        result.warning(
            result.marker_line,
            "W005",
            "STUB function missing 'blocker' explanation (set via rebrew match --fix-blocker or add to rebrew-function.toml)",
        )


def _check_W006_source(
    result: LintResult, module: str, found_keys: dict[str, str], cfg: ProjectConfig | None = None
) -> None:
    lib_modules = cfg.library_modules if cfg and cfg.library_modules is not None else set()
    if module in lib_modules and "SOURCE" not in found_keys:
        result.warning(
            result.marker_line,
            "W006",
            f"Library module {module!r} missing // SOURCE: annotation "
            "(reference file, e.g. SBHEAP.C:195 or deflate.c)",
        )


def _check_W015_va_case(result: LintResult, va_str: str) -> None:
    if va_str and va_str.startswith("0x"):
        hex_digits = va_str[2:]
        if hex_digits != hex_digits.lower() and hex_digits != hex_digits.upper():
            result.warning(
                result.marker_line,
                "W015",
                f"VA '{va_str}' has mixed-case hex digits (prefer consistent case)",
            )


def _check_config_rules(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    """Config-aware checks (E012)."""
    if cfg is None:
        return

    module = found_keys.get("MODULE", "")
    marker = getattr(cfg, "marker", None)
    if module and marker and module != marker:
        result.error(
            result.marker_line,
            "E012",
            f"Module '{module}' doesn't match configured marker '{marker}'",
        )


def _check_W016_section(result: LintResult, marker: str, found_keys: dict[str, str]) -> None:
    if marker in ("DATA", "GLOBAL") and "SECTION" not in found_keys:
        result.warning(
            result.marker_line,
            "W016",
            f"{marker} annotation missing // SECTION: (.data, .rdata, .bss)",
        )


def _check_W017_note_rebrew(result: LintResult, found_keys: dict[str, str]) -> None:
    note = found_keys.get("NOTE", "")
    if note.startswith("[rebrew]"):
        result.warning(
            result.marker_line,
            "W017",
            "NOTE starts with '[rebrew]' — this looks like auto-generated sync metadata, "
            "not a human note (likely from a bad pull)",
        )


# Keys owned by data_metadata (rebrew-data.toml) rather than the function metadata.
# Maps uppercase annotation key -> lowercase TOML field name.
_DATA_METADATA_KEY_MAP: dict[str, str] = {"SIZE": "size", "SECTION": "section", "NOTE": "note"}


def _check_W019_inline_metadata_keys(
    result: LintResult,
    found_keys: dict[str, str],
    metadata_sourced_keys: set[str],
    marker: str = "",
) -> None:
    """Warn when a rebrew-specific annotation key appears inline in source.

    These keys must live exclusively in the appropriate metadata TOML file.
    DATA/GLOBAL annotations write SIZE/SECTION/NOTE to ``rebrew-data.toml``;
    function annotations write everything else to ``rebrew-function.toml``.
    """
    is_data = marker in ("DATA", "GLOBAL")
    for key in METADATA_KEYS:
        if key in found_keys and key not in metadata_sourced_keys:
            # Choose the right metadata filename for this key.
            if is_data and key in _DATA_METADATA_KEY_MAP:
                toml_file = "rebrew-data.toml"
            elif key in _DATA_METADATA_KEY_MAP and not is_data:
                # SECTION/NOTE/SIZE on a function marker → still goes to functions metadata
                toml_file = "rebrew-function.toml"
            else:
                toml_file = "rebrew-function.toml"
            result.warning(
                result.marker_line,
                "W019",
                f"Inline // {key}: annotation must move to {toml_file}",
            )


def _check_body_rules(result: LintResult, lines: list[str], has_new: bool) -> None:
    """Check struct SIZE comments and code presence (W003, W007)."""
    has_code = False
    has_struct = False
    first_struct_line = 1
    struct_has_size = False
    for i, line in enumerate(lines[1:], start=2):
        stripped = line.strip()
        if (
            stripped
            and not stripped.startswith("//")
            and not stripped.startswith("/*")
            and not stripped.startswith("*")
        ):
            has_code = True
        if "typedef struct" in stripped or "struct " in stripped:
            if not has_struct:
                first_struct_line = i
            has_struct = True
        if _SIZE_ANNOTATION_RE.match(stripped):
            struct_has_size = True

    if not has_code and has_new:
        result.warning(1, "W003", "File has no function implementation")

    if has_struct and not struct_has_size:
        result.warning(
            first_struct_line,
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
        # Totally broken file — no recognisable annotation format found.
        # Synthesise a minimal entry so the loop below can report E001.
        all_headers = [
            ({}, {"has_new": False, "has_old": False, "has_block": False, "has_javadoc": False})
        ]

    # Load the per-directory metadata once so all annotation blocks in this file can use it.
    # Keys in the result: (module, va_int) -> {toml_field: value}
    from rebrew.metadata import load_metadata as _load_metadata

    _metadata_entries = _load_metadata(cfg.metadata_dir if cfg else filepath.parent)

    # Also load the data metadata for DATA/GLOBAL annotations.
    from rebrew.data_metadata import load_data_metadata as _load_data_metadata

    _data_metadata_entries = _load_data_metadata(cfg.metadata_dir if cfg else filepath.parent)

    # TOML field name -> uppercase found_keys name mapping
    _METADATA_TO_FOUND: dict[str, str] = {
        "status": "STATUS",
        "size": "SIZE",
        "cflags": "CFLAGS",
        "blocker": "BLOCKER",
        "blocker_delta": "BLOCKER_DELTA",
        "ghidra": "GHIDRA",
        "analysis": "ANALYSIS",
        "note": "NOTE",
        "skip": "SKIP",
        "globals": "GLOBALS",
        "section": "SECTION",
        "source": "SOURCE",
    }

    for i, (found_keys, flags) in enumerate(all_headers):
        result.marker_line = int(found_keys.get("_LINE", "1"))

        mod = found_keys.get("MODULE", "")
        va_str = found_keys.get("VA", "")

        # Overlay metadata fields into found_keys for this annotation block.
        # Metadata always wins for the fields it owns (STATUS, SIZE, CFLAGS, etc.),
        # but we only overlay if the key is not already present inline — this lets
        # any remaining inline annotation (from files not yet fully migrated) take
        # precedence so the check accurately reflects what the compiler will see.
        # We also track which keys were supplied by the metadata (vs inline) so
        # that W019 can distinguish between a key that must be migrated and one
        # that is correctly metadata-only.
        _metadata_sourced_keys: set[str] = set()
        if mod and va_str:
            try:
                _va_int = int(va_str, 16)
                _metadata_override = _metadata_entries.get((mod, _va_int), {})
                for _toml_key, _found_key in _METADATA_TO_FOUND.items():
                    if _toml_key in _metadata_override:
                        if _found_key not in found_keys:
                            found_keys[_found_key] = str(_metadata_override[_toml_key])
                        _metadata_sourced_keys.add(_found_key)
            except (ValueError, KeyError):
                pass

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
                _check_W018_cflags(result, found_keys, cfg)
                # SIZE check removed: // SIZE: is now metadata-only, not required in source.
            else:
                # For DATA/GLOBAL: overlay data metadata fields (size, section, note)
                if va_int is not None and mod:
                    _ds_override = _data_metadata_entries.get((mod, va_int), {})
                    _DS_TO_FOUND = {"size": "SIZE", "section": "SECTION", "note": "NOTE"}
                    for _ds_key, _ds_found_key in _DS_TO_FOUND.items():
                        if _ds_key in _ds_override:
                            if _ds_found_key not in found_keys:
                                found_keys[_ds_found_key] = str(_ds_override[_ds_key])
                            # Mark as metadata-sourced so W019 doesn't fire for these
                            _metadata_sourced_keys.add(_ds_found_key)

            module = found_keys.get("MODULE", "")
            status = found_keys.get("STATUS", "")

            # Collect summary data during the lint pass (used by _print_summary).
            if marker:
                result._marker_counts[marker] += 1
            if status:
                result._status_counts[status] += 1

            _check_E015_marker_consistency(result, marker, module, status, cfg)
            _check_W005_blocker(result, status, found_keys)
            _check_W006_source(result, module, found_keys, cfg)
            _check_W010_unknown_keys(result, found_keys)
            _check_E017_contradictory(result, status, marker)
            _check_config_rules(result, found_keys, cfg)

            _check_W015_va_case(result, va_str)
            _check_W016_section(result, marker, found_keys)
            _check_W017_note_rebrew(result, found_keys)
            _check_W019_inline_metadata_keys(result, found_keys, _metadata_sourced_keys, marker)

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
        va_str = m.group("va").lower()
        if not va_str.startswith("0x"):
            va_str = "0x" + va_str
        raw_cflags = m.group("cflags").strip()
        status = normalize_status(m.group("status"))
        marker = "STUB" if status == "STUB" else "FUNCTION"
        cflags_parts = raw_cflags.split()
        if "/Gd" not in cflags_parts:
            cflags_parts.append("/Gd")
        cflags = " ".join(cflags_parts)
        # Write only the marker + STATUS inline; route CFLAGS and other volatile
        # fields to the metadata so the .c file stays clean.
        annotation = f"// {marker}: {cfg.marker} {va_str}\n// STATUS: {status}\n"
        if cflags:
            # Write CFLAGS to metadata
            try:
                from rebrew.metadata import update_field as _update_field

                va_int = int(va_str, 16)
                _update_field(cfg.metadata_dir, va_int, "cflags", cflags, module=cfg.marker)
            except (OSError, ValueError, KeyError):
                # Metadata write failure is non-fatal; fall back to inline for now
                annotation += f"// CFLAGS: {cflags}\n"

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
        # Build a clean annotation: only marker + STATUS inline.
        # Route CFLAGS and other metadata fields to rebrew-function.toml.
        annotation = f"// {marker}: {module} {va_str}\n// STATUS: {status}\n"
        try:
            from rebrew.metadata import update_field as _update_field

            va_int = int(va_str, 16)
            for _extra_key in ("CFLAGS", "BLOCKER", "SOURCE", "NOTE", "SKIP"):
                if _extra_key in found_keys and found_keys[_extra_key]:
                    _update_field(
                        cfg.metadata_dir,
                        va_int,
                        _extra_key.lower(),
                        found_keys[_extra_key],
                        module=module,
                    )
        except (OSError, ValueError, KeyError):
            # Metadata write failure: fall back to inline for metadata keys
            for extra_key in ("CFLAGS", "BLOCKER", "SOURCE", "NOTE", "SKIP"):
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
            status = found_keys_jd.get("STATUS", "RELOC").upper()
            module = found_keys_jd.get("MODULE", cfg.marker)
            marker = marker_for_module(module, status)
            cflags = found_keys_jd.get("CFLAGS", "")
            annotation = f"// {marker}: {cfg.marker} {va_str}\n// STATUS: {status}\n"
            if cflags:
                annotation += f"// CFLAGS: {cflags}\n"

            new_text = annotation + "".join(lines[header_end:])
            atomic_write_text(filepath, new_text, encoding="utf-8")
            return True

    # --- W019: new-format files with inline metadata keys ---
    # Segment the file into annotation blocks, then for each block strip any
    # metadata-owned inline keys and route them to the correct TOML.
    # This handles multi-annotation files (e.g. globals.c) correctly because
    # each block's VA and marker type are resolved independently.
    from rebrew.annotation import METADATA_KEYS as _METADATA_KEYS

    _drop_lines: set[int] = set()
    _any_migrated = False

    # Split file into annotation blocks. Each block starts at a NEW_FUNC_RE
    # marker line and its KV lines follow (up to the next marker or blank/code line
    # that ends the annotation header).
    _block_start_indices: list[int] = []
    for _li, _line in enumerate(lines):
        if NEW_FUNC_RE.match(_line.strip()):
            _block_start_indices.append(_li)

    if not _block_start_indices:
        return False  # No new-format markers found; not a new-format file

    # Build per-block ranges: block i spans [_block_start_indices[i], _block_start_indices[i+1])
    _block_ranges = []
    for _bi, _start in enumerate(_block_start_indices):
        _end = _block_start_indices[_bi + 1] if _bi + 1 < len(_block_start_indices) else len(lines)
        _block_ranges.append((_start, _end))

    for _bstart, _bend in _block_ranges:
        # Parse marker line to get type, module, VA using the canonical regex.
        _marker_line = lines[_bstart].strip()
        _marker_m = NEW_FUNC_CAPTURE_RE.match(_marker_line)
        if not _marker_m:
            continue
        _marker_type = _marker_m.group("type").upper()
        _module = _marker_m.group("module")
        _va_hex = _marker_m.group("va").lower()
        if not _module or not _va_hex:
            continue

        _va_int: int | None = None
        with contextlib.suppress(ValueError):
            _va_int = int(_va_hex, 16)
        if _va_int is None:
            continue

        _is_data = _marker_type in ("GLOBAL", "DATA")

        # Collect inline metadata keys within this block's KV lines only.
        # KV lines are consecutive `// KEY: value` lines immediately after the marker.
        _block_metadata: dict[str, str] = {}
        for _li in range(_bstart + 1, _bend):
            _stripped = lines[_li].strip()
            if not _stripped or not _stripped.startswith("//"):
                break  # Blank or code — end of annotation header
            _km = NEW_KV_RE.match(_stripped)
            if not _km:
                break
            _k = _km.group("key").upper()
            if _k in _METADATA_KEYS:
                _block_metadata[_k] = _km.group("value").strip()
                _drop_lines.add(_li)

        if not _block_metadata:
            continue

        # Write metadata keys to the appropriate TOML.
        try:
            if _is_data:
                from rebrew.data_metadata import set_data_field as _set_data_field

                for _k, _toml_k in _DATA_METADATA_KEY_MAP.items():
                    if _k in _block_metadata:
                        _set_data_field(
                            cfg.metadata_dir if cfg else filepath.parent,
                            _va_int,
                            _toml_k,
                            _block_metadata[_k],
                            module=_module,
                        )
                _remaining = {
                    k: v for k, v in _block_metadata.items() if k not in _DATA_METADATA_KEY_MAP
                }
                if _remaining:
                    from rebrew.metadata import update_field as _update_field2

                    for _k, _v in _remaining.items():
                        if _k == "STATUS":
                            from rebrew.metadata import update_source_status as _update_status2

                            _update_status2(filepath, _v, _module, _va_int)
                        else:
                            _update_field2(
                                cfg.metadata_dir if cfg else filepath.parent,
                                _va_int,
                                _k.lower(),
                                _v,
                                module=_module,
                            )
            else:
                from rebrew.metadata import update_field as _update_field

                for _k, _v in _block_metadata.items():
                    if _k == "STATUS":
                        from rebrew.metadata import update_source_status as _update_status

                        _update_status(filepath, _v, _module, _va_int)
                    else:
                        _update_field(
                            cfg.metadata_dir if cfg else filepath.parent,
                            _va_int,
                            _k.lower(),
                            _v,
                            module=_module,
                        )
            _any_migrated = True
        except (OSError, ValueError, KeyError):
            # Metadata write failure for this block — skip stripping its lines
            _drop_lines -= {
                _li
                for _li in range(_bstart + 1, _bend)
                if (
                    (_km2 := NEW_KV_RE.match(lines[_li].strip()))
                    and _km2.group("key").upper() in _block_metadata
                )
            }

    if not _any_migrated:
        return False

    # Write the stripped source file (remove inline metadata key lines).
    new_text = "".join(line for li, line in enumerate(lines) if li not in _drop_lines)
    atomic_write_text(filepath, new_text, encoding="utf-8")
    return True


def _print_summary(results: list[LintResult]) -> None:
    """Print a breakdown table by status and marker type.

    Uses counters collected during the lint pass (LintResult._status_counts
    and _marker_counts) instead of re-reading every file.
    """
    status_counts: Counter[str] = Counter()
    marker_counts: Counter[str] = Counter()
    for r in results:
        status_counts += r._status_counts
        marker_counts += r._marker_counts

    console.print()
    table = Table(title="Summary", show_lines=False, pad_edge=False)
    table.add_column("Category", style="bold")
    table.add_column("Value")
    table.add_column("Count", justify="right")

    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        table.add_row("STATUS", status, str(count))
    for marker, count in sorted(marker_counts.items(), key=lambda x: -x[1]):
        table.add_row("MARKER", marker, str(count))

    console.print(table)


app = typer.Typer(
    help="Lint annotation standards for decomp C source files.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew lint                                  Lint all .c files in reversed_dir

rebrew lint --fix                            Auto-migrate old-format annotations

rebrew lint --fix --dry-run                  Preview which files would be changed

rebrew lint --quiet                          Errors only, suppress warnings

rebrew lint --json                           Machine-readable JSON output

rebrew lint --summary                        Show status/origin breakdown table

rebrew lint --files src/game/foo.c           Lint specific files only

[bold]Error codes:[/bold]

E001   Missing FUNCTION/LIBRARY/STUB annotation

E002   Invalid VA format or range

E003   Missing STATUS annotation

E013   Duplicate VA across files


W005   STUB without BLOCKER explanation

W016   DATA/GLOBAL missing SECTION annotation

W017   NOTE contains [rebrew] sync metadata

W019   Inline annotation that must live in rebrew-function.toml metadata

W010   Unknown annotation key

W018   Missing CFLAGS with no config fallback

[dim]Checks for reccmp-style annotations in the first 20 lines of each .c file.
Supports old-format, block-comment, and javadoc annotation styles (--fix migrates them).[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(False, help="Auto-migrate old-format headers to new annotations"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    quiet: bool = typer.Option(False, help="Only show errors, suppress warnings"),
    files: list[Path] = typer.Option(None, help="Check specific files instead of all *.c"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    summary: bool = typer.Option(False, "--summary", help="Print status/origin breakdown"),
) -> None:
    """Lint annotation standards in decomp C source files."""
    cfg = None
    try:
        cfg = get_config(target=target)
    except FileNotFoundError:
        pass  # No config file — lint without config-aware rules
    except (KeyError, ValueError) as exc:
        console.print(f"[yellow]Warning: config error ({exc}); config-aware rules disabled[/]")

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
        would_fix: list[str] = []
        for cfile in c_files:
            result = lint_file(cfile, cfg=cfg)
            needs_fix = any(
                code in ("W002", "W012", "W013", "W019") for _, code, _ in result.warnings
            )
            if needs_fix:
                if dry_run:
                    would_fix.append(cfile.name)
                elif fix_file(cfg, cfile):
                    fixed += 1
                else:
                    print(f"  Could not fix: {cfile.name}")
            else:
                already_ok += 1
        if dry_run:
            if would_fix:
                console.print(f"[dim]Would fix {len(would_fix)} files:[/]")
                for name in would_fix:
                    console.print(f"  {name}")
            else:
                console.print("[green]All files already compliant (nothing to fix)[/]")
        else:
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
        console.print(result_text)

        if summary:
            _print_summary(all_results)

    if error_count > 0:
        raise typer.Exit(code=1)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
