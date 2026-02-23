#!/usr/bin/env python3
"""lint.py - Annotation linter for rebrew decomp C files.

Check that all .c files in the reversed directory have proper reccmp-style annotations.
Supports --fix mode to auto-migrate from old format to new format.

Inspired by reccmp's decomplint tool.
"""

import json as _json
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
    JAVADOC_ADDR_RE,
    JAVADOC_KV_RE,
    NEW_FUNC_RE,
    NEW_KV_RE,
    OLD_RE,
    VALID_MARKERS,
    VALID_ORIGINS,
    VALID_STATUSES,
    marker_for_origin,
    normalize_status,
    origin_from_filename,
)
from rebrew.cli import TargetOption, get_config

console = Console(stderr=True)
err_console = Console(stderr=True)
out_console = Console()


@dataclass
class LintResult:
    filepath: Path
    errors: list[tuple[int, str, str]] = field(default_factory=list)
    warnings: list[tuple[int, str, str]] = field(default_factory=list)

    def error(self, line: int, code: str, msg: str):
        self.errors.append((line, code, msg))

    def warning(self, line: int, code: str, msg: str):
        self.warnings.append((line, code, msg))

    @property
    def passed(self) -> bool:
        return len(self.errors) == 0

    def display(self, quiet: bool = False):
        rel = self.filepath.name
        for line, code, msg in self.errors:
            out_console.print(f"  [bold]{rel}[/bold]:{line}: [red]{code}[/red]: {msg}")
        if not quiet:
            for line, code, msg in self.warnings:
                out_console.print(f"  [bold]{rel}[/bold]:{line}: [yellow]{code}[/yellow]: {msg}")

    def to_dict(self) -> dict:
        """Serialize for JSON output."""
        return {
            "file": str(self.filepath.name),
            "path": str(self.filepath),
            "errors": [{"line": l, "code": c, "message": m} for l, c, m in self.errors],
            "warnings": [{"line": l, "code": c, "message": m} for l, c, m in self.warnings],
            "passed": self.passed,
        }


def lint_file(
    filepath: Path,
    cfg: Any = None,
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

    has_new = False
    has_old = False
    has_block = False
    has_javadoc = False
    found_keys: dict[str, str] = {}

    for i, line in enumerate(lines[:20], 1):
        stripped = line.strip()
        if not stripped:
            continue

        # --- New format: // FUNCTION: SERVER 0x10008880 ---
        if NEW_FUNC_RE.match(stripped):
            has_new = True
            m = re.match(r"//\s*(\w+):\s*(\S+)\s+(0x[0-9a-fA-F]+)", stripped)
            if m:
                found_keys["MARKER"] = m.group(1)
                found_keys["MODULE"] = m.group(2)
                found_keys["VA"] = m.group(3)
            continue

        m = NEW_KV_RE.match(stripped)
        if m and has_new:
            found_keys[m.group("key").upper()] = m.group("value").strip()
            continue

        # --- Block-comment format: /* FUNCTION: SERVER 0x10003260 */ ---
        if BLOCK_FUNC_RE.match(stripped):
            has_block = True
            bm = BLOCK_FUNC_CAPTURE_RE.match(stripped)
            if bm:
                found_keys["MARKER"] = bm.group("type")
                found_keys["MODULE"] = bm.group("module")
                found_keys["VA"] = bm.group("va")
            continue

        bm = BLOCK_KV_RE.match(stripped)
        if bm and has_block and not has_new:
            found_keys[bm.group("key").upper()] = bm.group("value").strip()
            continue

        # --- Javadoc format: @address 0x... ---
        jm = JAVADOC_ADDR_RE.search(stripped)
        if jm:
            has_javadoc = True
            found_keys["VA"] = jm.group("va")
            continue

        jm = JAVADOC_KV_RE.match(stripped)
        if jm and has_javadoc:
            key = jm.group("key").upper()
            val = jm.group("value").strip()
            if key == "ADDRESS":
                found_keys["VA"] = val
            elif key in ("STATUS", "ORIGIN", "SIZE", "CFLAGS", "SYMBOL",
                         "SOURCE", "BLOCKER", "NOTE", "BRIEF"):
                if key != "BRIEF":
                    found_keys[key] = val
            continue

        if OLD_RE.match(stripped):
            has_old = True
            break

        if (not stripped.startswith("//")
                and not stripped.startswith("/*")
                and not stripped.startswith("*")
                and not stripped.startswith("*/")):
            break

    # --- Detect block-comment format (not yet auto-fixable) ---
    if has_block and not has_new:
        result.warning(
            1, "W012",
            "Block-comment annotation format detected "
            "(/* FUNCTION: ... */ — run with --fix to migrate)"
        )
        # Still validate the extracted keys below
        has_new = True  # treat as new-format for validation purposes

    # --- Detect javadoc format ---
    if has_javadoc and not has_new:
        result.warning(
            1, "W013",
            "Javadoc-style annotation format detected "
            "(@address — run with --fix to migrate)"
        )
        # Derive missing fields for javadoc format
        if "MARKER" not in found_keys:
            origin = found_keys.get("ORIGIN", "GAME")
            status = found_keys.get("STATUS", "RELOC")
            found_keys["MARKER"] = marker_for_origin(origin, status)
        has_new = True  # treat as new-format for validation

    if has_old and not has_new:
        result.warning(
            1, "W002", "Old-format header detected (run with --fix to migrate)"
        )
        return result

    if not has_new and not has_old:
        result.error(1, "E001", "Missing FUNCTION/LIBRARY/STUB annotation")
        return result

    if has_new:
        marker = found_keys.get("MARKER", "")
        if marker not in VALID_MARKERS:
            result.error(1, "E001", f"Invalid marker type: {marker}")

        va_str = found_keys.get("VA", "")
        va_int: int | None = None
        try:
            va_int = int(va_str, 16)
            # Generic sanity check: just ensure it's a reasonable 32-bit VA
            if not (0x1000 <= va_int <= 0xFFFFFFFF):
                result.error(1, "E002", f"VA {va_str} is suspicious (outside 32-bit range)")
        except ValueError:
            result.error(1, "E002", f"Invalid VA format: {va_str}")

        # E013: Duplicate VA across files
        if va_int is not None and seen_vas is not None:
            if va_int in seen_vas:
                result.error(
                    1,
                    "E013",
                    f"Duplicate VA {va_str} — also in {seen_vas[va_int]}",
                )
            else:
                seen_vas[va_int] = filepath.name

        if "STATUS" not in found_keys:
            result.error(1, "E003", "Missing // STATUS: annotation")
        elif found_keys["STATUS"] not in VALID_STATUSES:
            # E014: Check for corrupted values (literal \n in annotations)
            if "\\n" in found_keys["STATUS"]:
                result.error(
                    1, "E014",
                    f"Corrupted STATUS value contains literal '\\n': "
                    f"{found_keys['STATUS']!r}"
                )
            else:
                result.error(1, "E004", f"Invalid STATUS: {found_keys['STATUS']}")

        if "ORIGIN" not in found_keys:
            result.error(1, "E005", "Missing // ORIGIN: annotation")
        elif found_keys["ORIGIN"] not in VALID_ORIGINS:
            result.error(1, "E006", f"Invalid ORIGIN: {found_keys['ORIGIN']}")

        if "SIZE" not in found_keys:
            result.error(1, "E007", "Missing // SIZE: annotation")
        else:
            try:
                sz = int(found_keys["SIZE"])
                if sz <= 0:
                    result.error(1, "E008", f"Invalid SIZE: {found_keys['SIZE']}")
            except ValueError:
                result.error(1, "E008", f"Invalid SIZE: {found_keys['SIZE']}")

        if "CFLAGS" not in found_keys:
            result.error(1, "E009", "Missing // CFLAGS: annotation")

        if "SYMBOL" not in found_keys:
            result.warning(1, "W001", "Missing // SYMBOL: annotation (recommended)")

        origin = found_keys.get("ORIGIN", "GAME")
        status = found_keys.get("STATUS", "")

        expected_marker = marker_for_origin(origin, status)
        if marker != expected_marker and marker in VALID_MARKERS:
            result.warning(
                1,
                "W004",
                f"Marker {marker} inconsistent with ORIGIN {origin} "
                f"(expected {expected_marker})",
            )

        # W005: STUB functions should have // BLOCKER: explaining why
        if status == "STUB" and "BLOCKER" not in found_keys:
            result.warning(
                1,
                "W005",
                "STUB function missing // BLOCKER: annotation "
                "(explain why it doesn't match)",
            )

        # W006: CRT/ZLIB functions should have // SOURCE: pointing to reference
        if origin in ("MSVCRT", "ZLIB") and "SOURCE" not in found_keys:
            result.warning(
                1,
                "W006",
                f"{origin} function missing // SOURCE: annotation "
                "(reference file, e.g. SBHEAP.C:195 or deflate.c)",
            )

        # E010: Unknown annotation keys
        for key in found_keys:
            if key not in ALL_KNOWN_KEYS and key != "MODULE":
                result.error(1, "E010", f"Unknown annotation key: {key}")

        # W010: Contradictory MATCHING status with STUB marker
        if status in ("MATCHING", "MATCHING_RELOC") and marker == "STUB":
            result.warning(
                1,
                "W010",
                f"Contradictory: status is {status} but marker is STUB",
            )

        # ----- Config-aware checks (only when cfg is available) -----
        if cfg is not None:
            # W011: ORIGIN not in configured origins list (advisory — may
            # not be set yet in fresh projects)
            if (
                origin
                and hasattr(cfg, "origins")
                and cfg.origins
                and origin not in cfg.origins
            ):
                result.warning(
                    1,
                    "W011",
                    f"ORIGIN '{origin}' not in configured origins: {cfg.origins}",
                )

            # E012: Module name doesn't match configured marker
            module = found_keys.get("MODULE", "")
            if (
                module
                and hasattr(cfg, "marker")
                and cfg.marker
                and module != cfg.marker
            ):
                result.error(
                    1,
                    "E012",
                    f"Module '{module}' doesn't match configured marker '{cfg.marker}'",
                )

            # W008: CFLAGS don't match preset for this ORIGIN
            if (
                "CFLAGS" in found_keys
                and hasattr(cfg, "cflags_presets")
                and cfg.cflags_presets
                and origin in cfg.cflags_presets
            ):
                expected_cflags = cfg.cflags_presets[origin]
                actual_cflags = found_keys["CFLAGS"]
                if actual_cflags != expected_cflags:
                    result.warning(
                        1,
                        "W008",
                        f"CFLAGS '{actual_cflags}' differ from {origin} preset "
                        f"'{expected_cflags}'",
                    )

        # W009: Filename doesn't match function name
        symbol = found_keys.get("SYMBOL", "")
        if symbol:
            expected_stem = symbol.lstrip("_")
            actual_stem = filepath.stem
            if expected_stem and actual_stem != expected_stem:
                result.warning(
                    1,
                    "W009",
                    f"Filename '{filepath.name}' doesn't match SYMBOL "
                    f"'{symbol}' (expected '{expected_stem}.c')",
                )

        # W014: ORIGIN doesn't match filename prefix convention
        expected_origin = origin_from_filename(filepath.stem)
        if expected_origin and origin and expected_origin != origin:
            result.warning(
                1,
                "W014",
                f"Filename prefix suggests ORIGIN '{expected_origin}' "
                f"but annotation says '{origin}'",
            )

        # W015: VA hex digits should use lowercase for consistency
        va_str = found_keys.get("VA", "")
        if va_str and va_str.startswith("0x"):
            hex_digits = va_str[2:]
            if hex_digits != hex_digits.lower() and hex_digits != hex_digits.upper():
                result.warning(
                    1,
                    "W015",
                    f"VA '{va_str}' has mixed-case hex digits "
                    f"(prefer consistent case)",
                )

    # Check for struct SIZE comments (reccmp recommendation)
    has_code = False
    has_struct = False
    struct_has_size = False
    for line in lines[1:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            has_code = True
        if "typedef struct" in stripped or "struct " in stripped:
            has_struct = True
        if re.match(r"//\s*SIZE\s+0x[0-9a-fA-F]+", stripped):
            struct_has_size = True

    if not has_code and has_new:
        result.warning(1, "W003", "File has no function implementation")

    # W007: Structs without SIZE annotation
    if has_struct and not struct_has_size:
        result.warning(
            1,
            "W007",
            "File defines struct(s) without // SIZE 0xNN annotation "
            "(reccmp recommendation)",
        )

    return result


def fix_file(cfg: Any, filepath: Path) -> bool:
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
        if "/Gd" not in cflags_parts and origin == "GAME":
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
        filepath.write_text(new_text, encoding="utf-8")
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
        filepath.write_text(new_text, encoding="utf-8")
        return True

    # --- Try javadoc format: /** ... @address 0x... */ ---
    if first.startswith("/**") or first.startswith("/*"):
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
            filepath.write_text(new_text, encoding="utf-8")
            return True

    return False


def _print_summary(results: list[LintResult]):
    """Print a breakdown table by status and origin."""
    from collections import Counter

    status_counts: Counter = Counter()
    origin_counts: Counter = Counter()
    marker_counts: Counter = Counter()

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
                m2 = re.match(r"//\s*(\w+):", stripped)
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


app = typer.Typer(help="Lint annotation standards for decomp C source files.")


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(False, help="Auto-migrate old-format headers to new annotations"),
    quiet: bool = typer.Option(False, help="Only show errors, suppress warnings"),
    files: list[Path] = typer.Option(None, help="Check specific files instead of all *.c"),
    target: str | None = TargetOption,
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    summary: bool = typer.Option(False, "--summary", help="Print status/origin breakdown"),
):
    """Lint annotation standards in decomp C source files."""
    cfg = None
    try:
        cfg = get_config(target=target)
    except Exception:
        pass

    reversed_dir = cfg.reversed_dir if cfg else None

    if files:
        c_files = [f for f in files if f.suffix == ".c"]
    elif reversed_dir:
        c_files = sorted(reversed_dir.glob("*.c"))
    else:
        c_files = sorted(Path.cwd().glob("*.c"))

    if fix:
        if cfg is None:
            print("Error: --fix requires a valid rebrew.toml config")
            raise SystemExit(1)
        fixed = 0
        already_ok = 0
        for cfile in c_files:
            result = lint_file(cfile)
            needs_fix = any(
                code in ("W002", "W012", "W013")
                for _, code, _ in result.warnings
            )
            if needs_fix:
                if fix_file(cfg, cfile):
                    fixed += 1
                else:
                    print(f"  Could not fix: {cfile.name}")
            else:
                already_ok += 1
        print(f"Fixed {fixed} files, {already_ok} already compliant")
        raise SystemExit(0)

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
        if result.passed and (quiet or not result.warnings):
            passed += 1
        elif not json_output:
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
        print(_json.dumps(output, indent=2))
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

    raise SystemExit(1 if error_count > 0 else 0)


def main_entry():
    app()

if __name__ == "__main__":
    main_entry()
