#!/usr/bin/env python3
"""lint_annotations.py - Annotation linter for rebrew decomp C files.

Checks that all server_dll/*.c files have proper reccmp-style annotations.
Supports --fix mode to auto-migrate from old format to new format.

Inspired by reccmp's decomplint tool.
"""

import typer
import os
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple

VALID_MARKERS = {"FUNCTION", "LIBRARY", "STUB"}
VALID_STATUSES = {"EXACT", "RELOC", "MATCHING", "MATCHING_RELOC", "STUB"}
VALID_ORIGINS = {"GAME", "MSVCRT", "ZLIB"}

REQUIRED_KEYS = {"STATUS", "ORIGIN", "SIZE", "CFLAGS"}
RECOMMENDED_KEYS = {"SYMBOL"}
OPTIONAL_KEYS = {"SOURCE", "BLOCKER", "NOTE", "GLOBALS"}
ALL_KNOWN_KEYS = REQUIRED_KEYS | RECOMMENDED_KEYS | OPTIONAL_KEYS | {"MARKER", "VA"}

_OLD_RE = re.compile(
    r"/\*\s*"
    r"(?P<name>\S+)"
    r"\s+@\s+"
    r"(?P<va>0x[0-9a-fA-F]+)"
    r"\s+\((?P<size>\d+)B\)"
    r"\s*-\s*"
    r"(?P<cflags>[^-]+?)"
    r"\s*-\s*"
    r"(?P<status>[^[]+?)"
    r"\s*\[(?P<origin>[A-Z]+)\]"
    r"\s*\*/"
)

_NEW_FUNC_RE = re.compile(r"//\s*(?:FUNCTION|LIBRARY|STUB):\s*SERVER\s+0x[0-9a-fA-F]+")
_NEW_KV_RE = re.compile(r"//\s*([A-Z]+):\s*(.*)")

USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _red(s):
    return f"\033[31m{s}\033[0m" if USE_COLOR else s


def _yellow(s):
    return f"\033[33m{s}\033[0m" if USE_COLOR else s


def _green(s):
    return f"\033[32m{s}\033[0m" if USE_COLOR else s


def _bold(s):
    return f"\033[1m{s}\033[0m" if USE_COLOR else s


class LintResult:
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.errors: List[Tuple[int, str, str]] = []
        self.warnings: List[Tuple[int, str, str]] = []

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
            print(f"  {_bold(rel)}:{line}: {_red(code)}: {msg}")
        if not quiet:
            for line, code, msg in self.warnings:
                print(f"  {_bold(rel)}:{line}: {_yellow(code)}: {msg}")


def _normalize_status(raw: str) -> str:
    s = raw.strip().upper()
    if "EXACT" in s:
        return "EXACT"
    if "RELOC" in s:
        return "RELOC"
    if "STUB" in s:
        return "STUB"
    return s


def _marker_for_origin(origin: str, status: str) -> str:
    if status == "STUB":
        return "STUB"
    if origin in ("ZLIB", "MSVCRT"):
        return "LIBRARY"
    return "FUNCTION"


def lint_file(filepath: Path) -> LintResult:
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
    found_keys = {}

    for i, line in enumerate(lines[:20], 1):
        stripped = line.strip()
        if not stripped:
            continue

        if _NEW_FUNC_RE.match(stripped):
            has_new = True
            m = re.match(r"//\s*(\w+):\s*SERVER\s+(0x[0-9a-fA-F]+)", stripped)
            if m:
                found_keys["MARKER"] = m.group(1)
                found_keys["VA"] = m.group(2)
            continue

        m = _NEW_KV_RE.match(stripped)
        if m and has_new:
            found_keys[m.group(1).upper()] = m.group(2).strip()
            continue

        if _OLD_RE.match(stripped):
            has_old = True
            break

        if not stripped.startswith("//"):
            break

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
        try:
            va = int(va_str, 16)
            if not (0x10001000 <= va <= 0x1002FFFF):
                result.error(1, "E002", f"VA {va_str} outside server.dll .text range")
        except ValueError:
            result.error(1, "E002", f"Invalid VA format: {va_str}")

        if "STATUS" not in found_keys:
            result.error(1, "E003", "Missing // STATUS: annotation")
        elif found_keys["STATUS"] not in VALID_STATUSES:
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
        expected_marker = _marker_for_origin(origin, status)
        if marker != expected_marker and marker in VALID_MARKERS:
            result.warning(
                1,
                "W004",
                f"Marker {marker} inconsistent with ORIGIN {origin} "
                f"(expected {expected_marker})",
            )

        # E010: STUB functions should have // BLOCKER: explaining why
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
            if key not in ALL_KNOWN_KEYS:
                result.error(1, "E010", f"Unknown annotation key: {key}")

    # Check for struct SIZE comments (reccmp recommendation)
    has_code = False
    has_struct = False
    struct_has_size = False
    has_offset_comments = False
    for line in lines[1:]:
        stripped = line.strip()
        if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
            has_code = True
        if "typedef struct" in stripped or "struct " in stripped:
            has_struct = True
        if re.match(r"//\s*SIZE\s+0x[0-9a-fA-F]+", stripped):
            struct_has_size = True
        if re.search(r"//\s*0x[0-9a-fA-F]+\s*$", stripped):
            has_offset_comments = True

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


def fix_file(filepath: Path) -> bool:
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    lines = text.splitlines(keepends=True)
    if not lines:
        return False

    first = lines[0].strip()
    m = _OLD_RE.match(first)
    if not m:
        return False

    name = m.group("name")
    va_str = m.group("va").upper()
    if not va_str.startswith("0X"):
        va_str = "0x" + va_str
    else:
        va_str = "0x" + va_str[2:].upper()

    va_str_lower = "0x" + va_str[2:]
    size = m.group("size")
    raw_cflags = m.group("cflags").strip()
    status = _normalize_status(m.group("status"))
    origin = m.group("origin").strip().upper()

    marker = _marker_for_origin(origin, status)

    cflags_parts = raw_cflags.split()
    if "/Gd" not in cflags_parts and origin == "GAME":
        cflags_parts.append("/Gd")
    cflags = " ".join(cflags_parts)

    symbol = "_" + name

    annotation = (
        f"// {marker}: SERVER {va_str_lower}\n"
        f"// STATUS: {status}\n"
        f"// ORIGIN: {origin}\n"
        f"// SIZE: {size}\n"
        f"// CFLAGS: {cflags}\n"
        f"// SYMBOL: {symbol}\n"
    )

    rest = lines[1:]

    new_text = annotation + "".join(rest)
    filepath.write_text(new_text, encoding="utf-8")
    return True


app = typer.Typer(help="Lint annotation standards for decomp C source files.")


@app.command()
def main(
    fix: bool = typer.Option(False, help="Auto-migrate old-format headers to new annotations"),
    quiet: bool = typer.Option(False, help="Only show errors, suppress warnings"),
    files: list[Path] = typer.Option(None, help="Check specific files instead of all *.c"),
    root: Path = typer.Option(
        Path(__file__).resolve().parent.parent,
        help="Project root directory",
    ),
    target: str = typer.Option(
        None, "--target", "-t",
        help="Target name from rebrew.toml (default: first target)",
    ),
):
    """Lint annotation standards in decomp C source files."""
    try:
        from rebrew.config import load_config
        _c = load_config(root, target=target)
        reversed_dir = _c.reversed_dir
    except Exception:
        reversed_dir = root / "src" / "server_dll"

    if files:
        c_files = [f for f in files if f.suffix == ".c"]
    else:
        c_files = sorted(reversed_dir.glob("*.c"))

    if fix:
        fixed = 0
        already_ok = 0
        for cfile in c_files:
            result = lint_file(cfile)
            has_old_warning = any(code == "W002" for _, code, _ in result.warnings)
            if has_old_warning:
                if fix_file(cfile):
                    fixed += 1
                else:
                    print(f"  Could not fix: {cfile.name}")
            else:
                already_ok += 1
        print(f"Fixed {fixed} files, {already_ok} already compliant")
        raise SystemExit(0)

    total = 0
    passed = 0
    error_count = 0
    warning_count = 0

    for cfile in c_files:
        total += 1
        result = lint_file(cfile)
        if result.passed and (quiet or not result.warnings):
            passed += 1
        else:
            result.display(quiet=quiet)
        error_count += len(result.errors)
        warning_count += len(result.warnings)

    color_fn = _green if error_count == 0 else _red
    print(
        f"\nChecked {total} files: "
        f"{color_fn(f'{passed} passed')}, "
        f"{_red(f'{error_count} errors') if error_count else f'{error_count} errors'}, "
        f"{warning_count} warnings"
    )

    raise SystemExit(1 if error_count > 0 else 0)


if __name__ == "__main__":
    app()

