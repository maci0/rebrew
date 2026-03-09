"""lint.py - Annotation linter for rebrew decomp C files.

Check that all .c files in the reversed directory have proper reccmp-style annotations.
Supports --fix mode to auto-migrate from old format to new format.

Inspired by reccmp's decomplint tool.
"""

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
    NEW_FUNC_RE,
    NEW_KV_RE,
    VALID_MARKERS,
    marker_for_module,
)
from rebrew.cli import TargetOption, get_config, json_print
from rebrew.config import ProjectConfig

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
    current_flags = {"has_new": False}
    in_block = False
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


def _check_format_warnings(
    result: LintResult, found_keys: dict[str, str], flags: dict[str, bool]
) -> bool:
    """Check format-level warnings (W002, W012, W013). Returns True if validation should proceed."""
    if not flags["has_new"]:
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
    # STATUS is now strictly managed in rebrew-function.toml.
    # We no longer validate it here since it's verified when parsed from the sidecar.
    pass


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
    if status == "NEAR_MATCH" and marker == "STUB":
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
            f"Library module {module!r} missing // SOURCE: marker "
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
            f"{marker} marker missing // SECTION: (.data, .rdata, .bss)",
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
            "File defines struct(s) without // SIZE 0xNN marker (reccmp recommendation)",
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
        result.error(1, "E001", "Empty file, missing FUNCTION/LIBRARY/STUB marker")
        return result

    all_headers = _parse_multi_headers(lines)
    if not all_headers:
        # Totally broken file — no recognisable marker format found.
        # Synthesise a minimal entry so the loop below can report E001.
        all_headers = [
            ({}, {"has_new": False, "has_old": False, "has_block": False, "has_javadoc": False})
        ]

    # Load the per-directory metadata once so all marker blocks in this file can use it.
    # Keys in the result: (module, va_int) -> {toml_field: value}
    from rebrew.metadata import load_metadata as _load_metadata

    _metadata_entries = _load_metadata(cfg.metadata_dir if cfg else filepath.parent)

    # Also load the data metadata for DATA/GLOBAL markers.
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

        # Overlay metadata fields into found_keys for this marker block.
        # Metadata always wins for the fields it owns (STATUS, SIZE, CFLAGS, etc.),
        # but we only overlay if the key is not already present inline — this lets
        # any remaining inline marker (from files not yet fully migrated) take
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

    result.context_prefix = ""
    _check_body_rules(result, lines, all_headers[0][1]["has_new"] if all_headers else False)

    return result


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
    help="Lint source marker standards for decomp C source files.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew lint                                  Lint all .c files in reversed_dir

rebrew lint --quiet                          Errors only, suppress warnings

rebrew lint --json                           Machine-readable JSON output

rebrew lint --summary                        Show status/origin breakdown table

rebrew lint --files src/game/foo.c           Lint specific files only

[bold]Error codes:[/bold]

E001   Missing FUNCTION/LIBRARY/STUB marker

E002   Invalid VA format or range

E003   Missing STATUS metadata

E013   Duplicate VA across files


W005   STUB without BLOCKER explanation

W016   DATA/GLOBAL missing SECTION metadata

W017   NOTE contains [rebrew] sync metadata

W010   Unknown marker key

W018   Missing CFLAGS with no config fallback

[dim]Checks for reccmp-style markers in the first 20 lines of each .c file.[/dim]""",
)


@app.callback(invoke_without_command=True)
def main(
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    quiet: bool = typer.Option(False, help="Only show errors, suppress warnings"),
    files: list[Path] = typer.Option(None, help="Check specific files instead of all *.c"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
    summary: bool = typer.Option(False, "--summary", help="Print status/origin breakdown"),
) -> None:
    """Lint source marker standards in decomp C source files."""
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
