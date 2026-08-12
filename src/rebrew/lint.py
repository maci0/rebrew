"""lint.py - Annotation linter for rebrew decomp C files.

Check that all .c files in the reversed directory have proper reccmp-style
annotations (``// FUNCTION: MODULE 0xVA`` markers) and that volatile metadata
(STATUS, SIZE, CFLAGS, etc.) lives in ``rebrew-function.toml``.
Supports ``--fix`` to migrate inline metadata keys to the TOML metadata file.

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
    METADATA_KEYS,
    NEW_FUNC_RE,
    NEW_KV_RE,
    VALID_MARKERS,
)
from rebrew.cli import EXIT_MISMATCH, TargetOption, iter_sources, json_print, rel_display_path
from rebrew.config import ProjectConfig, load_config
from rebrew.data_metadata import load_data_metadata
from rebrew.metadata import load_metadata
from rebrew.utils import read_source_text

console = Console(stderr=True)

_HEADER_MARKER_RE = re.compile(r"//\s*(\w+):\s*(\S+)\s+(0x[0-9a-fA-F]+)")
_SIZE_ANNOTATION_RE = re.compile(r"//\s*SIZE\s+0x[0-9a-fA-F]+")


@dataclass
class LintResult:
    """Accumulated lint errors and warnings for a single source file.

    Why a custom linter? Standard C linters don't understand rebrew's
    annotation markers and metadata. We need strict validation to ensure
    the CI pipeline and other tools (like `rebrew test`) can parse them.
    """

    filepath: Path
    errors: list[tuple[int, str, str]] = field(default_factory=list)
    warnings: list[tuple[int, str, str]] = field(default_factory=list)
    context_prefix: str = ""
    marker_line: int = 1
    # Counters collected during lint for --summary (avoids re-reading files).
    _status_counts: Counter[str] = field(default_factory=Counter)
    _marker_counts: Counter[str] = field(default_factory=Counter)
    # Collected inline metadata for --fix migration: (module, va_int, key, value)
    _inline_fixes: list[tuple[str, int, str, str, str]] = field(default_factory=list)

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

        # Both NEW_FUNC_RE and NEW_KV_RE require a leading `//`; skip the
        # regex calls on non-comment lines (the bulk of source files).
        if not stripped.startswith("//"):
            if in_block:
                seen_code_after_marker = True
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


def _check_format_errors(result: LintResult, flags: dict[str, bool]) -> bool:
    """Check format-level errors (E001). Returns True if validation should proceed."""
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
    seen_vas: dict[Any, str] | None,
    module: str = "",
) -> None:
    if va_int is None or seen_vas is None:
        return
    # Key on (module, va) so a multi-module file whose blocks share a VA
    # (a valid layout) is not flagged, while a true duplicate — same module
    # + VA, in the same or another file — is.
    key: Any = (module, va_int) if module else va_int
    if key in seen_vas:
        result.error(result.marker_line, "E013", f"Duplicate VA {va_str} — also in {seen_vas[key]}")
    else:
        seen_vas[key] = rel_display_path(filepath)


def _check_W018_cflags(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    has_annotation = "CFLAGS" in found_keys and found_keys["CFLAGS"].strip()
    if has_annotation:
        return
    # Only warn if the target config also has no default cflags.  cfg.cflags
    # (the user-facing default, empty when unset) is the right fallback —
    # cfg.base_cflags is always-on /nologo /c /MT glue, so checking it would
    # make this warning never fire.
    has_config_default = bool(getattr(cfg, "cflags", "") if cfg else "")
    if not has_config_default:
        result.warning(
            result.marker_line,
            "W018",
            "Missing CFLAGS in metadata and no default cflags in project config",
        )


def _check_W010_unknown_keys(result: LintResult, found_keys: dict[str, str]) -> None:
    for key in found_keys:
        if key not in ALL_KNOWN_KEYS and key not in ("MODULE", "_LINE"):
            result.warning(result.marker_line, "W010", f"Unknown annotation key: {key}")


def _check_E015_marker_consistency(
    result: LintResult, marker: str, module: str, status: str, cfg: ProjectConfig | None = None
) -> None:
    # E015's intent is library-module attribution: a FUNCTION marker on a
    # module configured as library should be LIBRARY.  A STUB-status function
    # may legitimately keep either its STUB marker or the FUNCTION marker
    # (status lives in rebrew-function.toml per the metadata convention), so
    # both are allowed; anything else is inconsistent.
    lib_modules = cfg.library_modules if cfg and cfg.library_modules is not None else set()
    if module in lib_modules:
        expected_marker = "LIBRARY"
        allowed = {"LIBRARY"}
    elif status == "STUB":
        expected_marker = "FUNCTION"
        allowed = {"FUNCTION", "STUB"}
    else:
        expected_marker = "FUNCTION"
        allowed = {"FUNCTION"}
    if marker not in allowed and marker in VALID_MARKERS and marker not in ("GLOBAL", "DATA"):
        result.error(
            result.marker_line,
            "E015",
            f"Marker {marker} inconsistent with module {module!r} (expected {expected_marker})",
        )


def _check_E017_contradictory(result: LintResult, status: str, marker: str) -> None:
    if status == "NEAR_MATCHING" and marker == "STUB":
        result.error(
            result.marker_line, "E017", f"Contradictory: status is {status} but marker is STUB"
        )
    elif marker == "STUB" and status in ("EXACT", "RELOC", "PROVEN"):
        # A matched function marked STUB (stale marker from stub generation,
        # metadata later promoted). The STUB marker hides a byte-matched
        # function from status/todo and misleads reversers.
        result.error(
            result.marker_line,
            "E017",
            f"Contradictory: status is {status} but marker is STUB — "
            "remove the stale STUB marker (function is matched)",
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


def _check_W019_inline_metadata(
    result: LintResult,
    found_keys: dict[str, str],
    metadata_sourced_keys: set[str],
    module: str = "",
    va_int: int | None = None,
    marker: str = "",
) -> None:
    """Warn when metadata-owned keys appear as inline // KEY: comments.

    These keys should live exclusively in rebrew-function.toml (or rebrew-data.toml
    for DATA/GLOBAL markers).  Inline occurrences are deprecated.
    """
    for key in found_keys:
        if key in METADATA_KEYS and key not in metadata_sourced_keys:
            result.warning(
                result.marker_line,
                "W019",
                f"Inline '// {key}:' is deprecated — use rebrew-function.toml instead",
            )
            # Record for --fix migration (marker type routes the write to the
            # function vs data metadata store).
            if module and va_int is not None:
                result._inline_fixes.append((module, va_int, key, found_keys[key], marker))


def _check_W020_asm_dump(
    result: LintResult, lines: list[str], claimed_statuses: set[str] | None = None
) -> None:
    """Flag asm-dump placeholder implementations (W020).

    ``__declspec(naked)`` functions whose "implementation" is an ``__asm``
    block (often with raw ``__emit`` byte emission) are pasted disassembly,
    not real C source: they cannot be maintained, refactored, or matched
    beyond byte-identical reproduction.  Warn once per file at the first hit.

    Status-aware: a file whose metadata claims a non-stub status
    (``EXACT``/``RELOC``/...) while its body is an asm dump escalates the
    warning — an asm dump cannot be a byte-match, so the STATUS is wrong.
    That is how "documented STUB" (expected) is told apart from a "claimed
    match on an asm dump" (a metadata bug) at a glance.
    """
    claimed = sorted((claimed_statuses or set()) - {"STUB", "SKIP"})
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        # Ignore comment lines — "__asm" in a note is not an implementation.
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            continue
        if "__emit" in s:
            if claimed:
                result.warning(
                    i,
                    "W020",
                    f"__emit byte dump but STATUS claims {', '.join(claimed)} — an asm "
                    "placeholder cannot be a byte-match; fix the STATUS or mark BLOCKER",
                )
            else:
                result.warning(
                    i,
                    "W020",
                    "__emit byte dump — function is an asm placeholder, not real C "
                    "source; rewrite it as C (or mark it STUB/BLOCKER with a note)",
                )
            return
        if "__asm" in s:
            if claimed:
                result.warning(
                    i,
                    "W020",
                    f"inline __asm block but STATUS claims {', '.join(claimed)} — an asm "
                    "dump cannot be a byte-match; fix the STATUS or mark BLOCKER",
                )
            else:
                result.warning(
                    i,
                    "W020",
                    "inline __asm block — asm-dump placeholder instead of real C "
                    "source; rewrite the function as C where possible",
                )
            return


_ZERO_INIT_RE = re.compile(
    r"^\s*(?:extern\s+|static\s+)?(?:unsigned\s+|signed\s+|const\s+)?"
    r"[A-Za-z_][\w\s\*]*?\s+[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*=\s*\{?\s*0\s*\}?\s*;"
)

_GLOBAL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?[;=]")


def _check_W021_duplicate_globals(
    result: LintResult,
    lines: list[str],
    filepath: Path,
    seen_globals: dict[str, str] | None,
) -> None:
    """Warn when a DATA/GLOBAL symbol name is annotated in multiple files.

    Catches the np-rebrew pattern where ``globals.c`` and another source both
    annotate/define the same global (g_ vs DAT_ collisions, duplicate
    definitions).  ``seen_globals`` maps name → filepath, threaded across the
    batch like ``seen_vas``.
    """
    if seen_globals is None:
        return
    pending = False
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("// DATA:") or s.startswith("// GLOBAL:"):
            pending = True
            continue
        if not pending:
            continue
        if not s or s.startswith("//") or s.startswith("/*"):
            continue  # comment/blank lines inside the block
        pending = False
        m = _GLOBAL_NAME_RE.search(s)
        if m:
            name = m.group(1)
            prev = seen_globals.get(name)
            if prev is not None and prev != str(filepath):
                result.warning(
                    i,
                    "W021",
                    f"global '{name}' is also annotated in {prev} — duplicate "
                    "definition or naming collision",
                )
            else:
                seen_globals[name] = str(filepath)


def _strip_c_comments_strings(line: str, in_block: bool) -> tuple[str, bool]:
    """Remove C comments and string/char literals from *line* for brace counting.

    Returns ``(cleaned, in_block_comment)`` — *in_block_comment* carries the
    multi-line ``/* ... */`` state across calls.  A file-scope ``/* { */``
    comment must not permanently suppress W022's brace-depth tracking.
    """
    out: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if in_block:
            if c == "*" and i + 1 < n and line[i + 1] == "/":
                in_block = False
                i += 2
            else:
                i += 1
            continue
        if c == "/" and i + 1 < n:
            nxt = line[i + 1]
            if nxt == "/":
                break  # line comment — the rest of the line is comment
            if nxt == "*":
                in_block = True
                i += 2
                continue
        if c in ('"', "'"):
            quote = c
            i += 1
            while i < n and line[i] != quote:
                if line[i] == "\\":
                    i += 2
                else:
                    i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block


def _check_W022_zero_init_bss(result: LintResult, lines: list[str]) -> None:
    """Flag file-scope zero initializers (W022).

    A file-scope ``= {0}`` / ``= 0`` forces the global into ``.data``
    (initialized) instead of ``.bss`` (uninitialized, virtual-only) — this
    is exactly the np-rebrew .data bloat (41K of zero-init arrays).  Leave
    the global uninitialized for .bss.
    """
    depth = 0
    in_block_comment = False
    for i, line in enumerate(lines, start=1):
        cleaned, in_block_comment = _strip_c_comments_strings(line, in_block_comment)
        depth += cleaned.count("{") - cleaned.count("}")
        s = line.strip()
        if depth == 0 and _ZERO_INIT_RE.match(s):
            result.warning(
                i,
                "W022",
                "file-scope zero initializer (= {0} / = 0) puts the global in "
                ".data, not .bss — leave it uninitialized to keep the PE small",
            )
            return


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
        if (
            ("typedef struct" in stripped or "struct " in stripped)
            and not stripped.startswith("//")
            and not stripped.startswith("/*")
            and not stripped.startswith("*")
        ):
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
    seen_vas: dict[Any, str] | None = None,
    seen_globals: dict[str, str] | None = None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> LintResult:
    """Lint a single C file.

    Args:
        filepath: Path to the .c file.
        cfg: Optional ProjectConfig for config-aware checks.
        seen_vas: Optional dict mapping VA → filename for duplicate detection.
                  Will be mutated (VAs from this file are added).
        seen_globals: Optional dict mapping global symbol name → filename for
                      W021 duplicate-global detection. Will be mutated.
        preloaded_metadata: Pre-loaded metadata dict (avoids per-file I/O in batch).
        preloaded_data_metadata: Pre-loaded data metadata dict (avoids per-file I/O in batch).

    """
    result = LintResult(filepath)

    # A caller may pass a shared seen_vas dict for cross-file duplicate
    # detection; with None (single-file lint) duplicate VAs WITHIN this file
    # must still be caught, so fall back to a per-file dict.
    if seen_vas is None:
        seen_vas = {}

    try:
        text, _ = read_source_text(filepath)
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
        all_headers = [({}, {"has_new": False})]

    # Load per-directory metadata (keys: (module, va_int) -> {toml_field: value}).
    # Accept pre-loaded dicts from callers that process many files in the same directory
    # (avoids repeated I/O for the common batch-lint case).
    _metadata_dir = cfg.metadata_dir if cfg else filepath.parent
    _metadata_entries = (
        preloaded_metadata if preloaded_metadata is not None else load_metadata(_metadata_dir)
    )
    _data_metadata_entries = (
        preloaded_data_metadata
        if preloaded_data_metadata is not None
        else load_data_metadata(_metadata_dir)
    )

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

    # Statuses claimed by this file's annotations (for W020 escalation: a
    # non-STUB claim on an asm-dump body is a metadata error).
    _file_statuses: set[str] = set()

    for found_keys, flags in all_headers:
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
        _va_int: int | None = None
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

        if not _check_format_errors(result, flags):
            continue

        if flags["has_new"]:
            marker = found_keys.get("MARKER", "")
            _check_E001_marker(result, marker)

            va_int = _check_E002_va(result, va_str)

            # Check EVERY block (module + VA keyed): a duplicate appearing in
            # a later block of a multi-function file used to be skipped by the
            # old `i == 0` guard.  The (module, va) key keeps a multi-module
            # file whose blocks share a VA (a valid layout) unflagged.
            _check_E013_duplicate_va(result, va_int, va_str, filepath, seen_vas, module=mod)

            if marker not in ("GLOBAL", "DATA"):
                _check_W018_cflags(result, found_keys, cfg)
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
                _file_statuses.add(status)

            _check_E015_marker_consistency(result, marker, module, status, cfg)
            _check_W005_blocker(result, status, found_keys)
            _check_W006_source(result, module, found_keys, cfg)
            _check_W010_unknown_keys(result, found_keys)
            _check_E017_contradictory(result, status, marker)
            _check_config_rules(result, found_keys, cfg)

            _check_W015_va_case(result, va_str)
            _check_W016_section(result, marker, found_keys)
            _check_W019_inline_metadata(
                result,
                found_keys,
                _metadata_sourced_keys,
                module=mod,
                va_int=_va_int if mod else None,
                marker=marker,
            )

    result.context_prefix = ""
    _check_W020_asm_dump(result, lines, _file_statuses)
    _check_W021_duplicate_globals(result, lines, filepath, seen_globals)
    _check_W022_zero_init_bss(result, lines)
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
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew lint · · · · · · · · · · · · Lint all .c files in reversed_dir\n\n"
        "  rebrew lint --quiet · · · · · · · · Errors only, suppress warnings\n\n"
        "  rebrew lint --json · · · · · · · · · Machine-readable JSON output\n\n"
        "  rebrew lint --summary · · · · · · · Show status/origin breakdown table\n\n"
        "  rebrew lint src/game/foo.c · · · · · Lint specific files only\n\n"
        "  rebrew lint --fix --dry-run · · · · Preview inline-metadata migrations before commit\n\n"
        "[bold]Error codes:[/bold]\n\n"
        "  E001   Missing FUNCTION/LIBRARY/STUB marker\n\n"
        "  E002   Invalid VA format or range\n\n"
        "  E012   Module doesn't match configured marker\n\n"
        "  E013   Duplicate VA across files\n\n"
        "  W005   STUB without BLOCKER explanation\n\n"
        "  W016   DATA/GLOBAL missing SECTION metadata\n\n"
        "  W010   Unknown marker key\n\n"
        "  W018   Missing CFLAGS with no config fallback\n\n"
        "  W019   Inline metadata key (STATUS, SIZE, etc.) should be in rebrew-function.toml\n\n"
        "  W020   Asm-dump placeholder (__emit / __asm block) instead of real C source\n\n"
        "  W021   Duplicate global symbol annotated in multiple files\n\n"
        "  W022   File-scope zero initializer (= {0}) forces the global into .data, not .bss\n\n"
        "[dim]Checks for reccmp-style markers in each .c file.[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Migrate inline metadata to rebrew-function.toml and remove from source",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show errors, suppress warnings"),
    files: list[Path] | None = typer.Argument(
        None, help="Specific files to check (defaults to all *.c in project)"
    ),
    summary: bool = typer.Option(False, "--summary", help="Print status/origin breakdown"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Lint source marker standards in decomp C source files."""
    # Intentionally use load_config (not require_config) — lint degrades
    # gracefully when no config is present (e.g. linting standalone files).
    cfg = None
    try:
        cfg = load_config(target=target)
    except FileNotFoundError:
        pass  # No config file — lint without config-aware rules
    except (KeyError, ValueError) as exc:
        console.print(
            f"[yellow]warning:[/yellow] config error ({exc}); config-aware rules disabled"
        )

    reversed_dir = cfg.reversed_dir if cfg else None

    ext = cfg.source_ext if cfg else ".c"
    if files:
        c_files = [f for f in files if f.suffix == ext]
    elif reversed_dir:
        c_files = iter_sources(reversed_dir, cfg)
    else:
        c_files = sorted(Path.cwd().rglob(f"*{ext}"))

    # Cross-file duplicate tracking: VAs (E013) and global names (W021).
    seen_vas: dict[int, str] = {}
    seen_globals: dict[str, str] = {}

    # Pre-load metadata once for the whole batch (avoids per-file I/O).
    _preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    _preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    if cfg:
        _preloaded_metadata = load_metadata(cfg.metadata_dir)
        _preloaded_data_metadata = load_data_metadata(cfg.metadata_dir)

    total = 0
    passed = 0
    error_count = 0
    warning_count = 0
    all_results: list[LintResult] = []

    for cfile in c_files:
        total += 1
        result = lint_file(
            cfile,
            cfg=cfg,
            seen_vas=seen_vas,
            seen_globals=seen_globals,
            preloaded_metadata=_preloaded_metadata,
            preloaded_data_metadata=_preloaded_data_metadata,
        )
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

    # Apply --fix: migrate inline metadata to rebrew-function.toml /
    # rebrew-data.toml (the destination depends on the marker type).
    # Without a loaded config the migration has nowhere to write — say so
    # instead of silently doing nothing (functionality-review: a user running
    # --fix outside a project saw zero effect and no explanation).
    if fix and not cfg:
        console.print(
            "[yellow]warning:[/yellow] --fix needs a rebrew-project.toml — "
            "no config loaded, nothing migrated"
        )
    if fix and cfg:
        from rebrew.annotation import remove_inline_annotation_key
        from rebrew.data_metadata import get_data_entry, set_data_field
        from rebrew.metadata import (
            coerce_metadata_value,
            get_entry,
            set_field,
            update_source_status,
        )

        fix_count = 0
        for r in all_results:
            if not r._inline_fixes:
                continue
            for module, va, key, value, marker in r._inline_fixes:
                toml_key = key.lower()
                is_data_marker = marker in ("DATA", "GLOBAL")
                # ORIGIN is legacy everywhere; SECTION is legacy for functions
                # but a real data-metadata field for DATA/GLOBAL markers.
                # Legacy keys are never stored — just strip the inline form.
                if key == "ORIGIN" or (not is_data_marker and key == "SECTION"):
                    if not dry_run:
                        remove_inline_annotation_key(r.filepath, va, key)
                    fix_count += 1
                    continue
                # Check if the destination store already has this field.
                if is_data_marker:
                    existing = get_data_entry(cfg.metadata_dir, va, module)
                    present = toml_key in {k.lower() for k in existing}
                else:
                    existing = get_entry(cfg.metadata_dir, va, module)
                    present = toml_key in existing
                if not present:
                    if dry_run:
                        store = "rebrew-data.toml" if is_data_marker else "rebrew-function.toml"
                        console.print(
                            f"  [dim]Would migrate[/dim] {r.filepath.name} "
                            f"// {key}: {value!r} → {store}"
                        )
                    else:
                        # Coerce size/blocker_delta to int via the shared
                        # metadata facade (single canonical coercion).
                        write_value = coerce_metadata_value(toml_key, value)
                        if is_data_marker:
                            set_data_field(
                                cfg.metadata_dir, va, toml_key, write_value, module=module
                            )
                        elif toml_key == "status":
                            # STATUS must go through the promotion gate
                            # (validates the value, clears stale blockers,
                            # never silently demotes PROVEN).
                            update_source_status(
                                cfg.metadata_dir, write_value, module, va, force=True
                            )
                        else:
                            set_field(cfg.metadata_dir, va, toml_key, write_value, module=module)

                # Strip inline comment from source (file-only — the metadata
                # write above already owns the field; routing STATUS through
                # remove_annotation_key would raise, and removing any other
                # metadata key would delete the field we just migrated).
                if not dry_run:
                    remove_inline_annotation_key(r.filepath, va, key)
                fix_count += 1

        if not json_output:
            if dry_run:
                console.print(
                    f"\n[yellow]Dry run:[/yellow] {fix_count} inline annotations would be migrated"
                )
            elif fix_count > 0:
                console.print(
                    f"\n[green]Fixed:[/green] migrated {fix_count} inline annotations to rebrew-function.toml"
                )

    if error_count > 0:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
