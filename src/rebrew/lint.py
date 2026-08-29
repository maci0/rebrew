"""lint.py - Annotation linter for rebrew decomp C files.

Check that all .c files in the reversed directory have proper reccmp-style
annotations (``// FUNCTION: MODULE 0xVA`` markers) and that volatile metadata
(STATUS, SIZE, CFLAGS, etc.) lives in ``rebrew-functions.toml``.  Also
cross-checks FUNCTION/STUB marker VAs against the target's function list
(W028), flags redundant per-function / preset cflags that only repeat an
inherited value (W029), and otherwise catches stale annotations at lint time
instead of as confusing mismatches in ``rebrew test``.
Supports ``--fix`` to migrate inline metadata keys to the TOML metadata file.

Inspired by reccmp's decomplint tool.
"""

import bisect
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
    METADATA_KEYS,
    MIN_VALID_VA,
    NEW_FUNC_RE,
    NEW_KV_RE,
    VALID_MARKERS,
    min_valid_va_for,
)
from rebrew.cli import (
    EXIT_MISMATCH,
    TargetOption,
    json_print,
)
from rebrew.config import ProjectConfig, load_config
from rebrew.data_metadata import load_data_metadata
from rebrew.metadata import MATCHED_STATUSES, load_metadata
from rebrew.sources import (
    iter_sources,
)
from rebrew.utils import (
    read_source_text,
    rel_display_path,
)

console = Console(stderr=True)

_HEADER_MARKER_RE = re.compile(r"//\s*(\w+):\s*(\S+)\s+(0x[0-9a-fA-F]+)")
_SIZE_ANNOTATION_RE = re.compile(r"//\s*SIZE\s+0x[0-9a-fA-F]+")
# Patterns for default function names (to be used with --pedantic flag)
_DEFAULT_FUNC_NAME_PATTERNS = [
    r"\bfcn\b",
    r"\bfn\b",
    r"\bfun\b",
    r"\bFUN_[0-9A-Fa-f]+\b",
    r"\bsub_[0-9A-Fa-f]+\b",
    r"\bfunc_[0-9A-Fa-f]+\b",
    r"\bthunk_[0-9A-Fa-f]+\b",
]


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
    # Lines of the file for style checks
    _lines: list[str] = field(default_factory=list)

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

        # NEW_FUNC_RE and NEW_KV_RE match `//` and `/*` comment lines; skip
        # the regex calls on non-comment lines (the bulk of source files).
        if not (stripped.startswith("//") or stripped.startswith("/*")):
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

        # Any other line here is a comment (non-comment lines were handled
        # above): a bare function-name hint (``// Foo``), an explanation, or
        # a ``/* ... */`` block.  A comment is not code — keep the header
        # block open so a following ``// SIZE:``/``// CFLAGS:``/etc. still
        # attaches to the marker block (mirrors annotation.py's name-hint
        # handling; without this, the name line orphaned later KV keys and
        # W019/--fix could never see them).

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


def _check_E002_va(result: LintResult, va_str: str, min_va: int = MIN_VALID_VA) -> int | None:
    try:
        va_int = int(va_str, 16)
        if not (min_va <= va_int <= 0xFFFFFFFF):
            result.error(result.marker_line, "E002", f"VA {va_str} is suspicious (outside range)")
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


def _function_containing_va(
    spans: list[tuple[int, int, str]], va: int
) -> tuple[int, int, str] | None:
    """Return the ``(start, end, name)`` span containing *va*, or None.

    ``spans`` is a list sorted by start.  A span whose *start* equals *va*
    is NOT a "contains" — the caller already established that *va* is not a
    function start, so only strictly-inside hits qualify (a moved/merged
    annotation now points into the body of a different function).
    """
    if not spans or va < spans[0][0]:
        return None
    starts = [s[0] for s in spans]
    idx = bisect.bisect_right(starts, va) - 1
    if idx < 0:
        return None
    start, end, name = spans[idx]
    if start < va < end:
        return (start, end, name)
    return None


def _build_function_index(
    cfg: ProjectConfig,
) -> tuple[set[int], list[tuple[int, int, str]]] | None:
    """Build ``(starts, spans)`` from the target's function list, or None.

    ``starts`` is the set of function-start VAs; ``spans`` is the sorted
    ``(start, end, name)`` list used to detect annotations that fell inside
    another function after a move/merge.  Returns None when the list is
    missing or empty — the W028 check is then silent (nothing to check
    against), matching the old doctor behavior.
    """
    from rebrew.catalog import cached_function_list

    funcs = cached_function_list(cfg)
    if not funcs:
        return None
    starts: set[int] = set()
    spans: list[tuple[int, int, str]] = []
    for f in funcs:
        va = int(f.get("va", 0))
        if va <= 0:
            continue
        starts.add(va)
        spans.append((va, va + max(int(f.get("size", 0) or 0), 1), str(f.get("name", ""))))
    spans.sort()
    return starts, spans


def _staleness_fix(cfg: ProjectConfig | None) -> str:
    """Pick a staleness fix hint from which artifact is newer.

    Stale annotations have two very different causes: the target binary was
    replaced (refresh the function list), or the annotations moved / the list
    no longer reflects the target (re-annotate) — recommending ``rebrew
    intake`` for the second case is wrong.  The binary-vs-list mtime
    comparison is a cheap proxy: a binary newer than the list means it
    plausibly changed after the list was written; a list at least as new as
    the binary means the binary cannot have changed since, so the markers
    (or a list regenerated from a different binary, e.g. a rebuild) are at
    fault.  Falls back to a cause-neutral message when either file's mtime
    is unavailable.
    """
    binary_newer: bool | None = None
    try:
        bin_path = Path(str(getattr(cfg, "target_binary", "")))
        list_path: Path | None = getattr(cfg, "function_list", None) if cfg is not None else None
        if list_path is not None and bin_path.is_file() and list_path.is_file():
            binary_newer = bin_path.stat().st_mtime > list_path.stat().st_mtime
    except OSError:
        binary_newer = None

    annotate = "re-annotate the moved functions (`rebrew skeleton <new_va>` or edit the marker VA)"
    if binary_newer is True:
        return (
            "The target binary is newer than the function list — it likely changed: "
            "re-run `rebrew intake` / `rebrew discover` to refresh the list, then " + annotate
        )
    if binary_newer is False:
        return (
            "The function list is as new as the target binary, so the binary did not "
            "change: " + annotate + ". If the list was regenerated from a different "
            "binary (e.g. a rebuilt artifact) instead of the target, regenerate it "
            "from the target"
        )
    return (
        "The function list no longer matches these annotations: if the target binary "
        "changed, re-run `rebrew intake` / `rebrew discover` to refresh the list; "
        "otherwise " + annotate + " (or regenerate the list if it was built from a "
        "different binary, e.g. a rebuilt artifact)"
    )


def _check_W028_stale_annotation(
    result: LintResult,
    va_int: int,
    module: str,
    cfg: ProjectConfig | None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None,
) -> None:
    """Warn when a FUNCTION/STUB marker VA matches no function start (W028).

    A "stale annotation" is a ``// FUNCTION:``/``// STUB:`` marker whose VA
    no longer corresponds to a function in the current binary.  After a
    binary update or a re-discovery the function either moved — the marker
    now points *inside* another function's span — or was removed (no
    function at that VA).  Either way ``rebrew test``/``verify`` compile
    against the wrong bytes and status/todo keep reporting phantom
    functions.

    Uses the target's ``functions.txt`` (the same list ``rebrew intake`` /
    ``discover`` write) as ground truth.  ``LIBRARY`` markers are excluded
    (import stubs) and ``GLOBAL``/``DATA`` markers are data, not code;
    markers of a different target module are filtered by the caller's
    config.  Silent when no function index is available.
    """
    if function_index is None:
        return
    marker = getattr(cfg, "marker", None) if cfg is not None else None
    if marker and module and module != marker:
        return  # another target's marker — E012 already flags the module
    starts, spans = function_index
    if va_int in starts:
        return
    host = _function_containing_va(spans, va_int)
    # Append the mtime-aware fix hint only to the first stale marker in the
    # file — repeating it per marker would drown the signal.
    hint = _staleness_fix(cfg) if not any(c == "W028" for _, c, _ in result.warnings) else ""
    if host is not None:
        result.warning(
            result.marker_line,
            "W028",
            f"annotation VA 0x{va_int:x} points inside function "
            f"'{host[2] or 'a function'}' (moved/merged) — re-annotate the "
            "marker VA or refresh the function list" + hint,
        )
    else:
        result.warning(
            result.marker_line,
            "W028",
            f"annotation VA 0x{va_int:x} has no function in the current "
            "function list (removed or shifted) — re-annotate the marker VA "
            "or refresh the function list" + hint,
        )


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
    # (status lives in rebrew-functions.toml per the metadata convention), so
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
    elif marker == "STUB" and status in MATCHED_STATUSES:
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
    # BLOCKER lives in rebrew-functions.toml metadata; the metadata overlay already injects it
    # into found_keys before this check runs, so this fires only when absent from both.
    if status == "STUB" and "BLOCKER" not in found_keys:
        result.warning(
            result.marker_line,
            "W005",
            "STUB function missing 'blocker' explanation "
            '(run: rebrew blocker set <file|0xVA> "<reason>" — or: rebrew diff --fix-blocker)',
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
    metadata_size: str | None = None,
) -> None:
    """Warn when metadata-owned keys appear as inline // KEY: comments.

    These keys should live exclusively in rebrew-functions.toml (or rebrew-data.toml
    for DATA/GLOBAL markers).  Inline occurrences are deprecated.

    ``SIZE`` is exempt — ``// SIZE:`` is the reccmp-native contract in the
    ``.c`` (reccmp reads it there) and the TOML value is an override, not a
    migration target.  The only SIZE warning is a disagreement between the
    inline and the metadata value.
    """
    for key in found_keys:
        if key == "SOURCE" and found_keys[key].strip().lower() == "naked":
            # The file-borne naked-reconstruction marker written by
            # `rebrew asm --inline-c`: like the // CFLAGS:
            # /DREBREW_ALLOW_NAKED naked-guard convention, it must travel
            # with the file (self-clears when the C body replaces it) —
            # not a metadata-migration candidate.
            continue
        if key == "SIZE":
            if metadata_size and metadata_size != found_keys[key].strip():
                result.warning(
                    result.marker_line,
                    "W019",
                    f"Inline '// SIZE: {found_keys[key].strip()}' disagrees with "
                    f"metadata SIZE {metadata_size} — the compile contract is "
                    "ambiguous; align them",
                )
            continue
        if key in METADATA_KEYS and key not in metadata_sourced_keys:
            result.warning(
                result.marker_line,
                "W019",
                f"Inline '// {key}:' is deprecated — use rebrew-functions.toml instead",
            )
            # Record for --fix migration (marker type routes the write to the
            # function vs data metadata store).
            if module and va_int is not None:
                result._inline_fixes.append((module, va_int, key, found_keys[key], marker))


def _check_E023_naked_asm(
    result: LintResult,
    lines: list[str],
    claimed_statuses: set[str] | None = None,
    metadata_cflags: str = "",
) -> None:
    """Flag whole-function ``__declspec(naked)`` + ``__asm`` dumps (E023).

    ``__declspec(naked)`` is only allowed for *minor padding* (1-2 alignment
    ``nop``/``int3`` bytes, e.g. ``_emit 0x90`` / ``_emit 0xCC`` or
    ``__asm nop``).  A whole-function naked body pasted from disassembly is
    not a decompilation and must be flagged as an error.

    Heuristic: a naked function whose asm body exceeds minor padding — more
    than 2 ``__asm``/``_emit`` lines, or any ``_emit`` byte that is not
    padding (``0x90``/``0xCC``) / non-nop mnemonic — is a whole-function
    dump and earns E023.  1-2 nops for alignment are tolerated silently.
    """
    # The project's byte-identity guard: a naked body gated by
    # ``REBREW_ALLOW_NAKED`` — either fenced in ``#ifdef REBREW_ALLOW_NAKED``
    # (with a C fallback in ``#else``) or compiled via ``cflags`` carrying
    # ``/DREBREW_ALLOW_NAKED`` (in rebrew-functions.toml, or a remaining
    # inline ``// CFLAGS:`` annotation) — is the documented workflow for
    # reproducing a compiler whose codegen the available toolchains cannot
    # emit (see AGENTS.md / the naked-guard convention).  That is
    # intentional, not a decompilation shortcut — the flag marks it.
    # Skip E023 for naked bodies gated by REBREW_ALLOW_NAKED.
    if "REBREW_ALLOW_NAKED" in metadata_cflags:
        return
    for line in lines:
        if "REBREW_ALLOW_NAKED" in line:
            return

    # Find naked declaration outside comments.
    has_naked = False
    naked_line = 0
    for idx, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            continue
        if "__declspec(naked)" in line or "__declspec( naked" in line:
            has_naked = True
            naked_line = idx
            break
    if not has_naked:
        return

    asm_lines: list[int] = []
    emit_lines: list[int] = []
    meaningful_asm: list[int] = []
    for idx, line in enumerate(lines, start=1):
        s = line.strip()
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            continue
        # Use "_emit" so both "_emit" and "__emit" variants are caught.
        has_asm = "__asm" in s
        has_emit = "_emit" in s
        if has_asm:
            asm_lines.append(idx)
            payload = s.lower().split("__asm", 1)[1]
            payload = payload.replace("{", "").replace("}", "").replace(";", "").strip()
            # Only count as meaningful if it carries a mnemonic, not just braces.
            if payload:
                # Strip _emit payload — the emit line itself is counted via emit_lines.
                payload_no_emit = payload.replace("_emit", "").strip()
                # After removing _emit, if nothing left (or just hex) it's not a separate asm mnemonic.
                if (
                    payload_no_emit
                    and payload_no_emit not in ("", ",", "0x90", "0xcc", "0x90,", "0x90,")
                    and not all(
                        tok.strip() in ("", "0x90", "0xcc", ",")
                        for tok in payload_no_emit.replace(",", " , ").split()
                    )
                ):
                    meaningful_asm.append(idx)
        if has_emit:
            emit_lines.append(idx)

    total_meaningful = len(emit_lines) + len(meaningful_asm)
    if total_meaningful == 0:
        return

    # Minor padding allowance: 1-2 meaningful asm/emit lines that are *only*
    # padding (nop / 0x90 / 0xCC / int 3) are tolerated.  Bare `__asm {` /
    # `}` braces are structural and not counted.
    if total_meaningful <= 2:
        padding_only = True
        for idx in meaningful_asm:
            low = lines[idx - 1].lower()
            if "__asm" in low:
                payload = low.split("__asm", 1)[1]
                payload = payload.replace("{", "").replace("}", "").replace(";", "").strip()
                if payload and payload not in ("nop", "int 3", "") and "nop" not in payload:
                    padding_only = False
                    break
        for idx in emit_lines:
            low = lines[idx - 1].lower()
            if "0x90" not in low and "0xcc" not in low and "nop" not in low:
                padding_only = False
                break
        if padding_only:
            return

    claimed = sorted((claimed_statuses or set()) - {"STUB", "SKIP"})
    suffix = f" but STATUS claims {', '.join(claimed)}" if claimed else ""
    result.error(
        naked_line,
        "E023",
        f"whole-function __declspec(naked) + __asm/__emit is not allowed{suffix} — "
        "naked asm is only for minor padding (1-2 alignment bytes: nop / _emit 0x90 / 0xCC); "
        "decompile the function to C instead",
    )


def _check_W020_asm_dump(
    result: LintResult, lines: list[str], claimed_statuses: set[str] | None = None
) -> None:
    """Flag asm-dump placeholder implementations (W020).

    Non-naked ``__asm``/``__emit`` bodies are pasted disassembly, not real C
    source.  Whole-function ``__declspec(naked)`` + ``__asm`` is escalated to
    E023 (error); this warning covers the remaining non-naked asm dumps.
    Warn once per file at the first hit.

    Status-aware: a file whose metadata claims a non-stub status
    (``EXACT``/``RELOC``/...) while its body is an asm dump escalates the
    warning — an asm dump cannot be a byte-match, so the STATUS is wrong.
    That is how "documented STUB" (expected) is told apart from a "claimed
    match on an asm dump" (a metadata bug) at a glance.
    """
    # Whole-function naked asm is handled by E023 — don't double-report W020.
    for line in lines:
        s = line.strip()
        if s.startswith("//") or s.startswith("/*") or s.startswith("*"):
            continue
        if "__declspec(naked)" in line:
            return
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


_ZERO_INIT_RE = re.compile(
    r"^\s*(?:extern\s+|static\s+)?(?:unsigned\s+|signed\s+|const\s+)?"
    r"[A-Za-z_][\w\s\*]*?\s+[A-Za-z_]\w*\s*(?:\[[^\]]*\])?\s*=\s*\{?\s*0\s*\}?\s*;"
)

_GLOBAL_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?[;=]")


def _strip_c_comments_strings(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Remove C comments and string/char literals from *line*.

    Stateful: *in_block_comment* tracks a ``/* ... */`` block spanning
    lines (e.g. a multi-line file preamble).  Quote-aware — ``/*``/``*/``
    inside string or char literals are not comment delimiters, and ``//``
    line comments terminate the rest of the line.  Returns
    ``(cleaned, new_block_state)``; literal contents become spaces so they
    never match code patterns.
    """
    out: list[str] = []
    i = 0
    n = len(line)
    in_str = False
    in_char = False
    while i < n:
        c = line[i]
        nxt = line[i + 1] if i + 1 < n else ""
        if in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            out.append(" ")
            i += 1
            continue
        if in_char:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_char = False
            out.append(" ")
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(" ")
            i += 1
            continue
        if c == "'":
            in_char = True
            out.append(" ")
            i += 1
            continue
        if c == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if c == "/" and nxt == "/":
            break  # line comment — rest of the line is not code
        out.append(c)
        i += 1
    return "".join(out), in_block_comment


def _check_W022_zero_init_bss(
    result: LintResult, lines: list[str], data_section_names: frozenset[str] = frozenset()
) -> None:
    """Flag file-scope zero initializers (W022).

    A file-scope ``= {0}`` / ``= 0`` forces the global into ``.data``
    (initialized) instead of ``.bss`` (uninitialized, virtual-only) — this
    is exactly the np-rebrew .data bloat (41K of zero-init arrays).  Leave
    the global uninitialized for .bss.

    Exception: a global whose name appears in ``rebrew-data.toml`` with
    ``section = ".data"`` (passed via *data_section_names*) stored zero-init
    data in the original's ``.data`` as well — dropping the initializer
    would shrink the rebuilt section and break byte identity, so the warning
    is suppressed for it.
    """
    depth = 0
    in_block_comment = False
    for i, line in enumerate(lines, start=1):
        cleaned, in_block_comment = _strip_c_comments_strings(line, in_block_comment)
        depth += cleaned.count("{") - cleaned.count("}")
        if depth == 0 and _ZERO_INIT_RE.match(cleaned.strip()):
            if data_section_names:
                name_match = _GLOBAL_NAME_RE.search(cleaned)
                if name_match and name_match.group(1) in data_section_names:
                    continue
            result.warning(
                i,
                "W022",
                "file-scope zero initializer (= {0} / = 0) puts the global in "
                ".data, not .bss — leave it uninitialized to keep the PE small",
            )
            return


def _check_W023_default_func_names(result: LintResult, lines: list[str], pedantic: bool) -> None:
    """Warn about functions with default names (W023) when --pedantic is used.

    Looks for function names that match common default patterns from decompilers
    like fcn, fn, fun, FUN_<addr>, sub_<addr>, etc.
    """
    if not pedantic:
        return

    # Join lines and remove comments/strings to avoid false positives
    code = "\n".join(lines)
    # Simple comment/string removal (not perfect but good enough for this check)
    # Remove /* ... */ comments
    while True:
        start = code.find("/*")
        end = code.find("*/", start + 2)
        if start == -1 or end == -1:
            break
        code = code[:start] + code[end + 2 :]
    # Remove // comments
    code_lines = []
    for line in code.split("\n"):
        comment_pos = line.find("//")
        if comment_pos != -1:
            line = line[:comment_pos]
        code_lines.append(line)
    code = "\n".join(code_lines)

    # Look for function definitions with default names
    # Pattern: return_type function_name(...) {
    func_def_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{"

    # Matches are monotonic, so count newlines incrementally — rescanning
    # the whole prefix per match is quadratic on merged multi-function files.
    last_pos = 0
    line_num = 1
    for match in re.finditer(func_def_pattern, code):
        func_name = match.group(2)
        line_num += code.count("\n", last_pos, match.start())
        last_pos = match.start()

        # Check against default patterns
        for pattern in _DEFAULT_FUNC_NAME_PATTERNS:
            if re.fullmatch(pattern, func_name):
                result.warning(
                    line_num,
                    "W023",
                    f"Function '{func_name}' has a default name; consider renaming to something meaningful",
                )
                break


def _check_style_rules(result: LintResult, cfg: ProjectConfig | None) -> None:
    """Check code style rules from project config (W024-W027).

    Config keys (all optional, from ``rebrew-project.toml [project.lint]``):
    ``naming_convention`` (snake_case|camelCase), ``brace_style``
    (same_line|new_line), ``indent_style`` (spaces|tabs), ``indent_size``,
    ``max_line_length``.  Read defensively via ``getattr`` so mocks and
    configs without a ``[project.lint]`` section default to "no rule".
    """
    if cfg is None:
        return
    lines = result._lines

    # Naming convention (W024): function definitions should follow the rule.
    naming = getattr(cfg, "lint_naming_convention", "none")
    if naming != "none":
        func_pat = re.compile(
            r"([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{"
        )
        for i, line in enumerate(lines, start=1):
            m = func_pat.search(line)
            if not m:
                continue
            func_name = m.group(2)
            if naming == "snake_case" and not re.fullmatch(r"[a-z_][a-z0-9_]*", func_name):
                result.warning(i, "W024", f"Function '{func_name}' should be snake_case")
            elif naming == "camelCase" and not re.fullmatch(r"[a-z][a-zA-Z0-9]*", func_name):
                result.warning(i, "W024", f"Function '{func_name}' should be camelCase")

    # Brace style (W025).
    brace = getattr(cfg, "lint_brace_style", "none")
    if brace != "none":
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if brace == "new_line" and stripped.endswith("{") and not stripped.startswith("{"):
                result.warning(i, "W025", "Opening brace should be on new line")
            elif brace == "same_line" and stripped == "{":
                result.warning(
                    i, "W025", "Opening brace should be on same line as preceding statement"
                )

    # Indent style (W026).
    indent = getattr(cfg, "lint_indent_style", "none")
    if indent != "none":
        if indent == "spaces":
            for i, line in enumerate(lines, start=1):
                if line.startswith("\t"):
                    result.warning(i, "W026", "Line uses tab indent, expected spaces")
        elif indent == "tabs":
            for i, line in enumerate(lines, start=1):
                if line.startswith(" "):
                    result.warning(i, "W026", "Line uses space indent, expected tabs")

    # Max line length (W027).
    max_len = getattr(cfg, "lint_max_line_length", 0)
    if max_len and max_len > 0:
        for i, line in enumerate(lines, start=1):
            if len(line) > max_len:
                result.warning(i, "W027", f"Line too long ({len(line)} > {max_len})")


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


def _cflags_key(cflags: str) -> frozenset[str]:
    """Normalize a CFLAGS string for redundancy comparison (W029).

    Flag ORDER carries no meaning for MSVC (/O2 /Gd == /Gd /O2), so compare
    as token sets — a lower-level entry only counts as redundant when its
    whole flag set is what the higher level would already supply.
    """
    return frozenset(cflags.split())


def check_redundant_cflags(
    cfg: ProjectConfig | None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> tuple[list[str], list[str]]:
    """Collect redundant cflags entries for W029 (module presets + per-function).

    Returns ``(preset_redundant, function_redundant)`` as human-readable
    strings so callers can attribute them to the right file.  Pure metadata
    + config logic — no .c file I/O.  Order-invariant flag comparison via
    ``_cflags_key``.

    The level ladder is: per-function cflags (rebrew-functions.toml) →
    module preset (``compiler.cflags_presets.<MODULE>``) → project
    ``compiler.cflags``.
    """
    if cfg is None:
        return [], []
    from rebrew.cli import resolve_cflags
    from rebrew.metadata import load_metadata as _load_meta

    project_cflags = str(getattr(cfg, "cflags", "") or "")
    project_key = _cflags_key(project_cflags)
    presets: dict[str, str] = getattr(cfg, "cflags_presets", {}) or {}

    preset_redundant: list[str] = []
    for mod, preset_cflags in sorted(presets.items()):
        if project_key and _cflags_key(str(preset_cflags)) == project_key:
            preset_redundant.append(f"cflags_presets.{mod} = '{preset_cflags}' (= project cflags)")

    metadata = (
        preloaded_metadata if preloaded_metadata is not None else _load_meta(cfg.metadata_dir)
    )
    fn_redundant: list[str] = []
    for (module, va), meta in sorted(metadata.items(), key=lambda kv: kv[0][1]):
        fn_cflags = str(meta.get("cflags") or "").strip()
        if not fn_cflags:
            continue
        inherited = resolve_cflags(cfg, None, module)
        if _cflags_key(fn_cflags) == _cflags_key(inherited):
            fn_redundant.append(
                f"{module} 0x{va:x}: cflags '{fn_cflags}' (= inherited '{inherited}')"
            )
    return preset_redundant, fn_redundant


def lint_file(
    filepath: Path,
    cfg: ProjectConfig | None = None,
    seen_vas: dict[Any, str] | None = None,
    seen_globals: dict[str, str] | None = None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None = None,
    pedantic: bool = False,
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
        function_index: ``(starts, spans)`` from the target function list
                        (built once per batch); enables the W028
                        annotation-staleness cross-check.

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
    result._lines = lines
    # DEBUG
    # print(f"[DEBUG] Linting {filepath} with {len(lines)} lines")

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
    # CFLAGS from metadata/inline annotations (for the E023 REBREW_ALLOW_NAKED
    # guard — the flag lives in rebrew-functions.toml, not in source lines).
    _file_cflags: set[str] = set()

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
        _metadata_size: str | None = None
        if mod and va_str:
            try:
                _va_int = int(va_str, 16)
                _metadata_override = _metadata_entries.get((mod, _va_int), {})
                _metadata_size = str(_metadata_override.get("SIZE", "")).strip() or None
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

            va_int = _check_E002_va(
                result, va_str, min_va=min_valid_va_for(cfg) if cfg else MIN_VALID_VA
            )

            # Check EVERY block (module + VA keyed): a duplicate appearing in
            # a later block of a multi-function file used to be skipped by the
            # old `i == 0` guard.  The (module, va) key keeps a multi-module
            # file whose blocks share a VA (a valid layout) is not flagged.
            _check_E013_duplicate_va(result, va_int, va_str, filepath, seen_vas, module=mod)

            if marker in ("FUNCTION", "STUB") and va_int is not None:
                _check_W028_stale_annotation(result, va_int, mod, cfg, function_index)

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
            _file_cflags.update(found_keys.get("CFLAGS", "").split())

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
                metadata_size=_metadata_size,
            )

    result.context_prefix = ""
    # Names of globals annotated section=".data" in rebrew-data.toml — W022
    # exemption (the original binary stored the zero-init data in .data).
    _data_section_names = frozenset(
        str(entry["name"])
        for entry in _data_metadata_entries.values()
        if entry.get("section") == ".data" and entry.get("name")
    )
    _check_E023_naked_asm(result, lines, _file_statuses, " ".join(_file_cflags))
    _check_W020_asm_dump(result, lines, _file_statuses)
    _check_W021_duplicate_globals(result, lines, filepath, seen_globals)
    _check_W022_zero_init_bss(result, lines, _data_section_names)
    _check_body_rules(result, lines, all_headers[0][1]["has_new"] if all_headers else False)
    _check_W023_default_func_names(result, lines, pedantic)
    _check_style_rules(result, cfg)
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
        "  W019   Inline metadata key (STATUS, SIZE, etc.) should be in rebrew-functions.toml\n\n"
        "  W020   Asm-dump placeholder (__emit / __asm block) instead of real C source\n\n"
        "  E023   Whole-function __declspec(naked) + __asm/__emit (only 1-2 nop/0x90/0xCC padding bytes allowed)\n\n"
        "  W021   Duplicate global symbol annotated in multiple files\n\n"
        "  W022   File-scope zero initializer (= {0}) forces the global into .data, not .bss\n"
        '         (exempt: globals annotated section = ".data" in rebrew-data.toml)\n\n'
        "  W023   Function has a default name (fcn, fn, fun, etc.); consider renaming\n\n"
        "  W024   Function name does not match project naming convention\n\n"
        "  W025   Opening brace style does not match project configuration\n\n"
        "  W026   Line indent style does not match project configuration\n\n"
        "  W027   Line too long (exceeds max_line_length)\n\n"
        "  W028   Annotation VA matches no function in the current function list\n"
        "         (stale after a binary update — re-annotate or refresh the list)\n\n"
        "  W029   Redundant cflags — per-function or preset cflags that only repeat\n"
        "         the inherited value (project cflags / module preset) — drop it\n"
        "         (the fallback chain already supplies the same flags)\n\n"
        "[dim]Checks for reccmp-style markers in each .c file, plus project-level\n"
        "corpus hygiene (W029 cflags redundancy via rebrew-functions.toml / presets).[/dim]"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Migrate inline metadata to rebrew-functions.toml and remove from source",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without writing"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show errors, suppress warnings"),
    pedantic: bool = typer.Option(
        False,
        "--pedantic",
        help="Warn on functions that have not been renamed yet to a meaningful name",
    ),
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
    # seen_vas keys are (module, va) tuples — bare int would falsely flag
    # cross-module files that legitimately share a VA in different targets.
    seen_vas: dict[Any, str] = {}
    seen_globals: dict[str, str] = {}

    # Pre-load metadata once for the whole batch (avoids per-file I/O).
    _preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    _preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    if cfg:
        _preloaded_metadata = load_metadata(cfg.metadata_dir)
        _preloaded_data_metadata = load_data_metadata(cfg.metadata_dir)
    # Pre-load the function list once for the whole batch (W028).
    function_index = _build_function_index(cfg) if cfg else None

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
            function_index=function_index,
            pedantic=pedantic,
        )
        all_results.append(result)
        if result.passed:
            passed += 1
        if not json_output and (not result.passed or (not quiet and result.warnings)):
            result.display(quiet=quiet)
        error_count += len(result.errors)
        warning_count += len(result.warnings)

    # W029: redundant cflags across metadata + presets — batch-level, since
    # no single .c file owns a preset and the redundancy is about the fallback
    # ladder.  Attribute per-function warnings back to the file that hosts the
    # VA when possible; presets and unattributed VAs land on a synthetic entry.
    if cfg is not None:
        preset_redundant, fn_redundant = check_redundant_cflags(cfg, _preloaded_metadata)
        if preset_redundant or fn_redundant:
            # Build VA -> file index from this run, for per-function attribution.
            va_to_result: dict[tuple[str, int], LintResult] = {}
            for r in all_results:
                for keys, _flags in _parse_multi_headers(r._lines):
                    m = keys.get("MODULE", "")
                    v = keys.get("VA", "")
                    if not m or not v:
                        continue
                    with contextlib.suppress(ValueError):
                        va_to_result[(m, int(v, 16))] = r
            # Presets: no single file — emit on a synthetic "config" result.
            if preset_redundant:
                syn = LintResult(Path("rebrew-project.toml"))
                for msg in preset_redundant:
                    syn.warning(1, "W029", f"redundant cflags preset: {msg}")
                all_results.append(syn)
                if not json_output and not quiet:
                    syn.display(quiet=False)
                warning_count += len(syn.warnings)
            # Per-function redundancies: attribute per file when we can.
            unattributed: list[str] = []
            for msg in fn_redundant:
                # msg format: "MODULE 0xVA: cflags '...' (= inherited '...')"
                try:
                    head = msg.split(":", 1)[0].strip()
                    mod_s, va_s = head.rsplit(" ", 1)
                    va_i = int(va_s, 16)
                    dest = va_to_result.get((mod_s, va_i))
                except (ValueError, IndexError):
                    dest = None
                if dest is not None:
                    if not any(c == "W029" and msg in m for _, c, m in dest.warnings):
                        dest.warning(dest.marker_line, "W029", f"redundant cflags: {msg}")
                        warning_count += 1
                        if not json_output and not quiet:
                            # Show the newly added warning inline (the batch
                            # loop already printed this file — emit just this).
                            console.print(
                                f"  [bold]{dest.filepath.name}[/bold]:{dest.marker_line}: "
                                f"[yellow]W029[/yellow]: redundant cflags: {msg}"
                            )
                else:
                    unattributed.append(msg)
            if unattributed:
                syn2 = LintResult(Path("rebrew-functions.toml"))
                for msg in unattributed:
                    syn2.warning(1, "W029", f"redundant cflags: {msg}")
                all_results.append(syn2)
                if not json_output and not quiet:
                    syn2.display(quiet=False)
                warning_count += len(syn2.warnings)
            # Recompute passed in case we flipped some files from passed->warned.
            passed = sum(1 for r in all_results if r.passed)

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

    # Apply --fix: migrate inline metadata to rebrew-functions.toml /
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
                        store = "rebrew-data.toml" if is_data_marker else "rebrew-functions.toml"
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
                    f"\n[green]Fixed:[/green] migrated {fix_count} inline annotations to rebrew-functions.toml"
                )

    if error_count > 0:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
