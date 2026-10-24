"""Validate source bindings, dedicated metadata, and C source conventions.

Identity, kind and state live in metadata; optional ADDRESS comments anchor the
next definition or variable declaration. Legacy inline state is rejected. Check
native function boundaries (W028), redundant compiler flags (W029), data extents
and ownership. Fixes update dedicated metadata through its locked writers.
"""

import bisect
import contextlib
import logging
import re
import shlex
import threading
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.table import Table
from rich.text import Text

from rebrew.c_parser import (
    CALLING_CONVENTION,
    find_extern_variables,
    find_function_name_in_node,
    mask_msvc_syntax,
    msvc_asm_spans,
    parse_c_source,
)
from rebrew.cli import (
    EXIT_MISMATCH,
    AllTargetsOption,
    TargetOption,
    all_targets_run,
    console,
    error_exit,
    json_print,
    option_default,
)
from rebrew.config import (
    DEFAULT_LINT_MAX_LINE_LENGTH,
    ProjectConfig,
    inventory_path_for,
    load_config,
)
from rebrew.lint_cflags import (
    RedundantFunctionCflags,
    RedundantPreset,
    check_redundant_cflags,
    drop_redundant_presets,
)
from rebrew.metadata.anchors import metadata_comments, parse_address_anchors
from rebrew.metadata.bindings import (
    DATA_KINDS,
    MIN_VALID_VA,
    SYMBOL_KINDS,
    file_backed_by_metadata,
    function_rows_for_file,
    min_valid_va_for,
)
from rebrew.metadata.data import load_data_metadata
from rebrew.metadata.functions import (
    FUNCTION_IDENTITY_FIELDS,
    METADATA_FIELDS,
    canonical_status,
    load_metadata,
)
from rebrew.metadata.source_provenance import (
    SOURCE_PROVENANCE_FILENAME,
    function_definition_hashes,
    load_source_provenance,
)
from rebrew.sources import (
    iter_sources,
    source_exts,
)
from rebrew.utils import (
    preset_module_key,
    read_source_text,
    rel_display_path,
    untrusted_ident,
)
from rebrew.workspace.status import EARNED_STATUSES, KNOWN_STATUSES, MATCHED_STATUSES

log = logging.getLogger(__name__)


def _is_comment_line(text: str) -> bool:
    """True when *text* is a whole-line comment in either supported style."""
    stripped = text.lstrip()
    return stripped.startswith(("//", "/*"))


# Patterns for default function names (to be used with --pedantic flag).
# Pre-compiled: W023 runs ``fullmatch`` per function in the TU.
DEFAULT_FUNC_NAME_PATTERNS = [
    re.compile(r"\bfcn\b"),
    re.compile(r"\bfn\b"),
    re.compile(r"\bfun\b"),
    re.compile(r"\bFUN_[0-9A-Fa-f]+\b"),
    re.compile(r"\bsub_[0-9A-Fa-f]+\b"),
    re.compile(r"\bfunc_[0-9A-Fa-f]+\b"),
    re.compile(r"\bthunk_[0-9A-Fa-f]+\b"),
]
_FUNC_DEF_STYLE_RE = re.compile(
    r"([a-zA-Z_][a-zA-Z0-9_]*)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{"
)


@dataclass
class LintResult:
    """Accumulated lint errors and warnings for a single source file.

    Why a custom linter? Standard C linters don't understand rebrew's
    metadata bindings. We need strict validation to ensure
    the CI pipeline and other tools (like `rebrew test`) can parse them.
    """

    filepath: Path
    errors: list[tuple[int, str, str]] = field(default_factory=list)
    warnings: list[tuple[int, str, str]] = field(default_factory=list)
    context_prefix: str = ""
    binding_line: int = 1
    # Counters collected during lint for --summary (avoids re-reading files).
    _status_counts: Counter[str] = field(default_factory=Counter)
    _kind_counts: Counter[str] = field(default_factory=Counter)
    # Lines of the file for style checks
    _lines: list[str] = field(default_factory=list)
    # Address anchors parsed from _lines — reused by the batch W029 VA index
    # instead of re-parsing every file (was a second full header pass).
    _headers: list[tuple[dict[str, str], dict[str, bool]]] | None = None

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

    def _display_lines(self, quiet: bool = False) -> list[str]:
        """Formatted error/warning lines; callers batch them into one print."""
        rel = untrusted_ident(self.filepath.name)
        lines = [
            f"  [bold]{rel}[/bold]:{line}: [red]{code}[/red]: {untrusted_ident(msg)}"
            for line, code, msg in self.errors
        ]
        if not quiet:
            lines += [
                f"  [bold]{rel}[/bold]:{line}: [yellow]{code}[/yellow]: {untrusted_ident(msg)}"
                for line, code, msg in self.warnings
            ]
        return lines

    def display(self, quiet: bool = False) -> None:
        """Print errors (and optionally warnings) to the console."""
        lines = self._display_lines(quiet)
        if lines:
            # One console.print per call: per-line prints each paid Rich's
            # full markup+highlight+wrap pipeline (2401 calls — half of
            # batch-lint time).  highlight=False drops the ReprHighlighter
            # decoration only; the explicit colour tags above still apply.
            console.print("\n".join(lines), highlight=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output."""
        return {
            "file": str(self.filepath.name),
            "path": str(self.filepath),
            "errors": [{"line": ln, "code": c, "message": m} for ln, c, m in self.errors],
            "warnings": [{"line": ln, "code": c, "message": m} for ln, c, m in self.warnings],
            "passed": self.passed,
        }


def _check_format_errors(result: LintResult, flags: dict[str, bool]) -> bool:
    """Check format-level errors (E001). Returns True if validation should proceed."""
    if not flags["has_new"]:
        result.error(result.binding_line, "E001", "Missing function metadata binding")
        return False

    return True


def _check_E001_kind(result: LintResult, kind: str) -> None:
    if kind not in SYMBOL_KINDS:
        result.error(result.binding_line, "E001", f"Invalid metadata kind: {kind}")


def _check_E002_va(result: LintResult, va_str: str, min_va: int = MIN_VALID_VA) -> int | None:
    try:
        va_int = int(va_str, 16)
        if not (min_va <= va_int <= 0xFFFFFFFF):
            result.error(result.binding_line, "E002", f"VA {va_str} is suspicious (outside range)")
        return va_int
    except ValueError:
        result.error(result.binding_line, "E002", f"Invalid VA format: {va_str}")
        return None


def _check_E013_duplicate_va(
    result: LintResult,
    va_int: int | None,
    va_str: str,
    filepath: Path,
    seen_vas: dict[Any, str] | None,
    module: str = "",
    kind: str = "",
    lines: list[str] | None = None,
    binding_line: int = 0,
    seen_va_defines: dict[Any, bool] | None = None,
) -> None:
    if va_int is None or seen_vas is None:
        return
    # Key on (module, va) so a multi-module file whose blocks share a VA
    # (a valid layout) is not flagged, while a true duplicate — same module
    # + VA, in the same or another file — is.
    key: Any = (module, va_int) if module else va_int
    defines = _block_defines(lines, binding_line) if kind in DATA_KINDS else True
    if key in seen_vas:
        # Data-binding duplicates collide only when BOTH sides define the
        # symbol (two initializers = LNK4006 risk).  The normal
        # progressive-ownership shape — owner TU extern-declares (or bare
        # claim) while link scaffolding holds the single definition — is
        # unambiguous and must not fail the gate.
        if kind in DATA_KINDS and not (defines and (seen_va_defines or {}).get(key, False)):
            if seen_va_defines is not None:
                seen_va_defines[key] = seen_va_defines.get(key, False) or defines
            seen_vas[key] = f"{rel_display_path(filepath)}"
            return
        result.error(
            result.binding_line, "E013", f"Duplicate VA {va_str} — also in {seen_vas[key]}"
        )
    else:
        if seen_va_defines is not None:
            seen_va_defines[key] = defines
        seen_vas[key] = rel_display_path(filepath)


def _block_defines(lines: list[str] | None, binding_line: int) -> bool:
    """True when the declaration after a binding line is a definition.

    Skips blanks/comments; a first code line with an initializer (``=``)
    that is not ``extern`` counts as a definition.  Tentative definitions
    (``int x;``) and pure bindings (next binding follows) do not.
    """
    if not lines or binding_line < 1:
        return False
    for raw in lines[binding_line:]:
        stripped = raw.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        if stripped.startswith("extern"):
            return False
        return "=" in stripped
    return False


def _function_containing_va(
    spans: list[tuple[int, int, str]], va: int
) -> tuple[int, int, str] | None:
    """Return the ``(start, end, name)`` span containing *va*, or None.

    ``spans`` is a list sorted by start.  A span whose *start* equals *va*
    is NOT a "contains" — the caller already established that *va* is not a
    function start, so only strictly-inside hits qualify (a moved/merged
    annotation now points into the body of a different function).  A shorter
    span nested in a longer one does not hide the outer tail.
    """
    if not spans or va <= spans[0][0]:
        return None
    # bisect the span tuples themselves against (va, +inf, ""): the second and
    # third elements only break ties at an exact start match, so the probe
    # lands on the last span whose start is <= va, as a starts list did.
    idx = bisect.bisect_right(spans, (va, float("inf"), "")) - 1
    # The latest start is not enough: a shorter span nested in a longer one
    # hides the outer tail. Walk back to the nearest span that still covers va.
    while idx >= 0:
        start, end, name = spans[idx]
        if start < va < end:
            return (start, end, name)
        idx -= 1
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
        raw_va = f.get("va")
        if raw_va is None:
            continue
        va = int(raw_va)
        # 16-bit DOS targets address code from segment 0, so VA 0 is legitimate
        # there (min_valid_va_for returns 0) — dropping it fired a false W028 on
        # every `// FUNCTION: GAME 0x0` annotation.
        if va < min_valid_va_for(cfg):
            continue
        starts.add(va)
        spans.append((va, va + max(int(f.get("size", 0) or 0), 1), str(f.get("name", ""))))
    spans.sort()
    return starts, spans


def _staleness_fix(cfg: ProjectConfig | None) -> str:
    """Pick a staleness fix hint from which artifact is newer.

    Stale annotations have two very different causes: the target binary was
    replaced (refresh the function inventory), or the annotations moved / the inventory
    no longer reflects the target (re-annotate) — recommending ``rebrew
    intake`` for the second case is wrong.  The binary-vs-list mtime
    comparison is a cheap proxy: a binary newer than the list means it
    plausibly changed after the list was written; a list at least as new as
    the binary means the binary cannot have changed since, so the bindings
    (or a list regenerated from a different binary, e.g. a rebuild) are at
    fault.  Falls back to a cause-neutral message when either file's mtime
    is unavailable.
    """
    binary_newer: bool | None = None
    try:
        bin_path = Path(str(getattr(cfg, "target_binary", "")))
        rev_dir = getattr(cfg, "reversed_dir", None)
        inv_path = inventory_path_for(rev_dir, cfg) if rev_dir else None
        if inv_path is not None and bin_path.is_file() and inv_path.is_file():
            # Nanosecond mtimes: second-granularity floats tie when a rebuild
            # and inventory refresh land in the same wall-clock second (common
            # on scripts / coarse Docker volume clocks), flipping the hint.
            binary_newer = bin_path.stat().st_mtime_ns > inv_path.stat().st_mtime_ns
    except OSError:
        binary_newer = None

    annotate = "re-annotate the moved functions (`rebrew skeleton <new_va>` or edit the bound VA)"
    if binary_newer is True:
        return (
            "The target binary is newer than the function inventory — it likely changed: "
            "re-run `rebrew intake` / `rebrew binary functions` to refresh it, then " + annotate
        )
    if binary_newer is False:
        return (
            "The function inventory is as new as the target binary, so the binary did not "
            "change: " + annotate + ". If the inventory was regenerated from a different "
            "binary (e.g. a rebuilt artifact) instead of the target, regenerate it "
            "from the target"
        )
    return (
        "The function inventory no longer matches these annotations: if the target binary "
        "changed, re-run `rebrew intake` / `rebrew binary functions` to refresh it; "
        "otherwise " + annotate + " (or regenerate the inventory if it was built from a "
        "different binary, e.g. a rebuilt artifact)"
    )


def _check_W028_stale_annotation(
    result: LintResult,
    va_int: int,
    module: str,
    cfg: ProjectConfig | None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None,
    status: str = "",
    metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> None:
    """Warn when a FUNCTION/STUB kind VA matches no function start (W028).

    A stale FUNCTION/STUB metadata binding has a VA that
    no longer corresponds to a function in the current binary.  After a
    binary update or a re-discovery the function either moved — the binding
    now points *inside* another function's span — or was removed (no
    function at that VA).  Either way ``rebrew test``/``verify`` compile
    against the wrong bytes and status/todo keep reporting phantom
    functions.

    Uses the target's discovery inventory (the same file ``rebrew intake`` /
    ``discover`` write) as ground truth.  ``LIBRARY`` bindings are excluded
    (import stubs) and ``GLOBAL``/``DATA`` bindings are data, not code;
    bindings of a different target module are filtered by the caller's
    config.  Silent when no function index is available.
    """
    if function_index is None:
        return
    target_module_name = getattr(cfg, "module", None) if cfg is not None else None
    if target_module_name and module and module != target_module_name:
        return  # another target's module — E012 already flags the module
    starts, spans = function_index
    if va_int in starts:
        return
    # A byte-matched annotation outranks the inventory.  The inventory comes
    # from heuristic discovery (rizin + a capstone sweep), which merges
    # adjacent functions when the boundary is only `ret` + alignment padding;
    # EXACT/RELOC means this VA already compiled and compared byte-for-byte
    # against the target there, which is strictly stronger evidence than a
    # sweep's guess.  Warning on those is a false positive that cannot be
    # actioned -- "re-annotate the bound VA" would break a matched function.
    # guild-rebrew hit 15 of these at once, including an EXACT row whose
    # supposed host was split from it by `ret; nop; nop` at 0x1000d92d.
    if status.upper() in MATCHED_STATUSES:
        return
    host = _function_containing_va(spans, va_int)
    # The same merge, shown by the annotations themselves: the host's start is
    # an annotated function whose SIZE ends at or before this binding, so the
    # two annotations tile the host's range and discovery joined them.
    if host is not None and metadata is not None:
        try:
            host_size = int(metadata.get((module, host[0]), {}).get("size") or 0)
        except (TypeError, ValueError):
            host_size = 0
        if host_size and host[0] + host_size <= va_int:
            return
    # Append the mtime-aware fix hint only to the first stale address in the
    # file — repeating it per binding would drown the signal.
    hint = _staleness_fix(cfg) if not any(c == "W028" for _, c, _ in result.warnings) else ""
    if host is not None:
        result.warning(
            result.binding_line,
            "W028",
            f"annotation VA 0x{va_int:x} points inside function "
            f"'{host[2] or 'a function'}' (moved/merged) — re-annotate the "
            "bound VA or refresh the function inventory (`rebrew binary functions`)" + hint,
        )
    else:
        result.warning(
            result.binding_line,
            "W028",
            f"annotation VA 0x{va_int:x} has no function in the current "
            "function inventory (removed or shifted) — re-annotate the bound VA "
            "or refresh the function inventory (`rebrew binary functions`)" + hint,
        )


def _check_W030_va_order(result: LintResult, all_headers: list[Any], lines: list[str]) -> None:
    """Warn when a module's FUNCTION/STUB definitions do not ascend by VA (W030).

    The linker lays out a translation unit's functions in source order, so a
    definition placed above a lower-VA one links at the wrong address and
    displaces every function between them.  Bindings with only comments or
    blank lines between them share one body (identical copies at several VAs)
    and count as one definition, placed by its lowest VA.  Each module is
    checked on its own: a binding for another build carries that build's VA.
    """
    groups: list[dict[str, tuple[int, int]]] = []
    prev_line = -1
    prev_definition = 0
    for found_keys, _flags in all_headers:
        if found_keys.get("KIND", "") not in ("FUNCTION", "STUB"):
            continue
        try:
            va = int(found_keys.get("VA", ""), 16)
        except ValueError:
            continue
        line = int(found_keys.get("_LINE", "1"))
        definition = int(found_keys.get("_DEFINITION_LINE", "0"))
        if not definition:
            continue
        between = lines[prev_line : line - 1] if prev_line >= 0 else ["code"]
        separate = (
            definition != prev_definition
            if definition and prev_definition
            else any(t.strip() and not t.lstrip().startswith("//") for t in between)
        )
        if not groups or separate:
            groups.append({})
        mod = found_keys.get("MODULE", "")
        cur = groups[-1].get(mod)
        groups[-1][mod] = (va, line) if cur is None else (min(va, cur[0]), cur[1])
        prev_line = line
        prev_definition = definition
    highest: dict[str, int] = {}
    for group in groups:
        for mod, (va, line) in group.items():
            prev = highest.get(mod)
            if prev is not None and va < prev:
                result.warning(
                    line,
                    "W030",
                    f"{mod} 0x{va:x} is defined after {mod} 0x{prev:x}: the linker places "
                    "functions in source order, so move this definition above the "
                    "higher-VA one",
                )
            highest[mod] = va if prev is None else max(prev, va)


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
            result.binding_line,
            "W018",
            "Missing CFLAGS in metadata and no default cflags in project config",
        )


# Unknown keys that are safe for `--fix` to strip outright: retired
# annotations whose value is now derived from the C source itself, so the
# inline line carries no information (SYMBOL from the function definition,
# PROTOTYPE from the definition line).  Any other unknown key is only
# warned about — it may be a typo of a real key or a prose note, and
# deleting it would destroy information.
_FIXABLE_UNKNOWN_KEYS = frozenset({"SYMBOL", "PROTOTYPE"})

# Statuses that carry no claim about a function's body, so they cannot
# contradict what a check found. A file claiming only these does not gain
# a "but STATUS claims ..." suffix.
_UNCLAIMED_STATUSES = frozenset({"STUB", "SKIP"})


def _check_E015_kind_consistency(
    result: LintResult, kind: str, module: str, status: str, cfg: ProjectConfig | None = None
) -> None:
    # E015's intent is library-module attribution: a FUNCTION kind on a
    # module configured as library should be LIBRARY.  A STUB-status function
    # may legitimately keep either its STUB kind or the FUNCTION kind
    # (status lives in rebrew-functions.toml per the metadata convention), so
    # both are allowed. Explicit LIBRARY bindings may use the target module
    # for vendored source.
    lib_modules = cfg.library_modules if cfg and cfg.library_modules is not None else set()
    if module in lib_modules or kind == "LIBRARY":
        expected_kind = "LIBRARY"
        allowed = {"LIBRARY"}
    elif status == "STUB":
        expected_kind = "FUNCTION"
        allowed = {"FUNCTION", "STUB"}
    else:
        expected_kind = "FUNCTION"
        allowed = {"FUNCTION"}
    if kind not in allowed and kind in SYMBOL_KINDS and kind not in DATA_KINDS:
        result.error(
            result.binding_line,
            "E015",
            f"Kind {kind} inconsistent with module {module!r} (expected {expected_kind})",
        )


def _check_E004_status_value(result: LintResult, status: str) -> None:
    """A persisted STATUS outside KNOWN_STATUSES is a typo/legacy value.

    ``canonical_status`` upper-cases and maps the ``NEAR_MATCH`` alias; an
    unknown word still flows through the overlay as if valid, so flag it
    instead of silently treating it as a real classification.
    """
    if status and canonical_status(status) not in KNOWN_STATUSES:
        result.error(
            result.binding_line,
            "E004",
            f"Unknown STATUS {status!r}; known values: {', '.join(sorted(KNOWN_STATUSES))}",
        )


def _check_E008_size_value(result: LintResult, metadata_size: str | None) -> None:
    """A metadata SIZE that is not an integer misleads byte extraction.

    Validates the ``rebrew-functions.toml`` value only: ``// SIZE:`` inline is
    the reccmp-native contract (see W019) and is not part of this rule, matching
    the reserved E008 scope.  A non-numeric *metadata* SIZE would make a
    consumer slice the wrong byte count or silently fall back.
    """
    if not metadata_size:
        return
    try:
        int(metadata_size, 0)
    except ValueError:
        result.error(
            result.binding_line, "E008", f"metadata SIZE {metadata_size!r} is not an integer"
        )


def _check_E017_contradictory(result: LintResult, status: str, kind: str) -> None:
    if status == "NEAR_MATCHING" and kind == "STUB":
        result.error(
            result.binding_line, "E017", f"Contradictory: status is {status} but kind is STUB"
        )
    elif kind == "STUB" and status in EARNED_STATUSES:
        # A byte-matched or proven function marked STUB (stale address from
        # stub generation, metadata later promoted).  The STUB kind hides a
        # developed function from status/todo and misleads reversers.
        result.error(
            result.binding_line,
            "E017",
            f"Contradictory: status is {status} but kind is STUB — "
            "remove the stale STUB kind (function is developed)",
        )


def _check_W005_blocker(result: LintResult, status: str, found_keys: dict[str, str]) -> None:
    # BLOCKER lives in rebrew-functions.toml metadata; the metadata overlay already injects it
    # into found_keys before this check runs, so this fires only when absent from both.
    if status == "STUB" and "BLOCKER" not in found_keys:
        result.warning(
            result.binding_line,
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
            result.binding_line,
            "W006",
            f"Library module {module!r} missing source metadata "
            "(reference file, e.g. SBHEAP.C:195 or deflate.c)",
        )


def _check_W015_va_case(result: LintResult, va_str: str) -> None:
    if va_str and va_str.startswith("0x"):
        hex_digits = va_str[2:]
        if hex_digits != hex_digits.lower() and hex_digits != hex_digits.upper():
            result.warning(
                result.binding_line,
                "W015",
                f"VA '{va_str}' has mixed-case hex digits (prefer consistent case)",
            )


def _check_W031_metadata_store(cfg: ProjectConfig) -> list[LintResult]:
    """W031: the metadata TOMLs carry something a reader will not honour.

    The gated writers reject these shapes, so a file that holds one was edited
    by hand (or written by an older tree): an unknown field, a STATUS outside
    the store's vocabulary, half a provenance pair, a provenance tag outside
    :data:`rebrew.metadata.functions.PROVENANCE_TAGS`, a top-level key that is neither the
    format stamp nor a ``MODULE.0xVA`` entry, or a missing / foreign format
    stamp, or duplicate spellings of the same identity. A reader drops an
    unknown key silently and falls back to the
    default, so the symptom is a flag that "did not apply" with nothing to
    explain it.  Warn-only, reported per entry: the rest of the store loads.
    """
    from rebrew.metadata.data import (
        DATA_METADATA_FIELDS,
        DATA_METADATA_FILENAME,
        validate_data_field,
    )
    from rebrew.metadata.document import (
        FORMAT_KEY,
        FORMAT_VERSION,
        FUNCTION_FORMAT_VERSION,
        parse_metadata_key,
    )
    from rebrew.metadata.functions import PROVENANCE_TAGS, validate_metadata_field
    from rebrew.metadata.source_schema import validate_source_metadata
    from rebrew.metadata.storage import metadata_store
    from rebrew.workspace.status import KNOWN_STATUSES

    results: list[LintResult] = []

    def check_store(
        path: Path,
        fields: frozenset[str],
        *,
        data_store: bool,
    ) -> None:
        if not metadata_store(path).exists():
            return
        try:
            doc = metadata_store(path).read("metadata lint")
        except (OSError, ValueError) as exc:
            # Returning here would report a clean run over a store this check
            # could not read, losing every W031 finding it holds.
            res = LintResult(path)
            res.warning(1, "W031", f"store could not be parsed, contents unchecked: {exc}")
            results.append(res)
            return
        if not isinstance(doc, dict):
            res = LintResult(path)
            res.warning(1, "W031", "store is not a TOML table, contents unchecked")
            results.append(res)
            return
        problems: list[str] = []
        expected_format = FORMAT_VERSION if data_store else FUNCTION_FORMAT_VERSION
        stamp = doc.get(FORMAT_KEY)
        if stamp is None:
            problems.append(
                f"no {FORMAT_KEY} stamp (a writer adds {FORMAT_KEY} = {expected_format})"
            )
        elif isinstance(stamp, bool) or stamp != expected_format:
            problems.append(f"{FORMAT_KEY} = {stamp!r}, this rebrew reads {expected_format}")
        known_fields = {f.upper() for f in fields}
        identities: dict[tuple[str, int], str] = {}
        for key, entry in doc.items():
            if key == FORMAT_KEY:
                continue
            if key == "source" and not data_store:
                try:
                    validate_source_metadata(entry)
                except ValueError as exc:
                    problems.append(f"source: {exc}")
                continue
            if not isinstance(entry, dict):
                problems.append(
                    f"top-level {key!r} is neither {FORMAT_KEY!r} nor a MODULE.0xVA entry"
                )
                continue
            identity = parse_metadata_key(key)
            if identity is None:
                problems.append(f"top-level {key!r} is not a MODULE.0xVA entry")
            elif identity in identities:
                problems.append(
                    f"duplicate metadata keys {identities[identity]!r} and {key!r} "
                    "resolve to the same module and VA; writes require consolidation"
                )
            else:
                identities[identity] = key
            lower = {str(k).lower() for k in entry}
            for name in entry:
                if str(name).upper() not in known_fields:
                    problems.append(f"{key}: unknown field {name!r} (every reader ignores it)")
                elif str(name) != str(name).lower():
                    problems.append(f"{key}: field {name!r} must use lower-case spelling")
            for name, value in entry.items():
                if str(name).upper() not in known_fields:
                    continue
                try:
                    if data_store:
                        validate_data_field(str(name), value)
                    elif str(name).upper() in METADATA_FIELDS:
                        validate_metadata_field(str(name), value)
                        if (
                            str(name).lower() == "status"
                            and canonical_status(value) not in KNOWN_STATUSES
                        ):
                            raise ValueError(f"unknown STATUS {value!r}")
                    elif not isinstance(value, str):
                        raise ValueError(f"{name} must be a string, got {value!r}")
                except (TypeError, ValueError) as exc:
                    problems.append(f"{key}: {exc}")
            if ("updated_by" in lower) != ("updated_at" in lower):
                problems.append(
                    f"{key}: half a provenance pair (updated_by / updated_at are written together)"
                )
            tag = str(entry.get("updated_by") or "")
            if tag and tag not in PROVENANCE_TAGS:
                problems.append(f"{key}: unknown provenance tag {tag!r}")
        if problems:
            res = LintResult(path)
            for problem in problems:
                res.warning(1, "W031", problem)
            results.append(res)

    # METADATA_FIELDS is upper-case while FUNCTION_IDENTITY_FIELDS is lower-case
    # (`file`, `symbol`, `name`, `kind`): compare both spellings, or a
    # canonical identity field reads as unknown.
    function_fields = frozenset(f.upper() for f in METADATA_FIELDS) | frozenset(
        f.upper() for f in FUNCTION_IDENTITY_FIELDS
    )
    check_store(
        (Path(cfg.metadata_dir) / "rebrew-functions.toml").resolve(),
        function_fields,
        data_store=False,
    )
    check_store(
        (Path(cfg.metadata_dir) / DATA_METADATA_FILENAME).resolve(),
        DATA_METADATA_FIELDS,
        data_store=True,
    )
    return results


def _check_W034_identity_paths(cfg: ProjectConfig) -> list[LintResult]:
    """W034: a stored ``file`` identity that a consumer cannot safely join.

    ``verify`` compiles ``reversed_dir / file`` for a function row, data scans
    match a global to the source that owns it, ``rename`` rewrites the path,
    and BinSync reads it.  An absolute path or a ``..`` segment names a file
    the metadata's author chose rather than one in this checkout.  Writers
    refuse it (:func:`rebrew.metadata.functions.validate_identity_file`); this reports
    rows that were written before the gate, or edited by hand, in either store.
    """
    from rebrew.metadata.data import DATA_METADATA_FILENAME
    from rebrew.metadata.functions import validate_identity_file
    from rebrew.metadata.storage import metadata_store

    results: list[LintResult] = []
    for filename in ("rebrew-functions.toml", DATA_METADATA_FILENAME):
        path = (Path(cfg.metadata_dir) / filename).resolve()
        if not metadata_store(path).exists():
            continue
        try:
            doc = metadata_store(path).read("metadata identity lint")
        except (OSError, ValueError) as exc:
            # An unreadable store hides every W034 finding in it, which reads
            # as a clean run over identities this check never saw.
            res = LintResult(path)
            res.warning(1, "W034", f"store could not be parsed, identities unchecked: {exc}")
            results.append(res)
            continue
        if not isinstance(doc, dict):
            res = LintResult(path)
            res.warning(1, "W034", "store is not a TOML table, identities unchecked")
            results.append(res)
            continue
        problems: list[str] = []
        for key, entry in doc.items():
            if not isinstance(entry, dict):
                continue
            value = str(entry.get("file") or "")
            if not value:
                continue
            try:
                validate_identity_file(value)
            except ValueError as exc:
                problems.append(f"{key}: {exc}")
        if not problems:
            continue
        res = LintResult(path)
        for problem in problems:
            res.warning(1, "W034", problem)
        results.append(res)
    return results


def _check_W035_unknown_modules(cfg: ProjectConfig) -> list[LintResult]:
    """W035: a store row whose module belongs to no target in this project.

    ``status`` / ``todo`` / the dashboards filter rows by module, so a row left
    behind by a renamed target is invisible everywhere while still sitting in
    the store.  Known modules are the project module, every target module, the
    active target's library modules, and every target's external libraries —
    a D3DX8 row is read while server.dll is the default, but only the TL client
    links d3dx8.lib, so that row is live, not stale.
    """
    from rebrew.metadata.functions import load_metadata

    known = {preset_module_key(str(getattr(cfg, "module", "") or ""))}
    known |= {preset_module_key(str(name)) for name in (getattr(cfg, "target_modules", None) or ())}
    known |= {
        preset_module_key(str(name)) for name in (getattr(cfg, "library_modules", None) or ())
    }
    known |= {
        preset_module_key(str(name)) for name in (getattr(cfg, "all_library_modules", None) or ())
    }
    known.discard("")
    if not known:
        return []
    unknown = sorted(
        {
            str(module)
            for (module, _va) in load_metadata(cfg.metadata_dir, deepcopy=False)
            if preset_module_key(str(module)) not in known
        }
    )
    if not unknown:
        return []
    res = LintResult(Path("rebrew-functions.toml"))
    for module in unknown:
        res.warning(
            1,
            "W035",
            f"module {module!r} matches no target module or library module"
            " (rows for a renamed or removed target stay invisible to status/todo)",
        )
    return [res]


def _check_W036_stray_metadata_store(cfg: ProjectConfig) -> list[LintResult]:
    """W036: a metadata store living outside the directory the readers use.

    The stores are resolved by directory, not by search: a tool asked for a
    module reads ``<metadata_dir>/rebrew-data.toml`` and gets **whatever is
    there**, with no fallback to another copy.  So a second ``rebrew-data.toml``
    somewhere else in the tree is not a backup -- it is a file that answers for
    a directory if a tool is pointed at it, and is invisible otherwise.

    Measured on guild-rebrew (round 162): a stray ``./rebrew-data.toml`` at the
    project root held **1** entry while the store in ``src/`` held **1170**,
    and `rebrew lint` reported 0 warnings.  Loaded against the root, the store
    resolves and returns the 1 entry with no complaint.

    Warn-only: a stray copy is not itself a defect, it is a thing that will be
    read by accident.
    """
    from rebrew.metadata.storage import project_metadata_stores

    store_names = {"rebrew-data.toml", "rebrew-functions.toml", SOURCE_PROVENANCE_FILENAME}
    dirs: set[Path] = set()
    for attr in ("metadata_dir", "reversed_dir", "shared_dir"):
        value = getattr(cfg, attr, None)
        if value:
            dirs.add(Path(value).resolve())
    results: list[LintResult] = []
    skip = {".git", "build", ".scratch", "node_modules", ".venv"}
    project_root = Path(cfg.root).resolve()
    for store in project_metadata_stores(cfg.root, recursive=True):
        path = store.path
        if path.name not in store_names:
            continue
        # Ignore project descendants, not a parent hosting this project.
        parts = path.parent.resolve().relative_to(project_root, walk_up=True).parts
        if any(part in skip for part in parts):
            continue
        if path.parent.resolve() in dirs:
            continue
        res = LintResult(filepath=path)
        res.warning(
            1,
            "W036",
            "metadata store outside the configured directory; readers resolve "
            "stores by directory, so this one answers for "
            f"{path.parent} and is invisible otherwise",
        )
        results.append(res)
    return results


def _type_spelling(text: str) -> str:
    """*text* with whitespace collapsed and dropped beside punctuation."""
    return re.sub(r"\s*([^\w\s])\s*", r"\1", " ".join(text.split()))


def _check_W037_data_definition(
    result: LintResult, text: str, filepath: Path, cfg: ProjectConfig
) -> None:
    """W037: a data row's ``type`` / ``size`` disagree with its owning source.

    For every ``rebrew-data.toml`` row whose ``file`` names *filepath* and
    whose module belongs to the active target, find the file-scope definition
    of the row's ``name`` and compare its byte size with the extent of the
    row.  A row's ``size`` drives layout, verification and accounting, so a
    stale one silently claims bytes its symbol no longer owns (guild-rebrew
    ``g_gap_10034644``: the row said ``char[44]`` after a generator shrank the
    definition to 36 bytes, and the stale extent overlapped two globals).

    ``extern`` declarations are users, not the definition, and are ignored,
    except for ``storage_kind = "span"`` rows: a layout span has no standalone
    owner, so its owning file may hold only an ``extern`` inventory view
    (``extern unsigned char g_span[0x7];``), and that view is the extent the
    file records.  A definition still wins when the file has one.

    A tiled allocation is one reference allocation the source splits into a
    short leading definition plus separate definitions for its interior names
    and pads (guild-rebrew ``g_slot_table``: code needs the interior names as
    separate symbols for byte-identical codegen).  Its row keeps the full
    extent; each piece is an ``alias`` row whose ``backing`` names the
    allocation and whose name is defined in the same file.  The source extent
    is then the leading definition plus the pieces, walked in VA order while
    each starts where the previous one ends; a backed row without a definition
    here is a view and takes no part.  A hole before the next piece is
    reported as such; a tiling that ends short of or past the row is compared
    like a single definition.

    Skipped rather than guessed: a row or file without the name, a name with
    no definition (or span view) in the file, definitions that disagree with
    each other (``#if`` branches), and any size the x86_32 data model of
    :func:`rebrew.data_layout.data_symbol_size` cannot compute (struct, union
    and unknown typedef types, unsized arrays, other architectures).  Only
    byte sizes are compared, the row's ``size`` and its ``type``'s extent each
    against the source's: a spelling difference with equal size (``[0x104]``
    against ``[260]``, a typedef against its expansion) is not reported.
    """
    from rebrew.c_parser import find_extern_variables, find_variable_roles
    from rebrew.data_layout import data_symbol_size
    from rebrew.metadata.data import data_rows_for_path, module_visible_to_target

    try:
        rows = data_rows_for_path(cfg.metadata_dir, filepath)
    except (OSError, ValueError):
        return  # W031 reports an unreadable store.
    rows = [
        (module, va, entry)
        for module, va, entry in rows
        if entry.get("name") and module_visible_to_target(module, cfg)
    ]
    if not rows:
        return
    variables = find_extern_variables(text, include_definitions=True)
    defined, _declared, _uses = find_variable_roles(text)
    arch = str(getattr(cfg, "arch", "") or "x86_32")

    def source_extent(name: str, *, span: bool) -> tuple[str, int, int] | None:
        """``(type, bytes, line)`` of *name*'s definition (or span view) here."""
        named = [v for v in variables if v.name == name]
        externs = [v for v in named if re.match(r"\s*extern\b", v.declaration)]
        if name in defined:
            candidates = [v for v in named if v not in externs] or externs
        elif span:
            candidates = externs
        else:
            return None
        spellings = {_type_spelling(v.type_str) for v in candidates}
        if len(spellings) != 1:
            return None
        source_type = spellings.pop()
        size = data_symbol_size({"type": source_type}, arch=arch)
        return (source_type, size, candidates[0].line) if size else None

    pieces: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for module, va, entry in rows:
        if (
            entry.get("storage_kind") == "alias"
            and entry.get("backing")
            and str(entry["name"]) in defined
        ):
            pieces.setdefault((module, str(entry["backing"])), []).append((va, str(entry["name"])))
    for module, va, entry in rows:
        name = str(entry["name"])
        found = source_extent(name, span=entry.get("storage_kind") == "span")
        if found is None:
            continue
        source_type, source_size, line = found
        row_type = _type_spelling(str(entry.get("type") or ""))
        row_type_size = data_symbol_size({"type": row_type}, arch=arch) if row_type else 0
        row_size = data_symbol_size({"size": entry.get("size")}, arch=arch)
        row_desc = f"type {row_type!r} ({row_type_size or '?'} bytes)" if row_type else "no type"
        if row_size:
            row_desc += f", size {row_size}"
        where = f"data row {module}.0x{va:08x} {untrusted_ident(name)} says {row_desc}"
        tiles = sorted(p for p in pieces.get((module, name), []) if p[0] > va)
        if tiles:
            source_size, hole = _tiled_extent(va + source_size, tiles, source_extent)
            source_size -= va
            if hole is not None and hole[0] < va + max(row_size, row_type_size):
                result.warning(
                    line,
                    "W037",
                    f"{where} but its tiled definition here leaves "
                    f"[0x{hole[0]:08x}, 0x{hole[1]:08x}) uncovered before "
                    f"{untrusted_ident(hole[2])}; define the missing piece and record it "
                    "with rebrew data set --storage-kind 0xVA=alias and "
                    f"rebrew data set --backing {shlex.quote(f'0xVA={name}')}",
                )
                continue
            source_type = f"{source_type} plus {len(tiles)} backed definition(s)"
        fixes: list[str] = []
        if row_type_size and row_type_size != source_size:
            fixes.append(
                f"rebrew data set --type 0x{va:08x}=TYPE ({source_size} bytes)"
                if tiles
                else f"rebrew data set --type {shlex.quote(f'0x{va:08x}={source_type}')}"
            )
        if row_size and row_size != source_size:
            fixes.append(f"rebrew data set --size 0x{va:08x}={source_size}")
        if not fixes:
            continue
        kind = "tiled definition" if tiles else "definition" if name in defined else "span view"
        result.warning(
            line,
            "W037",
            f"{where} but its {kind} here is {source_type!r} ({source_size} bytes); "
            f"fix: {' and '.join(fixes)}",
        )


def _tiled_extent(
    end: int,
    tiles: list[tuple[int, str]],
    measure: Callable[..., tuple[str, int, int] | None],
) -> tuple[int, tuple[int, int, str] | None]:
    """End of a tiled allocation's contiguous definitions, and the first hole.

    *end* is where the leading definition stops; *tiles* are the backed
    ``(va, name)`` pieces in VA order.  A piece that starts inside the covered
    bytes is skipped: the walk measures coverage, and ``rebrew verify --data``
    checks where each definition lands.  A piece that starts later leaves a
    hole ``(start, stop, next piece)``; an unmeasurable piece ends the walk.
    """
    for piece_va, piece_name in tiles:
        if piece_va < end:
            continue
        if piece_va > end:
            return end, (end, piece_va, piece_name)
        piece = measure(piece_name, span=False)
        if piece is None:
            break
        end += piece[1]
    return end, None


def _check_W038_data_row_overlap(cfg: ProjectConfig) -> list[LintResult]:
    """W038: two named ``rebrew-data.toml`` rows of one module overlap.

    Each row's extent is ``[va, va + size)`` with the size from
    :func:`rebrew.data_layout.data_symbol_size` (explicit ``size``, else a
    computable ``type``); a row with no computable extent is skipped.  An
    ``alias`` row with a ``backing`` is a view inside another allocation and
    is excluded.  Two storage owners cannot share a byte, so an overlap is a
    stale extent (W037 usually names which row) or a view not yet recorded
    as one; ``rebrew status`` otherwise reports only the byte count it had to
    discount.  Rows touching end-to-start do not overlap.
    """
    from rebrew.data_layout import data_symbol_size
    from rebrew.metadata.data import DATA_METADATA_FILENAME

    arch = str(getattr(cfg, "arch", "") or "x86_32")
    by_module: dict[str, list[tuple[int, int, str]]] = {}
    for (module, va), entry in load_data_metadata(cfg.metadata_dir).items():
        name = str(entry.get("name") or "")
        if not name:
            continue
        if entry.get("storage_kind") == "alias" and entry.get("backing"):
            continue
        size = data_symbol_size(entry, arch=arch)
        if size > 0:
            by_module.setdefault(str(module), []).append((va, va + size, name))
    problems: list[str] = []
    for module, spans in sorted(by_module.items()):
        spans.sort()
        reach: tuple[int, int, str] | None = None
        for span in spans:
            if reach is not None and span[0] < reach[1]:
                shared = min(reach[1], span[1]) - span[0]
                problems.append(
                    f"{module}.0x{reach[0]:08x} {untrusted_ident(reach[2])} "
                    f"[0x{reach[0]:08x}, 0x{reach[1]:08x}) overlaps "
                    f"{module}.0x{span[0]:08x} {untrusted_ident(span[2])} by {shared} bytes; "
                    "correct the stale size/type, or record a view with "
                    "rebrew data set --storage-kind 0xVA=alias --backing 0xVA=GLOBAL"
                )
            if reach is None or span[1] > reach[1]:
                reach = span
    if not problems:
        return []
    res = LintResult((Path(cfg.metadata_dir) / DATA_METADATA_FILENAME).resolve())
    for problem in problems:
        res.warning(1, "W038", problem)
    return [res]


def _check_W033_agent_scaffold(cfg: ProjectConfig) -> list[LintResult]:
    """W033: the rendered agent workflow instructions have drifted.

    ``rebrew init`` writes `AGENTS.md`, `PRINCIPLES.md` and `.agents/skills/`
    from the packaged sources; an installed rebrew that gained a workflow fact
    (a new command, a new lint code, a store the tools now read) leaves every
    existing project describing the old one, and an agent follows the file it
    finds.  Compared against the same public renderer `--refresh-agents` uses,
    so the check cannot drift from the fix.  `AGENTS.md` is not compared here:
    its content is profile-rendered, and `rebrew init --refresh-agents --check`
    covers it with the full report.
    """
    from rebrew.init import agent_skill_files

    # The shared scaffold follows the configured default, independently of
    # the target selected for lint. Programmatic configs may have no TOML.
    targets = getattr(cfg, "all_targets", [])
    target_name = str((targets[0] if targets else getattr(cfg, "target_name", "")) or "")
    if not target_name or not getattr(cfg, "root", None):
        return []
    if (Path(cfg.root) / "rebrew-project.toml").is_file():
        target_name = load_config(Path(cfg.root)).target_name

    expected = {
        f".agents/skills/{rel}": data for rel, data in agent_skill_files(target_name).items()
    }
    principles = Path(__file__).parent / "PRINCIPLES.md"
    if principles.is_file():
        expected["PRINCIPLES.md"] = principles.read_bytes()

    drifted: list[str] = []
    for rel, want in sorted(expected.items()):
        path = Path(cfg.root) / rel
        if not path.is_file() or path.read_bytes() != want:
            drifted.append(rel)
    # A rendered skill file the packaged tree no longer ships is stale too
    # (`--refresh-agents` prunes it): the agent would read a workflow that
    # describes commands the installed rebrew does not have.
    skills_root = Path(cfg.root) / ".agents" / "skills"
    if skills_root.is_dir():
        # Paths relative to the skills root, the unit the listing yields.
        prefix = ".agents/skills/"
        packaged = {rel[len(prefix) :] for rel in expected if rel.startswith(prefix)}
        for path in sorted(skills_root.rglob("*")):
            rel = path.relative_to(skills_root).as_posix()
            # `.rebrew-scaffold.json` is the render manifest `--refresh-agents`
            # writes beside the skills, not a skill; a dotfile is never one.
            if path.is_file() and not rel.startswith(".") and rel not in packaged:
                drifted.append(f".agents/skills/{rel}")
    if not drifted:
        return []

    res = LintResult(Path("AGENTS.md"))
    shown = ", ".join(drifted[:6]) + (f", +{len(drifted) - 6} more" if len(drifted) > 6 else "")
    res.warning(
        1,
        "W033",
        f"{len(drifted)} generated instruction file(s) differ from the installed "
        f"rebrew ({shown}) — run rebrew init --refresh-agents",
    )
    return [res]


def _check_config_rules(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    """Config-aware checks (E012).

    A stacked shared-source address anchor for ANOTHER target (``// ADDRESS: V1 0xVA``
    in a file linted under V2) is not a mismatch: one ``src/shared`` file
    serves every target with one address anchor per target (ADR-010).  Accept any
    module that names a known project target; only a module naming NO
    target fires E012.
    """
    if cfg is None:
        return

    module = found_keys.get("MODULE", "")
    target_module_name = getattr(cfg, "module", None)
    if (
        module
        and target_module_name
        and preset_module_key(module) != preset_module_key(str(target_module_name))
    ):
        known = {preset_module_key(str(target_module_name))} | {
            preset_module_key(str(item))
            for item in (getattr(cfg, "target_modules", None) or ())
            if item
        }
        if preset_module_key(module) in known:
            return
        result.error(
            result.binding_line,
            "E012",
            f"Module '{module}' doesn't match configured module '{target_module_name}'",
        )


@dataclass(frozen=True)
class MissingSection:
    """A DATA/GLOBAL binding whose VA resolves to a known binary section (W016)."""

    module: str
    va: int
    section: str


def _check_W016_section(
    result: LintResult,
    kind: str,
    found_keys: dict[str, str],
    module: str = "",
    va_int: int | None = None,
    section_for_va: Any = None,
    section_hits: list[MissingSection] | None = None,
) -> None:
    if kind in DATA_KINDS and "SECTION" not in found_keys:
        result.warning(
            result.binding_line,
            "W016",
            f"{kind} metadata missing SECTION: (.data, .rdata, .bss)",
        )
        if (
            module
            and va_int is not None
            and section_for_va is not None
            and section_hits is not None
        ):
            section = section_for_va(va_int)
            if section:
                section_hits.append(MissingSection(module=module, va=va_int, section=section))


def _check_E023_naked_asm(
    result: LintResult,
    lines: list[str],
    code_lines: list[str],
    claimed_statuses: set[str] | None = None,
) -> None:
    """Flag whole-function ``__declspec(naked)`` + ``__asm`` dumps (E023).

    *code_lines* is the shared ``_strip_all`` view of *lines*; the raw
    *lines* are still read by the padding checks below, which inspect
    literal source text.

    ``__declspec(naked)`` is only allowed for *minor padding* (1-2 alignment
    ``nop``/``int3`` bytes, e.g. ``_emit 0x90`` / ``_emit 0xCC`` or
    ``__asm nop``).  A whole-function naked body pasted from disassembly is
    not a decompilation and must be flagged as an error.

    Heuristic: a naked function whose asm body exceeds minor padding — more
    than 2 ``__asm``/``_emit`` lines, or any ``_emit`` byte that is not
    padding (``0x90``/``0xCC``) / non-nop mnemonic — is a whole-function
    dump and earns E023.  1-2 nops for alignment are tolerated silently.
    """
    # Find the naked declaration in CODE.  The naive
    # `startswith("//")/"/*"/"*"` filter let the interior of a block comment
    # through (a commented-out body whose lines lack a leading `*`), reporting
    # a naked declaration that is not in the source at all.
    has_naked = False
    naked_line = 0
    for idx, code in enumerate(code_lines, start=1):
        if "__declspec(naked)" in code or "__declspec( naked" in code:
            has_naked = True
            naked_line = idx
            break
    if not has_naked:
        return

    source = "\n".join(code_lines)
    raw = source.encode("utf-8", errors="surrogateescape")
    spans = msvc_asm_spans(source)
    assembly = [raw[start:end].decode("utf-8", errors="surrogateescape") for start, end in spans]
    if not assembly:
        assembly = [code for code in code_lines if "_emit" in code]
    payloads: list[list[str]] = []
    for block in assembly:
        for line in block.splitlines():
            # C comments/strings are already stripped; ';' starts an asm comment.
            payload = line.lower().split(";", 1)[0]
            payload = payload.replace("__asm", " ").replace("_asm", " ")
            words = payload.replace("{", " ").replace("}", " ").split()
            if words and words[0].endswith(":"):
                words = words[1:]
            if words:
                payloads.append(words)
    if not payloads:
        return

    padding_count = 0
    padding_only = True
    for words in payloads:
        i = 0
        while i < len(words):
            if words[i] == "nop":
                i += 1
            elif words[i : i + 2] in (
                ["int", "3"],
                ["_emit", "0x90"],
                ["_emit", "0xcc"],
                ["__emit", "0x90"],
                ["__emit", "0xcc"],
            ):
                i += 2
            else:
                padding_only = False
                break
            padding_count += 1
        if not padding_only:
            break
    if padding_only and padding_count <= 2:
        return

    claimed = sorted((claimed_statuses or set()) - _UNCLAIMED_STATUSES)
    suffix = f" but STATUS claims {', '.join(claimed)}" if claimed else ""
    result.error(
        naked_line,
        "E023",
        f"whole-function __declspec(naked) + __asm/__emit is not allowed{suffix} — "
        "naked asm is only for minor padding (1-2 alignment bytes: nop / _emit 0x90 / 0xCC); "
        "decompile the function to C instead",
    )


def _check_W031_source_provenance(cfg: ProjectConfig) -> list[LintResult]:
    """Surface invalid or stale source evidence rather than silently trusting it."""
    result = LintResult(Path(SOURCE_PROVENANCE_FILENAME))
    try:
        records = load_source_provenance(cfg.metadata_dir)
    except (OSError, ValueError) as exc:
        result.warning(1, "W031", f"invalid source provenance store: {exc}")
        return [result]
    known = {
        preset_module_key(str(module))
        for module in (getattr(cfg, "target_modules", None) or [cfg.module])
        if module
    }
    hashes: dict[str, dict[str, str]] = {}
    for record in records:
        label = f"{record.module}:{record.file}:{record.symbol}"
        if known and record.module not in known:
            result.warning(1, "W031", f"source provenance {label} names an unknown target module")
            continue
        if cfg.module and record.module != preset_module_key(cfg.module):
            continue
        try:
            if record.file not in hashes:
                path = (cfg.metadata_dir / record.file).resolve()
                path.relative_to(cfg.metadata_dir.resolve())
                source, _ = read_source_text(path)
                hashes[record.file] = function_definition_hashes(source)
            current = hashes[record.file].get(record.symbol)
        except (OSError, ValueError, ImportError) as exc:
            result.warning(1, "W031", f"source provenance {label} cannot be checked: {exc}")
            continue
        if current != record.source_hash:
            result.warning(
                1,
                "W031",
                f"stale source provenance for {label} — definition changed, moved or "
                "is ambiguous; review evidence again or use rebrew source document-assembly --clear",
            )
    return [result] if result.warnings else []


def _check_W031_type_metadata(cfg: ProjectConfig) -> list[LintResult]:
    """Report invalid/stale managed type bindings without invoking the compiler."""
    from rebrew.type_metadata import TYPE_METADATA_FILENAME, check_types

    result = LintResult(Path(TYPE_METADATA_FILENAME))
    for finding in check_types(cfg):
        result.warning(1, "W031", f"type {finding['id']}:{finding['module']}: {finding['issue']}")
    return [result] if result.warnings else []


def _check_W020_asm_dump(
    result: LintResult,
    code_lines: list[str],
    source: str,
    rows: list[tuple[str, int, dict[str, Any]]],
    headers: list[tuple[dict[str, str], dict[str, bool]]],
    target_module_name: str | None,
    filepath: Path,
    metadata_dir: Path,
) -> None:
    """Warn once per undocumented assembly function, using its own target rows.

    A byte match alone does not establish original assembly provenance.
    Documented partial assembly can match bytes; its blocker suppresses only
    that definition. Naked assembly is handled by E023.
    """
    if not any("__asm" in code or "_emit" in code for code in code_lines):
        return
    from rebrew.rename_ops import c_name_from_symbol

    selected_rows = [
        row
        for module, _, row in rows
        if not target_module_name
        or preset_module_key(module) == preset_module_key(target_module_name)
    ]
    function_headers = [
        keys for keys, _ in headers if keys.get("KIND") in {"FUNCTION", "LIBRARY", "STUB"}
    ]
    if (
        target_module_name
        and (rows or function_headers)
        and not selected_rows
        and not any(
            preset_module_key(keys.get("MODULE", "")) == preset_module_key(target_module_name)
            for keys in function_headers
        )
    ):
        return
    definitions: list[tuple[int, int, str]] = []
    parsed = b""
    try:
        tree, parsed = parse_c_source(mask_msvc_syntax(source))
    except ImportError:
        tree = None
    pending = [tree.root_node] if tree is not None else []
    while pending:
        node = pending.pop()
        if node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            name = find_function_name_in_node(declarator, parsed) if declarator else None
            definitions.append((node.start_point[0] + 1, node.end_point[0] + 1, name or ""))
        else:
            pending.extend(reversed(node.children))
    definitions.sort()
    documented: set[str] = set()
    if target_module_name:
        try:
            relative = filepath.resolve().relative_to(metadata_dir.resolve()).as_posix()
            records = [
                record
                for record in load_source_provenance(metadata_dir)
                if record.file == relative
                and record.module == preset_module_key(target_module_name)
            ]
            hashes = function_definition_hashes(source) if records else {}
            documented = {r.symbol for r in records if hashes.get(r.symbol) == r.source_hash}
        except (OSError, ValueError, ImportError):
            # The batch artifact check reports unusable records; they never exempt assembly.
            pass
    seen: set[int] = set()
    for i, code in enumerate(code_lines, start=1):
        if "_emit" not in code and "__asm" not in code:
            continue
        start, end, name = next(
            (definition for definition in definitions if definition[0] <= i <= definition[1]),
            (0, len(code_lines), ""),
        )
        if start in seen:
            continue
        seen.add(start)
        if start and any("__declspec(naked)" in line for line in code_lines[start - 1 : end]):
            continue
        definition_rows = [
            row
            for _, _, row in rows
            if name and name in (row.get("name"), c_name_from_symbol(str(row.get("symbol") or "")))
        ]
        own_rows = [row for row in definition_rows if row in selected_rows]
        previous_end = max((hi for _, hi, _ in definitions if hi < start), default=0)
        definition_headers = [
            keys
            for keys, _ in headers
            if start
            and previous_end < int(keys.get("_LINE", "0")) <= start
            and keys.get("KIND") in {"FUNCTION", "LIBRARY", "STUB"}
        ]
        own_headers = [
            keys
            for keys in definition_headers
            if not target_module_name
            or preset_module_key(keys.get("MODULE", "")) == preset_module_key(target_module_name)
        ]
        if (
            target_module_name
            and (definition_rows or definition_headers)
            and not (own_rows or own_headers)
        ):
            continue
        if any(row.get("blocker") for row in own_rows) or any(
            keys.get("BLOCKER") for keys in own_headers
        ):
            continue
        if name in documented:
            continue
        statuses = {canonical_status(str(row.get("status") or "")) for row in own_rows}
        statuses.update(canonical_status(keys.get("STATUS", "")) for keys in own_headers)
        claimed = sorted(statuses - _UNCLAIMED_STATUSES - {""})
        kind = "_emit byte dump" if "_emit" in code else "inline __asm block"
        suffix = f"; STATUS claims {', '.join(claimed)}" if claimed else ""
        result.warning(
            i,
            "W020",
            f"{kind} in {name or '<unparsed definition>'}{suffix} — rewrite as C where possible "
            "or document original assembly provenance with a BLOCKER or "
            "rebrew source document-assembly",
        )


def _check_W021_duplicate_globals(
    result: LintResult,
    lines: list[str],
    filepath: Path,
    seen_globals: dict[str, tuple[str, int, bool]] | None,
) -> None:
    """Warn when a global's annotated address or initialized ownership conflicts.

    Catches the np-rebrew pattern where ``globals.c`` and another source both
    annotate/define the same global (g_ vs DAT_ collisions, duplicate
    definitions). ``seen_globals`` maps ``module:name`` to its defining path,
    address and initialized-definition flag, threaded across the batch like
    ``seen_vas``. Extern declarations at the owner's address are references,
    matching E013's progressive-ownership rule.

    The key carries the binding's module: a shared tree annotates the same
    symbol once per target (SERVER ``g_log_newline`` at 0x100270e4, the
    client's at 0x677ac8), and those are two binaries' globals, not a
    collision. Conflicting addresses or two initialized definitions under the
    same module still warn, including a DATA binding beside a GLOBAL binding.
    """
    if seen_globals is None:
        return
    text = "\n".join(lines)
    variables = {v.name: v for v in find_extern_variables(text, include_definitions=True)}
    from rebrew.metadata.bindings import source_bindings
    from rebrew.metadata.functions import resolve_metadata_dir

    for binding in source_bindings(
        text, filepath, None, None, resolve_metadata_dir(filepath.parent)
    ):
        if binding.kind not in DATA_KINDS or binding.name not in variables:
            continue
        variable = variables[binding.name]
        key = f"{binding.module}:{variable.name}"
        defines = _block_defines(lines, variable.line - 1)
        previous = seen_globals.get(key)
        if (
            previous is not None
            and previous[0] != str(filepath)
            and (previous[1] != binding.va or (previous[2] and defines))
        ):
            result.warning(
                variable.line, "W021", f"global '{variable.name}' is also defined in {previous[0]}"
            )
        elif previous is None or defines:
            seen_globals[key] = (str(filepath), binding.va, defines)


# Brackets may repeat, and one bound may contain one nested pair.
# Stopping at the first ``]`` skipped ``g[sizeof(wchar_t[3])] = {0}``
# and ``g[2][4] = {0}``, so W022 never saw them and W021 never named them.
# ``*name[N]`` glues the star to the name. ``(*name[N])`` and ``(*name)[N]``
# put the name inside parentheses. ``(*name[N])[M]`` has another bracket
# run after the closing parenthesis. ``(__cdecl *name[N])`` keeps the
# calling convention off the name. ``(* const name[N])`` keeps the
# qualifier off the name. ``(*name[N])(int)`` keeps the parameter list
# between the declarator and ``=``.
_POINTER_NAME_QUALIFIER = r"(?:(?:const|volatile)\b\s*)*"
_FN_PARAMS = r"(?:\((?:[^()]|\([^()]*\))*\))?"
_ZERO_INIT_RE = re.compile(
    r"^\s*(?:extern\s+|static\s+)?(?:unsigned\s+|signed\s+|const\s+)?"
    r"[A-Za-z_][\w\s\*]*?"
    r"(?:\s+[A-Za-z_]\w+"
    r"|\s*\*+\s*[A-Za-z_]\w+"
    r"|\(\s*"
    + CALLING_CONVENTION
    + r"\*+\s*"
    + _POINTER_NAME_QUALIFIER
    + r"[A-Za-z_]\w+\s*\)"
    + _FN_PARAMS
    + r"|\(\s*"
    + CALLING_CONVENTION
    + r"\**\s*"
    + _POINTER_NAME_QUALIFIER
    + r"[A-Za-z_]\w+\s*(?:\[(?:[^\[\]]|\[[^\]]*\])*\])+\s*\)"
    + _FN_PARAMS
    + r")"
    r"(?:\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*"
    r"\s*=\s*\{?\s*0\s*\}?\s*;"
)

# ``(int)`` after a function-pointer declarator also looks like a name
# followed by ``[;=]``. Match ``(*name)`` first, so the parameter type is
# not the global. ``__cdecl`` and ``const`` stay off that name.
_GLOBAL_NAME_RE = re.compile(
    r"(?:"
    r"\(\s*"
    + CALLING_CONVENTION
    + r"\*+\s*"
    + _POINTER_NAME_QUALIFIER
    + r"(?P<pointer>[A-Za-z_]\w*)"
    r"\s*(?:\[(?:[^\[\]]|\[[^\]]*\])*\])*\s*\)"
    r"(?:\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*"
    r"(?:\((?:[^()]|\([^()]*\))*\))?"
    r"|"
    r"(?:\(\s*\**\s*)?\b(?P<name>[A-Za-z_]\w*)\s*\)?"
    r"\s*(?:\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*"
    r"\s*\)?\s*"
    r"(?:\[(?:[^\[\]]|\[[^\]]*\])*\]\s*)*"
    r")"
    r"\s*[;=]"
)


def _declared_global_name(match: re.Match[str]) -> str:
    """Return the declarator name from a global-name match."""
    found = match.group("pointer") or match.group("name")
    return found if isinstance(found, str) else ""


# Event scanning for _strip_c_comments_strings: the characters that can change
# state, per state.  Ordinary runs between events are copied as bulk slices;
# the per-character loop this replaced was ~70% of batch-lint CPU.
_STRIP_CODE_RE = re.compile(r"""["'/]""")
_STRIP_BLOCK_RE = re.compile(r"\*/")
_STRIP_STR_RE = re.compile(r"""[\\"]""")
_STRIP_CHR_RE = re.compile(r"""[\\']""")
_STRIP_CODE, _STRIP_BLOCK, _STRIP_STR, _STRIP_CHR = range(4)


def _strip_c_comments_strings(line: str, in_block_comment: bool) -> tuple[str, bool]:
    """Remove C comments and string/char literals from *line*.

    Stateful: *in_block_comment* tracks a ``/* ... */`` block spanning
    lines (e.g. a multi-line file preamble).  Quote-aware — ``/*``/``*/``
    inside string or char literals are not comment delimiters, and ``//``
    line comments terminate the rest of the line.  Returns
    ``(cleaned, new_block_state)``; literal contents become spaces so they
    never match code patterns.
    """
    # Fast path: outside a block comment, a line without `"`, `'` or `/`
    # cannot open or close a comment or literal — return it untouched.
    if not in_block_comment and '"' not in line and "'" not in line and "/" not in line:
        return line, False
    out: list[str] = []
    i = 0
    n = len(line)
    state = _STRIP_BLOCK if in_block_comment else _STRIP_CODE
    while i < n:
        if state == _STRIP_BLOCK:
            m = _STRIP_BLOCK_RE.search(line, i)
            if m is None:
                i = n  # rest of the line stays inside the block comment
            else:
                i = m.end()
                state = _STRIP_CODE
            continue
        if state in (_STRIP_STR, _STRIP_CHR):
            # Literal: ordinary chars and the closing quote become one space
            # each; a backslash escape (and the char it escapes) emits
            # nothing — the oracle's exact behaviour, quirks included.
            special = _STRIP_STR_RE if state == _STRIP_STR else _STRIP_CHR_RE
            start = i
            while True:
                m = special.search(line, i) if i < n else None
                if m is None:
                    out.append(" " * (n - start))  # unterminated at EOL
                    i = n
                    break
                pos = m.start()
                if line[pos] == "\\":
                    out.append(" " * (pos - start))
                    i = pos + 2
                    start = i
                    continue
                out.append(" " * (pos - start + 1))  # run + closing quote
                i = pos + 1
                state = _STRIP_CODE
                break
            continue
        # state == _STRIP_CODE
        m = _STRIP_CODE_RE.search(line, i)
        if m is None:
            out.append(line[i:])
            break
        pos = m.start()
        c = line[pos]
        out.append(line[i:pos])
        if c == "/":
            nxt = line[pos + 1] if pos + 1 < n else ""
            if nxt == "*":
                i = pos + 2
                state = _STRIP_BLOCK
                continue
            if nxt == "/":
                break  # line comment — rest of the line is not code
            out.append("/")
            i = pos + 1
            continue
        out.append(" ")  # opening quote of a string/char literal
        i = pos + 1
        state = _STRIP_STR if c == '"' else _STRIP_CHR
    return "".join(out), state == _STRIP_BLOCK


def _strip_all(lines: list[str]) -> list[str]:
    """Return the comment/string-stripped *code view* of every line.

    One stateful pass over the whole file.  E023, W020 and W022 read this
    shared view instead of each re-stripping every line themselves —
    previously four full strip passes per file on the batch-lint hot path.
    """
    out: list[str] = []
    in_block = False
    for line in lines:
        code, in_block = _strip_c_comments_strings(line, in_block)
        out.append(code)
    return out


def _check_W022_zero_init_bss(
    result: LintResult, code_lines: list[str], data_section_names: frozenset[str] = frozenset()
) -> None:
    """Flag file-scope zero initializers (W022).

    A file-scope ``= {0}`` / ``= 0`` forces the global into ``.data``
    (initialized) instead of ``.bss`` (uninitialized, virtual-only) — this
    is exactly the np-rebrew .data bloat (41K of zero-init arrays).  Leave
    the global uninitialized for .bss.

    Exception: a global whose name, or ``link_symbol`` without its leading
    underscore, appears in ``rebrew-data.toml`` with
    ``section = ".data"`` or ``section = ".bss"`` (passed via
    *data_section_names*). A recorded ``.data`` zero-init is in the original
    image. A recorded ``.bss`` ``= 0`` is a placement pin: dropping it moves
    the symbol and rewrites absolute pointers stored in raw ``.data``.
    Untracked ``= 0`` still warns.
    """
    depth = 0
    for i, cleaned in enumerate(code_lines, start=1):
        depth += cleaned.count("{") - cleaned.count("}")
        if depth == 0 and _ZERO_INIT_RE.match(cleaned.strip()):
            if data_section_names:
                name_match = _GLOBAL_NAME_RE.search(cleaned)
                if name_match and _declared_global_name(name_match) in data_section_names:
                    continue
            result.warning(
                i,
                "W022",
                "file-scope zero initializer (= {0} / = 0) puts the global in "
                ".data, not .bss — leave it uninitialized to keep the PE small",
            )


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
    for line in code.splitlines():
        comment_pos = line.find("//")
        if comment_pos != -1:
            line = line[:comment_pos]
        code_lines.append(line)
    code = "\n".join(code_lines)

    # Look for function definitions with default names
    # Pattern: return_type function_name(...) {

    # Matches are monotonic, so count newlines incrementally — rescanning
    # the whole prefix per match is quadratic on merged multi-function files.
    last_pos = 0
    line_num = 1
    for match in _FUNC_DEF_STYLE_RE.finditer(code):
        func_name = match.group(2)
        line_num += code.count("\n", last_pos, match.start())
        last_pos = match.start()

        # Check against default patterns
        for pattern in DEFAULT_FUNC_NAME_PATTERNS:
            if pattern.fullmatch(func_name):
                result.warning(
                    line_num,
                    "W023",
                    f"Function '{func_name}' has a default name; consider renaming to something meaningful",
                )
                break


_SNAKE_CASE_RE = re.compile(r"[a-z_][a-z0-9_]*")
_CAMEL_CASE_RE = re.compile(r"[a-z][a-zA-Z0-9]*")


def _check_style_rules(result: LintResult, cfg: ProjectConfig | None) -> None:
    """Check code style rules from project config (W024-W027).

    Config keys (all optional, from ``rebrew-project.toml [project.lint]``):
    ``naming_convention`` (snake_case|camelCase|none), ``brace_style``
    (same_line|new_line|none), ``indent_style`` (spaces|tabs|none),
    ``max_line_length``.  Read defensively via ``getattr`` so mocks and
    configs without a ``[project.lint]`` section default to "no rule".
    Unknown enum values are rejected at config load (fall back to ``none``).
    """
    if cfg is None:
        return
    lines = result._lines

    # Naming convention (W024): function definitions should follow the rule.
    naming = getattr(cfg, "lint_naming_convention", "none")
    if naming != "none":
        for i, line in enumerate(lines, start=1):
            m = _FUNC_DEF_STYLE_RE.search(line)
            if not m:
                continue
            func_name = m.group(2)
            if naming == "snake_case" and not _SNAKE_CASE_RE.fullmatch(func_name):
                result.warning(i, "W024", f"Function '{func_name}' should be snake_case")
            elif naming == "camelCase" and not _CAMEL_CASE_RE.fullmatch(func_name):
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
    max_len = getattr(cfg, "lint_max_line_length", DEFAULT_LINT_MAX_LINE_LENGTH)
    if max_len and max_len > 0:
        for i, line in enumerate(lines, start=1):
            if len(line) > max_len:
                result.warning(i, "W027", f"Line too long ({len(line)} > {max_len})")


#: TOML field name -> uppercase ``found_keys`` name.
_METADATA_TO_FOUND: dict[str, str] = {
    "status": "STATUS",
    "size": "SIZE",
    "cflags": "CFLAGS",
    "toolchain": "TOOLCHAIN",
    "blocker": "BLOCKER",
    "blocker_delta": "BLOCKER_DELTA",
    "ghidra": "GHIDRA",
    "analysis": "ANALYSIS",
    "note": "NOTE",
    "skip": "SKIP",
    "globals": "GLOBALS",
    "locals": "LOCALS",
    "comments": "COMMENTS",
    "section": "SECTION",
    "source": "SOURCE",
}


def _check_body_rules(result: LintResult, lines: list[str], has_new: bool) -> None:
    """Check code presence (W003); struct size comments are not required."""
    has_code = any(
        line.strip() and not line.strip().startswith(("//", "/*", "*")) for line in lines
    )
    if not has_code and has_new:
        result.warning(1, "W003", "File has no function implementation")


#: W022 exemption set per loaded data-metadata document, and the document
#: itself pinned so a freed entry's ``id`` is never reused as a live key.
_DATA_SECTION_NAMES: dict[int, frozenset[str]] = {}
_DATA_SECTION_NAMES_OWNER: dict[int, dict[tuple[str, int], dict[str, Any]]] = {}
_DATA_SECTION_NAMES_MAX = 4
# The owner hit, the two eviction clears, and the two stores are one
# check-then-act over two parallel dicts — the same discipline as
# ``annotation._metadata_file_index``.  Held only for the dict work; the name
# set is built outside it.
_DATA_SECTION_NAMES_LOCK = threading.Lock()


def _data_section_names_for(entries: dict[tuple[str, int], dict[str, Any]]) -> frozenset[str]:
    """The ``.data``-section global names in *entries*, memoized per document.

    ``lint_file`` runs once per source file over a document that the batch
    driver already preloaded once, so rebuilding this set per file re-walked
    every ``rebrew-data.toml`` entry for every file in the tree.
    """
    key = id(entries)
    with _DATA_SECTION_NAMES_LOCK:
        # The eviction below clears both dicts, so a concurrent clear between
        # the owner check and the index read loses the entry: rebuild instead
        # of a KeyError.
        if _DATA_SECTION_NAMES_OWNER.get(key) is entries:
            cached = _DATA_SECTION_NAMES.get(key)
            if cached is not None:
                return cached
    names = frozenset(
        name
        for entry in entries.values()
        if entry.get("section") in (".data", ".bss")
        for name in (
            str(entry.get("name") or ""),
            # A C data definition links as ``_name``; the source spells ``name``.
            str(entry.get("link_symbol") or "").removeprefix("_"),
        )
        if name
    )
    with _DATA_SECTION_NAMES_LOCK:
        if len(_DATA_SECTION_NAMES) >= _DATA_SECTION_NAMES_MAX:
            _DATA_SECTION_NAMES.clear()
            _DATA_SECTION_NAMES_OWNER.clear()
        _DATA_SECTION_NAMES[key] = names
        _DATA_SECTION_NAMES_OWNER[key] = entries
    return names


def lint_file(
    filepath: Path,
    cfg: ProjectConfig | None = None,
    *,
    seen_vas: dict[Any, str] | None = None,
    seen_va_defines: dict[Any, bool] | None = None,
    seen_globals: dict[str, tuple[str, int, bool]] | None = None,
    preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None,
    function_index: tuple[set[int], list[tuple[int, int, str]]] | None = None,
    pedantic: bool = False,
    section_for_va: Any = None,
    section_hits: list[MissingSection] | None = None,
) -> LintResult:
    """Lint a single C file.

    Args:
        filepath: Path to the .c file.
        cfg: Optional ProjectConfig for config-aware checks.
        seen_vas: Optional dict mapping VA → filename for duplicate detection.
                  Will be mutated (VAs from this file are added).
        seen_va_defines: Optional parallel dict mapping the same keys to
                  whether the first-seen block defines its symbol (DATA/
                  GLOBAL E013 needs both sides defining to collide).
        seen_globals: Optional dict mapping module/global name to path, address
                      and initialized ownership for W021. Will be mutated.
        preloaded_metadata: Pre-loaded metadata dict (avoids per-file I/O in batch).
        preloaded_data_metadata: Pre-loaded data metadata dict (avoids per-file I/O in batch).
        function_index: ``(starts, spans)`` from the target function list
                        (built once per batch); enables the W028
                        annotation-staleness cross-check.
        section_for_va: Optional callable mapping a VA to its binary section
                        name; enables W016 autofix collection in
                        ``section_hits``.
        section_hits: Optional list collecting :class:`MissingSection` for
                      DATA/GLOBAL bindings whose VA resolves to a section.
        pedantic: Enable the pedantic-only W023 (default function name) check.

    """
    result = LintResult(filepath)

    # A caller may pass a shared seen_vas dict for cross-file duplicate
    # detection; with None (single-file lint) duplicate VAs WITHIN this file
    # must still be caught, so fall back to a per-file dict.
    if seen_vas is None:
        seen_vas = {}
    if seen_va_defines is None:
        seen_va_defines = {}

    try:
        text, _ = read_source_text(filepath)
    except OSError as e:
        result.error(0, "E000", f"Cannot read file: {e}")
        return result

    lines = text.splitlines()
    result._lines = lines

    for line, key in metadata_comments(text):
        result.error(
            line, "E024", f"{key} belongs in metadata; source accepts ADDRESS anchors only"
        )
    from rebrew.metadata.source_provenance import load_source_files

    directory = cfg.metadata_dir if cfg else filepath.parent
    relative = rel_display_path(filepath.resolve(), directory.resolve())
    support = [record for record in load_source_files(directory) if record.file == relative]
    if support:
        result._kind_counts["SUPPORT"] += 1
        _check_body_rules(result, lines, True)
        return result
    try:
        from rebrew.metadata.bindings import source_bindings

        bindings = source_bindings(
            text,
            filepath,
            None,
            None,
            cfg.metadata_dir if cfg else filepath.parent,
            project_root=getattr(cfg, "root", None),
        )
        definition_lines: dict[str, int] = {}
        if any(a.is_function for a in bindings):
            from rebrew.c_parser import find_c_function_definitions

            definition_lines = dict(find_c_function_definitions(text))
        all_headers = [
            (
                {
                    "KIND": a.kind,
                    "MODULE": a.module,
                    "VA": f"0x{a.va:08x}",
                    "_LINE": str(a.line or definition_lines.get(a.name, 1)),
                    "_DEFINITION_LINE": str(definition_lines.get(a.name, 0)),
                },
                {"has_new": True},
            )
            for a in bindings
        ]
        all_headers.sort(key=lambda header: int(header[0]["_LINE"]))
    except ValueError as exc:
        result.error(1, "E001", str(exc))
        return result

    # Load per-directory metadata (keys: (module, va_int) -> {toml_field: value}).
    # Accept pre-loaded dicts from callers that process many files in the same directory
    # (avoids repeated I/O for the common batch-lint case).
    # metadata_dir walks the tree upward per access, so resolve it only when a
    # preload does not already answer for this directory.
    _metadata_dir = (
        None
        if preloaded_metadata is not None and preloaded_data_metadata is not None
        else (cfg.metadata_dir if cfg else filepath.parent)
    )
    _metadata_entries = (
        preloaded_metadata
        if preloaded_metadata is not None
        else load_metadata(_metadata_dir, deepcopy=False)
    )
    _data_metadata_entries = (
        preloaded_data_metadata
        if preloaded_data_metadata is not None
        else load_data_metadata(_metadata_dir)
    )
    if not all_headers:
        from rebrew.metadata.binding_history import historical_source_files
        from rebrew.metadata.functions import resolve_metadata_dir
        from rebrew.workspace.config import walk_up_to_root

        directory = resolve_metadata_dir(cfg.metadata_dir if cfg else filepath.parent)
        project_root = cfg.root if cfg else walk_up_to_root(directory) or directory
        if any(
            filepath.resolve() in historical_source_files(row, directory, project_root)
            for row in _metadata_entries.values()
        ):
            # Explicitly retired TUs remain reviewable source, outside compilation.
            result._kind_counts["INACTIVE"] += 1
            return result
    # A pure-C file whose row names this path is annotated. A anchor-free
    # file with no row is still E001.
    metadata_backed = False
    if not all_headers:
        metadata_backed = file_backed_by_metadata(
            filepath,
            cfg.metadata_dir if cfg is not None else filepath.parent,
            project_root=getattr(cfg, "root", None),
            function_entries=_metadata_entries,
            data_entries=_data_metadata_entries,
        )
        if not metadata_backed:
            all_headers = [({}, {"has_new": False})]
    result._headers = all_headers

    # Module keys this project recognises, folded once per file: the NFC +
    # upper of every binding in cfg.target_modules is per-annotation work below
    # otherwise, on a tree with thousands of annotated blocks.
    _own_module = getattr(cfg, "module", None) if cfg is not None else None
    _target_modules = getattr(cfg, "target_modules", None) or (
        {_own_module} if _own_module else set()
    )
    _known_folded = {preset_module_key(str(item)) for item in _target_modules if item}

    # Statuses claimed by this file's annotations (for E023 diagnostics).
    _file_statuses: set[str] = set()

    if metadata_backed:
        # A pure-C file carries no metadata bindings: its blockers and statuses are
        # the store rows that name it, for this target only.
        for _row_module, _row_va, _row in function_rows_for_file(
            filepath,
            cfg.metadata_dir if cfg is not None else filepath.parent,
            _metadata_entries,
            project_root=getattr(cfg, "root", None),
        ):
            if _own_module and preset_module_key(_row_module) != preset_module_key(_own_module):
                continue
            _row_status = canonical_status(str(_row.get("status") or ""))
            if _row_status:
                _file_statuses.add(_row_status)

    for found_keys, flags in all_headers:
        result.binding_line = int(found_keys.get("_LINE", "1"))

        mod = found_keys.get("MODULE", "")
        va_str = found_keys.get("VA", "")

        # Populate metadata fields for this source binding.
        _metadata_sourced_keys: set[str] = set()
        _va_int: int | None = None
        _metadata_size: str | None = None
        _metadata_override: dict[str, Any] = {}
        if mod and va_str:
            try:
                _va_int = int(va_str, 16)
                _metadata_override = _metadata_entries.get((mod, _va_int), {})
                _metadata_size = str(_metadata_override.get("size", "")).strip() or None
                for _toml_key, _found_key in _METADATA_TO_FOUND.items():
                    if _toml_key not in _metadata_override:
                        continue
                    store_val = str(_metadata_override[_toml_key])
                    found_keys[_found_key] = store_val
                    _metadata_sourced_keys.add(_found_key)
            except (ValueError, KeyError) as exc:
                # A malformed inline block drops the key from the drift
                # comparison, so a disagreeing SIZE would go unreported.
                log.debug("unreadable inline metadata at %s: %s", result.binding_line, exc)

        ctx = f"[{mod} {va_str}] " if mod and va_str else ""

        if len(all_headers) > 1:
            result.context_prefix = ctx
        else:
            result.context_prefix = ""

        if not _check_format_errors(result, flags):
            continue

        if flags["has_new"]:
            kind = found_keys.get("KIND", "")
            _check_E001_kind(result, kind)

            va_int = _check_E002_va(
                result, va_str, min_va=min_valid_va_for(cfg) if cfg else MIN_VALID_VA
            )

            # Check EVERY block of a multi-function file, keyed on
            # (module, va) so a multi-module file whose blocks share a VA
            # (a valid layout) is not flagged.
            # DATA/GLOBAL also pass the binding kind + body so the check can
            # tell a second definition (real collision) from an extern/bare
            # claim beside the single definition (progressive ownership).
            _check_E013_duplicate_va(
                result,
                va_int,
                va_str,
                filepath,
                seen_vas,
                module=mod,
                kind=kind,
                lines=lines,
                binding_line=result.binding_line,
                seen_va_defines=seen_va_defines,
            )

            if kind in ("FUNCTION", "STUB") and va_int is not None:
                _check_W028_stale_annotation(
                    result,
                    va_int,
                    mod,
                    cfg,
                    function_index,
                    # Store-wins overlay (above): an EXACT/RELOC in
                    # rebrew-functions.toml suppresses W028 even when a stale
                    # inline // STATUS: STUB remains.
                    status=canonical_status(str(found_keys.get("STATUS", ""))),
                    metadata=_metadata_entries,
                )

            if kind not in DATA_KINDS:
                # A stacked shared-source block for ANOTHER target answers to
                # its own target's defaults, not this one's — flagging it for
                # missing CFLAGS here is misattribution (ADR-010).
                _own_key = preset_module_key(_own_module) if _own_module else ""
                _mod_key = preset_module_key(mod) if mod else ""
                if not (
                    cfg is not None
                    and _own_module
                    and mod
                    and _mod_key != _own_key
                    and _mod_key in _known_folded
                ):
                    _check_W018_cflags(result, found_keys, cfg)
            # For DATA/GLOBAL: overlay data metadata fields (size, section, note).
            # SIZE follows the same store-wins rule as SECTION and NOTE.
            elif va_int is not None and mod:
                _ds_override = _data_metadata_entries.get((mod, va_int), {})
                # A data symbol's SIZE lives in rebrew-data.toml, so W019 must
                # compare the inline copy against THAT store. Left at the
                # function-store value it saw, a DATA/GLOBAL block reported a
                # disagreement against a size it never read, and the
                # already-migrated hint from `_w019_key_backed` suppressed
                # the very warning that would have shown it.
                if "size" in _ds_override:
                    _metadata_size = str(_ds_override["size"]).strip() or None
                _DS_TO_FOUND = {"size": "SIZE", "section": "SECTION", "note": "NOTE"}
                for _ds_key, _ds_found_key in _DS_TO_FOUND.items():
                    if _ds_key not in _ds_override:
                        continue
                    store_val = str(_ds_override[_ds_key])
                    found_keys[_ds_found_key] = store_val
                    _metadata_sourced_keys.add(_ds_found_key)

            module = found_keys.get("MODULE", "")
            # Canonicalize so hand-edited `status = "exact"` / `// STATUS: stub`
            # feed E015/E017/MATCHED_STATUSES the same way update_source_status does.
            status = canonical_status(found_keys.get("STATUS", ""))

            # Collect summary data during the lint pass (used by _print_summary).
            if kind:
                result._kind_counts[kind] += 1
            if status:
                result._status_counts[status] += 1
                _file_statuses.add(status)

            _check_E015_kind_consistency(result, kind, module, status, cfg)
            _check_W005_blocker(result, status, found_keys)
            _check_W006_source(result, module, found_keys, cfg)
            _check_E017_contradictory(result, status, kind)
            _check_E004_status_value(result, status)
            _check_E008_size_value(result, _metadata_size)
            _check_config_rules(result, found_keys, cfg)

            _check_W015_va_case(result, va_str)
            _check_W016_section(
                result,
                kind,
                found_keys,
                module=mod,
                va_int=_va_int,
                section_for_va=section_for_va,
                section_hits=section_hits,
            )

    result.context_prefix = ""
    # Names of globals annotated section=".data" in rebrew-data.toml — W022
    # exemption (the original binary stored the zero-init data in .data).
    _data_section_names = _data_section_names_for(_data_metadata_entries)
    code_lines = _strip_all(lines)  # one strip pass shared by E023/W020/W022
    _check_E023_naked_asm(result, lines, code_lines, _file_statuses)
    _check_W020_asm_dump(
        result,
        code_lines,
        text,
        function_rows_for_file(
            filepath,
            cfg.metadata_dir if cfg else filepath.parent,
            _metadata_entries,
            project_root=getattr(cfg, "root", None),
        ),
        all_headers,
        _own_module,
        filepath,
        cfg.metadata_dir if cfg else filepath.parent,
    )
    _check_W021_duplicate_globals(result, lines, filepath, seen_globals)
    _check_W022_zero_init_bss(result, code_lines, _data_section_names)
    if cfg is not None:
        _check_W037_data_definition(result, text, filepath, cfg)
    _check_body_rules(
        result,
        lines,
        metadata_backed or (all_headers[0][1]["has_new"] if all_headers else False),
    )
    _check_W023_default_func_names(result, lines, pedantic)
    _check_W030_va_order(result, all_headers, lines)
    _check_style_rules(result, cfg)
    return result


def _print_summary(results: list[LintResult]) -> None:
    """Print a breakdown table by status and binding kind.

    Uses counters collected during the lint pass (LintResult._status_counts
    and _kind_counts) instead of re-reading every file.
    """
    status_counts: Counter[str] = Counter()
    kind_counts: Counter[str] = Counter()
    for r in results:
        status_counts += r._status_counts
        kind_counts += r._kind_counts

    console.print()
    table = Table(title="Summary", show_lines=False, pad_edge=False)
    table.add_column("Category", style="bold")
    table.add_column("Value")
    table.add_column("Count", justify="right", width=8, no_wrap=True)

    for status, count in sorted(status_counts.items(), key=lambda x: -x[1]):
        table.add_row("STATUS", untrusted_ident(status), str(count))
    for kind, count in sorted(kind_counts.items(), key=lambda x: -x[1]):
        table.add_row("KIND", kind, str(count))

    console.print(table)


app = typer.Typer(
    help="Check C source bindings, metadata, and project conventions.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew lint\n\n"
        "  rebrew lint src/game/foo.c --quiet\n\n"
        "  rebrew lint --summary\n\n"
        "  rebrew lint --fix --dry-run\n\n"
        "  rebrew lint --json\n\n"
        "[dim]Checks C bindings, dedicated metadata, compiler flags, project style, storage declarations, and scaffold drift. Optional ADDRESS comments bind the next definition; all identity/state stays in format-3 function metadata and format-2 data metadata. Unsupported inline state is diagnosed, not migrated.[/dim]\n\n"
        "[bold]Fixes:[/bold]\n\n"
        "  --fix removes redundant compiler flags and backfills known SECTION metadata. Preview with --dry-run; other findings require review.\n\n"
        "[bold]Common findings:[/bold]\n\n"
        "  E001: missing metadata identity or support purpose; E013: duplicate VA.\n\n"
        "  E023: whole-function naked assembly instead of reconstructed C.\n\n"
        "  W005: STUB without BLOCKER; W016: data without SECTION metadata.\n\n"
        "  E024: unsupported inline state; W028: bound VA absent from function inventory.\n\n"
        "  W029: redundant flags; W031: metadata schema/provenance problem.\n\n"
        "  W032-W035: coverage, scaffold, file identity, or module drift.\n\n"
    ),
)


@app.callback(invoke_without_command=True)
def main(
    fix: bool = typer.Option(
        False,
        "--fix",
        help=("Remove redundant compiler flags and backfill SECTION metadata (W016)"),
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
    all_targets: bool = AllTargetsOption,
) -> None:
    """Check C source bindings, metadata, and project conventions."""
    all_targets = option_default(all_targets, False)
    if all_targets_run(
        target=target,
        all_targets=all_targets,
        json_mode=json_output,
        run_one=lambda n: main(
            fix=fix,
            dry_run=dry_run,
            quiet=quiet,
            pedantic=pedantic,
            files=files,
            summary=summary,
            json_output=json_output,
            target=n,
            all_targets=False,
        ),
    ):
        return
    # `load_config`, not `require_config`: naming files explicitly lints them
    # without a project (config-aware rules off).  Bare `rebrew lint` has no
    # such fallback — see the `reversed_dir` branch below.
    cfg = None
    no_config = False
    try:
        cfg = load_config(target=target)
    except FileNotFoundError:
        no_config = True
    except (KeyError, ValueError) as exc:
        console.print(
            f"[yellow]warning:[/yellow] config error ({untrusted_ident(exc)}); "
            "config-aware rules disabled"
        )

    reversed_dir = cfg.reversed_dir if cfg else None

    exts = source_exts(cfg)
    if files:
        # `source_ext` may hold several comma-separated extensions; comparing
        # the raw string against `f.suffix` matched nothing, so `rebrew lint
        # foo.cpp` with `source_ext = ".c,.cpp"` silently checked 0 files.
        # Both sides are lowercased: `_parse_source_ext` keeps the configured
        # spelling, and `iter_sources` matches suffixes case-insensitively
        # (sources.files_with_ext), so `rebrew lint FOO.C` with
        # `source_ext = ".C"` must find the same file as a bare run.
        lowered = {ext.lower() for ext in exts}
        c_files = [f for f in files if f.suffix.lower() in lowered]
    elif reversed_dir:
        c_files = iter_sources(reversed_dir, cfg)
    elif no_config:
        # No project and no file list: the only thing left to guess is "every
        # C file under the cwd", which lints vendored trees (.venv, build/)
        # and reports their findings as the project's.  Exit 2 like every
        # other command that cannot find a project, naming both ways out.
        error_exit(
            "no rebrew-project.toml found and no files given. "
            "Run 'rebrew lint' from inside a project, or pass the files to "
            "check explicitly (rebrew lint path/to/file.c).",
            json_mode=json_output,
        )
    else:
        c_files = sorted({p for ext in exts for p in Path.cwd().rglob(f"*{ext}")})

    # Cross-file duplicate tracking: VAs (E013) and global names (W021).
    # seen_vas keys are (module, va) tuples — bare int would falsely flag
    # cross-module files that legitimately share a VA in different targets.
    seen_vas: dict[Any, str] = {}
    seen_va_defines: dict[Any, bool] = {}
    seen_globals: dict[str, tuple[str, int, bool]] = {}

    # Pre-load metadata once for the whole batch (avoids per-file I/O).
    _preloaded_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    _preloaded_data_metadata: dict[tuple[str, int], dict[str, Any]] | None = None
    if cfg:
        _preloaded_metadata = load_metadata(cfg.metadata_dir, deepcopy=False)
        _preloaded_data_metadata = load_data_metadata(cfg.metadata_dir)
    # Pre-load the function list once for the whole batch (W028).
    function_index = _build_function_index(cfg) if cfg else None
    # Section resolver for W016 autofix (DATA/GLOBAL bindings missing SECTION):
    # one binary parse per batch, mapping VA -> section name.  The load is
    # deferred to the first VA actually queried: a run without a SECTION-less
    # DATA/GLOBAL binding never pays LIEF's ~0.13 s import, and an unusable
    # binary just leaves the resolver returning "" (W016 stays warn-only).
    section_for_va: Any = None
    if cfg is not None and getattr(cfg, "target_binary", None):
        _bin_path = cfg.target_binary
        _loaded = False
        _ranges: list[tuple[int, int, str]] = []
        _starts: list[int] = []

        def section_for_va(va: int) -> str:
            nonlocal _loaded, _ranges, _starts
            if not _loaded:
                _loaded = True  # an unusable binary must not retry per VA
                try:
                    from rebrew.formats.binary_loader import load_binary

                    _info = load_binary(_bin_path)
                    _ranges = sorted(
                        ((s.va, s.va + s.size, s.name) for s in _info.sections.values()),
                        key=lambda t: t[0],
                    )
                    _starts = [r[0] for r in _ranges]
                except Exception as exc:
                    # W016 stays warn-only; record why every VA resolves to no section.
                    log.debug("W016 section lookup disabled: %s cannot be read: %s", _bin_path, exc)
                    _ranges = []
                    _starts = []
            idx = bisect.bisect_right(_starts, va) - 1
            # A shorter section nested in a longer one must not hide the outer tail.
            while idx >= 0:
                start, end, name = _ranges[idx]
                if start <= va < end:
                    return name
                idx -= 1
            return ""

    section_hits: list[MissingSection] = []

    total = 0
    passed = 0
    error_count = 0
    warning_count = 0
    all_results: list[LintResult] = []

    display_buf: list[str] = []
    for cfile in c_files:
        total += 1
        result = lint_file(
            cfile,
            cfg=cfg,
            seen_vas=seen_vas,
            seen_va_defines=seen_va_defines,
            seen_globals=seen_globals,
            preloaded_metadata=_preloaded_metadata,
            preloaded_data_metadata=_preloaded_data_metadata,
            function_index=function_index,
            pedantic=pedantic,
            section_for_va=section_for_va,
            section_hits=section_hits,
        )
        all_results.append(result)
        if result.passed:
            passed += 1
        if not json_output and (not result.passed or (not quiet and result.warnings)):
            display_buf.extend(result._display_lines(quiet))
        error_count += len(result.errors)
        warning_count += len(result.warnings)

    if display_buf:
        # One Rich print for the whole batch: nothing else prints during the
        # loop, so the output bytes are identical — one markup+wrap pass
        # instead of ~400 per-file envelopes (the largest remaining lint
        # cost after the W029 batching).
        console.print("\n".join(display_buf), highlight=False)

    # W029: redundant cflags across metadata + presets — batch-level, since
    # no single .c file owns a preset and the redundancy is about the fallback
    # ladder.  Attribute per-function warnings back to the file that hosts the
    # VA when possible; presets and unattributed VAs land on a synthetic entry.
    preset_redundant: list[RedundantPreset] = []
    fn_redundant: list[RedundantFunctionCflags] = []
    if cfg is not None:
        preset_redundant, fn_redundant = check_redundant_cflags(cfg, _preloaded_metadata)
        if preset_redundant or fn_redundant:
            # Build VA -> file index from this run, for per-function attribution.
            # LintResult.binding_line holds the LAST binding in the file, so
            # the header's own line travels with the index.
            va_to_result: dict[tuple[str, int], tuple[LintResult, int]] = {}
            for r in all_results:
                headers = r._headers if r._headers is not None else _source_headers(r._lines)
                for keys, _flags in headers:
                    m = keys.get("MODULE", "")
                    v = keys.get("VA", "")
                    if not m or not v:
                        continue
                    with contextlib.suppress(ValueError):
                        va_to_result[(m, int(v, 16))] = (r, int(keys.get("_LINE", "1")))
            # Presets: no single file — emit on a synthetic "config" result.
            if preset_redundant:
                syn = LintResult(Path("rebrew-project.toml"))
                for hit in preset_redundant:
                    syn.warning(1, "W029", f"redundant cflags preset: {hit.message()}")
                all_results.append(syn)
                if not json_output and not quiet:
                    syn.display(quiet=False)
                warning_count += len(syn.warnings)
            # Per-function redundancies: attribute per file when we can.
            unattributed: list[RedundantFunctionCflags] = []
            w029_inline: list[str] = []
            for fn_hit in fn_redundant:
                located = va_to_result.get((fn_hit.module, fn_hit.va))
                msg = fn_hit.message()
                if located is not None:
                    dest, line = located
                    if not any(c == "W029" and msg in m for _, c, m in dest.warnings):
                        dest.warning(line, "W029", f"redundant cflags: {msg}")
                        warning_count += 1
                        if not json_output and not quiet:
                            # Show the newly added warnings inline (the batch
                            # loop already printed these files) — collected
                            # and emitted as ONE Rich print below: per-hit
                            # prints were 1600 console calls on a
                            # 400-file tree, ~27% of lint's runtime.
                            w029_inline.append(
                                f"  [bold]{untrusted_ident(dest.filepath.name)}[/bold]:{line}: "
                                f"[yellow]W029[/yellow]: redundant cflags: "
                                f"{untrusted_ident(msg)}"
                            )
                else:
                    unattributed.append(fn_hit)
            if w029_inline:
                console.print("\n".join(w029_inline), highlight=False)
            if unattributed:
                syn2 = LintResult(Path("rebrew-functions.toml"))
                for fn_hit in unattributed:
                    syn2.warning(1, "W029", f"redundant cflags: {fn_hit.message()}")
                all_results.append(syn2)
                if not json_output and not quiet:
                    syn2.display(quiet=False)
                warning_count += len(syn2.warnings)

    # W031 / W032: the same batch-level shape as W029 — no .c file owns the
    # metadata store or the coverage directory, so each finding lands on the
    # artifact it describes and the per-file loop stays untouched.
    if cfg is not None:
        for artifact_result in (
            *_check_W031_metadata_store(cfg),
            *_check_W031_source_provenance(cfg),
            *_check_W031_type_metadata(cfg),
            *_check_W036_stray_metadata_store(cfg),
            *_check_W034_identity_paths(cfg),
            *_check_W035_unknown_modules(cfg),
            *_check_W038_data_row_overlap(cfg),
            *_check_W033_agent_scaffold(cfg),
        ):
            all_results.append(artifact_result)
            warning_count += len(artifact_result.warnings)
            if not json_output and not quiet:
                artifact_result.display(quiet=False)

    if json_output:
        # --quiet keeps the counts but lists only failing files, without
        # their warnings (docs: "Suppress warnings, show errors only").
        files_out = [r.to_dict() for r in all_results if not r.passed or (r.warnings and not quiet)]
        if quiet:
            for entry in files_out:
                entry["warnings"] = []
        output = {
            "total": total,
            "passed": passed,
            "errors": error_count,
            "warnings": warning_count,
            "files": files_out,
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

    # Fixes write dedicated metadata through its locked writers.
    if fix and not cfg:
        console.print(
            "[yellow]warning:[/yellow] --fix needs a rebrew-project.toml — "
            "no config loaded, no metadata updated"
        )
    if fix and cfg:
        from rebrew.metadata.data import get_data_entry, set_data_fields_batch
        from rebrew.metadata.functions import remove_fields_batch

        w029_fn_count = 0
        if fn_redundant:
            if dry_run:
                for fn_hit in fn_redundant:
                    console.print(
                        f"  [dim]Would drop[/dim] redundant cflags "
                        f"{untrusted_ident(fn_hit.module)} 0x{fn_hit.va:x} "
                        f"(inherited {fn_hit.inherited!r})"
                    )
                w029_fn_count = len(fn_redundant)
            else:
                w029_fn_count = remove_fields_batch(
                    cfg.metadata_dir,
                    [
                        {"module": fn_hit.module, "va": fn_hit.va, "keys": ["cflags"]}
                        for fn_hit in fn_redundant
                    ],
                )
        w029_preset_count = 0
        if preset_redundant:
            if dry_run:
                for preset_hit in preset_redundant:
                    console.print(
                        f"  [dim]Would drop[/dim] redundant preset "
                        f"cflags_presets.{untrusted_ident(preset_hit.module)}"
                    )
            w029_preset_count = drop_redundant_presets(cfg, preset_redundant, dry_run=dry_run)
            if dry_run and w029_preset_count == 0:
                w029_preset_count = len(preset_redundant)

        section_count = 0
        if section_hits:
            if dry_run:
                for section_hit in section_hits:
                    console.print(
                        f"  [dim]Would set[/dim] section {section_hit.section!r} "
                        f"for {untrusted_ident(section_hit.module)} "
                        f"0x{section_hit.va:x} (rebrew-data.toml)"
                    )
                section_count = len(section_hits)
            else:
                # One rebrew-data.toml rewrite for all hits, not one per symbol.
                section_updates: dict[tuple[str, int], dict[str, Any]] = {}
                for section_hit in section_hits:
                    hit_key = (section_hit.module, section_hit.va)
                    if hit_key in section_updates:
                        continue
                    existing = get_data_entry(cfg.metadata_dir, section_hit.va, section_hit.module)
                    if "section" in {k.lower() for k in existing}:
                        continue
                    section_updates[hit_key] = {
                        "module": section_hit.module,
                        "va": section_hit.va,
                        "fields": {"section": section_hit.section},
                        "updated_by": "lint",
                    }
                set_data_fields_batch(cfg.metadata_dir, list(section_updates.values()))
                section_count = len(section_updates)

        if not json_output:
            parts: list[str] = []
            # Merge the two strip streams: W010 unknown keys and redundant /
            # already-migrated inline copies are all pure source-line removals.
            if dry_run:
                if w029_fn_count:
                    parts.append(f"{w029_fn_count} redundant per-function cflags would be dropped")
                if w029_preset_count:
                    parts.append(f"{w029_preset_count} redundant cflags presets would be dropped")
                if section_count:
                    parts.append(f"{section_count} missing SECTIONs would be backfilled")
                if parts:
                    console.print(f"\n[yellow]Dry run:[/yellow] {'; '.join(parts)}")
            else:
                if w029_fn_count:
                    parts.append(f"dropped {w029_fn_count} redundant per-function cflags")
                if w029_preset_count:
                    parts.append(f"dropped {w029_preset_count} redundant cflags presets")
                if section_count:
                    parts.append(f"backfilled {section_count} missing SECTIONs")
                if parts:
                    console.print(f"\n[green]Fixed:[/green] {'; '.join(parts)}")

    if error_count > 0:
        raise typer.Exit(code=EXIT_MISMATCH)


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_standalone

    run_standalone(main)


def _source_headers(lines: list[str]) -> list[tuple[dict[str, str], dict[str, bool]]]:
    """Structural address headers only; never parse state from comments."""
    return [
        (
            {"KIND": a.kind, "MODULE": a.module, "VA": f"0x{a.va:08x}", "_LINE": str(a.line)},
            {"has_new": True},
        )
        for a in parse_address_anchors("\n".join(lines))
    ]


if __name__ == "__main__":
    main_entry()
