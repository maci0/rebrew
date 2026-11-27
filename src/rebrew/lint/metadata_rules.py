"""Metadata store, path identity, data extent, provenance, type, and scaffold lint rules."""

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
lazy import shlex
lazy from collections.abc import Callable
lazy from typing import Any

from rebrew.metadata.bindings import DATA_KINDS, MIN_VALID_VA, SYMBOL_KINDS
lazy from rebrew.config import ProjectConfig, load_config
lazy from rebrew.metadata.data import load_data_metadata
lazy from rebrew.metadata.functions import (
    FUNCTION_IDENTITY_FIELDS,
    METADATA_FIELDS,
    canonical_status,
)
lazy from rebrew.metadata.source_provenance import (
    SOURCE_PROVENANCE_FILENAME,
    function_definition_hashes,
    load_source_provenance,
)
lazy from rebrew.utils import (
    console,
    preset_module_key,
    read_source_text,
    rel_display_path,
    untrusted_ident,
)
lazy from rebrew.workspace.status import EARNED_STATUSES, KNOWN_STATUSES

__all__ = [
    "METADATA_TO_FOUND",
    "UNCLAIMED_STATUSES",
    "LintResult",
    "MissingSection",
    "block_defines",
    "check_E001_kind",
    "check_E002_va",
    "check_E004_status_value",
    "check_E008_size_value",
    "check_E013_duplicate_va",
    "check_E015_kind_consistency",
    "check_E017_contradictory",
    "check_W005_blocker",
    "check_W006_source",
    "check_W015_va_case",
    "check_W016_section",
    "check_W018_cflags",
    "check_W031_metadata_store",
    "check_W031_source_provenance",
    "check_W031_type_metadata",
    "check_W033_agent_scaffold",
    "check_W034_identity_paths",
    "check_W035_unknown_modules",
    "check_W036_stray_metadata_store",
    "check_W037_data_definition",
    "check_W038_data_row_overlap",
    "check_config_rules",
    "check_format_errors",
    "tiled_extent",
    "type_spelling",
]

_TYPE_SPELLING_RE = re.compile(r"\s*([^\w\s])\s*")
_EXTERN_DECL_RE = re.compile(r"\s*extern\b")

# Statuses that carry no claim about a function's body, so they cannot
# contradict what a check found. A file claiming only these does not gain
# a "but STATUS claims ..." suffix.
UNCLAIMED_STATUSES = frozenset({"STUB", "SKIP"})

#: TOML field name -> uppercase ``found_keys`` name.
METADATA_TO_FOUND: dict[str, str] = {
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


# ---------------------------------------------------------------------------
# Diagnostics and per-binding metadata checks
# ---------------------------------------------------------------------------


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

    def display_lines(self, quiet: bool = False) -> list[str]:
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

    def _display_lines(self, quiet: bool = False) -> list[str]:
        return self.display_lines(quiet)

    def display(self, quiet: bool = False) -> None:
        """Print errors (and optionally warnings) to the console."""
        lines = self.display_lines(quiet)
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


@dataclass(frozen=True)
class MissingSection:
    """A DATA/GLOBAL binding whose VA resolves to a known binary section (W016)."""

    module: str
    va: int
    section: str


def block_defines(lines: list[str] | None, binding_line: int) -> bool:
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


def check_format_errors(result: LintResult, flags: dict[str, bool]) -> bool:
    """Check format-level errors (E001). Returns True if validation should proceed."""
    if not flags["has_new"]:
        result.error(result.binding_line, "E001", "Missing function metadata binding")
        return False

    return True


def check_E001_kind(result: LintResult, kind: str) -> None:
    """Flag an unrecognised binding kind (E001)."""
    if kind not in SYMBOL_KINDS:
        result.error(result.binding_line, "E001", f"Invalid metadata kind: {kind}")


def check_E002_va(result: LintResult, va_str: str, min_va: int = MIN_VALID_VA) -> int | None:
    """Validate hex VA formatting and minimum target address (E002)."""
    try:
        va_int = int(va_str, 16)
        if not (min_va <= va_int <= 0xFFFFFFFF):
            result.error(result.binding_line, "E002", f"VA {va_str} is suspicious (outside range)")
        return va_int
    except ValueError:
        result.error(result.binding_line, "E002", f"Invalid VA format: {va_str}")
        return None


def check_E013_duplicate_va(
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
    """Flag duplicate VA claims within a module (E013)."""
    if va_int is None or seen_vas is None:
        return
    # Key on (module, va) so a multi-module file whose blocks share a VA
    # (a valid layout) is not flagged, while a true duplicate — same module
    # + VA, in the same or another file — is.
    key: Any = (module, va_int) if module else va_int
    defines = block_defines(lines, binding_line) if kind in DATA_KINDS else True
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


def check_W018_cflags(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    """Warn when a function has neither per-function CFLAGS nor a project default (W018)."""
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


def check_E015_kind_consistency(
    result: LintResult, kind: str, module: str, status: str, cfg: ProjectConfig | None = None
) -> None:
    """Check that binding kind aligns with module ownership and STUB status (E015)."""
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


def check_E004_status_value(result: LintResult, status: str) -> None:
    """Flag a persisted STATUS outside KNOWN_STATUSES (E004).

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


def check_E008_size_value(result: LintResult, metadata_size: str | None) -> None:
    """Flag a store SIZE that is not an integer (E008).

    Validates the size on the binding's owning store (``rebrew-functions.toml``
    for a function, ``rebrew-data.toml`` for data).  A non-numeric SIZE would
    make a consumer slice the wrong byte count or silently fall back.
    """
    if not metadata_size:
        return
    try:
        from rebrew.utils import parse_int_literal

        parse_int_literal(metadata_size)
    except ValueError:
        result.error(
            result.binding_line, "E008", f"metadata SIZE {metadata_size!r} is not an integer"
        )


def check_E017_contradictory(result: LintResult, status: str, kind: str) -> None:
    """Flag STUB kind paired with matched/near-matching status (E017)."""
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


def check_W005_blocker(result: LintResult, status: str, found_keys: dict[str, str]) -> None:
    """Warn when a STUB function lacks a BLOCKER note (W005)."""
    # BLOCKER lives in rebrew-functions.toml metadata; the metadata overlay already injects it
    # into found_keys before this check runs, so this fires only when absent from both.
    if status == "STUB" and "BLOCKER" not in found_keys:
        result.warning(
            result.binding_line,
            "W005",
            "STUB function missing 'blocker' explanation "
            '(run: rebrew blocker set <file|0xVA> "<reason>" — or: rebrew diff --fix-blocker)',
        )


def check_W006_source(
    result: LintResult, module: str, found_keys: dict[str, str], cfg: ProjectConfig | None = None
) -> None:
    """Warn when a library module entry lacks SOURCE reference metadata (W006)."""
    lib_modules = cfg.library_modules if cfg and cfg.library_modules is not None else set()
    if module in lib_modules and "SOURCE" not in found_keys:
        result.warning(
            result.binding_line,
            "W006",
            f"Library module {module!r} missing source metadata "
            "(reference file, e.g. SBHEAP.C:195 or deflate.c)",
        )


def check_W015_va_case(result: LintResult, va_str: str) -> None:
    """Warn on mixed-case hex digits in a VA literal (W015)."""
    if va_str and va_str.startswith("0x"):
        hex_digits = va_str[2:]
        if hex_digits != hex_digits.lower() and hex_digits != hex_digits.upper():
            result.warning(
                result.binding_line,
                "W015",
                f"VA '{va_str}' has mixed-case hex digits (prefer consistent case)",
            )


def check_config_rules(
    result: LintResult, found_keys: dict[str, str], cfg: ProjectConfig | None
) -> None:
    """Config-aware checks (E012).

    A stacked shared-source address anchor for ANOTHER target (``/* ADDRESS: V1 0xVA */``
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


def check_W016_section(
    result: LintResult,
    kind: str,
    found_keys: dict[str, str],
    module: str = "",
    va_int: int | None = None,
    section_for_va: Any = None,
    section_hits: list[MissingSection] | None = None,
) -> None:
    """Warn when a DATA/GLOBAL entry lacks SECTION metadata and record autofix hits (W016)."""
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


# ---------------------------------------------------------------------------
# Batch metadata store, data extent, provenance, type, and scaffold checks
# ---------------------------------------------------------------------------


def check_W031_metadata_store(cfg: ProjectConfig) -> list[LintResult]:
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
            if (
                not data_store
                and "similarity" in lower
                and (
                    not entry.get("status")
                    or not isinstance(entry.get("verification"), dict)
                    or entry.get("status") != entry.get("verification", {}).get("status")
                )
            ):
                problems.append(f"{key}: similarity requires a comparison verdict")
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


def check_W034_identity_paths(cfg: ProjectConfig) -> list[LintResult]:
    """W034: invalid stored file identities or a store that cannot be checked."""
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


def check_W035_unknown_modules(cfg: ProjectConfig) -> list[LintResult]:
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


def check_W036_stray_metadata_store(cfg: ProjectConfig) -> list[LintResult]:
    """W036: a metadata store living outside the directory the readers use.

    The stores are resolved by directory, not by search: a tool asked for a
    module reads ``<metadata_dir>/rebrew-data.toml`` and gets **whatever is
    there**, with no fallback to another copy.  So a second ``rebrew-data.toml``
    somewhere else in the tree is not a backup -- it is a file that answers for
    a directory if a tool is pointed at it, and is invisible otherwise.

    Measured on guild-rebrew: a stray ``./rebrew-data.toml`` at the
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


def type_spelling(text: str) -> str:
    """*text* with whitespace collapsed and dropped beside punctuation."""
    return _TYPE_SPELLING_RE.sub(r"\1", " ".join(text.split()))


def tiled_extent(
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


def check_W037_data_definition(
    result: LintResult, text: str, filepath: Path, cfg: ProjectConfig, directory: Path
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
    :func:`rebrew.data.layout.data_symbol_size` cannot compute (struct, union
    and unknown typedef types, unsized arrays, other architectures).  Only
    byte sizes are compared, the row's ``size`` and its ``type``'s extent each
    against the source's: a spelling difference with equal size (``[0x104]``
    against ``[260]``, a typedef against its expansion) is not reported.
    """
    from rebrew.c_syntax.parser import find_extern_variables, find_variable_roles
    from rebrew.data.layout import data_symbol_size
    from rebrew.metadata.data import data_rows_for_path, module_visible_to_target

    try:
        rows = data_rows_for_path(directory, filepath)
    except OSError, ValueError:
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
        externs = [v for v in named if _EXTERN_DECL_RE.match(v.declaration)]
        if name in defined:
            candidates = [v for v in named if v not in externs] or externs
        elif span:
            candidates = externs
        else:
            return None
        spellings = {type_spelling(v.type_str) for v in candidates}
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
        row_type = type_spelling(str(entry.get("type") or ""))
        row_type_size = data_symbol_size({"type": row_type}, arch=arch) if row_type else 0
        row_size = data_symbol_size({"size": entry.get("size")}, arch=arch)
        row_desc = f"type {row_type!r} ({row_type_size or '?'} bytes)" if row_type else "no type"
        if row_size:
            row_desc += f", size {row_size}"
        where = f"data row {module}.0x{va:08x} {untrusted_ident(name)} says {row_desc}"
        tiles = sorted(p for p in pieces.get((module, name), []) if p[0] > va)
        if tiles:
            source_size, hole = tiled_extent(va + source_size, tiles, source_extent)
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


def check_W038_data_row_overlap(cfg: ProjectConfig) -> list[LintResult]:
    """W038: two named ``rebrew-data.toml`` rows of one module overlap.

    Each row's extent is ``[va, va + size)`` with the size from
    :func:`rebrew.data.layout.data_symbol_size` (explicit ``size``, else a
    computable ``type``); a row with no computable extent is skipped.  An
    ``alias`` row with a ``backing`` is a view inside another allocation and
    is excluded.  Two storage owners cannot share a byte, so an overlap is a
    stale extent (W037 usually names which row) or a view not yet recorded
    as one; ``rebrew status`` otherwise reports only the byte count it had to
    discount.  Rows touching end-to-start do not overlap.
    """
    from rebrew.data.layout import data_symbol_size
    from rebrew.metadata.data import DATA_METADATA_FILENAME

    arch = str(getattr(cfg, "arch", "") or "x86_32")
    by_module: dict[str, list[tuple[int, int, str]]] = {}
    for (module, va), entry in load_data_metadata(cfg.metadata_dir, deepcopy=False).items():
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


def check_W033_agent_scaffold(
    cfg: ProjectConfig,
    *,
    skill_files_fn: Callable[[str], dict[str, bytes]] | None = None,
) -> list[LintResult]:
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
    if skill_files_fn is None:
        raise ValueError("skill_files_fn is required to check rendered agent skills")

    # The shared scaffold follows the configured default, independently of
    # the target selected for lint. Programmatic configs may have no TOML.
    targets = getattr(cfg, "all_targets", [])
    target_name = str((targets[0] if targets else getattr(cfg, "target_name", "")) or "")
    if not target_name or not getattr(cfg, "root", None):
        return []
    if (Path(cfg.root) / "rebrew-project.toml").is_file():
        target_name = load_config(Path(cfg.root)).target_name

    expected = {f".agents/skills/{rel}": data for rel, data in skill_files_fn(target_name).items()}
    principles = Path(__file__).resolve().parent.parent / "PRINCIPLES.md"
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


def check_W031_source_provenance(cfg: ProjectConfig) -> list[LintResult]:
    """Surface invalid or stale source evidence rather than silently trusting it."""
    result = LintResult(Path(SOURCE_PROVENANCE_FILENAME))
    # The store root does not move while the check runs; the property walks the
    # ancestors, and one file can carry many provenance records.
    metadata_dir = cfg.metadata_dir
    try:
        records = load_source_provenance(metadata_dir)
    except (OSError, ValueError) as exc:
        result.warning(1, "W031", f"invalid source provenance store: {exc}")
        return [result]
    known = {
        preset_module_key(str(module))
        for module in (getattr(cfg, "target_modules", None) or [cfg.module])
        if module
    }
    hashes: dict[str, dict[str, str]] = {}
    metadata_root: Path | None = None
    for record in records:
        label = f"{record.module}:{record.file}:{record.symbol}"
        if known and record.module not in known:
            result.warning(1, "W031", f"source provenance {label} names an unknown target module")
            continue
        if cfg.module and record.module != preset_module_key(cfg.module):
            continue
        try:
            if record.file not in hashes:
                if metadata_root is None:
                    metadata_root = metadata_dir.resolve()
                path = (metadata_dir / record.file).resolve()
                path.relative_to(metadata_root)
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


def check_W031_type_metadata(cfg: ProjectConfig) -> list[LintResult]:
    """Report invalid/stale managed type bindings without invoking the compiler."""
    from rebrew.c_syntax.type_metadata import TYPE_METADATA_FILENAME, check_types

    result = LintResult(Path(TYPE_METADATA_FILENAME))
    for finding in check_types(cfg):
        result.warning(1, "W031", f"type {finding['id']}:{finding['module']}: {finding['issue']}")
    return [result] if result.warnings else []
