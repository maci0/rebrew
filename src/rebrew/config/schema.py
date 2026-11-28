"""TOML section schemas (msgspec.Struct) and field validation helpers."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
lazy import math
lazy import shlex
lazy import tomllib
lazy import unicodedata
lazy from collections.abc import Mapping

lazy import msgspec

from rebrew.config.constants import (
    FUNCTION_STRUCTURE_JSON,
    config_warn,
)
from rebrew.errors import (
    ConfigError,
)
lazy from rebrew.utils import (
    load_tomllib,
    parse_int_literal,
    preset_module_key,
    try_parse_int,
)
lazy from rebrew.workspace.config import config_path


class AddressCommentsStruct(msgspec.Struct, kw_only=True):
    """Schema for ``address_comments`` tables."""

    style: str = "c89"
    regex: str = ""
    template: str = ""


class LintSectionStruct(msgspec.Struct, kw_only=True):
    """Schema for ``[project.lint]``."""

    naming_convention: str = "none"
    brace_style: str = "none"
    indent_style: str = "none"
    max_line_length: int = 200


class LinkSectionStruct(msgspec.Struct, kw_only=True):
    """Schema for ``[link]``."""

    file_align: int | None = None
    stack_reserve: int | None = None
    stack_commit: int | None = None
    tsaware: bool | None = None
    linker_version: str | None = None
    os_version: str | None = None
    subsystem_version: str | None = None
    timestamp: int | None = None


class LlmSectionStruct(msgspec.Struct, kw_only=True):
    """Schema for ``[llm]``."""

    endpoint: str = ""
    api_key: str = ""
    model: str = ""
    max_requests: int | str = ""
    max_tokens: int | str = ""
    timeout: int | str = ""


class CacheSectionStruct(msgspec.Struct, kw_only=True):
    """Schema for ``[cache]``."""

    backend: str = ""
    size_limit_mib: int = 0


class CompilerSectionStruct(msgspec.Struct, kw_only=True):
    """Schema for ``[compiler]`` and ``[targets.<name>.compiler]``."""

    command: str = "wine CL.EXE"
    runner: str = ""
    execution_backend: str = ""
    includes: str = ""
    libs: str = ""
    cflags: str = ""
    profile: str = "msvc-6.0"
    base_cflags: str = "/nologo /c /MT"
    timeout: int = 60
    recompile_url: str = ""
    recompile_emit_assembly: bool = False
    recompile_retries: int = 2
    recompile_concurrency: int = 2
    cflags_presets: dict[str, str] = msgspec.field(default_factory=dict)


class ProjectSectionStruct(msgspec.Struct, kw_only=True):
    """Schema for ``[project]``."""

    name: str = ""
    jobs: int = 4
    output_dir: str = "output"
    default_target: str = ""
    shared_dir: str = "src/shared"
    lint: dict[str, Any] = msgspec.field(default_factory=dict)
    address_comments: dict[str, Any] = msgspec.field(default_factory=dict)


class TargetSectionStruct(msgspec.Struct, kw_only=True):
    """Schema for ``[targets.<name>]``."""

    binary: str = ""
    arch: str = "x86_32"
    format: str = "pe"
    module: str = ""
    reversed_dir: str = ""
    bin_dir: str = ""
    source_ext: str = ".c"
    ghidra_program_path: str = ""
    ghidra_backend: str = ""
    binsync_state_dir: str = ""
    binsync_user: str = ""
    inventory_file: str = ""
    raw_link: str = ""
    check_known_bindings: bool = False
    defines: list[str] = msgspec.field(default_factory=list)
    r2_bogus_vas: list[Any] = msgspec.field(default_factory=list)
    iat_thunks: list[Any] = msgspec.field(default_factory=list)
    dll_exports: dict[str, str] = msgspec.field(default_factory=dict)
    ignored_symbols: list[str] = msgspec.field(default_factory=list)
    library_modules: list[str] = msgspec.field(default_factory=list)
    external_libs: dict[str, str] = msgspec.field(default_factory=dict)
    external_ranges: list[str] = msgspec.field(default_factory=list)
    crt_sources: dict[str, str] = msgspec.field(default_factory=dict)
    origins: list[str] = msgspec.field(default_factory=list)
    compiler: dict[str, Any] = msgspec.field(default_factory=dict)
    address_comments: dict[str, Any] = msgspec.field(default_factory=dict)


class ProjectDocumentStruct(msgspec.Struct, kw_only=True):
    """Top-level ``rebrew-project.toml`` document structure."""

    project: dict[str, Any] = msgspec.field(default_factory=dict)
    targets: dict[str, dict[str, Any]] = msgspec.field(default_factory=dict)
    compiler: dict[str, Any] = msgspec.field(default_factory=dict)
    link: dict[str, Any] = msgspec.field(default_factory=dict)
    llm: dict[str, Any] = msgspec.field(default_factory=dict)
    cache: dict[str, Any] = msgspec.field(default_factory=dict)
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


def read_toml_doc(path: Path) -> dict[str, Any]:
    """Read a TOML document at *path*."""
    return load_tomllib(path)


#: Characters stripped from a target name when deriving its module:
#: ``server.dll`` yields ``SERVERDLL``, an identifier-shaped module name.
#: Set ``module`` explicitly when the annotations use another module
#: (e.g. ``SERVER``).
MODULE_STRIP_RE = re.compile(r"[^A-Za-z0-9_]")


def target_module_value(raw: Any, target: str, field_name: str) -> str:
    """Return the annotation module for one target.

    Absent or blank ``module`` uses the derived name (target upper-cased,
    non-identifier characters stripped). An explicit module must be one
    token: whitespace never matches ``/* ADDRESS: MODULE 0xVA */``, and a
    module containing ``.0x`` makes ``parse_metadata_key`` split the module
    off the VA. A target whose name derives nothing and sets no module
    fails the load — an empty module drops every function out of
    verify/todo/status.
    """
    derived = MODULE_STRIP_RE.sub("", target).upper()
    if raw is None:
        text = derived
    elif isinstance(raw, str):
        text = raw.strip() or derived
    else:
        config_warn(
            f"Expected string for {field_name}, got {type(raw).__name__}; "
            f"using default {derived!r}",
        )
        text = derived
    if not text:
        raise ConfigError(
            f"rebrew-project.toml {field_name} is empty and {target!r} has no "
            "identifier characters to derive a module from"
        )
    if any(ch.isspace() for ch in text):
        raise ConfigError(
            f"rebrew-project.toml {field_name} = {text!r} is not a single token "
            "(address modules are one word: /* ADDRESS: MODULE 0xVA */)"
        )
    if ".0x" in text.casefold():
        raise ConfigError(
            f"rebrew-project.toml {field_name} = {text!r} contains '.0x', "
            "which breaks MODULE.0xVA metadata keys"
        )
    return unicodedata.normalize("NFC", text)


def target_module(cfg: Any) -> str:
    """Return the annotation module for *cfg*.

    The module is the ``MODULE`` half of every ``MODULE.0xVA`` metadata key
    and of every ``/* ADDRESS: MODULE 0xVA */`` line, so it must resolve the
    same way everywhere: an entry written under one spelling is invisible to
    a reader using another.  The rule is ``cfg.module``, else the target name
    with non-identifier characters stripped and upper-cased (the same
    derivation :func:`load_config` applies), else ``""``.

    Callers that write to the metadata store must reject an empty result:
    :func:`rebrew.metadata.document.qualified_key` renders a module-less entry as a bare
    ``0xVA`` key, which :func:`rebrew.metadata.document.parse_metadata_key` does not
    accept, so the write is silently unreadable.  Fabricating a placeholder
    module instead (``"SERVER"``, ``"GAME"``) is worse: it writes real data
    under another project's module name.

    Mock-safe via ``getattr`` — takes any config-shaped object.
    """
    target_module_name = str(getattr(cfg, "module", "") or "")
    if target_module_name:
        return unicodedata.normalize("NFC", target_module_name)
    target = str(getattr(cfg, "target_name", "") or "")
    return unicodedata.normalize("NFC", MODULE_STRIP_RE.sub("", target).upper())


def inventory_path_for(reversed_dir: Path | str, cfg: Any = None) -> Path:
    """Inventory path for a source dir, honouring a target's override.

    Drop-in for the ``X / FUNCTION_STRUCTURE_JSON`` joins scattered across
    the tools: when *cfg* names an ``inventory_file`` override AND *X* is
    that target's own ``reversed_dir``, the override wins; otherwise the
    legacy join.  Always returns a Path (possibly non-existent — callers
    check existence as before, and the old ``... if X else None`` guards
    stay at the call sites); mock-safe via getattr.
    """
    rd = Path(reversed_dir)
    override = str(getattr(cfg, "inventory_file", "") or "").strip()
    cfg_reversed = getattr(cfg, "reversed_dir", "")
    if override and cfg_reversed:
        try:
            if rd.resolve() == Path(cfg_reversed).resolve():
                p = config_path(override)
                root = getattr(cfg, "root", None)
                return p if p.is_absolute() else (Path(root) / p if root else p)
        except (OSError, ValueError, TypeError) as exc:
            # Falling through reads a different project's inventory; that is
            # silent data corruption, so name the failed comparison.
            logging.getLogger(__name__).warning(
                "inventory_file %r could not be resolved against reversed_dir %s (%s); "
                "using %s instead",
                override,
                rd,
                exc,
                rd / FUNCTION_STRUCTURE_JSON,
            )
    return rd / FUNCTION_STRUCTURE_JSON


def parse_va_ranges(values: list[Any] | None, field_name: str) -> list[tuple[int, int]]:
    """Parse ``["0x5e0000-0x64ffff", ...]`` into inclusive ``(lo, hi)`` pairs.

    Used by ``targets.<name>.external_ranges``: address bands the target's
    binary fills with code from a statically linked library rather than from
    the project's sources (the D3DX8/T&L band in a client build).  A band is a
    fact about the *link*, so it belongs in configuration next to
    ``external_libs`` — not hardcoded per tool.
    """
    if not isinstance(values, list):
        if values is not None:
            config_warn(f"Expected list for {field_name}, got {type(values).__name__}; ignoring")
        return []

    parsed: list[tuple[int, int]] = []
    for v in values:
        if not isinstance(v, str) or "-" not in v:
            config_warn(f"Invalid range {v!r} in {field_name}; expected '0xLO-0xHI'")
            continue
        lo_s, _, hi_s = v.partition("-")
        try:
            lo, hi = parse_int_literal(lo_s.strip()), parse_int_literal(hi_s.strip())
        except ValueError:
            config_warn(f"Invalid range {v!r} in {field_name}; expected '0xLO-0xHI'")
            continue
        if hi < lo:
            config_warn(f"Invalid range {v!r} in {field_name}: end before start; ignoring")
            continue
        parsed.append((lo, hi))
    return parsed


def parse_int_list(values: list[Any] | None, field_name: str) -> list[int]:
    """Parse a list of integers from a toml array, allowing hex strings."""
    if not isinstance(values, list):
        if values is not None:
            config_warn(
                f"Expected list for {field_name}, got {type(values).__name__}; ignoring",
            )
        return []

    parsed: list[int] = []
    for v in values:
        if isinstance(v, bool):
            # bool is an int subclass; True must not become reloc offset 1.
            config_warn(f"Unexpected type {type(v).__name__} in {field_name}; ignoring")
        elif isinstance(v, int):
            parsed.append(v)
        elif isinstance(v, float):
            if math.isfinite(v) and v.is_integer():
                parsed.append(int(v))
            else:
                config_warn(f"Unexpected type {type(v).__name__} in {field_name}; ignoring")
        elif isinstance(v, str):
            try:
                parsed.append(parse_int_literal(v))
            except ValueError:
                config_warn(f"Invalid integer '{v}' in {field_name}; ignoring")
        else:
            config_warn(f"Unexpected type {type(v).__name__} in {field_name}; ignoring")
    return parsed


#: A ``[targets.<name>].defines`` entry is emitted as ``/D{entry}`` or
#: ``-D{entry}``. ``NAME`` and ``NAME=value`` (no whitespace) are macros —
#: ``CLIENT=1`` has been a working ``/DCLIENT=1`` since defines shipped.
#: A token with spaces is not a macro, so ``#ifdef`` branches compile the
#: wrong side and the byte diff looks like a source bug.
DEFINE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:=[^\s]*)?$")


def parse_defines(values: Any, field_name: str) -> list[str]:
    """Parse a list of compile-time defines from a toml array.

    Entries are trimmed. Empty entries are dropped. Non-string entries warn
    and are dropped (``str(None)`` would otherwise become ``-DNone``). A
    string must be ``NAME`` or ``NAME=value`` with no whitespace. Anything
    else fails the load: it would be passed through as a ``-D``/``/D`` flag
    and compile the wrong ``#ifdef`` side. A valued macro stays accepted so
    a project that wrote ``defines = ["CLIENT=1"]`` under 2.9.0 still loads.
    """
    if not isinstance(values, list):
        if values is not None:
            config_warn(
                f"Expected list for {field_name}, got {type(values).__name__}; ignoring",
            )
        return []
    out: list[str] = []
    for v in values:
        if not isinstance(v, str):
            config_warn(f"{field_name}: non-string define {v!r} ignored")
            continue
        name = v.strip()
        if not name:
            continue
        if DEFINE_NAME_RE.fullmatch(name) is None:
            raise ConfigError(
                f"rebrew-project.toml {field_name}: {v!r} is not a C define name "
                "(NAME, or NAME=value with no whitespace)"
            )
        out.append(name)
    return out


def parse_hex_dict(mapping: dict[str, Any] | None) -> dict[int, str]:
    """Parse a dict where keys are hex strings and values are strings.

    A non-string value is dropped rather than coerced: the value is an export
    *name* (a `dll_exports` row, an import lookup), so a TOML integer such as
    `0x1000 = 42` is a typo, and `str()` would turn it into a plausible-looking
    name that silently matches nothing.
    """
    if not isinstance(mapping, dict):
        if mapping is not None:
            config_warn(
                f"Expected mapping for hex dict, got {type(mapping).__name__}; ignoring",
            )
        return {}

    result: dict[int, str] = {}
    for k, v in mapping.items():
        try:
            addr = parse_int_literal(str(k))
        except ValueError:
            config_warn(f"Invalid hex key '{k}' in mapping; ignoring")
            continue
        if not isinstance(v, str):
            config_warn(
                f"Expected string value for key {hex(addr)} in mapping, "
                f"got {type(v).__name__}; ignoring"
            )
            continue
        result[addr] = v
    return result


def parse_str_list(values: list[Any] | None, field_name: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        config_warn(
            f"Expected list for {field_name}, got {type(values).__name__}; using empty list",
        )
        return []
    result: list[str] = []
    for v in values:
        if isinstance(v, str):
            result.append(v)
        else:
            config_warn(f"Skipping non-string {field_name} value: {v!r}")
    return result


def safe_int(value: Any, default: int, field_name: str = "integer") -> int:
    """Convert *value* to int, returning *default* on failure.

    ``None`` (not set) returns *default* silently — matching ``as_str`` —
    so absent optional keys never warn on an otherwise valid config.
    Non-integral floats (``3.9``) are rejected rather than truncated: bare
    ``int(3.9)`` would silently store ``3`` for timeouts/jobs/limits.
    """
    if value is None:
        return default
    parsed = try_parse_int(value)
    if parsed is None:
        config_warn(f"Expected integer for {field_name}, got {value!r}; using default {default}")
        return default
    return parsed


def positive_int(value: Any, default: int, field_name: str) -> int:
    """Parse a positive integer config value, falling back to *default*."""
    parsed = safe_int(value, default, field_name)
    if parsed < 1:
        config_warn(
            f"Expected positive integer for {field_name}, got {value!r}; using default {default}"
        )
        return default
    return parsed


def non_negative_int(
    value: Any, default: int, field_name: str, *, maximum: int | None = None
) -> int:
    """Parse a non-negative integer, falling back to *default*; cap at *maximum* when set.

    The ceiling matters for a wall-clock budget, not a threshold the consumer
    merely compares: ``rebrew.compiler.compile`` turns ``recompile_retries``
    into ``retries + 1`` attempts that each wait ``retry_backoff_delay``, so
    the count multiplies directly into minutes a build spends retrying one
    transient error. Clamping with a warning, like :func:`llm_max_requests`,
    shows the operator the value they wrote and what it resolved to rather
    than watching a compile appear to hang.
    """
    parsed = safe_int(value, default, field_name)
    if parsed < 0:
        config_warn(
            f"Expected non-negative integer for {field_name}, got {value!r}; using default {default}"
        )
        return default
    if maximum is not None and parsed > maximum:
        config_warn(
            f"Expected at most {maximum} for {field_name}, got {value!r}; clamping to {maximum}"
        )
        return maximum
    return parsed


#: Link fields are stored in the PE optional header as unsigned 32-bit
#: values. ``patch_pe_headers`` masks with ``& 0xFFFFFFFF``, so a bool
#: (``True`` is an ``int``) or a negative / oversized number would be
#: written as a different header than the one configured.
_PE_U32_MAX = 0xFFFFFFFF


def parse_optional_int(value: Any, field_name: str) -> int | None:
    """Parse an optional PE unsigned-32 link field.

    ``None`` means unset. Decimal and ``0x`` strings are accepted. A bool
    is not an integer here (``True`` would become stack reserve 1). Values
    outside ``0 .. 0xFFFFFFFF`` raise :class:`ConfigError` instead of being
    truncated when the header is patched. Unparseable values warn and are
    treated as unset.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        config_warn(f"Expected integer for {field_name}, got {value!r}; ignoring")
        return None
    parsed: int | None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = parse_int_literal(value)
        except ValueError:
            config_warn(f"Invalid integer {value!r} for {field_name}; ignoring")
            return None
    else:
        config_warn(f"Expected integer for {field_name}, got {type(value).__name__}; ignoring")
        return None
    if parsed < 0 or parsed > _PE_U32_MAX:
        raise ConfigError(
            f"rebrew-project.toml {field_name} = {value!r} is outside "
            f"0..0x{_PE_U32_MAX:X} (PE optional-header fields are unsigned 32-bit; "
            "a wider value would be truncated when the header is patched)"
        )
    return parsed


def parse_str_dict(value: Any, field_name: str) -> dict[str, str]:
    """Parse a string-to-string mapping from config."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        config_warn(
            f"Expected mapping for {field_name}, got {type(value).__name__}; using empty mapping"
        )
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            config_warn(f"Skipping non-string {field_name} entry: {key!r} = {item!r}")
            continue
        result[key] = item
    return result


def parse_source_ext(value: Any) -> str:
    """Parse and normalize the configured source extension(s).

    Accepts a single extension (``".c"``) or a comma-separated list
    (``".c,.cpp"``) so projects with mixed C/C++ sources can declare both.
    """
    if value is None:
        return ".c"
    if not isinstance(value, str):
        config_warn(f"Expected string for source_ext, got {type(value).__name__}; using default .c")
        return ".c"
    exts = [part.strip() for part in value.split(",") if part.strip()]
    if not exts or exts == ["."]:
        config_warn("Expected non-empty source_ext; using default .c")
        return ".c"
    normalized: list[str] = []
    for ext in exts:
        if "/" in ext or "\\" in ext:
            config_warn(f"source_ext must be a file extension, got {value!r}; using default .c")
            return ".c"
        if not ext.startswith("."):
            config_warn(f"source_ext {ext!r} is missing a leading dot; using .{ext}")
            ext = f".{ext}"
        normalized.append(ext)
    return ",".join(normalized)


def as_table(value: Any, field_name: str) -> dict[str, Any]:
    """Return a TOML table as a dict or raise a clear config error."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"rebrew-project.toml [{field_name}] must be a TOML table")
    return value


#: ``rebrew-project.toml`` sections every :func:`load_config` reads as tables.
PROJECT_TABLE_SECTIONS = ("project", "targets", "compiler", "link", "llm", "cache", "metadata")


def check_project_document(raw: Mapping[str, Any]) -> None:
    """Raise :class:`ConfigError` unless *raw* has the shape every reader assumes.

    [project], [targets], [compiler], [link], [llm], [cache] and [metadata]
    must be tables when present, and every ``[targets.X]`` must be a table.
    ``load_config``, the ``cfg`` editor, ``build driver``, ``calibrate-bss``
    and ``init --refresh-agents`` all read the parsed document through these
    sections.
    """
    for name in PROJECT_TABLE_SECTIONS:
        as_table(raw.get(name), name)
    for name, target in as_table(raw.get("targets"), "targets").items():
        if not isinstance(target, dict):
            raise ConfigError(f"rebrew-project.toml [targets.{name}] must be a TOML table")


def read_project_toml(path: Path) -> dict[str, Any]:
    """The ``rebrew-project.toml`` at *path*, parsed and :func:`check_project_document`-checked.

    Raises :class:`ConfigError` when it does not parse or has the wrong shape,
    and ``OSError`` when it cannot be read.
    """
    try:
        raw = read_toml_doc(path)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from exc
    check_project_document(raw)
    return raw


def project_default_target(raw: Mapping[str, Any]) -> str | None:
    """``[project].default_target`` of a checked document, or ``None`` when unset.

    Raises :class:`ConfigError` when it is set to anything but a non-empty string.
    """
    target = as_table(raw.get("project"), "project").get("default_target")
    if target is None:
        return None
    if not isinstance(target, str):
        raise ConfigError(
            f"rebrew-project.toml [project].default_target must be a string, "
            f"got {type(target).__name__}"
        )
    if not target.strip():
        first = next(iter(as_table(raw.get("targets"), "targets")), None)
        hint = "" if first is None else f'. Add: default_target = "{first}"'
        raise ConfigError(f"rebrew-project.toml [project].default_target must not be empty{hint}")
    return str(target)


def as_str(value: Any, default: str, field_name: str) -> str:
    """Return a string config value, warning and using *default* on bad types.

    Distinguishes "not set" (``None`` → *default* silently) from "set to a
    non-string" (warn + *default*). Empty string is preserved when present so
    callers can treat "" as intentionally empty.
    """
    if value is None:
        return default
    if isinstance(value, str):
        return value
    config_warn(
        f"Expected string for {field_name}, got {type(value).__name__}; using default {default!r}",
    )
    return default


def validate_target_name(name: str, label: str = "target name") -> str:
    """Return *name* when it is usable as a single directory/file name.

    A target name becomes a path component (``src/<target>``, ``bin/<target>``,
    ``coverage-<target>.toml``, ``layout/<target>/``) and a TOML table key, so a
    name carrying a separator, a ``..`` segment, or a control character would
    place files outside the project on the next command.  Real targets are
    module stems (``SERVER.DLL``, ``client_exe``), so anything else is a typo
    and fails loud here instead of escaping a directory later.
    """
    if not name or not name.strip():
        raise ConfigError(f"{label} must not be empty")
    if name != name.strip() or name in (".", ".."):
        raise ConfigError(f"{label} {name!r} is not a plain file name")
    if "/" in name or "\\" in name or "\x00" in name:
        raise ConfigError(f"{label} {name!r} must not contain a path separator")
    if any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in name):
        raise ConfigError(f"{label} {name!r} must not contain control characters")
    return unicodedata.normalize("NFC", name)


def normalized_targets(targets: Mapping[str, Any]) -> dict[str, Any]:
    """``targets`` re-keyed to NFC, or a :class:`ConfigError` on a collision.

    A target name is an identity: ``--target`` on the command line, the module
    derived from it, ``coverage-<target>.toml`` and the ``[targets.X]``
    table all have to agree on one spelling.  The module side already
    normalizes (:func:`target_module_value`), so an NFD key in the TOML would
    produce an NFC module that no ``--target`` spelling reaches, and every
    function under it would drop out of verify/todo.  Normalizing the keys
    instead makes both sides agree.  Two keys that differ only in normalization
    are two names for one target: that is a real ambiguity, not a spelling to
    pick a winner for, so it fails loud.
    """
    out: dict[str, Any] = {}
    seen: dict[str, str] = {}
    for name, data in targets.items():
        if not isinstance(name, str):
            continue
        key = unicodedata.normalize("NFC", name)
        if key in out:
            raise ConfigError(
                f"rebrew-project.toml [targets] has two keys that are the same name "
                f"under Unicode normalization: {seen[key]!r} and {name!r}"
            )
        out[key] = data
        seen[key] = name
    return out


def as_bool(value: Any, field_name: str) -> bool:
    """Return a bool config value, warning and using ``False`` on bad types.

    TOML booleans are real ``bool``s.  Reject stringy ``"false"``/``"0"`` —
    ``bool("false")`` is ``True`` in Python, which would silently enable a
    assembly-output flag like ``recompile_emit_assembly``.
    """
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    config_warn(
        f"Expected boolean for {field_name}, got {value!r}; using default False",
    )
    return False


def resolve_path(root: Path, rel: str | Path | None) -> Path | None:
    """Resolve a path relative to project root.  Returns *None* if *rel* is ``None``."""
    if rel is None:
        return None
    if not isinstance(rel, (str, Path)):
        config_warn(f"Expected path string, got {type(rel).__name__}; ignoring")
        return None
    p = config_path(rel)
    if p.is_absolute():
        return p
    return root / p


def required_path(root: Path, value: Any, default: str, field_name: str) -> Path:
    """Resolve a configured path, rejecting explicit empty or invalid values."""
    if value is None:
        value = default
    if isinstance(value, str) and not value.strip():
        raise ConfigError(f"rebrew-project.toml {field_name} must not be empty")
    resolved = resolve_path(root, value)
    if resolved is None:
        raise ConfigError(f"rebrew-project.toml {field_name} must be a path string")
    return resolved


def install_tool_alt(path: Path, root: Path) -> Path | None:
    """The rebrew-install copy of a missing project-relative tools/ path."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    from rebrew.utils import find_install_tool

    return find_install_tool(rel)


def split_compiler_runner(compiler: dict[str, Any]) -> tuple[str, str]:
    command_raw = as_str(compiler.get("command"), "wine CL.EXE", "compiler.command")
    if not command_raw.strip():
        # Docker-only: an image-backed profile legitimately has no host
        # command (the image IS the compiler); native profiles still need
        # one and are rejected below.
        profile = str(compiler.get("profile") or "").strip()
        # Outside the try: the except clause below must be able to name it.
        from rebrew.registry import RegistryError

        try:
            from rebrew.compiler.toolchain import TOOLCHAINS

            spec = TOOLCHAINS.get(profile)
        except RegistryError:  # a plugin registration conflict is reported at load
            raise
        except Exception as exc:  # toolchain import is best-effort
            logging.getLogger(__name__).debug(
                "toolchain registry unavailable for profile %r: %s", profile, exc, exc_info=True
            )
            spec = None
        if spec is not None and spec.image is not None:
            return "", ""
        raise ConfigError("rebrew-project.toml compiler.command must not be empty")
    if "runner" in compiler:
        return as_str(compiler.get("runner"), "", "compiler.runner"), command_raw

    try:
        parts = shlex.split(command_raw)
    except ValueError as exc:
        # An unbalanced quote is a config typo, and the naive split below
        # cannot tell where the runner ends: the whole string lands in the
        # command either way, so the compile fails on argv rather than here.
        config_warn(f"compiler.command is not shell-parseable ({exc}); splitting on whitespace")
        parts = command_raw.split()

    if parts and parts[0] in {"wine", "wibo"}:
        runner = parts[0]
        return runner, command_raw

    return "", command_raw


def merge_cflags_presets(
    global_compiler: Mapping[str, Any],
    target_compiler: Mapping[str, Any],
    *,
    target_name: str = "",
) -> dict[str, str]:
    """Merge per-module cflags presets: global, overridden per-key by target.

    ``rebrew cfg module set-cflags MODULE FLAGS`` writes a global
    ``[compiler.cflags_presets]``; ``--target X`` writes
    ``[targets.X.compiler.cflags_presets]``.  The target's presets win for
    the same module key, matching the documented "per-target presets
    override global presets for the same origin key" semantics.
    """
    where = f"targets.{target_name}" if target_name else "targets.<target>"
    tables = [
        (global_compiler.get("cflags_presets"), "compiler.cflags_presets"),
        (target_compiler.get("cflags_presets"), f"{where}.compiler.cflags_presets"),
    ]
    merged: dict[str, str] = {}
    for value, label in tables:
        presets = as_table(value, label)
        for key, val in presets.items():
            if not isinstance(val, str):
                raise ConfigError(f"rebrew-project.toml {label}.{key} must be a string")
            merged[preset_module_key(str(key))] = val
    return merged


#: Prefix of a PE read to answer the header facts without LIEF.  A DOS stub,
#: optional header and section table fit inside it; a table past the window
#: clips to fewer sections, which sends the caller to the loader.
_PE_HEADER_READ = 64 * 1024


_as_bool = as_bool
