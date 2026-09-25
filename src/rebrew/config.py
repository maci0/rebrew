"""Centralised project configuration loader for rebrew.

Reads ``rebrew-project.toml`` from the project root and exposes every setting as
simple attributes so that tool scripts no longer need to hardcode paths,
image-base addresses, or compiler flags.

The configuration supports **multiple targets**.  Each target has its own
binary, source directory, and function list.  Compiler settings default to
the global ``[compiler]`` section but can be overridden per target.

Usage in any tool::

    from rebrew.config import load_config

    cfg = load_config()                  # default target
    bin_path = cfg.target_binary         # Path object
    src_dir  = cfg.reversed_dir          # Path object
    arch     = cfg.arch                  # "x86_32"
    base     = cfg.image_base            # int, e.g. 0x10000000

To load a specific target::

    cfg = load_config(target="client_exe")
"""

import ipaddress
import math
import os
import re
import shlex
import sys
import tomllib
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict, override
from urllib.parse import urlparse

from rebrew.errors import RebrewError
from rebrew.toolchain_spec import FlagsStyle
from rebrew.utils import load_tomllib, parse_int_literal
from rebrew.workspace import walk_up_to_root
from rebrew.workspace.config import config_path


class ConfigError(RebrewError, ValueError):
    """``rebrew-project.toml`` is unparsable or holds an invalid value.

    Base of every error :func:`load_config` / :func:`find_root` raise, so
    ``except ConfigError`` (or ``except RebrewError``) catches them all.
    """

    @override
    def __str__(self) -> str:
        # KeyError.__str__ would repr-quote the message for ConfigKeyError.
        return Exception.__str__(self)


class ConfigNotFoundError(ConfigError, FileNotFoundError):
    """No ``rebrew-project.toml`` at the given root or above the cwd."""


class ConfigKeyError(ConfigError, KeyError):
    """A required key or the requested target is missing from the config."""


class ConfigWarning(UserWarning):
    """Config problem already printed to stderr by :func:`_config_warn`.

    :func:`rebrew.cli.run_cli` ignores this category so a CLI run shows each
    warning once, not a second time through Python's warning display.
    """


def _config_warn(msg: str) -> None:
    """Emit a ConfigWarning and print a user-facing config warning to stderr."""
    import warnings

    warnings.warn(msg, ConfigWarning, stacklevel=2)
    try:
        from rich.console import Console

        Console(stderr=True).print(f"[yellow]warning:[/yellow] {msg}")
    except ImportError:
        print(f"warning: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Canonical filename for the function structure cache
# ---------------------------------------------------------------------------

FUNCTION_STRUCTURE_JSON = "function_structure.json"
"""Tool-agnostic structural cache: ``[{va, size, name?}]``.

This file stores function *boundaries* (VA + size) discovered by any RE
tool (Ghidra, radare2, rizin).  Names are optional hints used only when
no source annotation exists.  Source annotations are always authoritative
for naming.
"""

#: Seconds before a compile subprocess is killed.  The single source for
#: ``ProjectConfig.compile_timeout``: its dataclass default, the
#: ``[compiler] timeout`` fallback, and the ``getattr(cfg, ...)`` fallbacks in
#: ``rebrew.compile`` all read this, so a mock-backed call cannot get a
#: different budget than a configured one.
DEFAULT_COMPILE_TIMEOUT = 60

#: Maximum C source line length for lint W027 (0 disables the check).  Single
#: source for ``ProjectConfig.lint_max_line_length``, the
#: ``[project.lint] max_line_length`` fallback, and ``rebrew.lint``.
DEFAULT_LINT_MAX_LINE_LENGTH = 200
# ---------------------------------------------------------------------------
# Architecture presets
# ---------------------------------------------------------------------------


class _ArchPreset(TypedDict):
    capstone_arch: str
    capstone_mode: str
    pointer_size: int
    padding_bytes: list[int]
    symbol_prefix: str


_ARCH_PRESETS: dict[str, _ArchPreset] = {
    "x86_16": {
        "capstone_arch": "CS_ARCH_X86",
        "capstone_mode": "CS_MODE_16",
        "pointer_size": 2,
        "padding_bytes": [0x90, 0x00],
        "symbol_prefix": "_",
    },
    "x86_32": {
        "capstone_arch": "CS_ARCH_X86",
        "capstone_mode": "CS_MODE_32",
        "pointer_size": 4,
        "padding_bytes": [0xCC, 0x90],
        "symbol_prefix": "_",
    },
    "x86_64": {
        "capstone_arch": "CS_ARCH_X86",
        "capstone_mode": "CS_MODE_64",
        "pointer_size": 8,
        "padding_bytes": [0xCC, 0x90],
        "symbol_prefix": "",
    },
    "arm32": {
        "capstone_arch": "CS_ARCH_ARM",
        "capstone_mode": "CS_MODE_ARM",
        "pointer_size": 4,
        "padding_bytes": [0x00],
        "symbol_prefix": "",
    },
    "arm64": {
        "capstone_arch": "CS_ARCH_ARM64",
        "capstone_mode": "CS_MODE_ARM",
        "pointer_size": 8,
        "padding_bytes": [0x00],
        "symbol_prefix": "",
    },
    "mips32": {
        "capstone_arch": "CS_ARCH_MIPS",
        "capstone_mode": "CS_MODE_MIPS32",
        "pointer_size": 4,
        "padding_bytes": [0x00],
        "symbol_prefix": "",
    },
    "mips64": {
        "capstone_arch": "CS_ARCH_MIPS",
        "capstone_mode": "CS_MODE_MIPS64",
        "pointer_size": 8,
        "padding_bytes": [0x00],
        "symbol_prefix": "",
    },
    "ppc32": {
        "capstone_arch": "CS_ARCH_PPC",
        "capstone_mode": "CS_MODE_32",
        "pointer_size": 4,
        "padding_bytes": [0x60, 0x00, 0x00, 0x00],  # `nop`
        "symbol_prefix": "",
    },
    "ppc64": {
        "capstone_arch": "CS_ARCH_PPC",
        "capstone_mode": "CS_MODE_64",
        "pointer_size": 8,
        "padding_bytes": [0x60, 0x00, 0x00, 0x00],
        "symbol_prefix": "",
    },
    "sh2": {
        "capstone_arch": "CS_ARCH_SH",
        "capstone_mode": "CS_MODE_SH2",
        "pointer_size": 4,
        "padding_bytes": [0x00],
        "symbol_prefix": "",
    },
}


@dataclass
class LinkConfig:
    """Declarative linker settings for byte-identical PE reconstruction.

    Mirrors the ``[link]`` section of ``rebrew-project.toml``.  ``rebrew
    round-trip --fix-headers`` patches the reasm copy with these values, and
    the round-trip report's ``header_parity`` compares them against the
    original binary so header mismatches are visible (previously only .text
    bytes were checked).
    """

    file_align: int | None = None
    stack_reserve: int | None = None
    stack_commit: int | None = None
    tsaware: bool | None = None  # sets 0x8000 in dll_characteristics
    linker_version: str | None = None  # e.g. "5.12"
    os_version: str | None = None  # e.g. "5.0"
    subsystem_version: str | None = None  # e.g. "4.0"
    timestamp: int | None = None  # seconds since epoch, hex-accepting

    def _version_pair(self, label: str, ver: str | None) -> tuple[int, int] | None:
        """Parse a ``"N.N"`` version string into ``(major, minor)``, or None.

        Warns on malformed values (``"5"``, ``"abc"``) instead of silently
        dropping them — a typo'd ``linker_version`` otherwise makes
        ``--fix-headers`` skip the patch while the parity report shows a
        mismatch the user cannot explain.
        """
        if not ver:
            return None
        try:
            major, minor = ver.split(".", 1)
            maj, mn = int(major), int(minor)
            if not (0 <= maj <= 65535 and 0 <= mn <= 65535):
                raise ValueError("out of range")
            return maj, mn
        except ValueError:
            _config_warn(
                f"link.{label} = {ver!r} is not a valid 'N.N' version — "
                "the header patch for it will be skipped"
            )
            return None

    def to_patch_fields(self) -> dict[str, int]:
        """Map configured values to pe_headers field labels (empty if unset)."""
        fields: dict[str, int] = {}
        vp = self._version_pair("linker_version", self.linker_version)
        if vp is not None:
            fields["linker_version_major"], fields["linker_version_minor"] = vp
        for label, ver in (
            ("os_version", self.os_version),
            ("subsystem_version", self.subsystem_version),
        ):
            vp = self._version_pair(label, ver)
            if vp is not None:
                fields[f"{label}_major"], fields[f"{label}_minor"] = vp
        if self.tsaware is not None:
            fields["dll_characteristics"] = 0x8000 if self.tsaware else 0
        if self.stack_reserve is not None:
            fields["stack_reserve"] = self.stack_reserve
        if self.stack_commit is not None:
            fields["stack_commit"] = self.stack_commit
        if self.timestamp is not None:
            fields["timestamp"] = self.timestamp
        return fields


def profile_flags_style(profile: str) -> FlagsStyle | None:
    """The registered toolchain spec's ``flags_style`` for *profile*.

    ``None`` when *profile* is not a registry toolchain."""
    from rebrew.toolchain import TOOLCHAINS

    spec = TOOLCHAINS.get(profile)
    return getattr(spec, "flags_style", None) if spec is not None else None


@dataclass
class ProjectConfig:
    """Parsed project configuration with computed paths."""

    # Root directory (where rebrew-project.toml lives)
    root: Path

    # Target name (key under [targets])
    target_name: str = ""

    # --- target fields ---
    target_binary: Path = field(default_factory=lambda: Path())
    binary_format: str = "pe"  # "pe", "elf", "macho"
    arch: str = "x86_32"  # "x86_32", "x86_64", etc.

    # --- per-target sources ---
    reversed_dir: Path = field(default_factory=lambda: Path())
    shared_dir: Path | None = None
    """Project-level shared-sources root (``src/shared`` by default).

    Sources here are scanned for EVERY target and may carry one
    ``// FUNCTION: <target> <va>`` marker per target (the same function at
    a different VA in each version) plus ``#ifdef`` deltas driven by the
    per-target ``defines``.  ``None`` (or an empty ``[project] shared_dir``)
    disables shared sources.
    """
    bin_dir: Path = field(default_factory=lambda: Path())
    marker: str = ""  # Prefix used in annotations, e.g. // FUNCTION: SERVER 0x... (default: target_name.upper())
    r2_bogus_vas: list[int] = field(default_factory=list)  # VAs with known-bad r2 size data

    # --- project-level defaults ---
    project_name: str = ""
    default_jobs: int = 4  # Default parallelism for batch operations (matches [project] jobs)
    db_dir: Path = field(default_factory=lambda: Path())
    output_dir: Path = field(default_factory=lambda: Path())

    # --- compiler ---
    compiler_profile: str = "msvc-6.0"
    compiler_command: str = "wine CL.EXE"
    compiler_runner: str = ""
    compiler_includes: Path = field(default_factory=lambda: Path())
    compiler_libs: Path = field(default_factory=lambda: Path())
    cflags: str = ""  # Default compiler flags (from [compiler] or per-target override)
    # True when `cflags` was EXPLICITLY present in the TOML — an empty
    # string then means "no default flags", not "fall back to /O2 /Gd".
    # (`cflags = ""` silently compiled with /O2 /Gd.)
    cflags_explicit: bool = False
    cflags_presets: dict[str, str] = field(default_factory=dict)
    """Per-module compiler flag overrides (``rebrew cfg set-cflags``).

    ``[compiler.cflags_presets]`` (global) merged with
    ``[targets.X.compiler.cflags_presets]`` (per-key, target wins).  Used by
    ``rebrew match``/``diff`` as the CFLAGS fallback for functions whose
    module has a preset and whose per-function metadata has no CFLAGS.
    """
    base_cflags: str = "/nologo /c /MT"  # Always-on flags prepended to every compile
    compile_timeout: int = DEFAULT_COMPILE_TIMEOUT  # see DEFAULT_COMPILE_TIMEOUT

    # --- recompile remote backend ([compiler] recompile_url or
    # REBREW_RECOMPILE_URL env) ---
    recompile_url: str = ""
    """Base URL of the recompile compile service (e.g. ``http://localhost:8000``).

    When set, every compile routes through ``POST /api/v1/compile`` instead
    of local docker images — the same pinned toolchain images, plus the
    opt-in training tap (``emit_assembly``) that feeds resembl and LLM
    training.  Empty (the default) keeps local docker execution.
    """
    recompile_emit_assembly: bool = False
    """Pass ``emit_assembly=true`` on remote compiles (training-data tap).

    Off by default so compiles do not grow the service's
    ``train_data/train.jsonl``.  When on, every remote compile (test, verify,
    match) sends it; ``match --collect-pairs`` writes local pairs and does
    not touch this flag.
    """

    # --- per-target version defines ---
    defines: list[str] = field(default_factory=list)
    """Per-target compile-time defines (``targets.<name>.defines``).

    Each entry becomes ``-D<name>`` (posix) or ``/D<name>`` (MSVC) on every
    compile for this target — the version switch that makes shared
    multi-version sources work (``#ifdef V2`` blocks in a shared .c).
    """

    # --- [llm] section: optional LLM-assisted GA seeding ---
    # ``[llm] endpoint``/``model`` in rebrew-project.toml win over env;
    # ``REBREW_LLM_API_KEY`` wins when present (including empty) over TOML.
    llm_endpoint: str = ""
    llm_api_key: str = field(default="", repr=False)
    llm_model: str = ""
    cache_backend: str = "diskcache"  # compile-cache store ([cache] backend)

    @property
    def posix_style(self) -> bool:
        """True when the compiler profile uses POSIX-style flags (-I/-o/-c).

        Read from the registry spec's ``flags_style``: gcc/clang/mingw/watcom
        take dash flags and ship their own headers, MSVC profiles use
        ``/I``/``/Fo``/``/c``.  Single source of truth for compile/flag routing
        across compile.py, diff.py, match.py, and matcher/compiler.py.
        """
        return profile_flags_style(self.compiler_profile) == "posix"

    # --- Computed from arch ---
    pointer_size: int = 4
    padding_bytes: list[int] = field(default_factory=lambda: [0xCC, 0x90])

    # --- PE-specific (computed at load time if format == "pe") ---
    image_base: int = 0
    text_va: int = 0

    # --- Project-specific (loaded from TOML if present) ---
    iat_thunks: list[int] = field(default_factory=list)
    dll_exports: dict[int, str] = field(default_factory=dict)
    ignored_symbols: list[str] = field(default_factory=list)
    library_modules: set[str] = field(
        default_factory=set
    )  # Module names using LIBRARY marker (e.g. {"MSVCRT", "ZLIB"})
    # External .lib code, the one flag for "not our work": module name ->
    # link spec (the archive to link, e.g. "LIBCMT.lib",
    # "references/dxsdk8/lib/d3dx8.lib"; "" = identified external code with
    # no separate archive).  Rows attributed to these modules leave the
    # progress accounting, `rebrew lib-match` ingests the archives by
    # default, and `rebrew cmake-sources` emits them as REBREW_EXTERNAL_LIBS
    # so the build links the stock archive.
    external_libs: dict[str, str] = field(default_factory=dict)
    #: Inclusive ``(lo, hi)`` address bands the target's binary fills from a
    #: linked library rather than from project sources (``targets.<name>.
    #: external_ranges``).  Tools that enumerate "work left" must skip them.
    external_ranges: list[tuple[int, int]] = field(default_factory=list)
    crt_sources: dict[str, str] = field(default_factory=dict)
    source_ext: str = ".c"  # Source file extension (e.g. ".c", ".cpp")
    ghidra_program_path: str = ""
    ghidra_backend: str = "reva"  # "reva" (MCP) or "cli" (ghidra-cli binary)
    binsync_state_dir: str = ""  # BinSync state dir for field sync (--state-dir default)
    inventory_file: str = (
        ""  # Function inventory path override (default: reversed_dir/function_structure.json)
    )

    # --- Lint configuration ---
    lint_naming_convention: str = "none"  # "snake_case", "camelCase", or "none"
    lint_brace_style: str = "none"  # "same_line", "new_line", or "none"
    lint_indent_style: str = "none"  # "spaces", "tabs", or "none"
    lint_max_line_length: int = DEFAULT_LINT_MAX_LINE_LENGTH  # see DEFAULT_LINT_MAX_LINE_LENGTH

    # --- All known target names ---
    all_targets: list[str] = field(default_factory=list)

    # --- All known target markers (E012 allows stacked shared markers) ---
    all_markers: set[str] = field(default_factory=set)

    # --- Linker settings for byte-identical reconstruction ([link]) ---
    link: LinkConfig = field(default_factory=LinkConfig)

    @property
    def capstone_arch(self) -> int:
        """Return capstone CS_ARCH_* constant."""
        import capstone

        preset = _ARCH_PRESETS.get(self.arch)
        name = preset.get("capstone_arch", "CS_ARCH_X86") if preset else "CS_ARCH_X86"
        return int(getattr(capstone, name))

    @property
    def capstone_mode(self) -> int:
        """Return capstone CS_MODE_* constant."""
        import capstone

        preset = _ARCH_PRESETS.get(self.arch)
        name = preset.get("capstone_mode", "CS_MODE_32") if preset else "CS_MODE_32"
        return int(getattr(capstone, name))

    @property
    def metadata_dir(self) -> Path:
        """Directory for rebrew-functions.toml and rebrew-data.toml.

        This is the parent of ``reversed_dir`` — e.g. ``src/`` when
        ``reversed_dir`` is ``src/NP``.  When the whole tree is the source
        root (``reversed_dir`` is ``src`` itself) projects may keep the
        TOMLs inside it; prefer the parent, but fall back to
        ``reversed_dir`` when it holds ``rebrew-functions.toml`` and the
        parent does not.  All metadata reads/writes must go through this
        property so the location is centralized.
        """
        from rebrew.metadata import METADATA_FILENAME

        parent = self.reversed_dir.parent
        if (
            not (parent / METADATA_FILENAME).exists()
            and (self.reversed_dir / METADATA_FILENAME).exists()
        ):
            return self.reversed_dir
        return parent

    def as_dict(self, redact_secrets: bool = True) -> dict[str, Any]:
        """Return configuration as a dictionary, optionally redacting sensitive keys."""
        return {
            "root": str(self.root),
            "target_name": self.target_name,
            "target_binary": str(self.target_binary),
            "binary_format": self.binary_format,
            "arch": self.arch,
            "reversed_dir": str(self.reversed_dir),
            "shared_dir": str(self.shared_dir) if self.shared_dir else None,
            "bin_dir": str(self.bin_dir),
            "marker": self.marker,
            "project_name": self.project_name,
            "default_jobs": self.default_jobs,
            "db_dir": str(self.db_dir),
            "output_dir": str(self.output_dir),
            "compiler_profile": self.compiler_profile,
            "compiler_command": self.compiler_command,
            "compiler_runner": self.compiler_runner,
            "compiler_includes": str(self.compiler_includes),
            "compiler_libs": str(self.compiler_libs),
            "cflags": self.cflags,
            "base_cflags": self.base_cflags,
            "compile_timeout": self.compile_timeout,
            "recompile_url": self.recompile_url,
            "recompile_emit_assembly": self.recompile_emit_assembly,
            "defines": list(self.defines),
            "llm_endpoint": self.llm_endpoint,
            "llm_api_key": ("***" if self.llm_api_key else "")
            if redact_secrets
            else self.llm_api_key,
            "llm_model": self.llm_model,
            "cache_backend": self.cache_backend,
            "all_targets": list(self.all_targets),
        }

    def validate(self) -> None:
        """Validate configuration settings, raising :class:`ConfigError` on invalid values."""
        if self.arch and self.arch not in _ARCH_PRESETS:
            raise ConfigError(
                f"unknown arch {self.arch!r} (known: {', '.join(sorted(_ARCH_PRESETS))})"
            )
        if self.compiler_profile:
            from rebrew.toolchain import TOOLCHAINS

            if self.compiler_profile not in TOOLCHAINS:
                raise ConfigError(
                    f"unknown profile {self.compiler_profile!r} (known: {', '.join(sorted(TOOLCHAINS))})"
                )
        if self.recompile_url:
            validate_http_url(self.recompile_url, "compiler.recompile_url")
        if self.llm_endpoint:
            validate_http_url(self.llm_endpoint, "llm.endpoint")
        if self.llm_model:
            validate_llm_model(self.llm_model)
        if self.llm_api_key and self.llm_endpoint and not is_key_safe_endpoint(self.llm_endpoint):
            raise ConfigError(
                "LLM endpoint must use https when an API key is set "
                "(plain http is allowed only for loopback hosts)"
            )


#: Characters stripped from a target name when deriving its module marker:
#: ``server.dll`` yields ``SERVERDLL``, an identifier-shaped module name.
#: Set ``marker`` explicitly when the annotations use another module
#: (e.g. ``SERVER``).
_MARKER_STRIP_RE = re.compile(r"[^A-Za-z0-9_]")


def _module_marker_value(raw: Any, target: str, field_name: str) -> str:
    """Return the annotation module for one target.

    Absent or blank ``marker`` uses the derived name (target upper-cased,
    non-identifier characters stripped). An explicit marker must be one
    token: whitespace never matches ``// FUNCTION: MARKER 0xVA``, and a
    marker containing ``.0x`` makes ``parse_metadata_key`` split the module
    off the VA. A target whose name derives nothing and sets no marker
    fails the load — an empty marker drops every function out of
    verify/todo/status.
    """
    derived = _MARKER_STRIP_RE.sub("", target).upper()
    if raw is None:
        text = derived
    elif isinstance(raw, str):
        text = raw.strip() or derived
    else:
        _config_warn(
            f"Expected string for {field_name}, got {type(raw).__name__}; "
            f"using default {derived!r}",
        )
        text = derived
    if not text:
        raise ConfigError(
            f"rebrew-project.toml {field_name} is empty and {target!r} has no "
            "identifier characters to derive a module marker from"
        )
    if any(ch.isspace() for ch in text):
        raise ConfigError(
            f"rebrew-project.toml {field_name} = {text!r} is not a single token "
            "(annotation markers are one word: // FUNCTION: MARKER 0xVA)"
        )
    if ".0x" in text.casefold():
        raise ConfigError(
            f"rebrew-project.toml {field_name} = {text!r} contains '.0x', "
            "which breaks MODULE.0xVA metadata keys"
        )
    return text


def module_marker(cfg: Any) -> str:
    """Return the annotation module marker for *cfg*.

    The marker is the ``MODULE`` half of every ``MODULE.0xVA`` metadata key
    and of every ``// FUNCTION: MODULE 0xVA`` line, so it must resolve the
    same way everywhere: an entry written under one spelling is invisible to
    a reader using another.  The rule is ``cfg.marker``, else the target name
    with non-identifier characters stripped and upper-cased (the same
    derivation :func:`load_config` applies), else ``""``.

    Callers that write to the metadata store must reject an empty result:
    :func:`rebrew.utils.qualified_key` renders a module-less entry as a bare
    ``0xVA`` key, which :func:`rebrew.utils.parse_metadata_key` does not
    accept, so the write is silently unreadable.  Fabricating a placeholder
    module instead (``"SERVER"``, ``"GAME"``) is worse: it writes real data
    under another project's module name.

    Mock-safe via ``getattr`` — takes any config-shaped object.
    """
    marker = str(getattr(cfg, "marker", "") or "")
    if marker:
        return marker
    target = str(getattr(cfg, "target_name", "") or "")
    return _MARKER_STRIP_RE.sub("", target).upper()


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
    override = str(getattr(cfg, "inventory_file", "") or "").strip() if cfg is not None else ""
    cfg_reversed = getattr(cfg, "reversed_dir", "") if cfg is not None else ""
    if override and cfg_reversed:
        try:
            if rd.resolve() == Path(cfg_reversed).resolve():
                p = config_path(override)
                root = getattr(cfg, "root", None)
                return p if p.is_absolute() else (Path(root) / p if root else p)
        except (OSError, ValueError, TypeError):
            pass
    return rd / FUNCTION_STRUCTURE_JSON


def _parse_va_ranges(values: list[Any] | None, field_name: str) -> list[tuple[int, int]]:
    """Parse ``["0x5e0000-0x64ffff", ...]`` into inclusive ``(lo, hi)`` pairs.

    Used by ``targets.<name>.external_ranges``: address bands the target's
    binary fills with code from a statically linked library rather than from
    the project's sources (the D3DX8/T&L band in a client build).  A band is a
    fact about the *link*, so it belongs in configuration next to
    ``external_libs`` — not hardcoded per tool.
    """
    if not isinstance(values, list):
        if values is not None:
            _config_warn(f"Expected list for {field_name}, got {type(values).__name__}; ignoring")
        return []

    parsed: list[tuple[int, int]] = []
    for v in values:
        if not isinstance(v, str) or "-" not in v:
            _config_warn(f"Invalid range {v!r} in {field_name}; expected '0xLO-0xHI'")
            continue
        lo_s, _, hi_s = v.partition("-")
        try:
            lo, hi = parse_int_literal(lo_s.strip()), parse_int_literal(hi_s.strip())
        except ValueError:
            _config_warn(f"Invalid range {v!r} in {field_name}; expected '0xLO-0xHI'")
            continue
        if hi < lo:
            _config_warn(f"Invalid range {v!r} in {field_name}: end before start; ignoring")
            continue
        parsed.append((lo, hi))
    return parsed


def _parse_int_list(values: list[Any] | None, field_name: str) -> list[int]:
    """Parse a list of integers from a toml array, allowing hex strings."""
    if not isinstance(values, list):
        if values is not None:
            _config_warn(
                f"Expected list for {field_name}, got {type(values).__name__}; ignoring",
            )
        return []

    parsed: list[int] = []
    for v in values:
        if isinstance(v, bool):
            # bool is an int subclass; True must not become reloc offset 1.
            _config_warn(f"Unexpected type {type(v).__name__} in {field_name}; ignoring")
        elif isinstance(v, int):
            parsed.append(v)
        elif isinstance(v, float):
            if math.isfinite(v) and v.is_integer():
                parsed.append(int(v))
            else:
                _config_warn(f"Unexpected type {type(v).__name__} in {field_name}; ignoring")
        elif isinstance(v, str):
            try:
                parsed.append(parse_int_literal(v))
            except ValueError:
                _config_warn(f"Invalid integer '{v}' in {field_name}; ignoring")
        else:
            _config_warn(f"Unexpected type {type(v).__name__} in {field_name}; ignoring")
    return parsed


#: A ``[targets.<name>].defines`` entry is emitted as ``/DNAME`` or ``-DNAME``.
#: Anything else is one argv token the compiler will not treat as a macro,
#: so ``#ifdef`` branches compile the wrong side and the byte diff looks
#: like a source bug.
_DEFINE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _parse_defines(values: Any, field_name: str) -> list[str]:
    """Parse a list of compile-time define names from a toml array.

    Entries are trimmed. Empty entries are dropped. Non-string entries warn
    and are dropped (``str(None)`` would otherwise become ``-DNone``). A
    string that is not a C identifier fails the load: it would be passed
    through as a ``-D``/``/D`` flag and compile the wrong ``#ifdef`` side.
    """
    if not isinstance(values, list):
        if values is not None:
            _config_warn(
                f"Expected list for {field_name}, got {type(values).__name__}; ignoring",
            )
        return []
    out: list[str] = []
    for v in values:
        if not isinstance(v, str):
            _config_warn(f"{field_name}: non-string define {v!r} ignored")
            continue
        name = v.strip()
        if not name:
            continue
        if _DEFINE_NAME_RE.fullmatch(name) is None:
            raise ConfigError(
                f"rebrew-project.toml {field_name}: {v!r} is not a C define name "
                "(letter or underscore, then letters, digits, or underscores)"
            )
        out.append(name)
    return out


def _parse_hex_dict(mapping: dict[str, Any] | None) -> dict[int, str]:
    """Parse a dict where keys are hex strings and values are strings."""
    if not isinstance(mapping, dict):
        if mapping is not None:
            _config_warn(
                f"Expected mapping for hex dict, got {type(mapping).__name__}; ignoring",
            )
        return {}

    result: dict[int, str] = {}
    for k, v in mapping.items():
        try:
            addr = parse_int_literal(str(k))
            result[addr] = str(v)
        except ValueError:
            _config_warn(f"Invalid hex key '{k}' in mapping; ignoring")
    return result


def _parse_str_list(values: list[Any] | None, field_name: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        _config_warn(
            f"Expected list for {field_name}, got {type(values).__name__}; using empty list",
        )
        return []
    result: list[str] = []
    for v in values:
        if isinstance(v, str):
            result.append(v)
        else:
            _config_warn(f"Skipping non-string {field_name} value: {v!r}")
    return result


def _safe_int(value: Any, default: int, field_name: str = "integer") -> int:
    """Convert *value* to int, returning *default* on failure.

    ``None`` (not set) returns *default* silently — matching ``_as_str`` —
    so absent optional keys never warn on an otherwise valid config.
    Non-integral floats (``3.9``) are rejected rather than truncated: bare
    ``int(3.9)`` would silently store ``3`` for timeouts/jobs/limits.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        _config_warn(f"Expected integer for {field_name}, got {value!r}; using default {default}")
        return default
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            _config_warn(
                f"Expected integer for {field_name}, got {value!r}; using default {default}"
            )
            return default
        return int(value)
    try:
        return int(value)
    except (ValueError, TypeError, OverflowError):
        _config_warn(f"Expected integer for {field_name}, got {value!r}; using default {default}")
        return default


def _positive_int(value: Any, default: int, field_name: str) -> int:
    """Parse a positive integer config value, falling back to *default*."""
    parsed = _safe_int(value, default, field_name)
    if parsed < 1:
        _config_warn(
            f"Expected positive integer for {field_name}, got {value!r}; using default {default}"
        )
        return default
    return parsed


#: Link fields are stored in the PE optional header as unsigned 32-bit
#: values. ``patch_pe_headers`` masks with ``& 0xFFFFFFFF``, so a bool
#: (``True`` is an ``int``) or a negative / oversized number would be
#: written as a different header than the one configured.
_PE_U32_MAX = 0xFFFFFFFF


def _parse_optional_int(value: Any, field_name: str) -> int | None:
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
        _config_warn(f"Expected integer for {field_name}, got {value!r}; ignoring")
        return None
    parsed: int | None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            _config_warn(f"Invalid integer {value!r} for {field_name}; ignoring")
            return None
    else:
        _config_warn(f"Expected integer for {field_name}, got {type(value).__name__}; ignoring")
        return None
    if parsed < 0 or parsed > _PE_U32_MAX:
        raise ConfigError(
            f"rebrew-project.toml {field_name} = {value!r} is outside "
            f"0..0x{_PE_U32_MAX:X} (PE optional-header fields are unsigned 32-bit; "
            "a wider value would be truncated when the header is patched)"
        )
    return parsed


def _parse_str_dict(value: Any, field_name: str) -> dict[str, str]:
    """Parse a string-to-string mapping from config."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        _config_warn(
            f"Expected mapping for {field_name}, got {type(value).__name__}; using empty mapping"
        )
        return {}
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            _config_warn(f"Skipping non-string {field_name} entry: {key!r} = {item!r}")
            continue
        result[key] = item
    return result


def _parse_source_ext(value: Any) -> str:
    """Parse and normalize the configured source extension(s).

    Accepts a single extension (``".c"``) or a comma-separated list
    (``".c,.cpp"``) so projects with mixed C/C++ sources can declare both.
    """
    if value is None:
        return ".c"
    if not isinstance(value, str):
        _config_warn(
            f"Expected string for source_ext, got {type(value).__name__}; using default .c"
        )
        return ".c"
    exts = [part.strip() for part in value.split(",") if part.strip()]
    if not exts or exts == ["."]:
        _config_warn("Expected non-empty source_ext; using default .c")
        return ".c"
    normalized: list[str] = []
    for ext in exts:
        if "/" in ext or "\\" in ext:
            _config_warn(f"source_ext must be a file extension, got {value!r}; using default .c")
            return ".c"
        if not ext.startswith("."):
            _config_warn(f"source_ext {ext!r} is missing a leading dot; using .{ext}")
            ext = f".{ext}"
        normalized.append(ext)
    return ",".join(normalized)


def _as_table(value: Any, field_name: str) -> dict[str, Any]:
    """Return a TOML table as a dict or raise a clear config error."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"rebrew-project.toml [{field_name}] must be a TOML table")
    return value


def _as_str(value: Any, default: str, field_name: str) -> str:
    """Return a string config value, warning and using *default* on bad types.

    Distinguishes "not set" (``None`` → *default* silently) from "set to a
    non-string" (warn + *default*). Empty string is preserved when present so
    callers can treat "" as intentionally empty.
    """
    if value is None:
        return default
    if isinstance(value, str):
        return value
    _config_warn(
        f"Expected string for {field_name}, got {type(value).__name__}; using default {default!r}",
    )
    return default


def validate_http_url(value: str, field_name: str) -> str:
    """Return *value* when it is an http(s) URL with a host; else raise.

    Empty / whitespace-only input is treated as unset (returns ``""``) so
    optional URL knobs stay optional.  A non-empty garbage value must not
    reach compile/HTTP and fail later as a cryptic connection error.
    """
    text = value.strip()
    if not text:
        return ""
    message = f"{field_name} must be an http(s) URL with a host and a valid port"
    try:
        parsed = urlparse(text)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in text)
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)
        ):
            raise ConfigError(message)
    except ValueError:
        raise ConfigError(message) from None
    return text


_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_UNPINNED_MODELS = frozenset({"latest", "auto", "default"})


def is_key_safe_endpoint(endpoint: str) -> bool:
    """True when a bearer key may be sent to *endpoint*: https, or http to loopback."""
    parsed = urlparse(endpoint)
    if parsed.scheme == "https":
        return True
    host = parsed.hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_llm_model(model: str) -> str:
    """Validate a configured LLM model id, rejecting unpinned aliases and invalid chars."""
    if model.lower() in _UNPINNED_MODELS:
        raise ConfigError(f"LLM model {model!r} is an unpinned alias; set a dated model id")
    if not _MODEL_ID_RE.fullmatch(model):
        raise ConfigError(f"LLM model {model!r} has invalid characters or length")
    return model


def _as_bool(value: Any, default: bool, field_name: str) -> bool:
    """Return a bool config value, warning and using *default* on bad types.

    TOML booleans are real ``bool``s.  Reject stringy ``"false"``/``"0"`` —
    ``bool("false")`` is ``True`` in Python, which would silently enable a
    training-data tap like ``recompile_emit_assembly``.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    _config_warn(
        f"Expected boolean for {field_name}, got {value!r}; using default {default}",
    )
    return default


def _resolve(root: Path, rel: str | Path | None) -> Path | None:
    """Resolve a path relative to project root.  Returns *None* if *rel* is ``None``."""
    if rel is None:
        return None
    if not isinstance(rel, (str, Path)):
        _config_warn(f"Expected path string, got {type(rel).__name__}; ignoring")
        return None
    p = config_path(rel)
    if p.is_absolute():
        return p
    return root / p


def _required_path(root: Path, value: Any, default: str, field_name: str) -> Path:
    """Resolve a configured path, rejecting explicit empty or invalid values."""
    if value is None:
        value = default
    if isinstance(value, str) and not value.strip():
        raise ConfigError(f"rebrew-project.toml {field_name} must not be empty")
    resolved = _resolve(root, value)
    if resolved is None:
        raise ConfigError(f"rebrew-project.toml {field_name} must be a path string")
    return resolved


def _install_tool_alt(path: Path, root: Path) -> Path | None:
    """The rebrew-install copy of a missing project-relative tools/ path."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    from rebrew.utils import find_install_tool

    return find_install_tool(rel)


def _split_compiler_runner(compiler: dict[str, Any]) -> tuple[str, str]:
    command_raw = _as_str(compiler.get("command"), "wine CL.EXE", "compiler.command")
    if not command_raw.strip():
        # Docker-only: an image-backed profile legitimately has no host
        # command (the image IS the compiler); native profiles still need
        # one and are rejected below.
        profile = str(compiler.get("profile") or "").strip()
        # Outside the try: the except clause below must be able to name it.
        from rebrew.registry import RegistryError

        try:
            from rebrew.toolchain import TOOLCHAINS

            spec = TOOLCHAINS.get(profile)
        except RegistryError:  # a plugin registration conflict is reported at load
            raise
        except Exception:  # toolchain import is best-effort
            spec = None
        if spec is not None and spec.image is not None:
            return "", ""
        raise ConfigError("rebrew-project.toml compiler.command must not be empty")
    if "runner" in compiler:
        return _as_str(compiler.get("runner"), "", "compiler.runner"), command_raw

    try:
        parts = shlex.split(command_raw)
    except ValueError:
        parts = command_raw.split()

    if parts and parts[0] in {"wine", "wibo"}:
        runner = parts[0]
        return runner, command_raw

    return "", command_raw


def _merge_cflags_presets(
    global_compiler: dict[str, Any],
    target_compiler: dict[str, Any],
    *,
    target_data: Mapping[str, Any] | None = None,
    target_name: str = "",
) -> dict[str, str]:
    """Merge per-module cflags presets: global, overridden per-key by target.

    ``rebrew cfg set-cflags MODULE FLAGS`` writes a global
    ``[compiler.cflags_presets]``; ``--target X`` writes
    ``[targets.X.compiler.cflags_presets]``.  The target's presets win for
    the same module key, matching the documented "per-target presets
    override global presets for the same origin key" semantics.

    A legacy ``[targets.X.cflags_presets]`` table (wrong place; once written
    by older ``cfg set-cflags``) is still merged, with a warning pointing at
    the canonical ``[targets.X.compiler.cflags_presets]`` home — previously
    it was a silent no-op while remaining a "known" key.
    """
    where = f"targets.{target_name}" if target_name else "targets.<target>"
    tables = [
        (global_compiler.get("cflags_presets"), "compiler.cflags_presets"),
        (target_compiler.get("cflags_presets"), f"{where}.compiler.cflags_presets"),
    ]
    if target_data is not None and "cflags_presets" in target_data:
        tables.append((target_data["cflags_presets"], f"{where}.cflags_presets"))
    merged: dict[str, str] = {}
    for value, label in tables:
        presets = _as_table(value, label)
        for key, val in presets.items():
            if not isinstance(val, str):
                raise ConfigError(f"rebrew-project.toml {label}.{key} must be a string")
            merged[key.upper()] = val
        if presets and label == f"{where}.cflags_presets":
            _config_warn(
                f"[{where}].cflags_presets is misplaced — move it to "
                f"[{where}.compiler.cflags_presets] (honoured for now; "
                "`rebrew cfg set-cflags --target` writes the canonical path)"
            )
    return merged


def _detect_binary_layout(
    bin_path: Path, fmt: str = "auto", root: Path | None = None, target: str = ""
) -> dict[str, int]:
    """Read image base and .text section from binary headers.

    Layout-package first: when ``layout/<target>/rebrew-layout.toml`` is
    present and fresher than *bin_path*, its committed facts answer the
    question (~1 ms) instead of importing LIEF (~0.11 s) — every command
    pays this at ``load_config``.  Falls back to ``binary_loader`` (PE,
    ELF, Mach-O) when there is no usable package.
    """
    if root is not None and target:
        from rebrew.layout_meta import read_layout_header

        hdr = read_layout_header(root, target, bin_path)
        if hdr is not None:
            return {
                "image_base": hdr["image_base"],
                "text_va": hdr["text_va"],
                "text_raw_offset": hdr["text_raw_offset"],
            }
    try:
        from rebrew.binary_loader import load_binary

        info = load_binary(bin_path, fmt=fmt)
        return {
            "image_base": info.image_base,
            "text_va": info.text_va,
            "text_raw_offset": info.text_raw_offset,
        }
    except (ImportError, OSError, ValueError, AttributeError) as e:
        _config_warn(f"Could not detect binary layout for {bin_path}: {e}")
        return {"image_base": 0, "text_va": 0, "text_raw_offset": 0}


# Well-known MSVC CRT source directory patterns (relative to the project's
# toolchain/ dir).  Each tuple is (relative_path_from_toolchain, origin_name).
_CRT_SOURCE_PATTERNS: list[tuple[str, str]] = [
    ("msvc/6.0-win32/VC98/CRT/SRC", "MSVCRT"),
    ("MSVC400/CRT/SRC", "MSVCRT"),
    ("msvc/4.2-win32/CRT/SRC", "MSVCRT"),
    ("msvc/7.0-win32/crt/src", "MSVCRT"),
]


def detect_crt_sources(root: Path) -> dict[str, str]:
    """Scan the ``toolchain/`` directory for known MSVC CRT source trees.

    Returns a dict mapping origin names (e.g. ``"MSVCRT"``) to relative paths
    suitable for use in ``crt_sources`` config entries.  Uses case-insensitive
    directory matching to handle varying MSVC packaging conventions.

    Only returns the *first* match per origin so that projects with multiple
    MSVC versions don't get duplicate entries.
    """
    tools_dir = root / "toolchain"
    if not tools_dir.is_dir():
        return {}

    found: dict[str, str] = {}
    for pattern, origin in _CRT_SOURCE_PATTERNS:
        if origin in found:
            continue  # first match wins per origin
        # Case-insensitive search: walk each component
        candidate = tools_dir
        for component in pattern.split("/"):
            # Find a case-insensitive match in the current directory
            matched_child = None
            if candidate.is_dir():
                component_norm = unicodedata.normalize("NFC", component).casefold()
                for child in candidate.iterdir():
                    if (
                        child.is_dir()
                        and unicodedata.normalize("NFC", child.name).casefold() == component_norm
                    ):
                        matched_child = child
                        break
            if matched_child is None:
                break
            candidate = matched_child
        else:
            # All components matched
            rel = candidate.relative_to(root)
            found[origin] = rel.as_posix()

    return found


def find_root(start: Path | str | None = None) -> Path:
    """Walk up from cwd to find rebrew-project.toml.

    Since rebrew is an installable package, __file__ may point into
    site-packages rather than the project directory.  We therefore
    search from the current working directory upward, similar to how
    ``git`` locates ``.git/``.

    *start*, when given, is an EXPLICIT project root — returned verbatim
    (no walk-up); load_config(root=X) expects X to contain the toml.
    """
    if start is not None:
        start_p = Path(start)
        # Treat as explicit project root only when it looks like one
        if (start_p / "rebrew-project.toml").is_file():
            return start_p
        if not start_p.is_dir():
            return start_p
        # Bare temp dir without toml: legacy callers (e.g. find_root(tmp_path))
        # expect pass-through; let load_config raise the proper error
        return start_p
    found = walk_up_to_root(Path.cwd())
    if found is None:
        raise ConfigNotFoundError(
            "Could not find rebrew-project.toml in any parent of the current directory. "
            "Run rebrew commands from within a project that contains rebrew-project.toml."
        )
    return found


# ---------------------------------------------------------------------------
# Known TOML keys — validated at load time to catch typos
# ---------------------------------------------------------------------------

_KNOWN_TOP_KEYS = {"targets", "compiler", "project", "link", "llm", "cache"}

_KNOWN_CACHE_KEYS = {"backend"}

_KNOWN_LLM_KEYS = {"endpoint", "api_key", "model"}

_KNOWN_LINK_KEYS = {
    "file_align",
    "stack_reserve",
    "stack_commit",
    "tsaware",
    "linker_version",
    "os_version",
    "subsystem_version",
    "timestamp",
}

_KNOWN_TARGET_KEYS = {
    "binary",
    "arch",
    "format",
    "marker",
    "reversed_dir",
    "bin_dir",
    "compiler",
    "defines",  # per-target compile-time defines (shared multi-version sources)
    "r2_bogus_vas",
    "iat_thunks",
    "dll_exports",
    "ignored_symbols",
    "library_modules",
    "external_libs",
    "external_ranges",  # address bands filled by a statically linked library
    "crt_sources",
    "source_ext",
    "ghidra_program_path",
    "ghidra_backend",
    "binsync_state_dir",
    "inventory_file",
    "origins",  # written by `rebrew cfg add-target`; editor/UI only — NOT
    # used for annotation filtering (module filters come from the
    # annotations themselves).
    "cflags_presets",  # LEGACY misplaced table — loader still merges it with a
    # warning; canonical home is [targets.X.compiler.cflags_presets].  Kept in
    # known keys so projects that still have it do not also get an
    # "unrecognized keys" warning (and so a rewriter does not drop it).
    "layout",  # printed by `rebrew gen-layout --layout-config`: the position-alignment
    # package (image base, section geometry, exports, imports).  Not read by
    # this loader -- the layout tooling parses it directly -- but it must be
    # recognised here: a target carrying it warned "unrecognized keys:
    # {'layout'}" on every single rebrew invocation, and an unrecognised key is
    # one a config rewriter will silently drop.  guild-rebrew lost its whole
    # layout block that way.
}

_KNOWN_COMPILER_KEYS = {
    "command",
    "runner",
    "includes",
    "libs",
    "cflags",
    "profile",
    "base_cflags",
    "timeout",
    "recompile_url",  # remote compile backend (or REBREW_RECOMPILE_URL env)
    "recompile_emit_assembly",  # training-data tap for remote compiles
    "cflags_presets",  # written by `rebrew cfg set-cflags` without --target (per-origin compiler flag overrides)
}

_KNOWN_PROJECT_KEYS = {
    "name",
    "jobs",
    "db_dir",
    "output_dir",
    "default_target",
    "shared_dir",  # project-level shared sources root (multi-version)
    "lint",
}

_KNOWN_LINT_KEYS = {
    "naming_convention",
    "brace_style",
    "indent_style",
    "max_line_length",
}

_KNOWN_LINT_NAMING = frozenset({"none", "snake_case", "camelCase"})
_KNOWN_LINT_BRACE = frozenset({"none", "same_line", "new_line"})
_KNOWN_LINT_INDENT = frozenset({"none", "spaces", "tabs"})

_KNOWN_FORMATS = {"pe", "elf", "macho", "ne", "mz"}


def _lint_enum(value: Any, allowed: frozenset[str], field_name: str, default: str = "none") -> str:
    """Return a known lint enum value, warning and falling back on typos.

    A misspelled ``naming_convention = "snake-case"`` used to pass load and
    then silently disable the style rule (``!= "none"`` but matches no branch).
    """
    text = _as_str(value, default, field_name)
    if text in allowed:
        return text
    _config_warn(
        f"{field_name} = {text!r} is not one of {sorted(allowed)}; using {default!r}",
    )
    return default


def _load_lint_settings(project_raw: Mapping[str, Any]) -> dict[str, Any]:
    """Parse ``[project.lint]`` into ProjectConfig field kwargs."""
    lint_raw = _as_table(project_raw.get("lint", {}), "project.lint")
    unknown_lint = set(lint_raw) - _KNOWN_LINT_KEYS
    if unknown_lint:
        _config_warn(
            f"rebrew-project.toml [project.lint]: unrecognized keys: {sorted(unknown_lint)}"
        )
    return {
        "lint_naming_convention": _lint_enum(
            lint_raw.get("naming_convention"),
            _KNOWN_LINT_NAMING,
            "project.lint.naming_convention",
        ),
        "lint_brace_style": _lint_enum(
            lint_raw.get("brace_style"),
            _KNOWN_LINT_BRACE,
            "project.lint.brace_style",
        ),
        "lint_indent_style": _lint_enum(
            lint_raw.get("indent_style"),
            _KNOWN_LINT_INDENT,
            "project.lint.indent_style",
        ),
        "lint_max_line_length": _positive_int(
            lint_raw.get("max_line_length"),
            DEFAULT_LINT_MAX_LINE_LENGTH,
            "project.lint.max_line_length",
        ),
    }


def load_config(
    root: Path | str | None = None,
    target: str | None = None,
) -> ProjectConfig:
    """Load rebrew-project.toml.

    Args:
        root: Project root directory.  Auto-detected if ``None``.
        target: Name of the target to load (key under ``[targets]``).
                Defaults to ``project.default_target``.

    """
    root = find_root(root)
    toml_path = root / "rebrew-project.toml"
    if not toml_path.exists():
        raise ConfigNotFoundError(f"Config not found: {toml_path}")

    try:
        raw = load_tomllib(toml_path)
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{toml_path}: {exc}") from exc

    project_raw = _as_table(raw.get("project", {}), "project")
    targets_dict = _as_table(raw.get("targets", {}), "targets")
    global_compiler_raw = _as_table(raw.get("compiler", {}), "compiler")

    # --- Validate known keys to catch typos ---
    unknown_top = set(raw) - _KNOWN_TOP_KEYS
    if unknown_top:
        _config_warn(
            f"rebrew-project.toml: unrecognized top-level keys: {unknown_top}",
        )
    for sec_name, known_keys in (
        ("compiler", _KNOWN_COMPILER_KEYS),
        ("project", _KNOWN_PROJECT_KEYS),
        ("link", _KNOWN_LINK_KEYS),
    ):
        sec = global_compiler_raw if sec_name == "compiler" else project_raw
        if sec_name == "link":
            sec = _as_table(raw.get("link", {}), "link")
        unknown_sec = set(sec) - known_keys
        if unknown_sec:
            _config_warn(
                f"rebrew-project.toml [{sec_name}]: unrecognized keys: {unknown_sec}",
            )
    for tgt_name, tgt_data in targets_dict.items():
        if isinstance(tgt_data, dict):
            unknown_tgt = set(tgt_data) - _KNOWN_TARGET_KEYS
            if unknown_tgt:
                _config_warn(
                    f"rebrew-project.toml [targets.{tgt_name}]: unrecognized keys: {unknown_tgt}",
                )
            target_compiler = _as_table(
                tgt_data.get("compiler", {}), f"targets.{tgt_name}.compiler"
            )
            unknown_target_compiler = set(target_compiler) - _KNOWN_COMPILER_KEYS
            if unknown_target_compiler:
                _config_warn(
                    f"rebrew-project.toml [targets.{tgt_name}.compiler]: "
                    f"unrecognized keys: {unknown_target_compiler}",
                )
        else:
            raise ConfigError(f"rebrew-project.toml [targets.{tgt_name}] must be a TOML table")

    if not targets_dict:
        raise ConfigKeyError("rebrew-project.toml has no [targets] section")
    all_target_names = [k for k in targets_dict if isinstance(k, str)]
    if not all_target_names:
        raise ConfigKeyError("rebrew-project.toml [targets] section has no valid target names")

    global_compiler = global_compiler_raw

    if target is None:
        target = project_raw.get("default_target")
        if target is None:
            raise ConfigKeyError(
                "rebrew-project.toml [project] is missing 'default_target'. "
                f'Add: default_target = "{all_target_names[0]}"'
            )
        if not isinstance(target, str):
            raise ConfigError(
                f"rebrew-project.toml [project].default_target must be a string, "
                f"got {type(target).__name__}"
            )
        if not target.strip():
            raise ConfigError(
                "rebrew-project.toml [project].default_target must not be empty. "
                f'Add: default_target = "{all_target_names[0]}"'
            )
    if target not in targets_dict:
        raise ConfigKeyError(
            f"Target '{target}' not found in rebrew-project.toml.  Available targets: {all_target_names}"
        )
    tgt = targets_dict[target]
    target_compiler = _as_table(tgt.get("compiler", {}), f"targets.{target}.compiler")
    compiler = {**global_compiler, **target_compiler}
    compiler_runner, compiler_command = _split_compiler_runner(compiler)

    sources = tgt

    # --- Validate value types for known fields ---
    # A typo'd format or arch fails here: substituting pe / x86_32 would run
    # the wrong layout detection, disassembler, and pointer size on the binary.
    fmt_val = tgt.get("format", "pe")
    if not isinstance(fmt_val, str) or fmt_val not in _KNOWN_FORMATS:
        raise ConfigError(
            f"rebrew-project.toml [targets.{target}]: unknown format {fmt_val!r} "
            f"(known: {', '.join(sorted(_KNOWN_FORMATS))})"
        )

    arch_name = tgt.get("arch", "x86_32")
    if not isinstance(arch_name, str) or arch_name not in _ARCH_PRESETS:
        raise ConfigError(
            f"rebrew-project.toml [targets.{target}]: unknown arch {arch_name!r} "
            f"(known: {', '.join(sorted(_ARCH_PRESETS))})"
        )

    # A typo'd profile fails too: substituting msvc-6.0 would compile with the
    # wrong toolchain and let `rebrew test` demote earned STATUS.  A name is
    # valid when it is a registered toolchain (plugins add toolchains via
    # rebrew.registry without editing config.py).  `rebrew cfg set-compiler`
    # edits the TOML without loading it, so a bad profile stays repairable.
    from rebrew.toolchain import TOOLCHAINS

    profile_val = compiler.get("profile", "msvc-6.0")
    if not isinstance(profile_val, str) or profile_val not in TOOLCHAINS:
        raise ConfigError(
            f"rebrew-project.toml [compiler]: unknown profile {profile_val!r} "
            f"(known: {', '.join(sorted(TOOLCHAINS))})"
        )

    arch_preset = _ARCH_PRESETS[arch_name]
    bin_rel = tgt.get("binary")
    if bin_rel is None:
        raise ConfigKeyError(f"Target '{target}' in rebrew-project.toml is missing 'binary' path")
    if isinstance(bin_rel, str) and not bin_rel.strip():
        raise ConfigKeyError(f"Target '{target}' in rebrew-project.toml has empty 'binary' path")
    resolved_bin = _resolve(root, bin_rel)
    if resolved_bin is None:
        raise ConfigKeyError(f"Target '{target}' in rebrew-project.toml has invalid 'binary' path")
    bin_path: Path = resolved_bin

    reversed_dir = _required_path(
        root, sources.get("reversed_dir"), f"src/{target}", f"[targets.{target}].reversed_dir"
    )
    # Shared sources: one project-level root scanned for every target (the
    # same .c serving multiple binaries with per-version markers / #ifdefs).
    # An explicitly empty value disables shared sources (None).
    shared_dir_raw = project_raw.get("shared_dir", "src/shared")
    if shared_dir_raw is None or not str(shared_dir_raw).strip():
        shared_dir = None
    else:
        shared_dir = _required_path(root, shared_dir_raw, "src/shared", "[project].shared_dir")
    bin_dir = _required_path(
        root, sources.get("bin_dir"), f"bin/{target}", f"[targets.{target}].bin_dir"
    )
    db_dir = _required_path(root, project_raw.get("db_dir"), "db", "[project].db_dir")
    output_dir = _required_path(
        root, project_raw.get("output_dir"), "output", "[project].output_dir"
    )

    # An explicitly empty includes/libs is valid and means "no extra dir" —
    # needed by mingw/mingw (own headers) and by decomp.me MSVC tarballs
    # (msvc-6.0-sp3-win32/6.6/7.0 ship Bin+Include but no Lib).  A *missing* key still
    # falls back to the conventional default path.
    def _explicit_empty(key: str) -> bool:
        raw = compiler.get(key)
        if raw is not None and not isinstance(raw, str):
            raise ConfigError(f"rebrew-project.toml compiler.{key} must be a path string")
        return raw is not None and not raw.strip()

    from rebrew.utils import resolve_msvc_toolchain

    msvc_layout = resolve_msvc_toolchain(root, profile_val)
    if _explicit_empty("includes"):
        compiler_includes = Path("")
    else:
        default_inc = "toolchain/msvc/6.0-win32/source/VC98/Include"
        if msvc_layout is not None and msvc_layout[1]:
            default_inc = msvc_layout[1]
        compiler_includes = _required_path(
            root,
            compiler.get("includes"),
            default_inc,
            "compiler.includes",
        )
        # Project-local tools/ absent (no --link-tools-from)?  Fall back to
        # the rebrew install's own vendored tree so fresh projects compile
        # out of the box.  Only for project-relative defaults — an explicit
        # absolute path is the user's own.
        if not compiler_includes.exists():
            alt = _install_tool_alt(compiler_includes, root)
            if alt is not None:
                compiler_includes = alt
    if _explicit_empty("libs"):
        compiler_libs = Path("")
    else:
        default_lib = "toolchain/msvc/6.0-win32/source/VC98/Lib"
        if msvc_layout is not None and msvc_layout[2]:
            default_lib = msvc_layout[2]
        compiler_libs = _required_path(root, compiler.get("libs"), default_lib, "compiler.libs")
        if not compiler_libs.exists():
            alt = _install_tool_alt(compiler_libs, root)
            if alt is not None:
                compiler_libs = alt

    source_ext = _parse_source_ext(tgt.get("source_ext", ".c"))

    defines = _parse_defines(tgt.get("defines"), f"targets.{target}.defines")

    # A typo'd ghidra_backend fails instead of silently using the other transport.
    ghidra_backend_val = tgt.get("ghidra_backend", "reva")
    if not isinstance(ghidra_backend_val, str) or ghidra_backend_val not in ("reva", "cli"):
        raise ConfigError(
            f"rebrew-project.toml [targets.{target}]: unknown ghidra_backend "
            f"{ghidra_backend_val!r} (known: reva, cli)"
        )

    # Remote recompile URL: env wins when present (even if empty); otherwise TOML
    if "REBREW_RECOMPILE_URL" in os.environ:
        recompile_raw = os.environ["REBREW_RECOMPILE_URL"].strip()
        recompile_label = "REBREW_RECOMPILE_URL"
    else:
        recompile_raw = _as_str(compiler.get("recompile_url"), "", "compiler.recompile_url").strip()
        recompile_label = "compiler.recompile_url"
    recompile_url_val = validate_http_url(recompile_raw, recompile_label) if recompile_raw else ""

    # Every target, not just the active one: a bad marker on a sibling
    # target would otherwise wait until ``--target`` switched to it, and
    # ``all_markers`` would advertise a blank or unsplittable module.
    markers_by_target = {
        n: _module_marker_value(
            t.get("marker") if isinstance(t, dict) else None,
            n,
            f"targets.{n}.marker",
        )
        for n, t in targets_dict.items()
        if isinstance(n, str)
    }

    cfg = ProjectConfig(
        root=root,
        target_name=target or "",
        # target
        target_binary=bin_path,
        binary_format=fmt_val,
        arch=arch_name,
        # sources
        reversed_dir=reversed_dir,
        shared_dir=shared_dir,
        bin_dir=bin_dir,
        # Derived when blank: raw upper() of `server.dll` is "SERVER.DLL",
        # which matches no identifier-shaped annotation module and silently
        # filters every function out of verify/todo/status.
        marker=markers_by_target[target],
        r2_bogus_vas=_parse_int_list(tgt.get("r2_bogus_vas", []), "r2_bogus_vas"),
        # project-level defaults
        project_name=_as_str(project_raw.get("name"), "", "project.name"),
        default_jobs=_positive_int(project_raw.get("jobs", 4), 4, "project.jobs"),
        db_dir=db_dir,
        output_dir=output_dir,
        # compiler
        compiler_profile=profile_val,
        compiler_command=compiler_command,
        compiler_runner=compiler_runner,
        compiler_includes=compiler_includes,
        compiler_libs=compiler_libs,
        # User-facing defaults (optimization/codegen). base_cflags are always-on
        # flags prepended by compile_to_obj; they must stay separate.
        cflags=_as_str(compiler.get("cflags"), "", "compiler.cflags"),
        cflags_explicit="cflags" in compiler,
        cflags_presets=_merge_cflags_presets(
            global_compiler, target_compiler, target_data=tgt, target_name=target or ""
        ),
        defines=defines,
        base_cflags=_as_str(
            compiler.get("base_cflags"),
            # The MSVC glue default breaks a posix-style compiler
            # (/nologo /c /MT is not gcc syntax).  init writes base_cflags = ""
            # for those profiles; the loader default must match so hand-written
            # tomls work too.
            "" if profile_flags_style(profile_val) == "posix" else "/nologo /c /MT",
            "compiler.base_cflags",
        ),
        compile_timeout=_positive_int(
            compiler.get("timeout", DEFAULT_COMPILE_TIMEOUT),
            DEFAULT_COMPILE_TIMEOUT,
            "compiler.timeout",
        ),
        recompile_url=recompile_url_val,
        recompile_emit_assembly=_as_bool(
            compiler.get("recompile_emit_assembly"), False, "compiler.recompile_emit_assembly"
        ),
        # arch-derived
        pointer_size=arch_preset["pointer_size"],
        padding_bytes=arch_preset["padding_bytes"],
        # project-specific
        iat_thunks=_parse_int_list(tgt.get("iat_thunks", []), "iat_thunks"),
        dll_exports=_parse_hex_dict(tgt.get("dll_exports", {})),
        ignored_symbols=_parse_str_list(tgt.get("ignored_symbols", []), "ignored_symbols"),
        library_modules=set(_parse_str_list(tgt.get("library_modules", []), "library_modules")),
        # Marker modules are upper-case ("D3DX8"); normalize so lookups
        # against parsed annotations never miss on spelling.
        external_libs={
            k.upper(): v
            for k, v in _parse_str_dict(tgt.get("external_libs", {}), "external_libs").items()
        },
        external_ranges=_parse_va_ranges(
            tgt.get("external_ranges", []), f"targets.{target}.external_ranges"
        ),
        crt_sources=_parse_str_dict(tgt.get("crt_sources", {}), "crt_sources"),
        source_ext=source_ext,
        ghidra_program_path=_as_str(
            tgt.get("ghidra_program_path"), "", f"targets.{target}.ghidra_program_path"
        ),
        ghidra_backend=ghidra_backend_val,
        binsync_state_dir=_as_str(
            tgt.get("binsync_state_dir"), "", f"targets.{target}.binsync_state_dir"
        ),
        inventory_file=_as_str(tgt.get("inventory_file"), "", f"targets.{target}.inventory_file"),
        all_targets=all_target_names,
        all_markers=set(markers_by_target.values()),
        # lint configuration — validated enums; unknown keys warn like other sections
        **_load_lint_settings(project_raw),
    )

    # Auto-detect CRT sources if not explicitly configured
    if not cfg.crt_sources:
        cfg.crt_sources = detect_crt_sources(root)

    # Auto-detect binary layout if the binary exists
    if cfg.target_binary.exists():
        layout = _detect_binary_layout(
            cfg.target_binary,
            fmt=cfg.binary_format,
            root=root,
            target=str(getattr(cfg, "target_name", "") or ""),
        )
        cfg.image_base = layout["image_base"]
        cfg.text_va = layout["text_va"]
    else:
        # A typo'd/missing binary path silently leaves image_base/text_va at 0,
        # which surfaces later as baffling byte-offset math.  Warn at load time.
        _config_warn(
            f"target binary not found: {cfg.target_binary} — "
            "image_base/text_va auto-detection skipped"
        )

    # --- [link] section: byte-identical PE reconstruction settings ---
    link_raw = _as_table(raw.get("link", {}), "link")

    def _opt_str(key: str) -> str | None:
        v = link_raw.get(key)
        return v if isinstance(v, str) else None

    tsaware_raw = link_raw.get("tsaware")
    if tsaware_raw is None:
        tsaware_val: bool | None = None
    elif isinstance(tsaware_raw, bool):
        tsaware_val = tsaware_raw
    else:
        # Match _as_bool: reject stringy "false" (bool("false") is True).
        _config_warn(
            f"Expected boolean for link.tsaware, got {tsaware_raw!r}; ignoring",
        )
        tsaware_val = None

    cfg.link = LinkConfig(
        file_align=_parse_optional_int(link_raw.get("file_align"), "link.file_align"),
        stack_reserve=_parse_optional_int(link_raw.get("stack_reserve"), "link.stack_reserve"),
        stack_commit=_parse_optional_int(link_raw.get("stack_commit"), "link.stack_commit"),
        tsaware=tsaware_val,
        linker_version=_opt_str("linker_version"),
        os_version=_opt_str("os_version"),
        subsystem_version=_opt_str("subsystem_version"),
        timestamp=_parse_optional_int(link_raw.get("timestamp"), "link.timestamp"),
    )
    # link.file_align is informational: VC6's /ALIGN cannot raise FileAlignment,
    # so no patch path applies it (pe_headers.PATCHABLE excludes it and the
    # parity report iterates PATCHABLE).  Warn instead of silently ignoring it.
    if cfg.link.file_align is not None:
        _config_warn(
            "link.file_align is informational only — FileAlignment cannot be "
            "patched into the header (it needs a relink) and is not applied by "
            "round-trip --fix-headers"
        )
    if (
        cfg.link.stack_reserve is not None
        and cfg.link.stack_commit is not None
        and cfg.link.stack_commit > cfg.link.stack_reserve
    ):
        raise ConfigError(
            "rebrew-project.toml link.stack_commit "
            f"({cfg.link.stack_commit}) exceeds link.stack_reserve "
            f"({cfg.link.stack_reserve}); the Windows loader rejects that image"
        )

    # --- [llm] section: optional LLM-assisted GA seeding ---
    # Documented in CONFIG.md; keys populate cfg.llm_*; env vars are the
    # fallback when a TOML field is empty (see llm_seed.llm_config /
    # _resolve_model).  ``match --seed-llm`` points users at ``[llm]``.
    llm_raw = _as_table(raw.get("llm", {}), "llm")
    unknown_llm = set(llm_raw) - _KNOWN_LLM_KEYS
    if unknown_llm:
        _config_warn(f"rebrew-project.toml [llm]: unrecognized keys: {sorted(unknown_llm)}")

    raw_endpoint = _as_str(llm_raw.get("endpoint"), "", "llm.endpoint").strip()
    if raw_endpoint:
        cfg.llm_endpoint = validate_http_url(raw_endpoint, "llm.endpoint")
    elif "REBREW_LLM_ENDPOINT" in os.environ and os.environ["REBREW_LLM_ENDPOINT"].strip():
        cfg.llm_endpoint = validate_http_url(
            os.environ["REBREW_LLM_ENDPOINT"].strip(), "REBREW_LLM_ENDPOINT"
        )
    else:
        cfg.llm_endpoint = ""

    toml_api_key = _as_str(llm_raw.get("api_key"), "", "llm.api_key").strip()
    if toml_api_key:
        _config_warn(
            "[llm].api_key is set in rebrew-project.toml — prefer "
            "REBREW_LLM_API_KEY in the environment so the key is not committed"
        )
    if "REBREW_LLM_API_KEY" in os.environ:
        cfg.llm_api_key = os.environ["REBREW_LLM_API_KEY"].strip()
    else:
        cfg.llm_api_key = toml_api_key

    toml_model = _as_str(llm_raw.get("model"), "", "llm.model").strip()
    if toml_model:
        cfg.llm_model = toml_model
    elif "REBREW_LLM_MODEL" in os.environ and os.environ["REBREW_LLM_MODEL"].strip():
        cfg.llm_model = os.environ["REBREW_LLM_MODEL"].strip()
    else:
        cfg.llm_model = ""

    if cfg.llm_model:
        validate_llm_model(cfg.llm_model)

    if cfg.llm_api_key:
        if not cfg.llm_endpoint:
            _config_warn(
                "[llm].api_key is set but [llm].endpoint is empty — "
                "set endpoint (or REBREW_LLM_ENDPOINT) or LLM seeding stays disabled"
            )
        elif not is_key_safe_endpoint(cfg.llm_endpoint):
            raise ConfigError(
                "LLM endpoint must use https when an API key is set "
                "(plain http is allowed only for loopback hosts)"
            )

    if "REBREW_LLM_MAX_REQUESTS" in os.environ:
        raw_max = os.environ["REBREW_LLM_MAX_REQUESTS"].strip()
        if raw_max:
            try:
                val = int(raw_max)
                if val < 0:
                    raise ConfigError(f"REBREW_LLM_MAX_REQUESTS={raw_max!r} must be >= 0")
            except ValueError as exc:
                if not isinstance(exc, ConfigError):
                    raise ConfigError(f"REBREW_LLM_MAX_REQUESTS={raw_max!r} is not an int") from exc
                raise

    # --- [cache] section: compile-cache backend selection ---
    # The store is a pluggable component (rebrew.cache_backends entry-point
    # group); the keying semantics are shared and fixed.  Unknown cache
    # keys warn like the other sections.  An unknown or empty *backend*
    # name fails here so a typo does not wait until the first compile.
    cache_raw = _as_table(raw.get("cache", {}), "cache")
    unknown_cache = set(cache_raw) - _KNOWN_CACHE_KEYS
    if unknown_cache:
        _config_warn(f"rebrew-project.toml [cache]: unrecognized keys: {sorted(unknown_cache)}")
    from rebrew.compile_cache import DEFAULT_CACHE_BACKEND, available_cache_backends

    if "backend" in cache_raw:
        backend = _as_str(cache_raw.get("backend"), "", "cache.backend").strip()
        if not backend:
            raise ConfigError("rebrew-project.toml [cache].backend must not be empty")
    else:
        backend = DEFAULT_CACHE_BACKEND
    known_backends = available_cache_backends()
    if backend not in known_backends:
        raise ConfigError(
            f"rebrew-project.toml [cache].backend = {backend!r} is not a "
            f"registered backend (known: {', '.join(known_backends)})"
        )
    cfg.cache_backend = backend

    return cfg


__all__ = [
    "ConfigError",
    "ConfigKeyError",
    "ConfigNotFoundError",
    "DEFAULT_COMPILE_TIMEOUT",
    "DEFAULT_LINT_MAX_LINE_LENGTH",
    "FUNCTION_STRUCTURE_JSON",
    "LinkConfig",
    "ProjectConfig",
    "detect_crt_sources",
    "find_root",
    "is_key_safe_endpoint",
    "load_config",
    "module_marker",
    "profile_flags_style",
    "validate_http_url",
    "validate_llm_model",
]
