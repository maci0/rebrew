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

import re
import shlex
import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypedDict


def _config_warn(msg: str) -> None:
    """Emit a UserWarning and print a user-facing config warning to stderr."""
    import warnings

    warnings.warn(msg, UserWarning, stacklevel=2)
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

    def to_patch_fields(self) -> dict[str, int]:
        """Map configured values to pe_headers field labels (empty if unset)."""
        fields: dict[str, int] = {}
        if self.linker_version:
            try:
                major, minor = self.linker_version.split(".", 1)
                fields["linker_version_major"] = int(major)
                fields["linker_version_minor"] = int(minor)
            except ValueError:
                pass
        for label, ver in (
            ("os_version", self.os_version),
            ("subsystem_version", self.subsystem_version),
        ):
            if ver:
                try:
                    major, minor = ver.split(".", 1)
                    fields[f"{label}_major"] = int(major)
                    fields[f"{label}_minor"] = int(minor)
                except ValueError:
                    pass
        if self.tsaware is not None:
            fields["dll_characteristics"] = 0x8000 if self.tsaware else 0
        if self.stack_reserve is not None:
            fields["stack_reserve"] = self.stack_reserve
        if self.stack_commit is not None:
            fields["stack_commit"] = self.stack_commit
        if self.timestamp is not None:
            fields["timestamp"] = self.timestamp
        return fields


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
    function_list: Path = field(default_factory=lambda: Path())
    bin_dir: Path = field(default_factory=lambda: Path())
    marker: str = ""  # Prefix used in annotations, e.g. // FUNCTION: SERVER 0x... (default: target_name.upper())
    r2_bogus_vas: list[int] = field(default_factory=list)  # VAs with known-bad r2 size data

    # --- project-level defaults ---
    project_name: str = ""
    default_jobs: int = 4  # Default parallelism for batch operations
    db_dir: Path = field(default_factory=lambda: Path())
    output_dir: Path = field(default_factory=lambda: Path())

    # --- compiler ---
    compiler_profile: str = "msvc6"
    compiler_command: str = "wine CL.EXE"
    compiler_runner: str = ""
    compiler_includes: Path = field(default_factory=lambda: Path())
    compiler_libs: Path = field(default_factory=lambda: Path())
    cflags: str = ""  # Default compiler flags (from [compiler] or per-target override)
    cflags_presets: dict[str, str] = field(default_factory=dict)
    """Per-module compiler flag overrides (``rebrew cfg set-cflags``).

    ``[compiler.cflags_presets]`` (global) merged with
    ``[targets.X.compiler.cflags_presets]`` (per-key, target wins).  Used by
    ``rebrew match``/``diff`` as the CFLAGS fallback for functions whose
    module has a preset and whose per-function metadata has no CFLAGS.
    """
    base_cflags: str = "/nologo /c /MT"  # Always-on flags prepended to every compile
    compile_timeout: int = 60  # Seconds before a compile subprocess is killed

    @property
    def posix_style(self) -> bool:
        """True when the compiler profile uses POSIX-style flags (-I/-o/-c).

        POSIX-style profiles (gcc, gcc-pe, clang) take ``-I``/``-o``/``-c``
        and ship their own headers; MSVC profiles use ``/I``/``/Fo``/``/c``.
        Single source of truth for compile/flag routing across compile.py,
        diff.py, match.py, and matcher/compiler.py.
        """
        return self.compiler_profile in ("gcc", "gcc-pe", "clang")

    # --- Computed from arch ---
    pointer_size: int = 4
    padding_bytes: list[int] = field(default_factory=lambda: [0xCC, 0x90])
    symbol_prefix: str = "_"

    # --- PE-specific (computed at load time if format == "pe") ---
    image_base: int = 0
    text_va: int = 0
    text_raw_offset: int = 0

    # --- Project-specific (loaded from TOML if present) ---
    game_range_end: int | None = None
    iat_thunks: list[int] = field(default_factory=list)
    dll_exports: dict[int, str] = field(default_factory=dict)
    ignored_symbols: list[str] = field(default_factory=list)
    compiler_profiles: dict[str, dict[str, str]] = field(
        default_factory=dict
    )  # e.g. {"clang": {...}}
    library_modules: set[str] = field(
        default_factory=set
    )  # Module names using LIBRARY marker (e.g. {"MSVCRT", "ZLIB"})
    crt_sources: dict[str, str] = field(default_factory=dict)
    source_ext: str = ".c"  # Source file extension (e.g. ".c", ".cpp")
    ghidra_program_path: str = ""
    ghidra_backend: str = "reva"  # "reva" (MCP) or "cli" (ghidra-cli binary)

    # --- All known target names ---
    all_targets: list[str] = field(default_factory=list)

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

    def va_to_file_offset(self, va: int) -> int:
        """Convert VA to raw file offset using .text section constants."""
        return va - self.text_va + self.text_raw_offset

    @property
    def metadata_dir(self) -> Path:
        """Directory for rebrew-function.toml and rebrew-data.toml.

        This is the parent of ``reversed_dir`` — e.g. ``src/`` when
        ``reversed_dir`` is ``src/NP``.  All metadata reads/writes must
        go through this property so the location is centralized.
        """
        return self.reversed_dir.parent


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
        if isinstance(v, int):
            parsed.append(v)
        elif isinstance(v, str):
            try:
                parsed.append(int(v, 16) if v.startswith("0x") else int(v))
            except ValueError:
                _config_warn(f"Invalid integer '{v}' in {field_name}; ignoring")
        else:
            _config_warn(f"Unexpected type {type(v).__name__} in {field_name}; ignoring")
    return parsed


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
            addr = int(str(k), 16) if str(k).startswith("0x") else int(str(k))
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
    """Convert *value* to int, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
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


def _parse_optional_int(value: Any, field_name: str) -> int | None:
    """Parse an optional integer value, allowing decimal or ``0x`` strings."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            _config_warn(f"Invalid integer {value!r} for {field_name}; ignoring")
            return None
    _config_warn(f"Expected integer for {field_name}, got {type(value).__name__}; ignoring")
    return None


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


def _parse_profiles(value: Any) -> dict[str, dict[str, str]]:
    """Parse ``[compiler.profiles]`` into a typed nested mapping."""
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        _config_warn(
            f"Expected mapping for compiler.profiles, got {type(value).__name__}; using empty mapping"
        )
        return {}
    result: dict[str, dict[str, str]] = {}
    for profile_name, profile_data in value.items():
        if not isinstance(profile_name, str) or not isinstance(profile_data, Mapping):
            _config_warn(f"Skipping invalid compiler profile entry: {profile_name!r}")
            continue
        parsed = _parse_str_dict(profile_data, f"compiler.profiles.{profile_name}")
        if parsed:
            result[profile_name] = parsed
    return result


def _parse_source_ext(value: Any) -> str:
    """Parse and normalize the configured source extension."""
    if value is None:
        return ".c"
    if not isinstance(value, str):
        _config_warn(
            f"Expected string for source_ext, got {type(value).__name__}; using default .c"
        )
        return ".c"
    ext = value.strip()
    if not ext or ext == ".":
        _config_warn("Expected non-empty source_ext; using default .c")
        return ".c"
    if "/" in ext or "\\" in ext:
        _config_warn(f"source_ext must be a file extension, got {value!r}; using default .c")
        return ".c"
    if not ext.startswith("."):
        _config_warn(f"source_ext {value!r} is missing a leading dot; using .{ext}")
        ext = f".{ext}"
    return ext


def _as_table(value: Any, field_name: str) -> dict[str, Any]:
    """Return a TOML table as a dict or raise a clear config error."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"rebrew-project.toml [{field_name}] must be a TOML table")
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


def _resolve(root: Path, rel: str | Path | None) -> Path | None:
    """Resolve a path relative to project root.  Returns *None* if *rel* is ``None``."""
    if rel is None:
        return None
    if not isinstance(rel, (str, Path)):
        _config_warn(f"Expected path string, got {type(rel).__name__}; ignoring")
        return None
    p = Path(rel)
    if p.is_absolute():
        return p
    return root / p


def _required_path(root: Path, value: Any, default: str, field_name: str) -> Path:
    """Resolve a configured path, rejecting explicit empty or invalid values."""
    if value is None:
        value = default
    if isinstance(value, str) and not value.strip():
        raise ValueError(f"rebrew-project.toml {field_name} must not be empty")
    resolved = _resolve(root, value)
    if resolved is None:
        raise ValueError(f"rebrew-project.toml {field_name} must be a path string")
    return resolved


def _split_compiler_runner(compiler: dict[str, Any]) -> tuple[str, str]:
    command_raw = _as_str(compiler.get("command"), "wine CL.EXE", "compiler.command")
    if not command_raw.strip():
        raise ValueError("rebrew-project.toml compiler.command must not be empty")
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
    global_compiler: dict[str, Any], target_compiler: dict[str, Any]
) -> dict[str, str]:
    """Merge per-module cflags presets: global, overridden per-key by target.

    ``rebrew cfg set-cflags MODULE FLAGS`` writes a global
    ``[compiler.cflags_presets]``; ``--target X`` writes
    ``[targets.X.compiler.cflags_presets]``.  The target's presets win for
    the same module key, matching the documented "per-target presets
    override global presets for the same origin key" semantics.
    """
    merged: dict[str, str] = {}
    for table, label in (
        (global_compiler, "compiler.cflags_presets"),
        (target_compiler, "targets.<target>.compiler.cflags_presets"),
    ):
        for key, val in (table.get("cflags_presets", {}) or {}).items():
            merged[str(key).upper()] = _as_str(val, "", label)
    return merged


def _detect_binary_layout(bin_path: Path, fmt: str = "auto") -> dict[str, int]:
    """Read image base and .text section from binary headers.

    Uses ``binary_loader`` to support PE, ELF, and Mach-O.
    """
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


# Well-known MSVC CRT source directory patterns (relative to project root).
# Each tuple is (relative_path_from_tools, origin_name).
_CRT_SOURCE_PATTERNS: list[tuple[str, str]] = [
    ("MSVC600/VC98/CRT/SRC", "MSVCRT"),
    ("MSVC400/CRT/SRC", "MSVCRT"),
    ("MSVC420/CRT/SRC", "MSVCRT"),
    ("MSVC7/crt/src", "MSVCRT"),
]


def detect_crt_sources(root: Path) -> dict[str, str]:
    """Scan the ``tools/`` directory for known MSVC CRT source trees.

    Returns a dict mapping origin names (e.g. ``"MSVCRT"``) to relative paths
    suitable for use in ``crt_sources`` config entries.  Uses case-insensitive
    directory matching to handle varying MSVC packaging conventions.

    Only returns the *first* match per origin so that projects with multiple
    MSVC versions don't get duplicate entries.
    """
    tools_dir = root / "tools"
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
                component_lower = component.lower()
                for child in candidate.iterdir():
                    if child.name.lower() == component_lower and child.is_dir():
                        matched_child = child
                        break
            if matched_child is None:
                break
            candidate = matched_child
        else:
            # All components matched
            rel = candidate.relative_to(root)
            found[origin] = str(rel)

    return found


def find_root(start: Path | None = None) -> Path:
    """Walk up from cwd to find rebrew-project.toml.

    Since rebrew is an installable package, __file__ may point into
    site-packages rather than the project directory.  We therefore
    search from the current working directory upward, similar to how
    ``git`` locates ``.git/``.

    *start*, when given, is an EXPLICIT project root — returned verbatim
    (no walk-up); load_config(root=X) expects X to contain the toml.
    """
    if start is not None:
        return start
    candidate = Path.cwd().resolve()
    while candidate != candidate.parent:
        if (candidate / "rebrew-project.toml").exists():
            return candidate
        candidate = candidate.parent
    raise FileNotFoundError(
        "Could not find rebrew-project.toml in any parent of the current directory. "
        "Run rebrew commands from within a project that contains rebrew-project.toml."
    )


# ---------------------------------------------------------------------------
# Known TOML keys — validated at load time to catch typos
# ---------------------------------------------------------------------------

_KNOWN_TOP_KEYS = {"targets", "compiler", "project", "link"}

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
    "function_list",
    "bin_dir",
    "compiler",
    "r2_bogus_vas",
    "game_range_end",  # legacy/no-op: parsed and stored, never read by any tool
    "iat_thunks",
    "dll_exports",
    "ignored_symbols",
    "library_modules",
    "crt_sources",
    "source_ext",
    "ghidra_program_path",
    "ghidra_backend",
    "origins",  # written by `rebrew cfg add-target`; editor/UI only — NOT
    # used for annotation filtering (module filters come from the
    # annotations themselves).
    "cflags_presets",  # written by `rebrew cfg set-cflags` (per-origin compiler flag overrides)
}

_KNOWN_COMPILER_KEYS = {
    "command",
    "runner",
    "includes",
    "libs",
    "cflags",
    "profile",
    "profiles",  # reserved: per-compiler profiles are documented but not yet
    # wired into a profile-switch path (matcher/compiler.py keys off the
    # profile NAME only).
    "base_cflags",
    "timeout",
    "cflags_presets",  # written by `rebrew cfg set-cflags --global` (per-origin compiler flag overrides)
}

_KNOWN_PROJECT_KEYS = {
    "name",
    "jobs",
    "db_dir",
    "output_dir",
    "default_target",
}

_KNOWN_FORMATS = {"pe", "elf", "macho"}
_KNOWN_PROFILES = {
    "msvc400",
    "msvc420",
    "msvc5",
    "msvc6",
    "msvc6.3",
    "msvc6.6",
    "msvc7",
    "gcc",
    "gcc-pe",
    "clang",
}


def load_config(
    root: Path | None = None,
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
        raise FileNotFoundError(f"Config not found: {toml_path}")

    with toml_path.open("rb") as f:
        raw = tomllib.load(f)

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
            raise ValueError(f"rebrew-project.toml [targets.{tgt_name}] must be a TOML table")

    if not targets_dict:
        raise KeyError("rebrew-project.toml has no [targets] section")
    all_target_names = [k for k in targets_dict if isinstance(k, str)]
    if not all_target_names:
        raise KeyError("rebrew-project.toml [targets] section has no valid target names")

    global_compiler = {k: v for k, v in global_compiler_raw.items() if k not in ("profiles",)}
    compiler_profiles = _parse_profiles(global_compiler_raw.get("profiles", {}))

    if target is None:
        target = project_raw.get("default_target")
        if target is None:
            raise KeyError(
                "rebrew-project.toml [project] is missing 'default_target'. "
                f'Add: default_target = "{all_target_names[0]}"'
            )
        if not isinstance(target, str):
            raise ValueError(
                f"rebrew-project.toml [project].default_target must be a string, "
                f"got {type(target).__name__}"
            )
        if not target.strip():
            raise ValueError(
                "rebrew-project.toml [project].default_target must not be empty. "
                f'Add: default_target = "{all_target_names[0]}"'
            )
    if target not in targets_dict:
        raise KeyError(
            f"Target '{target}' not found in rebrew-project.toml.  Available targets: {all_target_names}"
        )
    tgt = targets_dict[target]
    target_compiler = _as_table(tgt.get("compiler", {}), f"targets.{target}.compiler")
    compiler = {**global_compiler, **target_compiler}
    compiler_runner, compiler_command = _split_compiler_runner(compiler)

    sources = tgt

    # --- Validate value types for known fields ---
    # Unknown/invalid format must not be stored: layout detection would fail
    # silently (image_base/text_va left at 0) and break VA→offset math.
    fmt_val = tgt.get("format", "pe")
    if not isinstance(fmt_val, str) or fmt_val not in _KNOWN_FORMATS:
        _config_warn(
            f"rebrew-project.toml [targets.{target}]: unknown format {fmt_val!r} "
            f"(known: {', '.join(sorted(_KNOWN_FORMATS))}); falling back to pe",
        )
        fmt_val = "pe"

    arch_raw = tgt.get("arch", "x86_32")
    if not isinstance(arch_raw, str):
        _config_warn(
            f"rebrew-project.toml [targets.{target}]: arch must be a string, "
            f"got {type(arch_raw).__name__}; falling back to x86_32",
        )
        arch_name = "x86_32"
    else:
        arch_name = arch_raw
    if arch_name not in _ARCH_PRESETS:
        _config_warn(
            f"rebrew-project.toml [targets.{target}]: unknown arch '{arch_name}' "
            f"(known: {', '.join(sorted(_ARCH_PRESETS))}); falling back to x86_32",
        )
        arch_name = "x86_32"

    # Unknown profiles are kept only as a warning elsewhere historically; store
    # a known default so flag sweeps / doctor report a real profile.
    profile_val = compiler.get("profile", "msvc6")
    if not isinstance(profile_val, str) or profile_val not in _KNOWN_PROFILES:
        _config_warn(
            f"rebrew-project.toml [compiler]: unknown profile {profile_val!r} "
            f"(known: {', '.join(sorted(_KNOWN_PROFILES))}); falling back to msvc6",
        )
        profile_val = "msvc6"

    arch_preset = _ARCH_PRESETS.get(arch_name, _ARCH_PRESETS["x86_32"])
    bin_rel = tgt.get("binary")
    if bin_rel is None:
        raise KeyError(f"Target '{target}' in rebrew-project.toml is missing 'binary' path")
    if isinstance(bin_rel, str) and not bin_rel.strip():
        raise KeyError(f"Target '{target}' in rebrew-project.toml has empty 'binary' path")
    resolved_bin = _resolve(root, bin_rel)
    if resolved_bin is None:
        raise KeyError(f"Target '{target}' in rebrew-project.toml has invalid 'binary' path")
    bin_path: Path = resolved_bin

    reversed_dir = _required_path(
        root, sources.get("reversed_dir"), f"src/{target}", f"[targets.{target}].reversed_dir"
    )
    function_list = _required_path(
        root,
        sources.get("function_list"),
        f"src/{target}/functions.txt",
        f"[targets.{target}].function_list",
    )
    bin_dir = _required_path(
        root, sources.get("bin_dir"), f"bin/{target}", f"[targets.{target}].bin_dir"
    )
    db_dir = _required_path(root, project_raw.get("db_dir"), "db", "[project].db_dir")
    output_dir = _required_path(
        root, project_raw.get("output_dir"), "output", "[project].output_dir"
    )

    # An explicitly empty includes/libs is valid and means "no extra dir" —
    # needed by gcc-pe/mingw (own headers) and by decomp.me MSVC tarballs
    # (msvc6.3/6.6/7.0 ship Bin+Include but no Lib).  A *missing* key still
    # falls back to the conventional default path.
    def _explicit_empty(key: str) -> bool:
        return compiler.get(key) is not None and not str(compiler.get(key) or "").strip()

    if _explicit_empty("includes"):
        compiler_includes = Path("")
    else:
        compiler_includes = _required_path(
            root,
            compiler.get("includes"),
            "tools/MSVC600/VC98/Include",
            "compiler.includes",
        )
    if _explicit_empty("libs"):
        compiler_libs = Path("")
    else:
        compiler_libs = _required_path(
            root, compiler.get("libs"), "tools/MSVC600/VC98/Lib", "compiler.libs"
        )

    source_ext = _parse_source_ext(tgt.get("source_ext", ".c"))

    # ghidra_backend must be one of the known transports; a typo silently
    # switching to the wrong backend would be confusing, so validate.
    ghidra_backend_raw = tgt.get("ghidra_backend", "reva")
    if not isinstance(ghidra_backend_raw, str) or ghidra_backend_raw not in ("reva", "cli"):
        _config_warn(
            f"rebrew-project.toml [targets.{target}]: unknown ghidra_backend "
            f"{ghidra_backend_raw!r} (known: reva, cli); falling back to reva",
        )
        ghidra_backend_raw = "reva"
    ghidra_backend_val = _as_str(ghidra_backend_raw, "reva", f"targets.{target}.ghidra_backend")

    cfg = ProjectConfig(
        root=root,
        target_name=target or "",
        # target
        target_binary=bin_path,
        binary_format=fmt_val,
        arch=arch_name,
        # sources
        reversed_dir=reversed_dir,
        function_list=function_list,
        bin_dir=bin_dir,
        # marker defaults to the target name upper-cased with non-identifier
        # characters stripped: for `server.dll` the raw upper() yields
        # "SERVER.DLL", which matches NO annotation module ("SERVER") and
        # silently filters every function out of verify/todo/status.
        marker=_as_str(
            tgt.get("marker"),
            re.sub(r"[^A-Za-z0-9_]", "", target).upper(),
            f"targets.{target}.marker",
        ),
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
        cflags_presets=_merge_cflags_presets(global_compiler, target_compiler),
        base_cflags=_as_str(compiler.get("base_cflags"), "/nologo /c /MT", "compiler.base_cflags"),
        compile_timeout=_positive_int(compiler.get("timeout", 60), 60, "compiler.timeout"),
        # arch-derived
        pointer_size=arch_preset["pointer_size"],
        padding_bytes=arch_preset["padding_bytes"],
        symbol_prefix=arch_preset["symbol_prefix"],
        # project-specific
        game_range_end=_parse_optional_int(tgt.get("game_range_end"), "game_range_end"),
        iat_thunks=_parse_int_list(tgt.get("iat_thunks", []), "iat_thunks"),
        dll_exports=_parse_hex_dict(tgt.get("dll_exports", {})),
        ignored_symbols=_parse_str_list(tgt.get("ignored_symbols", []), "ignored_symbols"),
        compiler_profiles=compiler_profiles,
        library_modules=set(_parse_str_list(tgt.get("library_modules", []), "library_modules")),
        crt_sources=_parse_str_dict(tgt.get("crt_sources", {}), "crt_sources"),
        source_ext=source_ext,
        ghidra_program_path=_as_str(
            tgt.get("ghidra_program_path"), "", f"targets.{target}.ghidra_program_path"
        ),
        ghidra_backend=ghidra_backend_val,
        all_targets=all_target_names,
    )

    # Auto-detect CRT sources if not explicitly configured
    if not cfg.crt_sources:
        cfg.crt_sources = detect_crt_sources(root)

    # Auto-detect binary layout if the binary exists
    if cfg.target_binary.exists():
        layout = _detect_binary_layout(cfg.target_binary, fmt=cfg.binary_format)
        cfg.image_base = layout["image_base"]
        cfg.text_va = layout["text_va"]
        cfg.text_raw_offset = layout["text_raw_offset"]
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

    cfg.link = LinkConfig(
        file_align=_parse_optional_int(link_raw.get("file_align"), "link.file_align"),
        stack_reserve=_parse_optional_int(link_raw.get("stack_reserve"), "link.stack_reserve"),
        stack_commit=_parse_optional_int(link_raw.get("stack_commit"), "link.stack_commit"),
        tsaware=link_raw.get("tsaware") if isinstance(link_raw.get("tsaware"), bool) else None,
        linker_version=_opt_str("linker_version"),
        os_version=_opt_str("os_version"),
        subsystem_version=_opt_str("subsystem_version"),
        timestamp=_parse_optional_int(link_raw.get("timestamp"), "link.timestamp"),
    )

    return cfg
