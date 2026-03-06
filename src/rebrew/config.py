"""Centralised project configuration loader for rebrew.

Reads ``rebrew-project.toml`` from the project root and exposes every setting as
simple attributes so that tool scripts no longer need to hardcode paths,
image-base addresses, or compiler flags.

The configuration supports **multiple targets**.  Each target has its own
binary, source directory, and function list.  Compiler settings are shared
across all targets.

Usage in any tool::

    from rebrew.config import cfg

    bin_path = cfg.target_binary        # Path object
    src_dir  = cfg.reversed_dir         # Path object
    arch     = cfg.arch                 # "x86_32"
    base     = cfg.image_base           # int, e.g. 0x10000000

To load a specific target::

    from rebrew.config import load_config
    cfg = load_config(target="client_exe")
"""

import copy as _copy_mod
import shlex
import sys
import tomllib
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
"""Tool-agnostic structural cache: ``[{va, size, tool_name?}]``.

This file stores function *boundaries* (VA + size) discovered by any RE
tool (Ghidra, radare2, rizin).  Names are optional hints used only when
no source annotation exists.  Source annotations are always authoritative
for naming.
"""

_LEGACY_GHIDRA_JSON = "ghidra_functions.json"
"""Legacy filename — kept for migration fallback."""

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
    origins: list[str] = field(default_factory=list)  # Valid ORIGIN values, e.g. ["GAME", "ZLIB"]
    default_origin: str = ""  # Default ORIGIN when not specified (first origin if empty)
    origin_prefixes: dict[str, str] = field(default_factory=dict)  # origin -> filename prefix
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
    base_cflags: str = "/nologo /c /MT"  # Always-on flags prepended to every compile
    compile_timeout: int = 60  # Seconds before a compile subprocess is killed

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
    cflags_presets: dict[str, str] = field(default_factory=dict)
    zlib_vas: list[int] = field(default_factory=list)
    ignored_symbols: list[str] = field(default_factory=list)
    compiler_profiles: dict[str, dict[str, str]] = field(
        default_factory=dict
    )  # e.g. {"clang": {...}}
    origin_compiler: dict[str, dict[str, str]] = field(
        default_factory=dict
    )  # Per-origin compiler overrides, e.g. {"ZLIB": {"command": "...", "cflags": "/O3"}}
    library_origins: set[str] = field(
        default_factory=set
    )  # Origins using LIBRARY marker (e.g. {"ZLIB", "MSVCRT"})
    origin_comments: dict[str, str] = field(
        default_factory=dict
    )  # Origin → skeleton preamble comment
    origin_todos: dict[str, str] = field(default_factory=dict)  # Origin → TODO text for skeleton
    crt_sources: dict[str, str] = field(default_factory=dict)
    source_ext: str = ".c"  # Source file extension (e.g. ".c", ".cpp")
    ghidra_program_path: str = ""

    # --- All known target names ---
    all_targets: list[str] = field(default_factory=list)

    @property
    def capstone_arch(self) -> int:
        """Return capstone CS_ARCH_* constant."""
        import capstone

        preset = _ARCH_PRESETS.get(self.arch)
        raw_name = preset.get("capstone_arch", "CS_ARCH_X86") if preset else "CS_ARCH_X86"
        name = raw_name if isinstance(raw_name, str) else "CS_ARCH_X86"
        return getattr(capstone, name)

    @property
    def capstone_mode(self) -> int:
        """Return capstone CS_MODE_* constant."""
        import capstone

        preset = _ARCH_PRESETS.get(self.arch)
        raw_name = preset.get("capstone_mode", "CS_MODE_32") if preset else "CS_MODE_32"
        name = raw_name if isinstance(raw_name, str) else "CS_MODE_32"
        return getattr(capstone, name)

    def va_to_file_offset(self, va: int) -> int:
        """Convert VA to raw file offset using .text section constants."""
        return va - self.text_va + self.text_raw_offset

    def for_origin(self, origin: str) -> "ProjectConfig":
        """Return config with per-origin compiler overrides applied.

        Looks up *origin* in ``origin_compiler`` and returns a shallow copy
        with the matching compiler fields overridden.  Returns ``self``
        unchanged if no overrides exist for the given origin.

        Uses ``copy.copy`` (shallow) rather than ``copy.deepcopy`` because
        only scalar fields are modified.  Mutable container fields (lists,
        dicts, sets) are shared but never mutated through the returned copy.
        """
        overrides = self.origin_compiler.get(origin, {})
        if not overrides:
            return self
        cfg = _copy_mod.copy(self)
        if "command" in overrides:
            cfg.compiler_command = overrides["command"]
        if "runner" in overrides:
            cfg.compiler_runner = overrides["runner"]
        if "includes" in overrides:
            cfg.compiler_includes = (
                _resolve(self.root, overrides["includes"]) or self.compiler_includes
            )
        if "libs" in overrides:
            cfg.compiler_libs = _resolve(self.root, overrides["libs"]) or self.compiler_libs
        if "cflags" in overrides:
            cfg.cflags = overrides["cflags"]
        if "base_cflags" in overrides:
            cfg.base_cflags = overrides["base_cflags"]
        if "profile" in overrides:
            cfg.compiler_profile = overrides["profile"]
        if "timeout" in overrides:
            try:
                timeout_val = int(overrides["timeout"])
            except (ValueError, TypeError):
                timeout_val = self.compile_timeout
            cfg.compile_timeout = max(timeout_val, 1)
        return cfg

    def resolve_origin_cflags(self, origin: str, fallback: str = "/O2 /Gd") -> str:
        """Return effective default cflags for a given origin.

        Resolution order (first non-empty wins):
        1. ``origin_compiler[origin]["cflags"]``
        2. ``cflags_presets[origin]``
        3. *fallback*
        """
        oc = self.origin_compiler.get(origin, {})
        if "cflags" in oc:
            return oc["cflags"]
        if origin in self.cflags_presets:
            return self.cflags_presets[origin]
        return fallback


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


def _safe_int(value: Any, default: int) -> int:
    """Convert *value* to int, returning *default* on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        _config_warn(f"Expected integer, got {value!r}; using default {default}")
        return default


def _resolve(root: Path, rel: str | None) -> Path | None:
    """Resolve a path relative to project root.  Returns *None* if *rel* is ``None``."""
    if rel is None:
        return None
    p = Path(rel)
    if p.is_absolute():
        return p
    return root / p


def _split_compiler_runner(compiler: dict[str, Any]) -> tuple[str, str]:
    command_raw = str(compiler.get("command", "wine CL.EXE"))
    if "runner" in compiler:
        return str(compiler.get("runner", "")), command_raw

    try:
        parts = shlex.split(command_raw)
    except ValueError:
        parts = command_raw.split()

    if parts and parts[0] in {"wine", "wibo"}:
        runner = parts[0]
        return runner, command_raw

    return "", command_raw


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
# Each tuple is (glob_pattern_under_tools, origin_name).
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


def _find_root(start: Path | None = None) -> Path:
    """Walk up from *start* (or cwd) to find rebrew-project.toml.

    Since rebrew is an installable package, __file__ may point into
    site-packages rather than the project directory.  We therefore
    search from the current working directory upward, similar to how
    ``git`` locates ``.git/``.
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

_KNOWN_TOP_KEYS = {"targets", "compiler", "project"}

_KNOWN_TARGET_KEYS = {
    "binary",
    "arch",
    "format",
    "marker",
    "origins",
    "reversed_dir",
    "function_list",
    "bin_dir",
    "compiler",
    "cflags_presets",
    "default_origin",
    "origin_prefixes",
    "r2_bogus_vas",
    "game_range_end",
    "iat_thunks",
    "dll_exports",
    "zlib_vas",
    "ignored_symbols",
    "library_origins",
    "origin_comments",
    "origin_todos",
    "crt_sources",
    "source_ext",
    "ghidra_program_path",
}

_KNOWN_COMPILER_KEYS = {
    "command",
    "runner",
    "includes",
    "libs",
    "cflags",
    "profile",
    "cflags_presets",
    "profiles",
    "origins",
    "base_cflags",
    "timeout",
}

_KNOWN_PROJECT_KEYS = {
    "name",
    "jobs",
    "db_dir",
    "output_dir",
}

_KNOWN_ORIGIN_COMPILER_KEYS = {
    "command",
    "runner",
    "includes",
    "libs",
    "cflags",
    "profile",
    "base_cflags",
    "timeout",
}

_KNOWN_FORMATS = {"pe", "elf", "macho"}
_KNOWN_PROFILES = {"msvc6", "msvc7", "gcc", "clang"}


def load_config(
    root: Path | None = None,
    target: str | None = None,
) -> ProjectConfig:
    """Load rebrew-project.toml.

    Args:
        root: Project root directory.  Auto-detected if ``None``.
        target: Name of the target to load (key under ``[targets]``).
                Defaults to the first target defined in the file.
    """
    root = _find_root(root)
    toml_path = root / "rebrew-project.toml"
    if not toml_path.exists():
        raise FileNotFoundError(f"Config not found: {toml_path}")

    with toml_path.open("rb") as f:
        raw = tomllib.load(f)

    # --- Validate known keys to catch typos ---
    unknown_top = set(raw) - _KNOWN_TOP_KEYS
    if unknown_top:
        _config_warn(
            f"rebrew-project.toml: unrecognized top-level keys: {unknown_top}",
        )
    for sec_name, known_keys in (
        ("compiler", _KNOWN_COMPILER_KEYS),
        ("project", _KNOWN_PROJECT_KEYS),
    ):
        sec = raw.get(sec_name, {})
        if isinstance(sec, dict):
            unknown_sec = set(sec) - known_keys
            if unknown_sec:
                _config_warn(
                    f"rebrew-project.toml [{sec_name}]: unrecognized keys: {unknown_sec}",
                )
    for tgt_name, tgt_data in raw.get("targets", {}).items():
        if isinstance(tgt_data, dict):
            unknown_tgt = set(tgt_data) - _KNOWN_TARGET_KEYS
            if unknown_tgt:
                _config_warn(
                    f"rebrew-project.toml [targets.{tgt_name}]: unrecognized keys: {unknown_tgt}",
                )

    for scope, origins_dict in (
        ("compiler", raw.get("compiler", {}).get("origins", {})),
        *(
            (
                f"targets.{tn}.compiler",
                raw.get("targets", {}).get(tn, {}).get("compiler", {}).get("origins", {}),
            )
            for tn in raw.get("targets", {})
        ),
    ):
        if isinstance(origins_dict, dict):
            for origin_name, origin_vals in origins_dict.items():
                if isinstance(origin_vals, dict):
                    unknown_origin = set(origin_vals) - _KNOWN_ORIGIN_COMPILER_KEYS
                    if unknown_origin:
                        _config_warn(
                            f"rebrew-project.toml [{scope}.origins.{origin_name}]: "
                            f"unrecognized keys: {unknown_origin}",
                        )

    targets_dict = raw.get("targets", {})
    if not targets_dict:
        raise KeyError("rebrew-project.toml has no [targets] section")
    all_target_names = [k for k in targets_dict if isinstance(k, str)]
    if not all_target_names:
        raise KeyError("rebrew-project.toml [targets] section has no valid target names")

    global_compiler_raw = raw.get("compiler", {})
    global_compiler = {
        k: v
        for k, v in global_compiler_raw.items()
        if k not in ("cflags_presets", "profiles", "origins")
    }

    compiler_profiles = global_compiler_raw.get("profiles", {})
    global_origins = global_compiler_raw.get("origins", {})

    if target is None:
        target = all_target_names[0]
    if target not in targets_dict:
        raise KeyError(
            f"Target '{target}' not found in rebrew-project.toml.  Available targets: {all_target_names}"
        )
    tgt = targets_dict[target]
    target_compiler_raw = tgt.get("compiler", {})
    target_compiler = {k: v for k, v in target_compiler_raw.items() if k not in ("origins",)}
    target_origins = target_compiler_raw.get("origins", {})
    compiler = {**global_compiler, **target_compiler}
    compiler_runner, compiler_command = _split_compiler_runner(compiler)

    # Merge per-origin compiler overrides: global → per-target
    merged_origin_compiler: dict[str, dict[str, str]] = {}
    for origin_key in sorted(set(global_origins) | set(target_origins)):
        merged_values = {
            **global_origins.get(origin_key, {}),
            **target_origins.get(origin_key, {}),
        }
        origin_runner, origin_command = _split_compiler_runner(merged_values)
        if "runner" not in merged_values and origin_runner:
            merged_values["runner"] = origin_runner
            merged_values["command"] = origin_command
        merged_origin_compiler[origin_key] = {str(k): str(v) for k, v in merged_values.items()}
    sources = tgt

    # --- Validate value types for known fields ---
    fmt_val = tgt.get("format", "pe")
    if fmt_val not in _KNOWN_FORMATS:
        _config_warn(
            f"rebrew-project.toml [targets.{target}]: unknown format '{fmt_val}' "
            f"(known: {', '.join(sorted(_KNOWN_FORMATS))})",
        )

    arch_name = str(tgt.get("arch", "x86_32"))
    if arch_name not in _ARCH_PRESETS:
        _config_warn(
            f"rebrew-project.toml [targets.{target}]: unknown arch '{arch_name}' "
            f"(known: {', '.join(sorted(_ARCH_PRESETS))}); falling back to x86_32",
        )

    profile_val = compiler.get("profile", "msvc6")
    if profile_val not in _KNOWN_PROFILES:
        _config_warn(
            f"rebrew-project.toml [compiler]: unknown profile '{profile_val}' "
            f"(known: {', '.join(sorted(_KNOWN_PROFILES))})",
        )

    arch_preset = _ARCH_PRESETS.get(arch_name, _ARCH_PRESETS["x86_32"])
    bin_rel = tgt.get("binary")
    if bin_rel is None:
        raise KeyError(f"Target '{target}' in rebrew-project.toml is missing 'binary' path")
    resolved_bin = _resolve(root, bin_rel)
    if resolved_bin is None:
        raise KeyError(f"Target '{target}' in rebrew-project.toml has invalid 'binary' path")
    bin_path: Path = resolved_bin

    project_raw = raw.get("project", {})

    # _resolve() never returns None here: .get() always supplies a non-None default.
    reversed_dir = _resolve(root, sources.get("reversed_dir", f"src/{target}"))
    if reversed_dir is None:  # pragma: no cover — always has non-None default
        raise ValueError(f"Failed to resolve reversed_dir for target '{target}'")
    function_list = _resolve(root, sources.get("function_list", f"src/{target}/functions.txt"))
    if function_list is None:  # pragma: no cover
        raise ValueError(f"Failed to resolve function_list for target '{target}'")
    bin_dir = _resolve(root, sources.get("bin_dir", f"bin/{target}"))
    if bin_dir is None:  # pragma: no cover
        raise ValueError(f"Failed to resolve bin_dir for target '{target}'")
    db_dir = _resolve(root, project_raw.get("db_dir", "db"))
    if db_dir is None:  # pragma: no cover
        raise ValueError("Failed to resolve db_dir")
    output_dir = _resolve(root, project_raw.get("output_dir", "output"))
    if output_dir is None:  # pragma: no cover
        raise ValueError("Failed to resolve output_dir")
    compiler_includes = _resolve(root, compiler.get("includes", "tools/MSVC600/VC98/Include"))
    if compiler_includes is None:  # pragma: no cover
        raise ValueError("Failed to resolve compiler includes path")
    compiler_libs = _resolve(root, compiler.get("libs", "tools/MSVC600/VC98/Lib"))
    if compiler_libs is None:  # pragma: no cover
        raise ValueError("Failed to resolve compiler libs path")

    # Merge cflags_presets: global first, then per-target overrides
    merged_presets = {
        **global_compiler_raw.get("cflags_presets", {}),
        **tgt.get("cflags_presets", {}),
    }

    cfg = ProjectConfig(
        root=root,
        target_name=target or "",
        # target
        target_binary=bin_path,
        binary_format=tgt.get("format", "pe"),
        arch=arch_name,
        # sources
        reversed_dir=reversed_dir,
        function_list=function_list,
        bin_dir=bin_dir,
        marker=tgt.get("marker", target.upper()),
        origins=_parse_str_list(tgt.get("origins", []), "origins"),
        default_origin=tgt.get("default_origin", ""),
        origin_prefixes=tgt.get("origin_prefixes", {}),
        r2_bogus_vas=_parse_int_list(tgt.get("r2_bogus_vas", []), "r2_bogus_vas"),
        # project-level defaults
        project_name=project_raw.get("name", ""),
        default_jobs=project_raw.get("jobs", 4),
        db_dir=db_dir,
        output_dir=output_dir,
        # compiler
        compiler_profile=compiler.get("profile", "msvc6"),
        compiler_command=compiler_command,
        compiler_runner=compiler_runner,
        compiler_includes=compiler_includes,
        compiler_libs=compiler_libs,
        cflags=compiler.get("cflags", ""),
        base_cflags=compiler.get("base_cflags", "/nologo /c /MT"),
        compile_timeout=_safe_int(compiler.get("timeout", 60), 60),
        # arch-derived
        pointer_size=arch_preset["pointer_size"],
        padding_bytes=arch_preset["padding_bytes"],
        symbol_prefix=arch_preset["symbol_prefix"],
        # project-specific
        game_range_end=tgt.get("game_range_end"),
        iat_thunks=_parse_int_list(tgt.get("iat_thunks", []), "iat_thunks"),
        dll_exports=_parse_hex_dict(tgt.get("dll_exports", {})),
        cflags_presets=merged_presets,
        zlib_vas=_parse_int_list(tgt.get("zlib_vas", []), "zlib_vas"),
        ignored_symbols=_parse_str_list(tgt.get("ignored_symbols", []), "ignored_symbols"),
        compiler_profiles=compiler_profiles,
        origin_compiler=merged_origin_compiler,
        library_origins=set(_parse_str_list(tgt.get("library_origins", []), "library_origins")),
        origin_comments=tgt.get("origin_comments", {}),
        origin_todos=tgt.get("origin_todos", {}),
        crt_sources=tgt.get("crt_sources", {}),
        source_ext=tgt.get("source_ext", ".c"),
        ghidra_program_path=tgt.get("ghidra_program_path", ""),
        # all targets
        all_targets=all_target_names,
    )

    # Default library_origins: all origins except the first (primary/FUNCTION origin)
    if not cfg.library_origins and len(cfg.origins) > 1:
        cfg.library_origins = set(cfg.origins[1:])

    # Auto-detect CRT sources if not explicitly configured
    if not cfg.crt_sources:
        cfg.crt_sources = detect_crt_sources(root)

    # Auto-detect binary layout if the binary exists
    if cfg.target_binary.exists():
        layout = _detect_binary_layout(cfg.target_binary, fmt=cfg.binary_format)
        cfg.image_base = layout["image_base"]
        cfg.text_va = layout["text_va"]
        cfg.text_raw_offset = layout["text_raw_offset"]

    return cfg
