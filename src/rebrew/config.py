"""Centralised project configuration loader for rebrew.

Reads ``rebrew.toml`` from the project root and exposes every setting as
simple attributes so that tool scripts no longer need to hardcode paths,
image-base addresses, or compiler flags.

The configuration supports **multiple targets** (similar to reccmp-project.yml).
Each target has its own binary, source directory, and function list.  Compiler
settings are shared across all targets.

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

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import]
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[import,no-redef]

# ---------------------------------------------------------------------------
# Architecture presets
# ---------------------------------------------------------------------------

_ARCH_PRESETS: dict[str, dict] = {
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

    # Root directory (where rebrew.toml lives)
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
    marker: str = "SERVER"  # Prefix used in annotations, e.g. // FUNCTION: SERVER 0x...
    origins: list[str] = field(default_factory=list)  # Valid ORIGIN values, e.g. ["GAME", "ZLIB"]

    # --- compiler ---
    compiler_profile: str = "msvc6"
    compiler_command: str = "wine CL.EXE"
    compiler_includes: Path = field(default_factory=lambda: Path())
    compiler_libs: Path = field(default_factory=lambda: Path())
    cflags: str = ""  # Default compiler flags (from [compiler] or per-target override)

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
    compiler_profiles: dict[str, dict] = field(default_factory=dict)  # e.g. {"clang": {...}}

    # --- All known target names ---
    all_targets: list[str] = field(default_factory=list)

    @property
    def capstone_arch(self):
        """Return capstone CS_ARCH_* constant."""
        import capstone
        name = _ARCH_PRESETS.get(self.arch, {}).get("capstone_arch", "CS_ARCH_X86")
        return getattr(capstone, name)

    @property
    def capstone_mode(self):
        """Return capstone CS_MODE_* constant."""
        import capstone
        name = _ARCH_PRESETS.get(self.arch, {}).get("capstone_mode", "CS_MODE_32")
        return getattr(capstone, name)

    def va_to_file_offset(self, va: int) -> int:
        """Convert VA to raw file offset using .text section constants."""
        return va - self.text_va + self.text_raw_offset

    def msvc_env(self) -> dict:
        """Return a subprocess env dict with MSVC6 VCVARS-equivalent variables.

        Sets INCLUDE, LIB, PATH (for DLL resolution), and WINEDEBUG=-all.
        This is the equivalent of running ``BIN/VCVARS32.BAT x86`` before
        invoking CL.EXE under Wine.
        """
        env = {**os.environ, "WINEDEBUG": "-all"}

        # Resolve paths relative to project root
        bin_dir = str(self.root / "tools" / "MSVC600" / "VC98" / "Bin")
        inc_dir = str(self.compiler_includes)
        lib_dir = str(self.compiler_libs)

        # Windows-style env vars consumed by CL.EXE
        env["INCLUDE"] = inc_dir
        env["LIB"] = lib_dir

        # Ensure Wine can find C1.DLL, C2.DLL etc. alongside CL.EXE
        existing_path = env.get("WINEPATH", "")
        env["WINEPATH"] = f"{bin_dir};{existing_path}" if existing_path else bin_dir
        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

        return env

    def extract_dll_bytes(self, va: int, size: int) -> bytes:
        """Read raw bytes from the target binary at a given VA."""
        with open(self.target_binary, "rb") as f:
            f.seek(self.va_to_file_offset(va))
            return f.read(size)


def _resolve(root: Path, rel: str | None) -> Path | None:
    """Resolve a path relative to project root.  Returns *None* if *rel* is ``None``."""
    if rel is None:
        return None
    p = Path(rel)
    if p.is_absolute():
        return p
    return root / p


def _detect_binary_layout(bin_path: Path, fmt: str = "auto") -> dict:
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
    except Exception:
        return {"image_base": 0, "text_va": 0, "text_raw_offset": 0}


# Backward-compatible alias
_detect_pe_layout = _detect_binary_layout


def _find_root(start: Path | None = None) -> Path:
    """Walk up from *start* (or cwd) to find rebrew.toml.

    Since rebrew is an installable package, __file__ may point into
    site-packages rather than the project directory.  We therefore
    search from the current working directory upward, similar to how
    ``git`` locates ``.git/``.
    """
    if start is not None:
        return start
    candidate = Path.cwd().resolve()
    while candidate != candidate.parent:
        if (candidate / "rebrew.toml").exists():
            return candidate
        candidate = candidate.parent
    raise FileNotFoundError(
        "Could not find rebrew.toml in any parent of the current directory. "
        "Run rebrew commands from within a project that contains rebrew.toml."
    )


def load_config(
    root: Path | None = None,
    target: str | None = None,
) -> ProjectConfig:
    """Load rebrew.toml.

    Args:
        root: Project root directory.  Auto-detected if ``None``.
        target: Name of the target to load (key under ``[targets]``).
                Defaults to the first target defined in the file.
                For backward compatibility, a single ``[target]`` section
                is also recognised as a legacy format.
    """
    root = _find_root(root)
    toml_path = root / "rebrew.toml"
    if not toml_path.exists():
        raise FileNotFoundError(f"Config not found: {toml_path}")

    with open(toml_path, "rb") as f:
        raw = tomllib.load(f)

    # --- Resolve target section (multi-target or legacy) ---
    targets_dict = raw.get("targets", {})
    all_target_names = list(targets_dict.keys())

    # Global compiler defaults — support both flat [compiler] and nested [compiler.preset]
    global_compiler_raw = raw.get("compiler", {})
    global_compiler = {k: v for k, v in global_compiler_raw.items()
                       if k not in ("cflags_presets", "profiles", "preset")}
    # Backward compat: merge [compiler.preset] into top-level
    if "preset" in global_compiler_raw:
        global_compiler = {**global_compiler, **global_compiler_raw["preset"]}

    # Compiler profiles (e.g. [compiler.profiles.clang])
    compiler_profiles = global_compiler_raw.get("profiles", {})
    # Backward compat: [compiler.profile."clang"] (old key)
    if not compiler_profiles:
        compiler_profiles = global_compiler_raw.get("profile", {})
        # Filter out string values (the "profile" key may hold the profile name)
        if isinstance(compiler_profiles, str):
            compiler_profiles = {}

    if targets_dict:
        # Multi-target format: [targets.<name>]
        if target is None:
            target = all_target_names[0]
        if target not in targets_dict:
            raise KeyError(
                f"Target '{target}' not found in rebrew.toml.  "
                f"Available targets: {all_target_names}"
            )
        tgt = targets_dict[target]
        # Merge target compiler overrides — support both flat and nested .preset
        target_compiler = tgt.get("compiler", {})
        if "preset" in target_compiler:
            target_compiler = {**target_compiler, **target_compiler["preset"]}
        compiler = {**global_compiler, **target_compiler}
        sources = tgt
    elif "target" in raw:
        # Legacy single-target format: [target] + [sources]
        tgt = raw["target"]
        sources = raw.get("sources", {})
        target = tgt.get("binary", "default").replace("/", "_").replace(".", "_")
        all_target_names = [target]
        compiler = global_compiler
    else:
        raise KeyError("rebrew.toml has no [targets] or [target] section")

    arch_name = tgt.get("arch", "x86_32")
    arch_preset = _ARCH_PRESETS.get(arch_name, _ARCH_PRESETS["x86_32"])
    bin_rel = tgt.get("binary")
    if bin_rel is None:
        raise KeyError(f"Target '{target}' in rebrew.toml is missing 'binary' path")
    bin_path = _resolve(root, bin_rel)

    # Merge cflags_presets: global first, then per-target overrides
    merged_presets = {
        **global_compiler_raw.get("cflags_presets", {}),
        **tgt.get("cflags_presets", {}),
    }

    cfg = ProjectConfig(
        root=root,
        target_name=target,
        # target
        target_binary=bin_path,
        binary_format=tgt.get("format", "pe"),
        arch=arch_name,
        # sources (from target section in multi-target, or [sources] in legacy)
        reversed_dir=_resolve(root, sources.get("reversed_dir")),
        function_list=_resolve(root, sources.get("function_list")),
        bin_dir=_resolve(root, sources.get("bin_dir")),
        marker=tgt.get("marker", "SERVER"),
        origins=tgt.get("origins", []),
        # compiler
        compiler_profile=compiler.get("profile", "msvc6"),
        compiler_command=compiler.get("command", "wine CL.EXE"),
        compiler_includes=_resolve(root, compiler.get("includes", "tools/MSVC600/VC98/Include")),
        compiler_libs=_resolve(root, compiler.get("libs", "tools/MSVC600/VC98/Lib")),
        cflags=compiler.get("cflags", ""),
        # arch-derived
        pointer_size=arch_preset["pointer_size"],
        padding_bytes=arch_preset["padding_bytes"],
        symbol_prefix=arch_preset["symbol_prefix"],
        # project-specific
        game_range_end=tgt.get("game_range_end"),
        iat_thunks=tgt.get("iat_thunks", []),
        dll_exports={int(k, 16) if k.startswith("0x") else int(k): v for k, v in tgt.get("dll_exports", {}).items()},
        cflags_presets=merged_presets,
        zlib_vas=tgt.get("zlib_vas", []),
        ignored_symbols=tgt.get("ignored_symbols", []),
        compiler_profiles=compiler_profiles,
        # all targets
        all_targets=all_target_names,
    )

    # Auto-detect binary layout if the binary exists
    if cfg.target_binary.exists():
        layout = _detect_binary_layout(cfg.target_binary, fmt=cfg.binary_format)
        cfg.image_base = layout["image_base"]
        cfg.text_va = layout["text_va"]
        cfg.text_raw_offset = layout["text_raw_offset"]

    return cfg



