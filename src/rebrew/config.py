"""Centralised project configuration loader for rebrew.

Reads ``rebrew.toml`` from the project root and exposes every setting as
simple attributes so that tool scripts no longer need to hardcode paths,
image-base addresses, or compiler flags.

The configuration supports **multiple targets** (similar to reccmp-project.yml).
Each target has its own binary, source directory, and function list.  Compiler
settings are shared across all targets.

Usage in any tool::

    from rebrew.config import cfg

    dll_path = cfg.target_binary        # Path object
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
from typing import Dict, List, Optional

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

_ARCH_PRESETS: Dict[str, dict] = {
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

    # --- [compiler] (shared across targets) ---
    compiler_profile: str = "msvc6"
    compiler_command: str = "wine CL.EXE"
    compiler_includes: Path = field(default_factory=lambda: Path())
    compiler_libs: Path = field(default_factory=lambda: Path())

    # --- Computed from arch ---
    pointer_size: int = 4
    padding_bytes: List[int] = field(default_factory=lambda: [0xCC, 0x90])
    symbol_prefix: str = "_"

    # --- PE-specific (computed at load time if format == "pe") ---
    image_base: int = 0
    text_va: int = 0
    text_raw_offset: int = 0

    # --- All known target names ---
    all_targets: List[str] = field(default_factory=list)

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
        import os
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


def _resolve(root: Path, rel: str) -> Path:
    """Resolve a path relative to project root."""
    p = Path(rel)
    if p.is_absolute():
        return p
    return root / p


def _detect_pe_layout(dll_path: Path) -> dict:
    """Read image base and .text section from PE headers."""
    try:
        import pefile
        pe = pefile.PE(str(dll_path), fast_load=True)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        text_va = image_base
        text_raw = 0
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode(errors="replace")
            if name == ".text":
                text_va = image_base + sec.VirtualAddress
                text_raw = sec.PointerToRawData
                break
        pe.close()
        return {"image_base": image_base, "text_va": text_va, "text_raw_offset": text_raw}
    except Exception:
        return {"image_base": 0, "text_va": 0, "text_raw_offset": 0}


def _find_root(start: Optional[Path] = None) -> Path:
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
    root: Optional[Path] = None,
    target: Optional[str] = None,
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

    compiler = raw.get("compiler", {})

    # --- Resolve target section (multi-target or legacy) ---
    targets_dict = raw.get("targets", {})
    all_target_names = list(targets_dict.keys())

    if targets_dict:
        # Multi-target format: [targets.<name>]
        if target is None:
            # Default to first target
            target = all_target_names[0]
        if target not in targets_dict:
            raise KeyError(
                f"Target '{target}' not found in rebrew.toml.  "
                f"Available targets: {all_target_names}"
            )
        tgt = targets_dict[target]
        # Sources are per-target in multi-target format
        sources = tgt
    elif "target" in raw:
        # Legacy single-target format: [target] + [sources]
        tgt = raw["target"]
        sources = raw.get("sources", {})
        target = tgt.get("binary", "default").replace("/", "_").replace(".", "_")
        all_target_names = [target]
    else:
        raise KeyError("rebrew.toml has no [targets] or [target] section")

    arch_name = tgt.get("arch", "x86_32")
    arch_preset = _ARCH_PRESETS.get(arch_name, _ARCH_PRESETS["x86_32"])
    dll_path = _resolve(root, tgt.get("binary", "original/Server/server.dll"))

    cfg = ProjectConfig(
        root=root,
        target_name=target,
        # target
        target_binary=dll_path,
        binary_format=tgt.get("format", "pe"),
        arch=arch_name,
        # sources (from target section in multi-target, or [sources] in legacy)
        reversed_dir=_resolve(root, sources.get("reversed_dir", "src/server_dll")),
        function_list=_resolve(root, sources.get("function_list", "src/server_dll/r2_functions.txt")),
        bin_dir=_resolve(root, sources.get("bin_dir", "bin/server_dll")),
        # compiler
        compiler_profile=compiler.get("profile", "msvc6"),
        compiler_command=compiler.get("command", "wine CL.EXE"),
        compiler_includes=_resolve(root, compiler.get("includes", "tools/MSVC600/VC98/Include")),
        compiler_libs=_resolve(root, compiler.get("libs", "tools/MSVC600/VC98/Lib")),
        # arch-derived
        pointer_size=arch_preset["pointer_size"],
        padding_bytes=arch_preset["padding_bytes"],
        symbol_prefix=arch_preset["symbol_prefix"],
        # all targets
        all_targets=all_target_names,
    )

    # Auto-detect PE layout if the binary exists
    if cfg.binary_format == "pe" and cfg.target_binary.exists():
        pe_info = _detect_pe_layout(cfg.target_binary)
        cfg.image_base = pe_info["image_base"]
        cfg.text_va = pe_info["text_va"]
        cfg.text_raw_offset = pe_info["text_raw_offset"]

    return cfg


# ---------------------------------------------------------------------------
# Module-level singleton — imported as ``from rebrew.config import cfg``
# ---------------------------------------------------------------------------

try:
    cfg = load_config()
except FileNotFoundError:
    # Graceful fallback: let scripts that don't need config still import
    cfg = None  # type: ignore[assignment]
