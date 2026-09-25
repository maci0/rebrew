"""compile_overrides.py — resolve effective toolchain + CFLAGS for a source.

Domain resolution for the compiler/flags fallback chain (per-function
metadata → nearest ``rebrew-libraries.toml`` → project defaults).  Lives
outside :mod:`rebrew.cli` so library code (``compile``, ``verify``,
``match``, …) does not depend on the CLI transport layer for a pure
config decision.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rebrew.config import ProjectConfig
from rebrew.utils import preset_module_key


def resolve_cflags(
    cfg: ProjectConfig | None, per_function_cflags: str | None, module: str = ""
) -> str:
    """Resolve the effective CFLAGS for a function.

    Fallback chain: per-function metadata CFLAGS → per-module
    ``cflags_presets`` (``rebrew cfg set-cflags``) → ``[compiler].cflags``
    → ``"/O2 /Gd"``.  Single source of truth so match/diff/verify/test/
    prove/probe/gap-trace agree on the flags a function compiles with — a per-module preset
    must not make ``rebrew match`` report EXACT while ``rebrew verify``
    recompiles with different flags and demotes it.
    """
    cflags = (per_function_cflags or "").strip()
    if not cflags and cfg is not None:
        cflags = getattr(cfg, "cflags_presets", {}).get(preset_module_key(module), "")
    if not cflags:
        cfg_cflags = getattr(cfg, "cflags", "") if cfg is not None else ""
        # An EXPLICITLY set empty cflags means "no default flags": the
        # /O2 /Gd fallback applies only when the key is absent.
        if not (cfg is not None and getattr(cfg, "cflags_explicit", False)):
            # The /O2 /Gd fallback is MSVC-only: gcc/watcom/tcc reject "/O2"
            # as a nonexistent input file.  Posix-style profiles fall back to
            # no user flags instead — mirroring the base_cflags loader
            # default in config.py, which fixed this same bug class there.
            msvc_default = "" if getattr(cfg, "posix_style", False) else "/O2 /Gd"
            cfg_cflags = cfg_cflags or msvc_default
        cflags = cfg_cflags
    return cflags


def resolve_overrides_steps(
    cfg: ProjectConfig | None,
    source_dir: str | Path,
    per_function_toolchain: str | None,
    per_function_cflags: str | None,
    module: str = "",
) -> tuple[str | None, str, list[dict[str, Any]]]:
    """Resolve the effective (toolchain, cflags) and record the decision chain.

    Core of :func:`resolve_compile_overrides` — same fallback chain, plus a
    list of *steps* documenting every decision point so ``rebrew diagnose``
    can explain *why* a function compiles with the compiler+flags it does.
    Each step is a dict with a ``source`` key: ``"function"`` (per-function
    metadata), ``"library"`` (nearest ``rebrew-libraries.toml`` + presets), or
    ``"project"`` (project defaults and which fallbacks applied).
    """
    steps: list[dict[str, Any]] = []
    toolchain = (per_function_toolchain or "").strip() or None
    cflags = (per_function_cflags or "").strip()
    steps.append({"source": "function", "toolchain": toolchain or "", "cflags": cflags})
    if toolchain is None or not cflags:
        from rebrew.metadata import find_library_override

        root = getattr(cfg, "root", None) if cfg is not None else None
        ovr = find_library_override(source_dir, root)
        if ovr is not None:
            if toolchain is None and ovr.toolchain:
                toolchain = ovr.toolchain
            if not cflags and ovr.cflags:
                cflags = ovr.cflags
            steps.append(
                {
                    "source": "library",
                    "path": str(ovr.path),
                    "toolchain": ovr.toolchain,
                    "cflags": ovr.cflags,
                    "presets": list(ovr.presets),
                }
            )
        else:
            steps.append({"source": "library", "path": None})
    final_cflags = resolve_cflags(cfg, cflags or None, module)
    steps.append(
        {
            "source": "project",
            "profile": getattr(cfg, "compiler_profile", "") if cfg is not None else "",
            "cflags": getattr(cfg, "cflags", "") if cfg is not None else "",
            "cflags_explicit": bool(getattr(cfg, "cflags_explicit", False))
            if cfg is not None
            else False,
            "posix_style": bool(getattr(cfg, "posix_style", False)) if cfg is not None else False,
            "module_preset": (
                getattr(cfg, "cflags_presets", {}).get(preset_module_key(module), "")
                if cfg is not None
                else ""
            ),
        }
    )
    return toolchain, final_cflags, steps


def resolve_compile_overrides(
    cfg: ProjectConfig | None,
    source_dir: str | Path,
    per_function_toolchain: str | None,
    per_function_cflags: str | None,
    module: str = "",
) -> tuple[str | None, str]:
    """Resolve the effective (toolchain, cflags) for one source file.

    Fallback chain, most specific first:

    1. per-function metadata (rebrew-functions.toml TOOLCHAIN / CFLAGS),
    2. the nearest per-library ``rebrew-libraries.toml`` (walk-up from
       *source_dir*; its known-library presets fill missing fields),
    3. project defaults (``[compiler]`` profile/cflags via ``resolve_cflags``).

    This is the single source of truth so verify / test / match / prove all
    compile every function of a library with the same compiler + flags.
    Returns ``(toolchain, cflags)`` — toolchain is ``None`` when no override
    names a compiler (project default profile applies).
    """
    toolchain, cflags, _steps = resolve_overrides_steps(
        cfg, source_dir, per_function_toolchain, per_function_cflags, module
    )
    return toolchain, cflags
