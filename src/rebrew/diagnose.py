"""diagnose.py — `rebrew diagnose`: explain the compile-config resolution.

For each function in a source file, prints the declared-dependency chain
that determined its toolchain + CFLAGS:

    per-function metadata (rebrew-functions.toml / annotations)
      → nearest rebrew-libraries.toml (walk-up, presets applied)
      → project defaults ([compiler] profile + cflags fallbacks)

and validates the declarations along the chain — an unknown toolchain name,
a library preset contradicted by the resolved toolchain, or a per-function
toolchain whose family disagrees with the enclosing library's.  The chain is
acyclic by construction (a function resolves toward the project root; no
declaration references another), so "cycle" failures cannot arise; what the
paper's model calls a dependency conflict appears here as a declaration
warning instead.

This mirrors :func:`rebrew.cli.resolve_compile_overrides` step for step via
its ``_resolve_overrides_steps`` core, so the trace can never drift from
what verify/test/match/prove actually compile with.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from rebrew.annotation import parse_c_file_multi
from rebrew.cli import (
    TargetOption,
    error_exit,
    json_print,
    require_config,
    resolve_source_arg,
)
from rebrew.config import ProjectConfig
from rebrew.sources import iter_sources

console = Console(stderr=True)

app = typer.Typer(
    help="Explain why a function compiles with its toolchain+flags (resolution trace).",
    rich_markup_mode="rich",
)


def _warnings_for(steps: list[dict[str, Any]], effective_toolchain: str | None) -> list[str]:
    """Validate the declarations in a resolution chain.

    Returns human-readable warnings; an empty list means the declarations
    are consistent.  Unknown toolchain names, a library preset contradicted
    by the resolved toolchain, and a per-function toolchain whose family
    disagrees with the enclosing library's are each reported."""
    warnings: list[str] = []
    from rebrew.metadata import all_library_presets
    from rebrew.toolchain import TOOLCHAINS

    func_step = next((s for s in steps if s["source"] == "function"), None)
    lib_step = next((s for s in steps if s["source"] == "library" and s.get("path")), None)

    func_tc = (func_step or {}).get("toolchain") or ""
    lib_tc = (lib_step or {}).get("toolchain") or ""
    for label, name in (("function metadata", func_tc), ("library", lib_tc)):
        if name and name not in TOOLCHAINS:
            warnings.append(
                f"{label} declares unknown toolchain {name!r} "
                f"(known: {', '.join(sorted(TOOLCHAINS))})"
            )

    if lib_step and lib_step.get("presets"):
        preset = str(lib_step["presets"][0])
        expected = all_library_presets().get(preset, {}).get("toolchain", "")
        resolved = effective_toolchain or ""
        if expected and resolved and resolved != expected:
            warnings.append(
                f"library preset {preset!r} expects toolchain {expected!r} but the "
                f"resolved toolchain is {resolved!r} — the preset's flags may not be "
                f"valid for it (conflicting declarations)"
            )

    if func_tc and lib_tc:
        fspec = TOOLCHAINS.get(func_tc)
        lspec = TOOLCHAINS.get(lib_tc)
        if fspec is not None and lspec is not None and fspec.family != lspec.family:
            warnings.append(
                f"function pinned to {func_tc!r} (family {fspec.family}) inside a "
                f"library declaring {lib_tc!r} (family {lspec.family}) — possible drift"
            )
    return warnings


def diagnose_source(cfg: ProjectConfig, source: Path) -> dict[str, Any]:
    """The full resolution trace + validation for one source file.

    Walks every function annotation in *source* (metadata merged), resolves
    each through the shared fallback chain, and validates the declarations.
    A file with no annotations still reports the project-default chain."""
    from rebrew.cli import _resolve_overrides_steps

    annos = parse_c_file_multi(source, metadata_dir=cfg.metadata_dir)
    functions: list[dict[str, Any]] = []
    for anno in annos:
        toolchain, cflags, steps = _resolve_overrides_steps(
            cfg,
            source.parent,
            getattr(anno, "toolchain", "") or None,
            getattr(anno, "cflags", "") or None,
            getattr(anno, "module", ""),
        )
        effective_toolchain = toolchain or getattr(cfg, "compiler_profile", "")
        functions.append(
            {
                "va": getattr(anno, "va", None),
                "module": getattr(anno, "module", ""),
                "steps": steps,
                "effective": {
                    "toolchain": effective_toolchain,
                    "cflags": cflags,
                },
                "warnings": _warnings_for(steps, toolchain),
            }
        )
    if not functions:
        toolchain, cflags, steps = _resolve_overrides_steps(cfg, source.parent, None, None, "")
        functions.append(
            {
                "va": None,
                "module": "",
                "steps": steps,
                "effective": {
                    "toolchain": toolchain or getattr(cfg, "compiler_profile", ""),
                    "cflags": cflags,
                },
                "warnings": _warnings_for(steps, toolchain),
            }
        )
    return {"source": str(source), "functions": functions}


def _print_trace(entry: dict[str, Any]) -> None:
    """Human-readable rendering of one source file's resolution trace."""
    console.print(f"[bold]{entry['source']}[/bold]")
    for fn in entry["functions"]:
        if fn["va"] is not None:
            console.print(f"  [cyan]0x{fn['va']:08x}[/cyan]  ({fn['module']})")
        for step in fn["steps"]:
            if step["source"] == "function":
                tc = step["toolchain"] or "(inherit)"
                cf = step["cflags"] or "(inherit)"
                console.print(f"    function metadata:  toolchain={tc}  cflags={cf}")
            elif step["source"] == "library":
                if step.get("path"):
                    presets = f"  presets={step['presets']}" if step.get("presets") else ""
                    console.print(
                        f"    library {step['path']}:  toolchain={step['toolchain'] or '(inherit)'}"
                        f"  cflags={step['cflags'] or '(inherit)'}{presets}"
                    )
                else:
                    console.print("    library:            (no rebrew-libraries.toml found)")
            else:  # project
                mod_preset = (
                    f"  module preset={step['module_preset']!r}" if step["module_preset"] else ""
                )
                eff = fn["effective"]
                fallback_applied = (
                    not step["cflags_explicit"]
                    and not step["cflags"]
                    and not step["module_preset"]
                    and eff["cflags"] == "/O2 /Gd"
                )
                note = (
                    "  (cflags key absent → /O2 /Gd fallback applied)" if fallback_applied else ""
                )
                console.print(
                    f"    project default:    profile={step['profile']}  cflags={step['cflags']!r}"
                    f"{note}{mod_preset}"
                )
        eff = fn["effective"]
        console.print(
            f"    [bold]effective:[/bold] toolchain={eff['toolchain']}  cflags={eff['cflags']}"
        )
        for warn in fn["warnings"]:
            console.print(f"    [yellow]warning:[/yellow] {warn}")
        if not fn["warnings"]:
            console.print("    [green]declarations consistent[/green]")


@app.callback(invoke_without_command=True)
def main(
    source_arg: str = typer.Argument(
        ..., help="Source file, directory, symbol name, or hex VA (0x…)"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Print the toolchain+flags resolution chain for one or more functions."""
    cfg = require_config(target=target)
    p = Path(source_arg)
    if p.is_dir():
        sources = sorted(iter_sources(p, cfg))
        if not sources:
            error_exit(f"no source files found under {p}", json_mode=json_output)
    else:
        resolved = resolve_source_arg(cfg, source_arg)
        if not resolved.exists():
            error_exit(f"no such source: {source_arg}", json_mode=json_output)
        sources = [resolved]
    results = [diagnose_source(cfg, src) for src in sources]
    if json_output:
        json_print({"sources": results})
        return
    for entry in results:
        _print_trace(entry)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
