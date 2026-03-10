"""rebrew cfg: Programmatic editor for rebrew-project.toml.

Uses tomlkit for format-preserving round-trip editing (comments,
ordering, and whitespace are retained).

Dotted key paths (e.g. ``targets.mygame.arch``) are resolved
using greedy longest-match so TOML keys that contain dots (like
target names) are handled correctly.

Usage::

    rebrew cfg list-targets
    rebrew cfg show [KEY]
    rebrew cfg set KEY VALUE
    rebrew cfg raw [--format toml]
    rebrew cfg path
    rebrew cfg add-target mygame --binary original/mygame
    rebrew cfg remove-target old_target
    rebrew cfg add-module ZLIB --target mygame
    rebrew cfg remove-module ZLIB --target mygame
    rebrew cfg set-cflags ZLIB "/O3" --target mygame
    rebrew cfg detect-crt [--write]
"""

import contextlib
import json
import shutil
from pathlib import Path
from typing import Any

import tomlkit
import typer
from rich.console import Console

from rebrew.binary_loader import detect_format_and_arch as _bl_detect_format_and_arch
from rebrew.cli import error_exit, json_print
from rebrew.config import _find_root as _config_find_root
from rebrew.utils import atomic_write_text

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_dotted_key(
    doc: dict[str, Any], key: str, *, create_missing: bool = False
) -> tuple[dict[str, Any], str, list[str]]:
    """Resolve a dotted key path against a TOML document, handling keys with dots.

    Uses greedy matching: at each level, tries the *longest* matching key first.
    For example, ``targets.mygame.arch`` resolves through the ``mygame``
    key under ``targets``, not through ``server`` then ``dll``.

    Args:
        doc: The TOML document (or nested table) to resolve against.
        key: Dot-separated key path, e.g. ``targets.mygame.arch``.
        create_missing: If ``True``, create intermediate tables that don't exist
            (used by ``set``).  If ``False``, error on missing keys.

    Returns:
        ``(parent, final_key, resolved_parts)`` where *parent* is the innermost
        table containing *final_key*, and *resolved_parts* is the decomposed
        key path (for display).

    """
    parts = key.split(".")
    current: Any = doc
    resolved: list[str] = []
    i = 0

    while i < len(parts) - 1:
        if not isinstance(current, dict):
            error_exit(f"Key '{'.'.join(resolved)}' is not a table; cannot descend further.")

        # Try longest match first (greedy): combine parts[i..j] and check
        matched = False
        for j in range(len(parts) - 1, i, -1):
            candidate = ".".join(parts[i:j])
            if candidate in current:
                resolved.append(candidate)
                current = current[candidate]
                i = j
                matched = True
                break

        if not matched:
            # Single-part key
            part = parts[i]
            if part in current:
                resolved.append(part)
                current = current[part]
            elif create_missing:
                resolved.append(part)
                current[part] = tomlkit.table()
                current = current[part]
            else:
                error_exit(
                    f"Key '{key}' not found (no match for '{part}' in '{'.'.join(resolved) or '<root>'}')."
                )
            i += 1

    final_key = parts[-1] if parts else key
    resolved.append(final_key)
    return current, final_key, resolved


def _find_root() -> Path:
    """Walk up from cwd to find rebrew-project.toml; exit with message on failure."""
    try:
        return _config_find_root()
    except FileNotFoundError:
        error_exit(
            "Could not find rebrew-project.toml in any parent directory.\n"
            "Run this command from within a rebrew project, or use 'rebrew init' first.",
        )
        raise AssertionError("unreachable")


def _load_toml(root: Path | None = None) -> tuple[tomlkit.TOMLDocument, Path]:
    """Load rebrew-project.toml as a tomlkit document, preserving formatting."""
    if root is None:
        root = _find_root()
    toml_path = root / "rebrew-project.toml"
    if not toml_path.exists():
        error_exit(f"{toml_path} not found.")
    doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
    return doc, toml_path


def _save_toml(doc: tomlkit.TOMLDocument, path: Path) -> None:
    """Write tomlkit document back, preserving formatting."""
    atomic_write_text(path, tomlkit.dumps(doc), encoding="utf-8")


def _resolve_target(doc: tomlkit.TOMLDocument, target: str | None) -> str:
    """Resolve a target name: use given name, or default to first target."""
    targets = doc.get("targets", {})
    if not targets:
        error_exit("No [targets] section in rebrew-project.toml.")
    if target is None:
        target = next(iter(targets))
    if target not in targets:
        error_exit(f"Target '{target}' not found. Available: {list(targets)}")
    return target


def _detect_format_and_arch(path: Path) -> tuple[str, str | None]:
    """Detect binary format and architecture from file header.

    CLI-friendly wrapper around :func:`rebrew.binary_loader.detect_format_and_arch`.
    Returns ``(format, arch)``; on ``OSError`` or ``ValueError`` prints a warning
    to stderr and defaults to ``("pe", None)`` instead of raising.
    """
    try:
        return _bl_detect_format_and_arch(path)
    except OSError:
        console.print(
            f"[yellow]Warning:[/] cannot read '{path}' for format detection, defaulting to PE"
        )
        return "pe", None
    except ValueError:
        console.print(
            f"[yellow]Warning:[/] unrecognized binary format for '{path}', defaulting to PE"
        )
        return "pe", None


# ---------------------------------------------------------------------------
# Typer app
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Read and edit rebrew-project.toml programmatically.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew cfg show compiler.command · · · · Read a config value\n\n"
        "  rebrew cfg set compiler.timeout 120 · · · Set a config value\n\n"
        "  rebrew cfg show targets.main.binary · · · Read target-specific setting\n\n"
        "  rebrew cfg raw · · · · · · · · · · · · · Dump rebrew-project.toml as JSON\n\n"
        "  rebrew cfg raw --format toml · · · · · · Dump as TOML\n\n"
        "  rebrew cfg path · · · · · · · · · · · · · Print path to rebrew-project.toml\n\n"
        "[dim]Useful for scripting and automation. Supports dotted key paths "
        "for nested TOML tables (e.g. 'targets.main.binary').[/dim]"
    ),
)


@app.command("list-targets")
def list_targets(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List all targets defined in rebrew-project.toml."""
    doc, _ = _load_toml()
    targets = doc.get("targets", {})
    if not targets:
        if json_output:
            json_print({"targets": []})
        else:
            console.print("No targets defined.")
        return
    if json_output:
        result = []
        for i, name in enumerate(targets):
            tgt = targets[name]
            result.append(
                {
                    "name": name,
                    "binary": tgt.get("binary", "?"),
                    "arch": tgt.get("arch", "?"),
                    "default": i == 0,
                }
            )
        json_print({"targets": result})
    else:
        for i, name in enumerate(targets):
            tgt = targets[name]
            binary = tgt.get("binary", "?")
            arch = tgt.get("arch", "?")
            marker = "→" if i == 0 else " "
            console.print(f"  {marker} {name}  ({arch}, {binary})")
        console.print("\n  [dim]→ = default target[/dim]")


@app.command("show")
def show(
    key: str | None = typer.Argument(
        None, help="Dot-separated key to show, e.g. 'compiler.cflags'"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Target name (for target-scoped keys)."
    ),
) -> None:
    """Show the current config, or a specific key."""
    doc, _ = _load_toml()

    if key is None:
        if json_output:
            import tomllib

            raw_doc = tomllib.loads(tomlkit.dumps(doc))
            json_print(raw_doc)
        else:
            print(tomlkit.dumps(doc))
        return

    # Resolve dotted key path (handles keys containing dots like target names)
    parent, final_key, _ = _resolve_dotted_key(doc, key)
    if not isinstance(parent, dict) or final_key not in parent:
        error_exit(f"Key '{key}' not found.", json_mode=json_output)
    current = parent[final_key]

    if json_output:
        import tomllib

        raw_val = tomllib.loads(tomlkit.dumps(current)) if isinstance(current, dict) else current
        json_print({"key": key, "value": raw_val})
    elif isinstance(current, (dict, list)):
        print(tomlkit.dumps(current) if isinstance(current, dict) else str(current))
    else:
        print(str(current))


@app.command("raw")
def raw(
    fmt: str = typer.Option("json", "--format", "-f", help="Output format: json, toml"),
) -> None:
    """Dump entire rebrew-project.toml as JSON or TOML (raw machine-readable output)."""
    doc, _ = _load_toml()
    if fmt == "toml":
        print(tomlkit.dumps(doc))
    else:
        # Default: JSON — convert tomlkit doc to plain dict for serialization
        import tomllib

        raw_doc = tomllib.loads(tomlkit.dumps(doc))
        print(json.dumps(raw_doc, indent=2, default=str))


@app.command("path")
def path_cmd() -> None:
    """Print the absolute path to rebrew-project.toml."""
    root = _find_root()
    print(str(root / "rebrew-project.toml"))


@app.command("add-target")
def add_target(
    name: str = typer.Argument(..., help="Target name (e.g. 'mygame')."),
    binary: str = typer.Option(..., "--binary", "-b", help="Path to the original binary."),
    arch: str | None = typer.Option(
        None,
        "--arch",
        "-a",
        help="Architecture: x86_32, x86_64, arm32, arm64 (auto-detected if omitted).",
    ),
    fmt: str | None = typer.Option(
        None, "--format", "-f", help="Binary format: pe, elf, macho (auto-detected if omitted)."
    ),
    origins: str | None = typer.Option(
        None,
        "--modules",
        help="Comma-separated module list (inherits from project or defaults to GAME).",
    ),
    source_ext: str | None = typer.Option(
        None,
        "--source-ext",
        help="Source file extension (e.g. .c, .cpp). Auto-detected from binary if omitted.",
    ),
    copy_binary: bool = typer.Option(True, "--copy/--no-copy", help="Copy binary into original/."),
) -> None:
    """Add a new target section to rebrew-project.toml (idempotent).

    Auto-detects binary format and architecture from file headers when not
    specified.  Origins and other defaults are inherited from the first
    existing target in the project if available.
    """
    root = _find_root()
    doc, toml_path = _load_toml(root)

    # Ensure [targets] exists
    targets = doc.get("targets")
    if targets is None:
        targets = tomlkit.table()
        doc["targets"] = targets

    # Idempotent: if target already exists, just ensure dirs exist and return
    if name in targets:
        console.print(f"[yellow]Target '{name}' already exists (no changes made).[/yellow]")
        (root / "src" / name).mkdir(parents=True, exist_ok=True)
        (root / "bin" / name).mkdir(parents=True, exist_ok=True)
        return

    binary_path = Path(binary)

    # Auto-detect format and arch from binary headers
    resolved = (root / binary_path) if not binary_path.is_absolute() else binary_path
    if resolved.exists():
        detected_fmt, detected_arch = _detect_format_and_arch(resolved)
    else:
        detected_fmt, detected_arch = "pe", None

    if fmt is None:
        fmt = detected_fmt
    if arch is None:
        arch = detected_arch or "x86_32"

    # Auto-detect source language from binary symbols
    detected_lang = "C"
    if source_ext is None:
        if resolved.exists():
            from rebrew.binary_loader import detect_source_language

            detected_lang, source_ext = detect_source_language(resolved)
        else:
            source_ext = ".c"

    # Inherit defaults from first existing target in the project
    first_target: Any = None
    if targets:
        first_key = next(iter(targets), None)
        if first_key:
            first_target = targets[first_key]

    if origins is None:
        if first_target and "origins" in first_target:
            origins = ",".join(first_target["origins"])
        else:
            origins = "GAME"

    # Copy binary if requested
    if copy_binary and binary_path.is_absolute() and binary_path.exists():
        original_dir = root / "original"
        original_dir.mkdir(exist_ok=True)
        dest = original_dir / binary_path.name
        if not dest.exists():
            shutil.copy2(binary_path, dest)
            console.print(f"  [green]Copied {binary_path.name} → original/[/green]")
        binary = f"original/{binary_path.name}"

    # Create directories
    src_dir = root / "src" / name
    src_dir.mkdir(parents=True, exist_ok=True)
    bin_dir = root / "bin" / name
    bin_dir.mkdir(parents=True, exist_ok=True)

    # Create empty function list
    func_list = src_dir / "functions.txt"
    func_list.touch(exist_ok=True)

    # Build target table
    tgt = tomlkit.table()
    tgt.add("binary", binary)
    tgt.add("format", fmt)
    tgt.add("arch", arch)
    tgt.add("reversed_dir", f"src/{name}")
    tgt.add("function_list", f"src/{name}/functions.txt")
    tgt.add("bin_dir", f"bin/{name}")
    tgt.add("source_ext", source_ext)

    # Parse origins
    origin_list = [o.strip() for o in origins.split(",") if o.strip()]
    tgt.add("origins", origin_list)

    targets[name] = tgt
    _save_toml(doc, toml_path)

    console.print(f'[green]Added [targets."{name}"] to rebrew-project.toml[/green]')
    console.print(f"[green]  Format: {fmt}, Arch: {arch} (auto-detected)[/green]")
    console.print(f"[green]  Language: {detected_lang} ({source_ext})[/green]")
    console.print(f"[green]  Created src/{name}/ and bin/{name}/[/green]")
    console.print(f'\nNext: rebrew next --target "{name}" --stats')


@app.command("remove-target")
def remove_target(
    name: str = typer.Argument(..., help="Target name to remove."),
) -> None:
    """Remove a target section from rebrew-project.toml (idempotent)."""
    doc, toml_path = _load_toml()
    targets = doc.get("targets", {})
    if name not in targets:
        console.print(f"[yellow]Target '{name}' not found (already removed).[/yellow]")
        return

    del targets[name]
    _save_toml(doc, toml_path)
    console.print(f'[green]Removed [targets."{name}"] from rebrew-project.toml[/green]')
    console.print("  [dim]Note: src/ and bin/ directories were NOT deleted.[/dim]")


@app.command("set")
def set_value(
    key: str = typer.Argument(
        ..., help="Dot-separated key, e.g. 'compiler.cflags' or 'targets.mygame.arch'."
    ),
    value: str = typer.Argument(..., help="Value to set."),
) -> None:
    """Set a scalar config key."""
    doc, toml_path = _load_toml()

    # Resolve dotted key path (creates intermediate tables as needed)
    parent, final_key, _ = _resolve_dotted_key(doc, key, create_missing=True)

    # Try to coerce value to int/float/bool
    parsed_value: str | int | float | bool = value
    if value.lower() in ("true", "false"):
        parsed_value = value.lower() == "true"
    else:
        try:
            parsed_value = int(value, 16) if value.startswith(("0x", "0X")) else int(value)
        except ValueError:
            with contextlib.suppress(ValueError):
                parsed_value = float(value)

    parent[final_key] = parsed_value
    _save_toml(doc, toml_path)
    console.print(f"[green]Set {key} = {parsed_value!r}[/green]")


@app.command("add-module")
def add_module(
    module: str = typer.Argument(..., help="Module name to add (e.g. 'ZLIB')."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name."),
) -> None:
    """Add a module to a target's origins list."""
    doc, toml_path = _load_toml()
    target = _resolve_target(doc, target)
    targets_table: Any = doc["targets"]
    tgt: Any = targets_table[target]

    origins = tgt.get("origins")
    if origins is None:
        origins = []
        tgt["origins"] = origins

    module_upper = module.upper()
    if module_upper in origins:
        console.print(f"[yellow]Module '{module_upper}' already exists in {target}.[/yellow]")
        return

    origins.append(module_upper)
    _save_toml(doc, toml_path)
    console.print(
        f"[green]Added module '{module_upper}' to {target}. Modules: {list(origins)}[/green]"
    )


@app.command("remove-module")
def remove_module(
    module: str = typer.Argument(..., help="Module name to remove."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name."),
) -> None:
    """Remove a module from a target's origins list (idempotent)."""
    doc, toml_path = _load_toml()
    target = _resolve_target(doc, target)
    targets_table: Any = doc["targets"]
    tgt: Any = targets_table[target]

    origins = tgt.get("origins")
    if origins is None or module.upper() not in origins:
        console.print(
            f"[yellow]Module '{module.upper()}' not in {target} (already removed).[/yellow]"
        )
        return

    origins.remove(module.upper())
    _save_toml(doc, toml_path)
    console.print(
        f"[green]Removed module '{module.upper()}' from {target}. Modules: {list(origins)}[/green]"
    )


@app.command("set-cflags")
def set_cflags(
    module: str = typer.Argument(..., help="Module/preset name (e.g. 'ZLIB', 'GAME')."),
    flags: str = typer.Argument(..., help="Compiler flags string (e.g. '/O3')."),
    target: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Target name (sets per-target preset). Omit to set global preset.",
    ),
) -> None:
    """Set cflags preset for a module."""
    doc, toml_path = _load_toml()

    if target is not None:
        # Per-target cflags_presets
        target = _resolve_target(doc, target)
        targets_table: Any = doc["targets"]
        tgt: Any = targets_table[target]
        presets = tgt.get("cflags_presets")
        if presets is None:
            presets = tomlkit.table()
            tgt["cflags_presets"] = presets
        presets[module.upper()] = flags
        scope = f'targets."{target}"'
    else:
        # Global cflags_presets
        compiler: Any = doc.get("compiler")
        if compiler is None:
            compiler = tomlkit.table()
            doc["compiler"] = compiler
        presets = compiler.get("cflags_presets")
        if presets is None:
            presets = tomlkit.table()
            compiler["cflags_presets"] = presets
        presets[module.upper()] = flags
        scope = "compiler"

    _save_toml(doc, toml_path)
    console.print(f'[green]Set {scope}.cflags_presets.{module.upper()} = "{flags}"[/green]')


@app.command("detect-crt")
def detect_crt(
    write: bool = typer.Option(
        False, "--write", "-w", help="Write detected paths into rebrew-project.toml."
    ),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Target to write crt_sources into (default: first target)."
    ),
) -> None:
    """Auto-detect CRT source directories from MSVC tools in the project tree."""
    from rebrew.config import detect_crt_sources

    root = _find_root()
    detected = detect_crt_sources(root)
    if not detected:
        console.print("[yellow]No CRT source directories found under tools/.[/yellow]")
        return

    for origin, rel_path in sorted(detected.items()):
        console.print(f"  {origin} → {rel_path}")

    if write:
        doc, toml_path = _load_toml(root)
        target_name = _resolve_target(doc, target)
        targets_table: Any = doc["targets"]
        tgt: Any = targets_table[target_name]

        crt_sources = tgt.get("crt_sources")
        if crt_sources is None:
            crt_sources = tomlkit.table()
            tgt["crt_sources"] = crt_sources

        written = 0
        for origin, rel_path in sorted(detected.items()):
            if origin not in crt_sources:
                crt_sources[origin] = rel_path
                written += 1

        if written:
            _save_toml(doc, toml_path)
            console.print(
                f'[green]Wrote {written} crt_sources entries to [targets."{target_name}"].[/green]'
            )
        else:
            console.print("[yellow]All detected paths already configured (no changes).[/yellow]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
