"""rebrew cfg: Programmatic editor for rebrew-project.toml.

Uses tomlkit for format-preserving round-trip editing (comments,
ordering, and whitespace are retained).

Usage::

    rebrew cfg list-targets
    rebrew cfg show [KEY]
    rebrew cfg add-target server.dll --binary original/server.dll
    rebrew cfg remove-target old_target
    rebrew cfg set compiler.cflags "/O2 /Gd"
    rebrew cfg add-origin ZLIB --target server.dll
    rebrew cfg remove-origin ZLIB --target server.dll
    rebrew cfg set-cflags ZLIB "/O3" --target server.dll
"""

import contextlib
import shutil
from pathlib import Path

import tomlkit
import typer

from rebrew.binary_loader import detect_format_and_arch as _bl_detect_format_and_arch
from rebrew.cli import error_exit
from rebrew.config import _find_root as _config_find_root
from rebrew.utils import atomic_write_text

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_root() -> Path:
    """Walk up from cwd to find rebrew-project.toml; exit with message on failure."""
    try:
        return _config_find_root()
    except FileNotFoundError:
        error_exit(
            "Could not find rebrew-project.toml in any parent directory.\n"
            "Run this command from within a rebrew project, or use 'rebrew init' first.",
        )


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


def _detect_format(path: Path) -> str:
    """Detect binary format from file header magic bytes.

    CLI-friendly wrapper: defaults to ``"pe"`` on errors instead of raising.
    """
    fmt, _ = _detect_format_and_arch(path)
    return fmt


def _detect_format_and_arch(path: Path) -> tuple[str, str | None]:
    """Detect binary format and architecture from file header.

    CLI-friendly wrapper around :func:`rebrew.binary_loader.detect_format_and_arch`.
    Returns ``(format, arch)``; on ``OSError`` or ``ValueError`` prints a warning
    to stderr and defaults to ``("pe", None)`` instead of raising.
    """
    try:
        return _bl_detect_format_and_arch(path)
    except OSError:
        typer.echo(
            f"Warning: cannot read '{path}' for format detection, defaulting to PE",
            err=True,
        )
        return "pe", None
    except ValueError:
        typer.echo(
            f"Warning: unrecognized binary format for '{path}', defaulting to PE",
            err=True,
        )
        return "pe", None


# ---------------------------------------------------------------------------
# Typer app
# ---------------------------------------------------------------------------

app = typer.Typer(
    help="Read and edit rebrew-project.toml programmatically.",
    rich_markup_mode="rich",
    epilog="""\
[bold]Examples:[/bold]

rebrew cfg get compiler.command            Read a config value

rebrew cfg set compiler.timeout 120        Set a config value

rebrew cfg get targets.main.binary         Read target-specific setting

rebrew cfg dump                            Dump entire rebrew-project.toml as JSON

rebrew cfg path                            Print path to rebrew-project.toml

[dim]Useful for scripting and automation. Supports dotted key paths
for nested TOML tables (e.g. 'targets.main.binary').[/dim]""",
)


@app.command("list-targets")
def list_targets() -> None:
    """List all targets defined in rebrew-project.toml."""
    doc, _ = _load_toml()
    targets = doc.get("targets", {})
    if not targets:
        typer.echo("No targets defined.")
        return
    for i, name in enumerate(targets):
        tgt = targets[name]
        binary = tgt.get("binary", "?")
        arch = tgt.get("arch", "?")
        marker = "→" if i == 0 else " "
        typer.echo(f"  {marker} {name}  ({arch}, {binary})")
    typer.secho("\n  → = default target", dim=True)


@app.command("show")
def show(
    key: str | None = typer.Argument(
        None, help="Dot-separated key to show, e.g. 'compiler.cflags'"
    ),
    target: str | None = typer.Option(
        None, "--target", "-t", help="Target name (for target-scoped keys)."
    ),
) -> None:
    """Show the current config, or a specific key."""
    doc, _ = _load_toml()

    if key is None:
        # Print the whole file
        typer.echo(tomlkit.dumps(doc))
        return

    # Navigate dot-separated key
    parts = key.split(".")
    current = doc
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            error_exit(f"Key '{key}' not found.")

    if isinstance(current, (dict, list)):
        typer.echo(tomlkit.dumps(current) if isinstance(current, dict) else str(current))
    else:
        typer.echo(str(current))


@app.command("add-target")
def add_target(
    name: str = typer.Argument(..., help="Target name (e.g. 'server.dll')."),
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
        "--origins",
        help="Comma-separated origin list (inherits from project or defaults to GAME).",
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
        typer.secho(f"Target '{name}' already exists (no changes made).", fg=typer.colors.YELLOW)
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
    first_target = None
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
            typer.secho(f"  Copied {binary_path.name} → original/", fg=typer.colors.GREEN)
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

    typer.secho(f'Added [targets."{name}"] to rebrew-project.toml', fg=typer.colors.GREEN)
    typer.secho(f"  Format: {fmt}, Arch: {arch} (auto-detected)", fg=typer.colors.GREEN)
    typer.secho(f"  Language: {detected_lang} ({source_ext})", fg=typer.colors.GREEN)
    typer.secho(f"  Created src/{name}/ and bin/{name}/", fg=typer.colors.GREEN)
    typer.echo(f'\nNext: rebrew next --target "{name}" --stats')


@app.command("remove-target")
def remove_target(
    name: str = typer.Argument(..., help="Target name to remove."),
) -> None:
    """Remove a target section from rebrew-project.toml (idempotent)."""
    doc, toml_path = _load_toml()
    targets = doc.get("targets", {})
    if name not in targets:
        typer.secho(f"Target '{name}' not found (already removed).", fg=typer.colors.YELLOW)
        return

    del targets[name]
    _save_toml(doc, toml_path)
    typer.secho(f'Removed [targets."{name}"] from rebrew-project.toml', fg=typer.colors.GREEN)
    typer.secho("  Note: src/ and bin/ directories were NOT deleted.", dim=True)


@app.command("set")
def set_value(
    key: str = typer.Argument(
        ..., help="Dot-separated key, e.g. 'compiler.cflags' or 'targets.server.dll.arch'."
    ),
    value: str = typer.Argument(..., help="Value to set."),
) -> None:
    """Set a scalar config key."""
    doc, toml_path = _load_toml()

    parts = key.split(".")
    current = doc
    for part in parts[:-1]:
        if part not in current:
            current[part] = tomlkit.table()
        current = current[part]

    final_key = parts[-1]

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

    current[final_key] = parsed_value
    _save_toml(doc, toml_path)
    typer.secho(f"Set {key} = {parsed_value!r}", fg=typer.colors.GREEN)


@app.command("add-origin")
def add_origin(
    origin: str = typer.Argument(..., help="Origin name to add (e.g. 'ZLIB')."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name."),
) -> None:
    """Add an origin to a target's origins list."""
    doc, toml_path = _load_toml()
    target = _resolve_target(doc, target)
    tgt = doc["targets"][target]

    origins = tgt.get("origins")
    if origins is None:
        origins = []
        tgt["origins"] = origins

    origin_upper = origin.upper()
    if origin_upper in origins:
        typer.secho(f"Origin '{origin_upper}' already exists in {target}.", fg=typer.colors.YELLOW)
        return

    origins.append(origin_upper)
    _save_toml(doc, toml_path)
    typer.secho(
        f"Added origin '{origin_upper}' to {target}. Origins: {list(origins)}",
        fg=typer.colors.GREEN,
    )


@app.command("remove-origin")
def remove_origin(
    origin: str = typer.Argument(..., help="Origin name to remove."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name."),
) -> None:
    """Remove an origin from a target's origins list (idempotent)."""
    doc, toml_path = _load_toml()
    target = _resolve_target(doc, target)
    tgt = doc["targets"][target]

    origins = tgt.get("origins")
    if origins is None or origin.upper() not in origins:
        typer.secho(
            f"Origin '{origin.upper()}' not in {target} (already removed).", fg=typer.colors.YELLOW
        )
        return

    origins.remove(origin.upper())
    _save_toml(doc, toml_path)
    typer.secho(
        f"Removed origin '{origin.upper()}' from {target}. Origins: {list(origins)}",
        fg=typer.colors.GREEN,
    )


@app.command("set-cflags")
def set_cflags(
    origin: str = typer.Argument(..., help="Origin/preset name (e.g. 'ZLIB', 'GAME')."),
    flags: str = typer.Argument(..., help="Compiler flags string (e.g. '/O3')."),
    target: str | None = typer.Option(
        None,
        "--target",
        "-t",
        help="Target name (sets per-target preset). Omit to set global preset.",
    ),
) -> None:
    """Set cflags preset for an origin."""
    doc, toml_path = _load_toml()

    if target is not None:
        # Per-target cflags_presets
        target = _resolve_target(doc, target)
        tgt = doc["targets"][target]
        presets = tgt.get("cflags_presets")
        if presets is None:
            presets = tomlkit.table()
            tgt["cflags_presets"] = presets
        presets[origin.upper()] = flags
        scope = f'targets."{target}"'
    else:
        # Global cflags_presets
        compiler = doc.get("compiler")
        if compiler is None:
            compiler = tomlkit.table()
            doc["compiler"] = compiler
        presets = compiler.get("cflags_presets")
        if presets is None:
            presets = tomlkit.table()
            compiler["cflags_presets"] = presets
        presets[origin.upper()] = flags
        scope = "compiler"

    _save_toml(doc, toml_path)
    typer.secho(f'Set {scope}.cflags_presets.{origin.upper()} = "{flags}"', fg=typer.colors.GREEN)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
