"""rebrew-cfg: Programmatic editor for rebrew.toml.

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

from __future__ import annotations

import shutil
from pathlib import Path

import tomlkit
import typer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_root() -> Path:
    """Walk up from cwd to find rebrew.toml."""
    candidate = Path.cwd().resolve()
    while candidate != candidate.parent:
        if (candidate / "rebrew.toml").exists():
            return candidate
        candidate = candidate.parent
    typer.secho(
        "Error: Could not find rebrew.toml in any parent directory.\n"
        "Run this command from within a rebrew project, or use 'rebrew-init' first.",
        fg=typer.colors.RED,
        err=True,
    )
    raise typer.Exit(1)


def _load_toml(root: Path | None = None) -> tuple[tomlkit.TOMLDocument, Path]:
    """Load rebrew.toml as a tomlkit document, preserving formatting."""
    if root is None:
        root = _find_root()
    toml_path = root / "rebrew.toml"
    if not toml_path.exists():
        typer.secho(f"Error: {toml_path} not found.", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    doc = tomlkit.parse(toml_path.read_text(encoding="utf-8"))
    return doc, toml_path


def _save_toml(doc: tomlkit.TOMLDocument, path: Path) -> None:
    """Write tomlkit document back, preserving formatting."""
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")


def _resolve_target(doc: tomlkit.TOMLDocument, target: str | None) -> str:
    """Resolve a target name: use given name, or default to first target."""
    targets = doc.get("targets", {})
    if not targets:
        typer.secho("Error: No [targets] section in rebrew.toml.", fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    if target is None:
        target = list(targets.keys())[0]
    if target not in targets:
        typer.secho(
            f"Error: Target '{target}' not found. Available: {list(targets.keys())}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(1)
    return target


def _detect_format(path: Path) -> str:
    """Detect binary format from file header magic bytes."""
    fmt, _ = _detect_format_and_arch(path)
    return fmt


def _detect_format_and_arch(path: Path) -> tuple:
    """Detect binary format and architecture from file header.

    Returns (format, arch) where arch may be None if detection fails.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(64)  # enough for PE/ELF/Mach-O headers
    except OSError:
        return "pe", None

    magic = header[:4]

    if magic[:2] == b"MZ":
        # PE: check optional header machine type
        arch = None
        if len(header) >= 64:
            import struct
            pe_offset_loc = 60
            if len(header) > pe_offset_loc + 4:
                pe_off = struct.unpack_from("<I", header, pe_offset_loc)[0]
                # Read COFF header machine field (need to re-read if pe_off is far)
                try:
                    with open(path, "rb") as f:
                        f.seek(pe_off)
                        pe_sig = f.read(4)
                        if pe_sig == b"PE\x00\x00":
                            machine = struct.unpack("<H", f.read(2))[0]
                            if machine == 0x14C:    # IMAGE_FILE_MACHINE_I386
                                arch = "x86_32"
                            elif machine == 0x8664: # IMAGE_FILE_MACHINE_AMD64
                                arch = "x86_64"
                            elif machine == 0x1C0:  # IMAGE_FILE_MACHINE_ARM
                                arch = "arm32"
                            elif machine == 0xAA64: # IMAGE_FILE_MACHINE_ARM64
                                arch = "arm64"
                except OSError:
                    pass
        return "pe", arch

    elif magic[:4] == b"\x7fELF":
        # ELF: byte 4 is class (1=32-bit, 2=64-bit), byte 18-19 is machine
        arch = None
        if len(header) >= 20:
            import struct
            ei_class = header[4]  # 1=32, 2=64
            # Machine is at offset 18 in both 32/64 ELF
            machine = struct.unpack_from("<H", header, 18)[0]
            if machine == 3:      # EM_386
                arch = "x86_32"
            elif machine == 62:   # EM_X86_64
                arch = "x86_64"
            elif machine == 40:   # EM_ARM
                arch = "arm32"
            elif machine == 183:  # EM_AARCH64
                arch = "arm64"
            elif ei_class == 1:
                arch = "x86_32"  # 32-bit fallback
            elif ei_class == 2:
                arch = "x86_64"  # 64-bit fallback
        return "elf", arch

    elif magic[:4] in (
        b"\xfe\xed\xfa\xce",  # Mach-O 32-bit
        b"\xfe\xed\xfa\xcf",  # Mach-O 64-bit
        b"\xce\xfa\xed\xfe",  # Mach-O 32-bit LE
        b"\xcf\xfa\xed\xfe",  # Mach-O 64-bit LE
    ):
        arch = "x86_64" if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else "x86_32"
        return "macho", arch

    return "pe", None


# ---------------------------------------------------------------------------
# Typer app
# ---------------------------------------------------------------------------

app = typer.Typer(help="Read and edit rebrew.toml programmatically.")


@app.command("list-targets")
def list_targets():
    """List all targets defined in rebrew.toml."""
    doc, _ = _load_toml()
    targets = doc.get("targets", {})
    if not targets:
        typer.echo("No targets defined.")
        return
    for i, name in enumerate(targets.keys()):
        tgt = targets[name]
        binary = tgt.get("binary", "?")
        arch = tgt.get("arch", "?")
        marker = "→" if i == 0 else " "
        typer.echo(f"  {marker} {name}  ({arch}, {binary})")
    if len(targets) > 0:
        typer.secho("\n  → = default target", dim=True)


@app.command("show")
def show(
    key: str | None = typer.Argument(None, help="Dot-separated key to show, e.g. 'compiler.cflags'"),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name (for target-scoped keys)."),
):
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
            typer.secho(f"Key '{key}' not found.", fg=typer.colors.RED, err=True)
            raise typer.Exit(1)

    if isinstance(current, (dict, list)):
        typer.echo(tomlkit.dumps(current) if isinstance(current, dict) else str(current))
    else:
        typer.echo(str(current))


@app.command("add-target")
def add_target(
    name: str = typer.Argument(..., help="Target name (e.g. 'server.dll')."),
    binary: str = typer.Option(..., "--binary", "-b", help="Path to the original binary."),
    arch: str | None = typer.Option(None, "--arch", "-a", help="Architecture: x86_32, x86_64, arm32, arm64 (auto-detected if omitted)."),
    fmt: str | None = typer.Option(None, "--format", "-f", help="Binary format: pe, elf, macho (auto-detected if omitted)."),
    origins: str | None = typer.Option(None, "--origins", help="Comma-separated origin list (inherits from project or defaults to GAME)."),
    copy_binary: bool = typer.Option(True, "--copy/--no-copy", help="Copy binary into original/."),
):
    """Add a new target section to rebrew.toml (idempotent).

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

    # Parse origins
    origin_list = [o.strip() for o in origins.split(",") if o.strip()]
    tgt.add("origins", origin_list)

    targets[name] = tgt
    _save_toml(doc, toml_path)

    typer.secho(f"Added [targets.\"{name}\"] to rebrew.toml", fg=typer.colors.GREEN)
    typer.secho(f"  Format: {fmt}, Arch: {arch} (auto-detected)", fg=typer.colors.GREEN)
    typer.secho(f"  Created src/{name}/ and bin/{name}/", fg=typer.colors.GREEN)
    typer.echo(f"\nNext: rebrew-next --target \"{name}\" --stats")


@app.command("remove-target")
def remove_target(
    name: str = typer.Argument(..., help="Target name to remove."),
):
    """Remove a target section from rebrew.toml (idempotent)."""
    doc, toml_path = _load_toml()
    targets = doc.get("targets", {})
    if name not in targets:
        typer.secho(f"Target '{name}' not found (already removed).", fg=typer.colors.YELLOW)
        return

    del targets[name]
    _save_toml(doc, toml_path)
    typer.secho(f"Removed [targets.\"{name}\"] from rebrew.toml", fg=typer.colors.GREEN)
    typer.secho("  Note: src/ and bin/ directories were NOT deleted.", dim=True)


@app.command("set")
def set_value(
    key: str = typer.Argument(..., help="Dot-separated key, e.g. 'compiler.cflags' or 'targets.server.dll.arch'."),
    value: str = typer.Argument(..., help="Value to set."),
):
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
    parsed_value: object = value
    if value.lower() in ("true", "false"):
        parsed_value = value.lower() == "true"
    else:
        try:
            if value.startswith("0x") or value.startswith("0X"):
                parsed_value = int(value, 16)
            else:
                parsed_value = int(value)
        except ValueError:
            try:
                parsed_value = float(value)
            except ValueError:
                pass  # keep as string

    current[final_key] = parsed_value
    _save_toml(doc, toml_path)
    typer.secho(f"Set {key} = {parsed_value!r}", fg=typer.colors.GREEN)


@app.command("add-origin")
def add_origin(
    origin: str = typer.Argument(..., help="Origin name to add (e.g. 'ZLIB')."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name."),
):
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
    typer.secho(f"Added origin '{origin_upper}' to {target}. Origins: {list(origins)}", fg=typer.colors.GREEN)


@app.command("remove-origin")
def remove_origin(
    origin: str = typer.Argument(..., help="Origin name to remove."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name."),
):
    """Remove an origin from a target's origins list (idempotent)."""
    doc, toml_path = _load_toml()
    target = _resolve_target(doc, target)
    tgt = doc["targets"][target]

    origins = tgt.get("origins")
    if origins is None or origin.upper() not in origins:
        typer.secho(f"Origin '{origin.upper()}' not in {target} (already removed).", fg=typer.colors.YELLOW)
        return

    origins.remove(origin.upper())
    _save_toml(doc, toml_path)
    typer.secho(f"Removed origin '{origin.upper()}' from {target}. Origins: {list(origins)}", fg=typer.colors.GREEN)


@app.command("set-cflags")
def set_cflags(
    origin: str = typer.Argument(..., help="Origin/preset name (e.g. 'ZLIB', 'GAME')."),
    flags: str = typer.Argument(..., help="Compiler flags string (e.g. '/O3')."),
    target: str | None = typer.Option(None, "--target", "-t", help="Target name (sets per-target preset). Omit to set global preset."),
):
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
        scope = f"targets.\"{target}\""
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
    typer.secho(f"Set {scope}.cflags_presets.{origin.upper()} = \"{flags}\"", fg=typer.colors.GREEN)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main_entry():
    app()


if __name__ == "__main__":
    main_entry()
