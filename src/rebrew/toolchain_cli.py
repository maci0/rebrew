"""toolchain_cli.py — `rebrew toolchain` subcommands.

Standardized toolchain management: list the registry, check docker status,
and pull toolchain images.  This is the host-side face of the
docker-first toolchain abstraction (see rebrew.toolchain): every compiler
profile resolves to a ToolchainSpec, and the CLI surfaces how each is
invoked (docker image vs vendored path vs PATH binary).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from rebrew.cli import TargetOption, json_print
from rebrew.toolchain import (
    ToolchainError,
    docker_available,
    list_toolchains,
    pull_toolchain,
)

console = Console(stderr=True)

app = typer.Typer(
    help="Standardized toolchain management (docker-first, host fallback).",
    rich_markup_mode="rich",
    no_args_is_help=True,
)


@app.command("list")
def list_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List known toolchains and how each is invoked."""
    rows = list_toolchains()
    if json_output:
        json_print({"toolchains": rows, "docker_available": docker_available()})
        return
    table = Table(title="Toolchains", header_style="bold")
    for col in ("Name", "Image", "Binary", "Runtime", "Flags", "Obj"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["name"],
            r["image"] or "host-only",
            r["binary"],
            r["runtime"],
            r["flags_style"],
            r["obj_ext"],
        )
    console.print(table)
    console.print(f"[dim]docker: {'available' if docker_available() else 'NOT available'}[/dim]")


@app.command("status")
def status_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. msvc6, delphi16)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show how one toolchain resolves (image pulled? host binary present?)."""
    import shutil

    from rebrew.toolchain import ToolchainError, _resolve_binary, get_toolchain

    spec = get_toolchain(name)
    host_ok: bool | None = None
    if spec.host_path is not None:
        # Use the shared resolver (case-insensitive host_bin subdir — the
        # vendored DOS-era trees are BIN, not Bin) so status agrees with
        # run_toolchain's host fallback.
        try:
            _resolve_binary(spec)
            host_ok = True
        except ToolchainError:
            host_ok = False
    elif spec.image is None:
        host_ok = shutil.which(spec.binary) is not None
    image_ok: bool | None = None
    if spec.image is not None and docker_available():
        r = __import__("subprocess").run(
            ["docker", "image", "inspect", spec.image],
            capture_output=True,
            text=True,
            timeout=30,
        )
        image_ok = r.returncode == 0
    data: dict[str, Any] = {
        "name": spec.name,
        "image": spec.image,
        "image_pulled": image_ok,
        "host_binary_present": host_ok,
        "binary": spec.binary,
        "description": spec.description,
    }
    if json_output:
        json_print(data)
        return
    console.print(f"[bold]{spec.name}[/bold]: {spec.description}")
    console.print(
        f"  image:  {spec.image or 'host-only'}  {'✅ pulled' if image_ok else ('⬜ not pulled' if image_ok is False else '')}"
    )
    console.print(
        f"  host:   {spec.host_path or spec.binary}  {'✅ present' if host_ok else '⬜ absent'}"
    )


@app.command("detect")
def detect_cmd(
    binary: str = typer.Argument(..., help="Path to the target binary (PE/NE/ELF/Mach-O)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Detect which compiler/toolchain built a binary; check profile alignment."""
    from rebrew.cli import error_exit
    from rebrew.toolchain_detect import (
        _PROFILE_COMPAT,
        detect_toolchain,
        profile_matches_detection,
    )

    binary_path = Path(binary)
    if not binary_path.is_file():
        error_exit(f"Binary not found: {binary}", json_mode=json_output, code=2)
    try:
        info = detect_toolchain(binary_path)
    except Exception as exc:  # noqa: BLE001 — detection is best-effort
        error_exit(f"Detection failed: {exc}", json_mode=json_output, code=2)

    compat: set[str] | None = _PROFILE_COMPAT.get(info.family)
    data: dict[str, Any] = {
        "binary": str(binary_path),
        "family": info.family,
        "version_hint": info.version_hint,
        "confidence": info.confidence,
        "detected_by": info.detected_by,
        "arch": info.arch,
        "flags": info.flags,
        "evidence": info.evidence,
        "crt": info.crt or None,
        "crt_linkage": info.crt_linkage or None,
        "base_cflags_hint": info.base_cflags or None,
        "compatible_profiles": sorted(compat) if compat else None,
    }

    # Alignment against a configured project profile (optional — detect works
    # standalone; the check is what init/intake/doctor surface per-project).
    cfg = None
    try:
        from rebrew.config import load_config

        cfg = load_config(target=target)
    except FileNotFoundError:
        pass  # no project — report detection only
    except (KeyError, ValueError) as exc:
        if not json_output:
            console.print(
                f"[yellow]warning:[/yellow] config error ({exc}); alignment check disabled"
            )
    if cfg is not None:
        profile = getattr(cfg, "compiler_profile", "") or "msvc6"
        aligned, explanation = profile_matches_detection(profile, info)
        data["profile"] = profile
        data["aligned"] = aligned
        data["explanation"] = explanation

    if json_output:
        json_print(data)
        return

    console.print(
        f"[bold]{info.family}[/bold]"
        f"{(' — ' + info.version_hint) if info.version_hint else ''}"
        f"  [dim](confidence: {info.confidence}"
        f"{', via ' + info.detected_by if info.detected_by else ''})[/dim]"
    )
    if info.arch:
        console.print(f"  arch:      {info.arch}")
    if info.flags:
        console.print(f"  flags:     {' '.join(info.flags)}")
    if info.crt:
        console.print(f"  crt:       {info.crt} ({info.crt_linkage})")
        if info.base_cflags:
            console.print(f"  base flags: {info.base_cflags} (use in [cyan]base_cflags[/])")
    for e in info.evidence:
        console.print(f"  [dim]•[/dim] {e}")
    compat = data["compatible_profiles"]
    if compat:
        console.print(f"  compatible profiles: {', '.join(compat)}")
    elif info.family != "unknown":
        console.print("[yellow]  no rebrew compiler profile can byte-match this family[/yellow]")
    if "aligned" in data:
        if data["aligned"]:
            console.print(f"[green]  profile {data['profile']} aligns with detection[/green]")
        else:
            console.print(
                f"[red]  profile {data['profile']} does NOT align:[/red] {data['explanation']}"
            )


@app.command("pull")
def pull_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. delphi16)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Pull a toolchain's docker image."""
    try:
        tag, was_present = pull_toolchain(name)
    except ToolchainError as exc:
        if json_output:
            json_print({"error": str(exc), "code": 2})
        else:
            console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2)
    if json_output:
        json_print({"pulled": tag, "already_present": was_present})
    else:
        if was_present:
            console.print(f"[green]Already present[/green] {tag} (locally built)")
        else:
            console.print(f"[green]Pulled[/green] {tag}")


@app.command("build")
def build_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. watcom, msvc6)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Build a toolchain's docker image from toolchain-images/<name>/<ver>-<arch>/Dockerfile."""
    import subprocess

    from rebrew.toolchain import get_toolchain

    spec = get_toolchain(name)
    if spec.image is None:
        msg = f"toolchain {name!r} is host-only (no image to build)"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)
    if spec.image is None or ":" not in spec.image:
        msg = f"toolchain {name!r} image tag {spec.image!r} has no version-arch tag"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)
    tag, verarch = spec.image.rsplit(":", 1)
    build_dir = Path(__file__).resolve().parents[2] / "toolchain-images" / spec.family / verarch
    if not (build_dir / "Dockerfile").exists():
        msg = f"no Dockerfile at {build_dir}"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)
    r = subprocess.run(
        ["docker", "build", "-t", spec.image, str(build_dir)],
        capture_output=True,
        text=True,
        timeout=3600,
    )
    if r.returncode != 0:
        msg = f"docker build {spec.image} failed: {r.stderr[-300:]}"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)
    if json_output:
        json_print({"built": spec.image})
    else:
        console.print(f"[green]Built[/green] {spec.image}")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
