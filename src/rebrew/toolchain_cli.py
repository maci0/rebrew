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

from rebrew.cli import json_print
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

    from rebrew.toolchain import get_toolchain

    spec = get_toolchain(name)
    host_ok = None
    if spec.host_path is not None:
        from pathlib import Path as _Path

        host = _Path(spec.host_path)
        host_ok = (host / spec.binary).exists() or (host / spec.host_bin / spec.binary).exists()
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
