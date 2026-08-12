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
    resolved_cmd: str | None = None
    if spec.host_path is not None:
        # Use the shared resolver (case-insensitive host_bin subdir — the
        # vendored DOS-era trees are BIN, not Bin) so status agrees with
        # run_toolchain's host fallback.
        try:
            _resolve_binary(spec)
            host_ok = True
        except ToolchainError:
            host_ok = False
            # The master layout may be absent (machines with only the
            # compile-only mirrors) — resolve the best present layout and
            # report it instead of a bare "absent".
            try:
                from rebrew.utils import resolve_msvc_toolchain

                root = Path(__file__).resolve().parents[2]
                layout = resolve_msvc_toolchain(root, name)
                if layout is not None:
                    resolved_cmd = layout[0]
            except Exception:
                pass
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
        "resolved_host": resolved_cmd,
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
    if resolved_cmd:
        console.print(f"  host:   {resolved_cmd}  ✅ present (resolved mirror)")
    else:
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


@app.command("vendor")
def vendor_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. msvc1.52, borlandc55)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Assemble the host toolchain tree from the pinned source.

    Downloads (sha256-verified) or extracts the committed in-repo tarball
    into ``toolchain/<family>/<version>-<arch>`` — the same source the
    docker image builds from, so host trees and containers are
    byte-identical.  Refuses to clobber an existing tree unless empty.
    """
    import hashlib
    import subprocess
    import tempfile

    from rebrew.toolchain import _REPO_TOOLS, _SOURCES

    src = _SOURCES.get(name)
    if src is None:
        msg = f"no pinned source for toolchain {name!r} (known: {sorted(_SOURCES)})"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)

    host = _REPO_TOOLS / src.host_dir
    if host.exists() and any(host.iterdir()):
        msg = f"{host} already has files — refusing to clobber"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[yellow]{msg}[/yellow]")
        raise typer.Exit(code=2)
    host.mkdir(parents=True, exist_ok=True)

    try:
        if src.is_in_repo():
            tarball = Path(__file__).resolve().parents[2] / src.in_repo
            subprocess.run(
                ["tar", "xJf", str(tarball), "-C", str(host)],
                check=True,
                capture_output=True,
            )
            console.print(f"[green]Extracted[/green] {src.in_repo} -> {src.host_dir}")
        else:
            with tempfile.TemporaryDirectory(prefix="rebrew_vendor_") as td:
                archive = Path(td) / "src.bin"
                subprocess.run(
                    ["curl", "-sL", "-o", str(archive), src.url],
                    check=True,
                    timeout=1800,
                    capture_output=True,
                )
                actual = hashlib.sha256(archive.read_bytes()).hexdigest()
                if actual != src.sha256:
                    msg = f"sha256 mismatch for {name}: expected {src.sha256}, got {actual}"
                    if json_output:
                        json_print({"error": msg, "code": 2})
                    else:
                        console.print(f"[red]Error:[/red] {msg}")
                    raise typer.Exit(code=2)
                if src.layout == "zip-installshield":
                    subprocess.run(
                        ["unzip", "-q", str(archive), "-d", td + "/zip"],
                        check=True,
                        capture_output=True,
                    )
                    installer = next(Path(td + "/zip").iterdir())
                    subprocess.run(
                        ["7z", "x", "-y", str(installer), f"-o{td}/pay"],
                        capture_output=True,
                    )  # warning exits tolerated — the final check below guards
                    payload = Path(td + "/pay")
                    for sub in ("Bin", "Include", "Lib"):
                        (payload / sub).rename(host / sub)
                elif src.layout == "tar-strip1":
                    subprocess.run(
                        ["tar", "xJf", str(archive), "-C", str(host), "--strip-components=1"],
                        check=True,
                        capture_output=True,
                    )
                else:
                    subprocess.run(
                        ["tar", "xzf", str(archive), "-C", str(host)],
                        check=True,
                        capture_output=True,
                    )
                console.print(f"[green]Downloaded + verified[/green] {src.url} -> {src.host_dir}")
    except (subprocess.CalledProcessError, OSError) as exc:
        msg = f"vendor {name} failed: {exc}"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)

    # Guard: a bad extraction must fail loudly (the images do the same).
    from rebrew.toolchain import get_toolchain

    spec = get_toolchain(name)
    probe = host / spec.host_bin / spec.binary
    if not probe.exists():
        probe = host / spec.binary
    if not probe.exists():
        msg = f"vendor {name} produced no {spec.binary} under {host}"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)
    if json_output:
        json_print({"vendored": src.host_dir, "binary": str(probe)})


#: Golden object hashes — the byte-exact output each toolchain image must
#: produce for the fixed smoke source (reproducibility evidence: the same
#: source + toolchain → the same object, every build).
_SMOKE_SOURCE = "int add(int a, int b) { return a + b; }\n"
_SMOKE_DPR = "program hello;\nbegin\nend.\n"
_SMOKE_GOLDEN: dict[str, tuple[list[str], str, str, str, tuple[int, int] | None]] = {
    # name -> (flags, out, golden, src, timestamp-mask (zeroed before hashing) | None)
    "msvc6": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp
    "msvc1.52": (
        ["/c", "t.c"],
        "t.OBJ",
        "d3bf67158b4d52bd24cb7b137e803491080cf221ffcd6b5dc9dafb885ab36dc2",
        "t.c",
        None,
    ),
    "borlandc55": (
        ["-c", "t.c"],
        "t.obj",
        "76f45489734e9e2d58ed42d999f570204755566d135e757d27a754c194fdc8f1",
        "t.c",
        None,
    ),
    "watcom": (
        ["-fo=w.o", "t.c"],
        "w.o",
        "44a6354f779f2c504384019c6786ec1831ca7b5cc20721e1a678295753f08220",
        "t.c",
        None,
    ),
    "delphi16": (
        ["hello.dpr"],
        "hello.EXE",
        "efd1ee34584a19852afe42cccf0b9e03b217c006c7132f50651a601c595630b9",
        "hello.dpr",
        None,
    ),
}


@app.command("smoke")
def smoke_cmd(
    name: str | None = typer.Argument(None, help="Toolchain name; all image-backed by default"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Compile the fixed smoke source in each image and verify the object
    hash matches the golden bytes (reproducibility gate).

    Deterministic inputs: a FIXED work directory (/tmp/rebrew-smoke) and a
    FIXED source mtime (the object metadata embeds both the source path and
    its modification time — fresh writes would break the golden hashes).
    """
    import hashlib
    import os
    import shutil
    import subprocess

    from rebrew.toolchain import get_toolchain

    # SOURCE_DATE_EPOCH convention: a fixed source mtime makes the object
    # metadata deterministic across runs.
    _SDE = 1767225600  # 2026-01-01 00:00:00 UTC

    targets = [name] if name else sorted(_SMOKE_GOLDEN)
    results: dict[str, str] = {}
    ok = True
    workdir = Path("/tmp/rebrew-smoke")
    shutil.rmtree(workdir, ignore_errors=True)
    workdir.mkdir(parents=True)
    for tool in targets:
        spec = get_toolchain(tool)
        if spec.image is None:
            results[tool] = "skip (host-only)"
            continue
        flags, out_name, golden, src_name, mask = _SMOKE_GOLDEN[tool]
        src = _SMOKE_SOURCE if src_name == "t.c" else _SMOKE_DPR
        src_path = workdir / src_name
        src_path.write_text(src, encoding="utf-8")
        os.utime(src_path, (int(_SDE), int(_SDE)))
        r = subprocess.run(
            ["docker", "run", "--rm", "-v", f"{workdir}:/work", "-w", "/work", spec.image, *flags],
            capture_output=True,
            text=True,
            timeout=300,
        )
        obj = workdir / out_name
        if not obj.exists():
            results[tool] = "FAIL (no object: " + (r.stdout + r.stderr)[-120:].strip() + ")"
            ok = False
            continue
        raw = obj.read_bytes()
        if mask is not None:
            # Zero the compiler's build-timestamp field (e.g. the COFF
            # TimeDateStamp) — MSVC6 stamps the build time, so the rest of
            # the object is what determinism covers.
            masked = bytearray(raw)
            masked[mask[0] : mask[1]] = b"\x00" * (mask[1] - mask[0])
            raw = bytes(masked)
        actual = hashlib.sha256(raw).hexdigest()
        results[tool] = "OK" if actual == golden else f"MISMATCH ({actual[:12]}…)"
        ok = ok and actual == golden
        obj.unlink(missing_ok=True)
    if json_output:
        json_print({"results": results, "passed": ok})
        return
    for tool, status in results.items():
        console.print(f"  [{'green' if status == 'OK' else 'red'}]{tool:12s}[/] {status}")
    if ok:
        console.print(
            f"[green]Smoke: {sum(1 for s in results.values() if s == 'OK')} toolchains byte-reproducible[/green]"
        )
    else:
        raise typer.Exit(code=2)


@app.command("build")
def build_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. watcom, msvc6)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Build a toolchain's docker image from toolchain/<name>/<ver>-<arch>/Dockerfile."""
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
    build_dir = Path(__file__).resolve().parents[2] / "toolchain" / spec.family / verarch
    if not (build_dir / "Dockerfile").exists():
        msg = f"no Dockerfile at {build_dir}"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)

    # Every toolchain image inherits FROM rebrew/base — build it first so a
    # fresh docker daemon resolves the dependency.
    base_dir = Path(__file__).resolve().parents[2] / "toolchain" / "base"
    base_from = None
    for line in (build_dir / "Dockerfile").read_text(encoding="utf-8").splitlines():
        if line.upper().startswith("FROM "):
            base_from = line.split()[1]
            break
    if base_from and base_from.startswith("rebrew/"):
        base_tag = base_from
        base_dockerfile = base_dir / "Dockerfile"
        if base_dockerfile.exists():
            r = subprocess.run(
                ["docker", "build", "-t", base_tag, str(base_dir)],
                capture_output=True,
                text=True,
                timeout=3600,
            )
            if r.returncode != 0:
                msg = f"docker build {base_tag} failed: {r.stderr[-300:]}"
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
