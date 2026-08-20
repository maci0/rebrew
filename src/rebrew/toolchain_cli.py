"""toolchain_cli.py — `rebrew toolchain` subcommands.

Standardized toolchain management: list the registry, check docker status,
and pull toolchain images.  This is the host-side face of the
docker-first toolchain abstraction (see rebrew.toolchain): every compiler
profile resolves to a ToolchainSpec, and the CLI surfaces how each is
invoked (docker image vs vendored path vs PATH binary).
"""

from __future__ import annotations

from dataclasses import replace
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
    """Show how one toolchain resolves (image built? vendored tree present?).

    Execution is docker-only for every Windows/DOS toolchain, so the image
    state is the primary signal; the vendored tree is informational (it is
    the byte-identical source the image builds from)."""
    import shutil

    from rebrew.toolchain import _vendored_binary, get_toolchain

    spec = get_toolchain(name)
    host_ok: bool | None = None
    resolved_cmd: str | None = None
    if spec.host_path is not None:
        # Informational: the vendored tree (source for image builds) —
        # nothing executes from it anymore.
        try:
            hit = _vendored_binary(spec)
            host_ok = hit is not None
            if hit is not None:
                resolved_cmd = str(hit)
        except Exception:
            host_ok = False
    elif spec.image is None:
        # Native-Linux toolchains (gcc-pe, watcom16 wcc) exec their binary
        # directly — that IS the execution path.
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
        "packed": info.packed or None,
        "msvc_version": info.msvc_version or None,
        "suggested_profiles": info.suggested_profiles or None,
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
    if info.msvc_version:
        console.print(f"  msvc:      {info.msvc_version}")
    if info.suggested_profiles:
        console.print(f"  suggest:   {', '.join(info.suggested_profiles)}")
    if info.packed:
        console.print(f"  packed:    [yellow]{info.packed}[/yellow] (unpack before analysis)")
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


#: Legacy ``tools/<name>`` aliases → ``toolchain/<family>/<version>-<arch>``
#: dir, so projects whose rebrew-project.toml predates the restructure keep
#: resolving ``tools/<name>/...`` through the rebrew install
#: (find_install_tool fallback in config/compile).  Classic MSVC names
#: (MSVC600/VC98, MSVC7) and the dash-versioned aliases both map here; the
#: links are gitignored and recreated by ``ensure_compat_links`` on every
#: vendor, so fresh clones get them automatically.
_COMPAT_LINK_ALIASES: dict[str, str] = {
    "MSVC600": "msvc/6.0-win32",
    "msvc-6.0-win32": "msvc/6.0-win32",
    "MSVC500": "msvc/5.0-win32",
    "msvc-5.0-win32": "msvc/5.0-win32",
    "MSVC420": "msvc/4.2-win32",
    "msvc-4.2-win32": "msvc/4.2-win32",
    "MSVC400": "msvc/4.0-win32",
    "msvc-4.0-win32": "msvc/4.0-win32",
    "MSVC7": "msvc/7.0-win32",
    "msvc7.0": "msvc/7.0-win32",
    "msvc-7.0-win32": "msvc/7.0-win32",
    "msvc6.3": "msvc/6.0-sp3-win32",
    "msvc-6.0-sp3-win32": "msvc/6.0-sp3-win32",
    "msvc6.6": "msvc/6.0-sp6-win32",
    "msvc-6.0-sp6-win32": "msvc/6.0-sp6-win32",
    "MSVC152": "msvc/1.52-win16",
    "msvc-1.52-win16": "msvc/1.52-win16",
    "DELPHI10": "delphi/1.0-win16",
    "delphi-1.0-win16": "delphi/1.0-win16",
    "WATCOM": "watcom/2.0-win32",
    "watcom-win32": "watcom/2.0-win32",
    "TC": "borland/3.1-win16",
    "MSVC200": "msvc/2.0-win32",
    "msvc-2.0-win32": "msvc/2.0-win32",
    "MSVC410": "msvc/4.1-win32",
    "msvc-4.1-win32": "msvc/4.1-win32",
    "msvc-5.0-sp1-win32": "msvc/5.0-sp1-win32",
    "msvc-5.0-sp2-win32": "msvc/5.0-sp2-win32",
    "msvc-5.0-sp3-win32": "msvc/5.0-sp3-win32",
    "msvc-6.0-sp5-win32": "msvc/6.0-sp5-win32",
    "MSVC7RTM": "msvc/7.0-rtm-win32",
    "msvc-7.0-rtm-win32": "msvc/7.0-rtm-win32",
    "msvc-7.0-sp1-win32": "msvc/7.0-sp1-win32",
    "msvc-7.1-win32": "msvc/7.1-win32",
    "msvc-7.1-sp1-win32": "msvc/7.1-sp1-win32",
    "msvc-8.0-win32": "msvc/8.0-win32",
    "msvc-8.0-sp1-win32": "msvc/8.0-sp1-win32",
    "msvc-9.0-win32": "msvc/9.0-win32",
    "msvc-10.0-win32": "msvc/10.0-win32",
    "msvc-10.0-sp1-win32": "msvc/10.0-sp1-win32",
    "MSVC15": "msvc/1.5-win16",
    "msvc-1.5-win16": "msvc/1.5-win16",
    "MSVC10": "msvc/1.0-win16",
    "msvc-1.0-win16": "msvc/1.0-win16",
}


def ensure_compat_links(root: Path) -> list[Path]:
    """Create missing ``tools/<alias> → ../toolchain/<dir>`` compat symlinks.

    Only aliases whose vendored tree exists are linked (a fresh clone with no
    trees gets nothing dangling).  Returns the links created.
    """
    created: list[Path] = []
    tools_dir = root / "tools"
    tools_dir.mkdir(parents=True, exist_ok=True)
    for alias, rel in sorted(_COMPAT_LINK_ALIASES.items()):
        target = root / "toolchain" / rel
        if not target.is_dir():
            continue
        dest = tools_dir / alias
        if dest.is_symlink() or dest.exists():
            continue
        dest.symlink_to(f"../toolchain/{rel}", target_is_directory=True)
        created.append(dest)
    return created


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
    # Tracked metadata lives beside the vendored tree (Dockerfile, wrapper
    # scripts, the in-repo tarball the tree is extracted from, pak_extract.py)
    # — those are not vendored content, so a dir holding only them is empty
    # for clobber purposes.
    _META = {
        "Dockerfile",
        "pak_extract.py",
        "wrapper-common.sh",
        *("*.sh", "*.tar.xz"),
    }
    content = (
        [p for p in host.iterdir() if not any(p.match(m) for m in _META)] if host.exists() else []
    )
    if content:
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
                # No explicit -z/-J: GNU tar auto-detects gzip/xz compression,
                # so in-repo .tar.xz and remote codeload .tar.gz both extract.
                ["tar", "xf", str(tarball), "-C", str(host)],
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
                elif src.layout == "zip-strip1":
                    # A zip with a single top-level wrapper dir (e.g. TC/) —
                    # strip the wrapper so BIN/INCLUDE/LIB sit at the top of
                    # the host tree like the other toolchains.
                    subprocess.run(
                        ["unzip", "-q", str(archive), "-d", td + "/zip"],
                        check=True,
                        capture_output=True,
                    )
                    payload = Path(td + "/zip")
                    contents = [p for p in payload.iterdir() if p.is_dir()]
                    if len(contents) == 1 and not any(p.is_file() for p in payload.iterdir()):
                        payload = contents[0]
                    for child in payload.iterdir():
                        child.rename(host / child.name)
                elif src.layout == "tar-strip1":
                    subprocess.run(
                        # Auto-detect compression (no -z/-J): the pinned
                        # sources are gzip codeload tarballs (msvc400/420/5)
                        # and xz snapshots (watcom) alike.
                        ["tar", "xf", str(archive), "-C", str(host), "--strip-components=1"],
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

    # MSVC 6.0's classic master layout wraps the tree in VC98/ (the decomp.me
    # tarball is flat) — canonical config paths and every legacy
    # tools/MSVC600/VC98/... reference expect the wrapper.
    if src.vc98_wrap and not (host / "VC98").exists():
        vc98 = host / "VC98"
        vc98.mkdir()
        for child in list(host.iterdir()):
            if child == vc98 or any(child.match(m) for m in _META):
                continue
            child.rename(vc98 / child.name)

    # The archaic MSVC 6.0 SP5 repo stashes mspdb60.dll in the IDE dir
    # (Common/MSDev98/Bin) while CL.EXE 12.00.8804 statically imports it and
    # only searches its own directory — relocate the official file so host
    # compiles work (the sp5 Dockerfile does the same relocation).
    ide_dll = host / "Common" / "MSDev98" / "Bin" / "MSPDB60.DLL"
    bin_dll = host / "VC98" / "Bin" / "MSPDB60.DLL"
    if ide_dll.exists() and not bin_dll.exists():
        bin_dll.write_bytes(ide_dll.read_bytes())
        console.print("[dim]relocated MSPDB60.DLL -> VC98/Bin (CL requires it in-dir)[/dim]")

    # Guard: a bad extraction must fail loudly (the images do the same).
    # Probe the ACTUAL extracted dir (src.host_dir) — the spec's host_path
    # is captured at import time and may predate the extraction.
    from rebrew.toolchain import _vendored_binary, get_toolchain

    spec = get_toolchain(name)
    probe = _vendored_binary(replace(spec, host_path=host))
    if probe is None:
        # Legacy VC98-wrapped layout (MSVC 6 master tree).
        probe = _vendored_binary(replace(spec, host_path=host / "VC98"))
    if probe is None:
        msg = f"vendor {name} produced no {spec.binary} under {host}"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)

    # Existing projects resolve legacy tools/<name> paths through the
    # gitignored compat links — recreate any that are missing now that the
    # tree exists.
    root = Path(__file__).resolve().parents[2]
    created = ensure_compat_links(root)
    for link in created:
        console.print(f"[dim]linked tools/{link.name} -> {link.readlink()}[/dim]")

    if json_output:
        json_print({"vendored": src.host_dir, "binary": str(probe), "compat_links": len(created)})


#: Golden object hashes — the byte-exact output each toolchain image must
#: produce for the fixed smoke source (reproducibility evidence: the same
#: source + toolchain → the same object, every build).
_SMOKE_SOURCE = "int add(int a, int b) { return a + b; }\n"
_SMOKE_DPR = "program hello;\nbegin\nend.\n"
_SMOKE_GOLDEN: dict[
    str, tuple[list[str], str, str, str, tuple[int, int] | list[tuple[int, int]] | None]
] = {
    # name -> (flags, out, golden, src, timestamp-mask (zeroed before hashing) | None)
    "msvc400": (
        ["/c", "t.c"],
        "t.obj",
        "d420f2d9626c270866ba1d1d718a19cd39a59d07c8fe9d2999bde3ffd4bd9f4a",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc420 (same
    # compiler lineage; cross-validates both goldens) (host-only — wine)
    "msvc420": (
        ["/c", "t.c"],
        "t.obj",
        "d420f2d9626c270866ba1d1d718a19cd39a59d07c8fe9d2999bde3ffd4bd9f4a",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp (host-only — wine runner, see smoke_cmd)
    "msvc5": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp (host-only — wine runner, see smoke_cmd)
    "msvc6": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp
    "msvc200": (
        ["/c", "t.c"],
        "t.obj",
        "3df39750075ba99bba6f9418a9cb399eedfe48149132bb6a49f2045239cad25f",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp
    "msvc410": (
        ["/c", "t.c"],
        "t.obj",
        "d420f2d9626c270866ba1d1d718a19cd39a59d07c8fe9d2999bde3ffd4bd9f4a",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc400/msvc420
    "msvc500sp1": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc5 (same CL)
    "msvc500sp2": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),
    "msvc500sp3": (
        ["/c", "t.c"],
        "t.obj",
        "3fdf875c176b0abc8614f7208053d0b53193e73466f0c52c3cabc80a065dc897",
        "t.c",
        (4, 8),
    ),
    "msvc600sp3": (
        ["/c", "t.c"],
        "t.obj",
        "7e4ff03b2845d2268b2c0d27d35e63cea41d2e44320e821f6f6438da41873774",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — comp.id differs from msvc6 (SP3 passes)
    "msvc600sp5": (
        ["/c", "t.c"],
        "t.obj",
        "547b88f827c13e9273f46b1a72415002289fac62d0f65dc0ef9289dbc5a3e546",
        "t.c",
        (4, 8),
    ),
    "msvc600sp6": (
        ["/c", "t.c"],
        "t.obj",
        "7ec66aebd67075b5e1482d9ee05f4a53134925a4e6a79101446e9a7b31eb3994",
        "t.c",
        (4, 8),
    ),
    "msvc7": (
        ["/c", "t.c"],
        "t.obj",
        "77c906d5556114c01e11cb6d6afa1beed3e0b0dea6f9f04351ce6775f9303071",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc710 (same CL)
    "msvc700": (
        ["/c", "t.c"],
        "t.obj",
        "9e42bfe45c02ff046d13ce6c32b7fc1d422b30bf225ff4b64f659a16cadd9f4b",
        "t.c",
        (4, 8),
    ),
    "msvc700sp1": (
        ["/c", "t.c"],
        "t.obj",
        "138377065cf5e3ac2f7afd6252f9f39e18996cbb5f0e8cf2956ab20fb42d0af7",
        "t.c",
        (4, 8),
    ),
    "msvc710": (
        ["/c", "t.c"],
        "t.obj",
        "77c906d5556114c01e11cb6d6afa1beed3e0b0dea6f9f04351ce6775f9303071",
        "t.c",
        (4, 8),
    ),
    "msvc710sp1": (
        ["/c", "t.c"],
        "t.obj",
        "edf732bc642630021456f567636c08dac2ee2ef5a5cc6f69b646fcc0dc3377bf",
        "t.c",
        (4, 8),
    ),
    "msvc800": (
        ["/c", "t.c"],
        "t.obj",
        "c6d82406d884675a4be4910786da9350baa8b9e4ad1fb60de94abaa4e2e5bee2",
        "t.c",
        (4, 8),
    ),  # identical masked object to msvc800sp1 (same CL)
    "msvc800sp1": (
        ["/c", "t.c"],
        "t.obj",
        "c6d82406d884675a4be4910786da9350baa8b9e4ad1fb60de94abaa4e2e5bee2",
        "t.c",
        (4, 8),
    ),
    "msvc900": (
        ["/c", "t.c"],
        "t.obj",
        "8fed9b3cbb029773d2a5ec6aeb7a9643cee319005554a127a814c2862f1a80d4",
        "t.c",
        (4, 8),
    ),
    "msvc1000": (
        ["/c", "t.c"],
        "t.obj",
        "df2bfe3ec2234bb4525ae45136b7fe47b0e7f3af353662e13e8ae156b984ea0e",
        "t.c",
        (4, 8),
    ),
    "msvc1000sp1": (
        ["/c", "t.c"],
        "t.obj",
        "778fe81a9d24c919e7f19026f5ff4ef5f08435cbda4e33659435fd0ca96351be",
        "t.c",
        (4, 8),
    ),
    "msvc15": (
        ["/c", "t.c"],
        "t.OBJ",
        "d3bf67158b4d52bd24cb7b137e803491080cf221ffcd6b5dc9dafb885ab36dc2",
        "t.c",
        None,
    ),  # identical OMF to msvc1.52 (same 16-bit codegen)
    "msvc10": (
        ["/c", "t.c"],
        "t.OBJ",
        "d3bf67158b4d52bd24cb7b137e803491080cf221ffcd6b5dc9dafb885ab36dc2",
        "t.c",
        None,
    ),  # identical OMF to msvc1.52/msvc15 (same 16-bit codegen)
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
    "watcom16": (
        ["-fo=w.o", "t.c"],
        "w.o",
        "c44434a24aa1c6dbb36fe3a0a203992f79ea6e11cd95233da66e968ed4111acd",
        "t.c",
        None,  # wcc embeds the source path (fixed /tmp/rebrew-smoke) but no
        # timestamp — fixed-workdir runs are byte-identical (host-only).
    ),
    "delphi16": (
        ["hello.dpr"],
        "hello.EXE",
        "efd1ee34584a19852afe42cccf0b9e03b217c006c7132f50651a601c595630b9",
        "hello.dpr",
        None,
    ),
    "tc16": (
        ["t.c"],
        "t.OBJ",
        "2fc719cfdfa0ba7c61667505f41f8bbccf22cf716614ff53056073f40a48cd85",
        "t.c",
        [
            (48, 60),
            (201, 207),
        ],  # Borland COMENT run-timestamp (sub-second ticks) + record checksums
    ),
    "tc20": (
        ["t.c"],
        "t.OBJ",
        "20f53956d747afe5d0d66f2e3f2b9a8dbc8b7c150fd85dfdf774d12b5925cecc",
        "t.c",
        [
            (44, 49),
            (57, 58),
        ],  # Borland COMENT run-timestamp (sub-second ticks) + record checksum
    ),
}


@app.command("smoke")
def smoke_cmd(
    name: str | None = typer.Argument(None, help="Toolchain name; all image-backed by default"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    print_goldens: bool = typer.Option(
        False,
        "--print-goldens",
        help="Print the computed masked sha256 per toolchain (for updating "
        "_SMOKE_GOLDEN after a toolchain source change) instead of comparing",
    ),
) -> None:
    """Compile the fixed smoke source in each image and verify the object
    hash matches the golden bytes (reproducibility gate).

    Deterministic inputs: a FIXED work directory (/tmp/rebrew-smoke) and a
    FIXED source mtime (the object metadata embeds both the source path and
    its modification time — fresh writes would break the golden hashes).

    --print-goldens recomputes the masked hashes WITHOUT comparing, so a
    maintainer who bumps a pinned toolchain source (new tarball/snapshot)
    can regenerate the _SMOKE_GOLDEN table mechanically: run it, verify the
    new hashes are stable across a second run, then paste them in.
    """
    import hashlib
    import os
    import subprocess

    from rebrew.toolchain import get_toolchain

    # SOURCE_DATE_EPOCH convention: a fixed source mtime makes the object
    # metadata deterministic across runs.
    _SDE = 1767225600  # 2026-01-01 00:00:00 UTC

    targets = [name] if name else sorted(_SMOKE_GOLDEN)
    results: dict[str, str] = {}
    ok = True
    # A real-disk, docker-visible workdir (the system temp dir may be
    # tmpfs or docker-invisible in sandboxed environments).
    from rebrew.utils import writable_temp_dir

    workdir = writable_temp_dir("rebrew_smoke_")
    for tool in targets:
        spec = get_toolchain(tool)
        if spec.image is None and spec.host_path is None:
            results[tool] = "skip (no image, no vendored host tree)"
            continue
        flags, out_name, golden, src_name, mask = _SMOKE_GOLDEN[tool]
        src = _SMOKE_SOURCE if src_name == "t.c" else _SMOKE_DPR
        src_path = workdir / src_name
        src_path.write_text(src, encoding="utf-8")
        os.utime(src_path, (int(_SDE), int(_SDE)))
        if spec.image is not None:
            r = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{workdir}:/work",
                    "-w",
                    "/work",
                    spec.image,
                    *flags,
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )
            detail = (r.stdout + r.stderr)[-120:].strip()
        else:
            # Host-only vendored toolchain (msvc420/msvc5 under wine, watcom16
            # native wcc): gate its reproducibility through the uniform host
            # runner (resolves the vendored binary, sets the wine env).  The
            # same fixed-workdir + fixed-mtime determinism contract applies —
            # previously these had NO reproducibility gate at all.
            from rebrew.toolchain import ToolchainError, run_toolchain

            try:
                rr = run_toolchain(spec, flags, workdir=workdir, timeout=300)
                detail = (rr.stdout + rr.stderr)[-120:].strip()
            except ToolchainError as exc:
                results[tool] = "FAIL (" + str(exc)[-120:] + ")"
                ok = False
                continue
        obj = workdir / out_name
        if not obj.exists():
            results[tool] = "FAIL (no object: " + detail + ")"
            ok = False
            continue
        raw = obj.read_bytes()
        if mask is not None:
            # Zero the compiler's build-timestamp fields (e.g. the COFF
            # TimeDateStamp, or Turbo C's per-run COMENT ticks + record
            # checksums) — the rest of the object is what determinism
            # covers.  A single range or a list of ranges both work.
            ranges = mask if isinstance(mask, list) else [mask]
            masked = bytearray(raw)
            for start, end in ranges:
                masked[start:end] = b"\x00" * (end - start)
            raw = bytes(masked)
        actual = hashlib.sha256(raw).hexdigest()
        if print_goldens:
            results[tool] = actual
            obj.unlink(missing_ok=True)
            continue
        results[tool] = "OK" if actual == golden else f"MISMATCH ({actual[:12]}…)"
        ok = ok and actual == golden
        obj.unlink(missing_ok=True)
    if json_output:
        json_print({"goldens": results} if print_goldens else {"results": results, "passed": ok})
        return
    if print_goldens:
        for tool, h in results.items():
            console.print(f"  {tool:12s} {h}")
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


_SDE = 1767225600  # 2026-01-01 00:00:00 UTC — fixed source mtime so the
# object metadata is deterministic across runs.


def _image_smoke_hash(tool: str, workdir: Path) -> str | None:
    """Masked smoke-object sha256 for an image-backed toolchain (docker run).

    Image-backed goldens are workdir-independent (the container always sees
    the source at /work), so any host workdir gives the same hash — this is
    the helper 'rebrew toolchain update' uses to regenerate _SMOKE_GOLDEN
    after re-pinning and rebuilding an image.  Returns None when the
    compile produced no object."""
    import hashlib
    import os
    import subprocess

    from rebrew.toolchain import get_toolchain

    spec = get_toolchain(tool)
    if spec.image is None:
        return None
    flags, out_name, _golden, src_name, mask = _SMOKE_GOLDEN[tool]
    src = _SMOKE_SOURCE if src_name == "t.c" else _SMOKE_DPR
    src_path = workdir / src_name
    src_path.write_text(src, encoding="utf-8")
    os.utime(src_path, (int(_SDE), int(_SDE)))
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{workdir}:/work",
            "-w",
            "/work",
            spec.image,
            *flags,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    obj = workdir / out_name
    if not obj.exists():
        return None
    raw = obj.read_bytes()
    if mask is not None:
        ranges = mask if isinstance(mask, list) else [mask]
        masked = bytearray(raw)
        for start, end in ranges:
            masked[start:end] = b"\x00" * (end - start)
        raw = bytes(masked)
    obj.unlink(missing_ok=True)
    return hashlib.sha256(raw).hexdigest()


_CODELOAD_RE = r"https://codeload\.github\.com/([^/]+)/([^/]+)/tar\.gz/refs/heads/([A-Za-z0-9._-]+)"
_MOVING_RELEASE = "Last-CI-build"


def _github_auth_headers() -> dict[str, str]:
    """GitHub API headers (auth when GH_TOKEN/GITHUB_TOKEN is set)."""
    import os

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    base = {"User-Agent": "rebrew-toolchain"}
    if token:
        base["Authorization"] = f"Bearer {token}"
    return base


def _live_commit_sha(owner: str, repo: str, branch: str) -> str:
    """Current default-branch commit sha for a GitHub repo (GitHub API —
    cheap: no tarball download)."""
    import json
    import urllib.request

    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
    req = urllib.request.Request(url, headers=_github_auth_headers())
    with urllib.request.urlopen(req, timeout=20) as resp:
        return str(json.load(resp)["sha"])


@app.command("check-updates")
def check_updates_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Detect upstream drift in pinned toolchain sources.

    GitHub-codeload sources (archaic-msvc, archaic-toolchains, itsmattkc,
    open-watcom): compares the live default-branch commit sha (GitHub API —
    no download) against the commit the pin was taken from.  The Open
    Watcom snapshot (a moving 'Last-CI-build' release tag) is re-downloaded
    and re-hashed.  Immutable release assets (decomp.me, archive.org) and
    in-repo tarballs are reported as static."""
    import hashlib
    import re
    import tempfile
    import urllib.request

    from rebrew.toolchain import _SOURCES

    rows: dict[str, str] = {}
    drifted: list[str] = []
    for name, src in sorted(_SOURCES.items()):
        if src.in_repo:
            rows[name] = "static (in-repo tarball)"
            continue
        url = src.url or ""
        m = re.match(_CODELOAD_RE, url)
        if m:
            owner, repo, branch = m.group(1), m.group(2), m.group(3)
            try:
                live = _live_commit_sha(owner, repo, branch)
            except Exception as exc:  # noqa: BLE001
                rows[name] = f"check failed ({exc.__class__.__name__})"
                continue
            if not src.commit:
                rows[name] = f"unpinned (live {live[:12]})"
                continue
            if live == src.commit:
                rows[name] = "current"
            else:
                rows[name] = f"DRIFTED {src.commit[:12]} -> {live[:12]}"
                drifted.append(name)
            continue
        if _MOVING_RELEASE in url:
            try:
                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "src.bin"
                    urllib.request.urlretrieve(url, path)
                    actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual == src.sha256:
                    rows[name] = "current"
                else:
                    rows[name] = f"DRIFTED sha256 {src.sha256[:12]} -> {actual[:12]}"
                    drifted.append(name)
            except Exception as exc:  # noqa: BLE001
                rows[name] = f"check failed ({exc.__class__.__name__})"
            continue
        rows[name] = "static (immutable release asset)"
    if json_output:
        json_print({"toolchains": rows, "drifted": drifted})
        return
    for name, status in rows.items():
        color = (
            "green"
            if status == "current"
            else ("red" if status.startswith("DRIFTED") else "yellow")
        )
        console.print(f"  [{color}]{name:14s}[/] {status}")
    if drifted:
        console.print(
            "[red]drifted: "
            + ", ".join(drifted)
            + " — run 'rebrew toolchain update <name> --apply'[/red]"
        )


def _rewrite_source_pin(name: str, sha256: str, commit: str) -> None:
    """Rewrite the _SOURCES entry for *name* in toolchain.py (sha256 + commit).

    The entry block is located by the unique '"name": ToolchainSource('
    header; only the pinned sha256/commit lines inside it are touched, so a
    shared checksum across entries never mutates a neighbour."""
    import re

    path = Path(__file__).resolve().parent / "toolchain.py"
    text = path.read_text(encoding="utf-8")
    esc = re.escape(name)
    block = re.search('"' + esc + '": ToolchainSource\\((.*?)\\n\\s*\\),', text, re.S)
    if block is None:
        raise ToolchainError(f"could not locate _SOURCES entry for {name!r}")
    body = block.group(1)
    m = re.search(r'sha256="[0-9a-f]{64}"', body)
    if m is None:
        raise ToolchainError(f"no sha256 pin found for {name!r}")
    body = body[: m.start()] + f'sha256="{sha256}"' + body[m.end() :]
    if re.search(r'commit="[0-9a-f]{40}"', body):
        body = re.sub(r'commit="[0-9a-f]{40}"', f'commit="{commit}"', body, count=1)
    else:
        body = re.sub(
            r'(sha256="[0-9a-f]{64}",)(\n\s*)',
            r'\1\2commit="' + commit + r'",\2',
            body,
            count=1,
        )
    text = (
        text[: block.start()]
        + text[block.start() : block.end()].replace(block.group(1), body)
        + text[block.end() :]
    )
    path.write_text(text, encoding="utf-8")


def _rewrite_golden(name: str, golden: str) -> None:
    """Rewrite the _SMOKE_GOLDEN entry for *name* (the golden hex line)."""
    import re

    path = Path(__file__).resolve().parents[0] / "toolchain_cli.py"
    text = path.read_text(encoding="utf-8")
    esc = re.escape(name)
    block = re.search('"' + esc + '": \\(\\n(.*?)\\n\\s*\\),', text, re.S)
    if block is None:
        raise ToolchainError(f"no _SMOKE_GOLDEN entry for {name!r}")
    body = block.group(1)
    m = re.search(r'\n\s*"[0-9a-f]{64}",', body)
    if m is None:
        raise ToolchainError(f"no golden hex found for {name!r}")
    body = body[: m.start()] + '\n        "' + golden + '",' + body[m.end() :]
    text = (
        text[: block.start()]
        + text[block.start() : block.end()].replace(block.group(1), body)
        + text[block.end() :]
    )
    path.write_text(text, encoding="utf-8")


def _rewrite_dockerfile_sha(name: str, sha256: str) -> None:
    """Rewrite the sha256 pin embedded in the toolchain's Dockerfile.

    The Dockerfiles hardcode the sha256 (verified at build time with
    `sha256sum -c`), mirroring _SOURCES — a re-pin must update both or the
    image rebuild fails."""
    import re

    from rebrew.toolchain import get_toolchain

    spec = get_toolchain(name)
    if spec.image is None or ":" not in spec.image:
        return
    tag, verarch = spec.image.rsplit(":", 1)
    df = Path(__file__).resolve().parents[2] / "toolchain" / spec.family / verarch / "Dockerfile"
    if not df.exists():
        return
    text = df.read_text(encoding="utf-8")
    m = re.search(r"[0-9a-f]{64}", text)
    if m is None:
        return
    text = text[: m.start()] + sha256 + text[m.end() :]
    df.write_text(text, encoding="utf-8")


@app.command("update")
def update_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. msvc6, watcom)"),
    apply: bool = typer.Option(
        False, "--apply", help="Apply the re-pin, re-vendor, rebuild and re-golden"
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Re-pin a toolchain source to the current upstream and rebuild.

    Dry-run (default): downloads the current source and reports the
    old -> new pin (sha256 + commit).  --apply additionally rewrites
    _SOURCES, clears + re-vendors the host tree, rebuilds the docker
    image, regenerates the smoke golden (verified stable across two
    compiles) and runs the smoke gate for that toolchain."""
    import hashlib
    import re
    import shutil
    import subprocess
    import tempfile
    from dataclasses import replace

    from rebrew.toolchain import _REPO_TOOLS, _SOURCES, get_toolchain

    src = _SOURCES.get(name)
    if src is None:
        msg = f"no pinned source for toolchain {name!r} (known: {sorted(_SOURCES)})"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(code=2)
    if src.in_repo:
        msg = f"toolchain {name!r} is an in-repo tarball (static) — nothing to update"
        if json_output:
            json_print({"error": msg, "code": 2})
        else:
            console.print(f"[yellow]{msg}[/yellow]")
        raise typer.Exit(code=2)
    url = src.url
    with tempfile.TemporaryDirectory(prefix="rebrew_update_") as td:
        archive = Path(td) / "src.bin"
        subprocess.run(
            ["curl", "-sL", "-o", str(archive), url], check=True, timeout=1800, capture_output=True
        )
        actual_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual_sha == src.sha256:
            msg = f"toolchain {name!r} is already current (sha256 {src.sha256[:16]}…)"
            if json_output:
                json_print({"toolchain": name, "status": "current", "sha256": src.sha256})
            else:
                console.print(f"[green]{msg}[/green]")
            return
        m = re.match(_CODELOAD_RE, url)
        live_commit = ""
        if m:
            try:
                live_commit = _live_commit_sha(m.group(1), m.group(2), m.group(3))
            except Exception:  # noqa: BLE001
                live_commit = ""
        old_pin = f"sha256={src.sha256[:12]}…" + (
            f" commit={src.commit[:12]}" if src.commit else ""
        )
        new_pin = f"sha256={actual_sha[:12]}…" + (
            f" commit={live_commit[:12]}" if live_commit else ""
        )
        if json_output:
            json_print({"toolchain": name, "old": old_pin, "new": new_pin, "applied": False})
        else:
            console.print(f"[yellow]{name}:[/yellow] {old_pin} -> {new_pin}")
        if not apply:
            console.print(
                "[dim]dry-run — pass --apply to re-pin, re-vendor, rebuild and re-golden[/dim]"
            )
            return
        # 1. rewrite the pin in _SOURCES (file) + the in-memory dict so
        #    vendor_cmd below verifies against the new sha256.
        _rewrite_source_pin(name, actual_sha, live_commit)
        _rewrite_dockerfile_sha(name, actual_sha)
        _SOURCES[name] = replace(src, sha256=actual_sha, commit=live_commit)
        # 2. clear the vendored host tree (keep Dockerfile/wrappers) + re-vendor.
        host = _REPO_TOOLS / src.host_dir
        _META_PATTERNS = ("Dockerfile", "pak_extract.py", "wrapper-common.sh", "*.sh", "*.tar.xz")
        if host.exists():
            for child in list(host.iterdir()):
                if any(child.match(p) for p in _META_PATTERNS):
                    continue
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
        vendor_cmd(name, json_output=False)
        # 3. rebuild the docker image.
        build_cmd(name, json_output=False)
        # 4. regenerate the smoke golden (stable across two compiles) + write it.
        from rebrew.utils import writable_temp_dir

        workdir = writable_temp_dir("rebrew_smoke_")
        h1 = _image_smoke_hash(name, workdir)
        h2 = _image_smoke_hash(name, workdir)
        if h1 is None or h2 is None:
            msg = f"update {name}: smoke compile failed after rebuild — golden not updated"
            if json_output:
                json_print({"error": msg, "code": 2})
            else:
                console.print(f"[red]Error:[/red] {msg}")
            raise typer.Exit(code=2)
        if h1 != h2:
            msg = (
                f"update {name}: smoke hash unstable ({h1[:12]} vs {h2[:12]}) — golden not updated"
            )
            if json_output:
                json_print({"error": msg, "code": 2})
            else:
                console.print(f"[red]Error:[/red] {msg}")
            raise typer.Exit(code=2)
        golden_changed = name in _SMOKE_GOLDEN and _SMOKE_GOLDEN[name][2] != h1
        if name in _SMOKE_GOLDEN:
            _rewrite_golden(name, h1)
        if json_output:
            json_print(
                {
                    "toolchain": name,
                    "sha256": actual_sha,
                    "commit": live_commit,
                    "golden": h1,
                    "golden_changed": golden_changed,
                    "applied": True,
                }
            )
        else:
            console.print(f"[green]{name} re-pinned:[/green] {new_pin}")
            console.print(f"  host tree re-vendored, image rebuilt ({get_toolchain(name).image})")
            if name in _SMOKE_GOLDEN:
                if golden_changed:
                    console.print(f"  smoke golden updated: {h1[:16]}…")
                else:
                    console.print(f"  smoke golden unchanged ({h1[:16]}…)")
            else:
                console.print("[dim]  no smoke golden for this toolchain[/dim]")


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
