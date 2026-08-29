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

from rebrew.cli import TargetOption, error_exit, json_print
from rebrew.toolchain import (
    ToolchainError,
    docker_available,
    list_toolchains,
    pull_toolchain,
)

console = Console(stderr=True)

#: Cap on each archive-extraction subprocess in `rebrew toolchain vendor`
#: (matches the curl download timeout).  Without it a stuck filesystem or
#: an unzip prompting for an encrypted-archive password hangs forever.
_EXTRACT_TIMEOUT_S = 1800

app = typer.Typer(
    help="Standardized toolchain management (Windows/DOS profiles run in docker).",
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
    show_origin = any(r.get("origin", "packaged") != "packaged" for r in rows)
    columns = ["Name", "Image", "Binary", "Runtime", "Flags", "Obj"]
    if show_origin:
        columns.append("Origin")
    for col in columns:
        table.add_column(col)
    for r in rows:
        row = [
            r["name"],
            r["image"] or "host-only",
            r["binary"],
            r["runtime"],
            r["flags_style"],
            r["obj_ext"],
        ]
        if show_origin:
            row.append(r.get("origin", "packaged"))
        table.add_row(*row)
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

    from rebrew.toolchain import get_toolchain, vendored_binary

    spec = get_toolchain(name)
    host_ok: bool | None = None
    resolved_cmd: str | None = None
    if spec.host_path is not None:
        # Informational: the vendored tree (source for image builds) —
        # nothing executes from it anymore.
        try:
            hit = vendored_binary(spec)
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
    except Exception as exc:  # detection is best-effort
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
        error_exit(str(exc), json_mode=json_output)
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

    Downloads (sha256-verified) or extracts the pinned tarball into
    ``<family>/<version>-<arch>/source`` under the rebrew-toolchains
    checkout — the same source the docker image builds from, so host trees
    and containers are byte-identical.  Refuses to clobber an existing tree
    unless empty.
    """
    import hashlib
    import subprocess
    import tempfile

    from rebrew.toolchain import _SOURCES, REPO_TOOLS, require_toolchains_repo

    require_toolchains_repo()
    src = _SOURCES.get(name)
    if src is None:
        msg = f"no pinned source for toolchain {name!r} (known: {sorted(_SOURCES)})"
        error_exit(msg, json_mode=json_output)

    host = REPO_TOOLS / src.host_dir
    # Canonical layout: every vendored tree nests the actual toolchain one
    # level under ``source/`` (<family>/<ver>-<arch>/source/...), so all
    # toolchain folders share the same shape.  Tracked metadata (Dockerfile,
    # wrapper scripts, the pinned tarball, pak_extract.py) lives beside it
    # and is not vendored content, so a dir holding only those is empty for
    # clobber purposes.
    _META = {
        "Dockerfile",
        "pak_extract.py",
        "wrapper-common.sh",
        ".dockerignore",
        *("*.sh", "*.tar.xz", "*.md"),
    }
    content = (
        [p for p in host.iterdir() if not any(p.match(m) for m in _META)] if host.exists() else []
    )
    if content:
        msg = f"{host} already has files — refusing to clobber"
        error_exit(msg, json_mode=json_output)
    host.mkdir(parents=True, exist_ok=True)
    extract_dir = host / "source"
    extract_dir.mkdir()

    try:
        if src.is_in_repo():
            tarball = REPO_TOOLS / src.in_repo
            subprocess.run(
                # No explicit -z/-J: GNU tar auto-detects gzip/xz compression,
                # so in-repo .tar.xz and remote codeload .tar.gz both extract.
                ["tar", "xf", str(tarball), "-C", str(extract_dir)],
                check=True,
                capture_output=True,
                timeout=_EXTRACT_TIMEOUT_S,
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
                    error_exit(msg, json_mode=json_output)
                if src.layout == "zip-installshield":
                    subprocess.run(
                        ["unzip", "-q", str(archive), "-d", td + "/zip"],
                        check=True,
                        capture_output=True,
                        stdin=subprocess.DEVNULL,
                        timeout=_EXTRACT_TIMEOUT_S,
                    )
                    installer = next(Path(td + "/zip").iterdir())
                    subprocess.run(
                        ["7z", "x", "-y", str(installer), f"-o{td}/pay"],
                        capture_output=True,
                        stdin=subprocess.DEVNULL,
                        timeout=_EXTRACT_TIMEOUT_S,
                    )  # warning exits tolerated — the final check below guards
                    payload = Path(td + "/pay")
                    for sub in ("Bin", "Include", "Lib"):
                        (payload / sub).rename(extract_dir / sub)
                elif src.layout == "zip-strip1":
                    # A zip with a single top-level wrapper dir (e.g. TC/) —
                    # strip the wrapper so BIN/INCLUDE/LIB sit at the top of
                    # the host tree like the other toolchains.
                    subprocess.run(
                        ["unzip", "-q", str(archive), "-d", td + "/zip"],
                        check=True,
                        capture_output=True,
                        stdin=subprocess.DEVNULL,
                        timeout=_EXTRACT_TIMEOUT_S,
                    )
                    payload = Path(td + "/zip")
                    contents = [p for p in payload.iterdir() if p.is_dir()]
                    if len(contents) == 1 and not any(p.is_file() for p in payload.iterdir()):
                        payload = contents[0]
                    for child in payload.iterdir():
                        child.rename(extract_dir / child.name)
                elif src.layout == "tar-strip1":
                    subprocess.run(
                        # Auto-detect compression (no -z/-J): the pinned
                        # sources are gzip codeload tarballs (msvc400/420/5)
                        # and xz snapshots (watcom) alike.
                        ["tar", "xf", str(archive), "-C", str(extract_dir), "--strip-components=1"],
                        check=True,
                        capture_output=True,
                        timeout=_EXTRACT_TIMEOUT_S,
                    )
                else:
                    subprocess.run(
                        ["tar", "xzf", str(archive), "-C", str(extract_dir)],
                        check=True,
                        capture_output=True,
                        timeout=_EXTRACT_TIMEOUT_S,
                    )
                console.print(f"[green]Downloaded + verified[/green] {src.url} -> {src.host_dir}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        msg = f"vendor {name} failed: {exc}"
        error_exit(msg, json_mode=json_output)

    # MSVC 6.0's classic master layout wraps the tree in VC98/ (the decomp.me
    # tarball is flat) — canonical config paths and every legacy
    # tools/MSVC600/VC98/... reference expect the wrapper.
    if src.vc98_wrap and not (extract_dir / "VC98").exists():
        vc98 = extract_dir / "VC98"
        vc98.mkdir()
        for child in list(extract_dir.iterdir()):
            if child == vc98 or any(child.match(m) for m in _META):
                continue
            child.rename(vc98 / child.name)

    # The archaic MSVC 6.0 SP5 repo stashes mspdb60.dll in the IDE dir
    # (Common/MSDev98/Bin) while CL.EXE 12.00.8804 statically imports it and
    # only searches its own directory — relocate the official file so host
    # compiles work (the sp5 Dockerfile does the same relocation).
    ide_dll = extract_dir / "Common" / "MSDev98" / "Bin" / "MSPDB60.DLL"
    bin_dll = extract_dir / "VC98" / "Bin" / "MSPDB60.DLL"
    if ide_dll.exists() and not bin_dll.exists():
        bin_dll.write_bytes(ide_dll.read_bytes())
        console.print("[dim]relocated MSPDB60.DLL -> VC98/Bin (CL requires it in-dir)[/dim]")

    # Guard: a bad extraction must fail loudly (the images do the same).
    # Probe the ACTUAL extracted dir (src.host_dir) — the spec's host_path
    # is captured at import time and may predate the extraction.
    from rebrew.toolchain import get_toolchain, vendored_binary

    spec = get_toolchain(name)
    probe = vendored_binary(replace(spec, host_path=host))
    if probe is None:
        # Pre-source/ flat layout (trees vendored before the canonical
        # nesting) — still resolve so re-vendoring is not blocked.
        probe = vendored_binary(replace(spec, host_path=host / "source"))
    if probe is None:
        msg = f"vendor {name} produced no {spec.binary} under {host}"
        error_exit(msg, json_mode=json_output)

    if json_output:
        json_print({"vendored": src.host_dir, "binary": str(probe)})


#: Golden object hashes — the byte-exact output each toolchain image must
#: produce for the fixed smoke source (reproducibility evidence: the same
#: source + toolchain → the same object, every build).
_SMOKE_SOURCE = "int add(int a, int b) { return a + b; }\n"
_SMOKE_DPR = "program hello;\nbegin\nend.\n"
# SOURCE_DATE_EPOCH convention: a fixed source mtime makes the object
# metadata deterministic across runs (the object embeds the source path
# and its modification time — fresh writes would break the golden hashes).
_SDE = 1767225600  # 2026-01-01 00:00:00 UTC
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
    "msvc600sp1": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — identical masked object to msvc6 (same CL+C1)
    "msvc600sp2": (
        ["/c", "t.c"],
        "t.obj",
        "4b50f0dbba945a5bc80f9e40ed05bcfb06505fff2204a4b567192c7e5fb1e224",
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
    "msvc600sp4": (
        ["/c", "t.c"],
        "t.obj",
        "e9427fee0356ef5f8f569e2450a75b753e5fc28070b5d31916516992bbb20687",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — same C1 as sp5 but distinct comp.id (image path)
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
    "msvc900sp1": (
        ["/c", "t.c"],
        "t.obj",
        "c11006fdd4ae42814472be29f400b8147bd3d42e4f976de9248727bb7459b8d8",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — 15.00.30729 SP1 compiler
    "msvc1100": (
        ["/c", "t.c"],
        "t.obj",
        "90f064ea1bd8f8b76e7df38a8d3bfc0905b68f9b523d219e575bf3bda9e20bd5",
        "t.c",
        (4, 8),
    ),  # COFF TimeDateStamp — 17.00.50522 VS2012 compiler
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
    "ido5.3": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "23d42a2d1b2bf56d013a803db6d0d458c693e48f932d1859ad9ec5df881018a6",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
    ),
    "ido7.1": (
        ["-c", "-O2", "-o", "t.o", "t.c"],
        "t.o",
        "6af67c000618e1acb476b58ff8dae30e727934ad78e819bc87305d7e2ebc8672",
        "t.c",
        None,  # ELF object — no timestamp; src path/mtime are fixed by the gate
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

    Deterministic inputs: a FIXED work directory and a FIXED source mtime
    (the object metadata embeds both the source path and its modification
    time — fresh writes would break the golden hashes).

    --print-goldens recomputes the masked hashes WITHOUT comparing, so a
    maintainer who bumps a pinned toolchain source (new tarball/snapshot)
    can regenerate the _SMOKE_GOLDEN table mechanically: run it, verify the
    new hashes are stable across a second run, then paste them in.
    """
    import os
    import subprocess

    from rebrew.toolchain import get_toolchain

    targets = [name] if name else sorted(_SMOKE_GOLDEN)
    results: dict[str, str] = {}
    ok = True
    # A real-disk, docker-visible workdir (the system temp dir may be
    # tmpfs or docker-invisible in sandboxed environments).
    from rebrew.utils import remove_temp_dir, writable_temp_dir

    workdir = writable_temp_dir("rebrew_smoke_")
    try:
        for tool in targets:
            spec = get_toolchain(tool)
            if spec.image is None and spec.host_path is None:
                results[tool] = "skip (no image, no vendored host tree)"
                continue
            flags, out_name, golden, src_name, mask = _SMOKE_GOLDEN[tool]
            src = _SMOKE_SOURCE if src_name == "t.c" else _SMOKE_DPR
            src_path = workdir / src_name
            src_path.write_text(src, encoding="utf-8")
            os.utime(src_path, (_SDE, _SDE))
            if spec.image is not None:
                container = f"rebrew-smoke-{spec.name}-{tool}"
                try:
                    r = subprocess.run(
                        [
                            "docker",
                            "run",
                            "--rm",
                            "--network=none",  # compile-only container
                            # Named so the timeout path can kill it (a killed
                            # docker CLI leaves the container under dockerd).
                            "--name",
                            container,
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
                except subprocess.TimeoutExpired:
                    from rebrew.toolchain import kill_container

                    kill_container(container)
                    results[tool] = "FAIL (docker run timed out after 300s)"
                    ok = False
                    continue
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
            # Zero the compiler's build-timestamp fields (e.g. the COFF
            # TimeDateStamp, or Turbo C's per-run COMENT ticks + record
            # checksums) — the rest of the object is what determinism
            # covers.  A single range or a list of ranges both work.
            actual = _masked_obj_sha256(obj, mask)
            if print_goldens:
                results[tool] = actual
                obj.unlink(missing_ok=True)
                continue
            results[tool] = "OK" if actual == golden else f"MISMATCH ({actual[:12]}…)"
            ok = ok and actual == golden
            obj.unlink(missing_ok=True)
        if json_output:
            json_print(
                {"goldens": results} if print_goldens else {"results": results, "passed": ok}
            )
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
    finally:
        remove_temp_dir(workdir)


@app.command("build")
def build_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. watcom, msvc6)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Build a toolchain's docker image from the rebrew-toolchains checkout."""
    import subprocess

    from rebrew.toolchain import (
        REPO_TOOLS,
        ToolchainError,
        get_toolchain,
        require_toolchains_repo,
        swap_toolchain_image,
    )

    require_toolchains_repo()
    spec = get_toolchain(name)
    if spec.image is None:
        msg = f"toolchain {name!r} is host-only (no image to build)"
        error_exit(msg, json_mode=json_output)
    if spec.image is None or ":" not in spec.image:
        msg = f"toolchain {name!r} image tag {spec.image!r} has no version-arch tag"
        error_exit(msg, json_mode=json_output)
    tag, verarch = spec.image.rsplit(":", 1)
    image = spec.image  # narrowed local — mypy does not narrow into the closure
    build_dir = REPO_TOOLS / spec.family / verarch
    if not (build_dir / "Dockerfile").exists():
        msg = f"no Dockerfile at {build_dir}"
        error_exit(msg, json_mode=json_output)

    # Every toolchain image inherits FROM rebrew/base — build it first so a
    # fresh docker daemon resolves the dependency.
    base_dir = REPO_TOOLS / "base"
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
                error_exit(msg, json_mode=json_output)

    # Build through swap_toolchain_image (backup→swap→rollback): docker tags
    # on success, and a failed build leaves the previous image under the tag —
    # the swap verifies that and restores it if the tag was ever left dangling.
    def _build_image() -> None:
        r = subprocess.run(
            ["docker", "build", "-t", image, str(build_dir)],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        if r.returncode != 0:
            raise ToolchainError(f"docker build {image} failed: {r.stderr[-300:]}")

    try:
        swap_toolchain_image(image, _build_image)
    except ToolchainError as exc:
        msg = str(exc)
        error_exit(msg, json_mode=json_output)
    if json_output:
        json_print({"built": spec.image})
    else:
        console.print(f"[green]Built[/green] {spec.image}")


def _masked_obj_sha256(obj: Path, mask: tuple[int, int] | list[tuple[int, int]] | None) -> str:
    """sha256 of *obj* with the masked byte ranges zeroed (golden hashing)."""
    import hashlib

    raw = obj.read_bytes()
    if mask is not None:
        ranges = mask if isinstance(mask, list) else [mask]
        masked = bytearray(raw)
        for start, end in ranges:
            masked[start:end] = b"\x00" * (end - start)
        raw = bytes(masked)
    return hashlib.sha256(raw).hexdigest()


def _image_smoke_hash(tool: str, workdir: Path) -> str | None:
    """Masked smoke-object sha256 for an image-backed toolchain (docker run).

    Image-backed goldens are workdir-independent (the container always sees
    the source at /work), so any host workdir gives the same hash — this is
    the helper 'rebrew toolchain update' uses to regenerate _SMOKE_GOLDEN
    after re-pinning and rebuilding an image.  Returns None when the
    compile produced no object."""
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
    os.utime(src_path, (_SDE, _SDE))
    # Named so the timeout path can kill it (a killed docker CLI leaves the
    # container under dockerd) — same discipline as smoke_cmd above.
    container = f"rebrew-smoke-hash-{tool}"
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",  # compile-only container
                "--name",
                container,
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
    except subprocess.TimeoutExpired:
        from rebrew.toolchain import kill_container

        kill_container(container)
        return None
    except OSError:
        # A hung daemon or missing docker degrades to "no object" — the
        # caller reports the golden mismatch instead of crashing mid-update.
        return None
    obj = workdir / out_name
    if not obj.exists():
        return None
    digest = _masked_obj_sha256(obj, mask)
    obj.unlink(missing_ok=True)
    return digest


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
    import httpx

    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{branch}"
    resp = httpx.get(url, headers=_github_auth_headers(), timeout=20, follow_redirects=True)
    resp.raise_for_status()
    return str(resp.json()["sha"])


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
    pinned tarballs (16-bit media in the rebrew-toolchains checkout) are
    reported as static."""
    import hashlib
    import re
    import tempfile

    import httpx

    from rebrew.toolchain import _SOURCES

    rows: dict[str, str] = {}
    drifted: list[str] = []
    for name, src in sorted(_SOURCES.items()):
        if src.in_repo:
            rows[name] = "static (pinned tarball in rebrew-toolchains)"
            continue
        url = src.url or ""
        m = re.match(_CODELOAD_RE, url)
        if m:
            owner, repo, branch = m.group(1), m.group(2), m.group(3)
            try:
                live = _live_commit_sha(owner, repo, branch)
            except Exception as exc:
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
                    with httpx.stream("GET", url, timeout=60, follow_redirects=True) as resp:
                        resp.raise_for_status()
                        with path.open("wb") as fh:
                            for chunk in resp.iter_bytes():
                                fh.write(chunk)
                    actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual == src.sha256:
                    rows[name] = "current"
                else:
                    rows[name] = f"DRIFTED sha256 {src.sha256[:12]} -> {actual[:12]}"
                    drifted.append(name)
            except Exception as exc:
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

    from rebrew.toolchain import REPO_TOOLS, get_toolchain

    spec = get_toolchain(name)
    if spec.image is None or ":" not in spec.image:
        return
    tag, verarch = spec.image.rsplit(":", 1)
    df = REPO_TOOLS / spec.family / verarch / "Dockerfile"
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
    import contextlib
    import hashlib
    import re
    import shutil
    import subprocess
    import tempfile
    from dataclasses import replace

    from rebrew.toolchain import _SOURCES, REPO_TOOLS, get_toolchain, require_toolchains_repo

    require_toolchains_repo()
    src = _SOURCES.get(name)
    if src is None:
        msg = f"no pinned source for toolchain {name!r} (known: {sorted(_SOURCES)})"
        error_exit(msg, json_mode=json_output)
    if src.in_repo:
        msg = f"toolchain {name!r} is a pinned tarball (static) — nothing to update"
        error_exit(msg, json_mode=json_output)
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
            except Exception:
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
        # 1-3. Rewrite pin → clear + re-vendor → rebuild, transactionally:
        #      a failure at any step must not leave the source pin ahead of
        #      the image (a half-registered state) — restore the previous pin
        #      before propagating.  The vendored host tree is a reproducible
        #      artifact; the pin (the registration) is what the rollback
        #      restores, so the repo state matches the unchanged image.
        try:
            # 1. rewrite the pin in _SOURCES (file) + the in-memory dict so
            #    vendor_cmd below verifies against the new sha256.
            _rewrite_source_pin(name, actual_sha, live_commit)
            _rewrite_dockerfile_sha(name, actual_sha)
            _SOURCES[name] = replace(src, sha256=actual_sha, commit=live_commit)
            # 2. clear the vendored host tree (keep Dockerfile/wrappers) + re-vendor.
            host = REPO_TOOLS / src.host_dir
            _META_PATTERNS = (
                "Dockerfile",
                "pak_extract.py",
                "wrapper-common.sh",
                "*.sh",
                "*.tar.xz",
            )
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
        except Exception:
            # Rollback the pin (file + Dockerfile) to the pre-update values.
            with contextlib.suppress(ToolchainError):
                _rewrite_source_pin(name, src.sha256, src.commit)
                _rewrite_dockerfile_sha(name, src.sha256)
            raise
        # 4. regenerate the smoke golden (stable across two compiles) + write it.
        from rebrew.utils import remove_temp_dir, writable_temp_dir

        workdir = writable_temp_dir("rebrew_smoke_")
        try:
            h1 = _image_smoke_hash(name, workdir)
            h2 = _image_smoke_hash(name, workdir)
            if h1 is None or h2 is None:
                msg = f"update {name}: smoke compile failed after rebuild — golden not updated"
                error_exit(msg, json_mode=json_output)
            if h1 != h2:
                msg = f"update {name}: smoke hash unstable ({h1[:12]} vs {h2[:12]}) — golden not updated"
                error_exit(msg, json_mode=json_output)
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
                console.print(
                    f"  host tree re-vendored, image rebuilt ({get_toolchain(name).image})"
                )
                if name in _SMOKE_GOLDEN:
                    if golden_changed:
                        console.print(f"  smoke golden updated: {h1[:16]}…")
                    else:
                        console.print(f"  smoke golden unchanged ({h1[:16]}…)")
                else:
                    console.print("[dim]  no smoke golden for this toolchain[/dim]")
        finally:
            remove_temp_dir(workdir)


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
