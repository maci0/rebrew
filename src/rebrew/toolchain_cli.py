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
        "packed": info.packed or None,
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


def main_entry() -> None:
    """Run the Typer CLI application."""
    app()


if __name__ == "__main__":
    main_entry()
