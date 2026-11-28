"""toolchain_cli — `rebrew toolchain` subcommands.

Standardized toolchain management: list the registry, check docker status,
and pull toolchain images.  This is the host-side face of the
docker-first toolchain abstraction (see rebrew.compiler.toolchain): every compiler
profile resolves to a ToolchainSpec, and the CLI surfaces how each is
invoked (docker image vs vendored path vs PATH binary).
"""

from __future__ import annotations

from typing import Any
lazy import logging
lazy import re
lazy import shutil
lazy import subprocess
lazy import time as time
lazy from pathlib import Path
lazy from string import Template

import typer

from rebrew.cli import (
    EXIT_ERROR,
    EXIT_MISMATCH,
    EXIT_OK,
    TargetOption,
    console,
    error_exit,
    json_print,
    require_config,
)
lazy from rebrew.compiler.toolchain import (
    ToolchainError,
    docker_available,
    list_toolchains,
    pull_toolchain,
)
lazy from rebrew.toolchain_cli.smoke import (
    SDE as _SDE,
)
lazy from rebrew.toolchain_cli.smoke import (
    SMOKE_DPR as _SMOKE_DPR,
)
lazy from rebrew.toolchain_cli.smoke import (
    SMOKE_GOLDEN as _SMOKE_GOLDEN,
)
lazy from rebrew.toolchain_cli.smoke import (
    SMOKE_SOURCE as _SMOKE_SOURCE,
)
lazy from rebrew.toolchain_cli.smoke import (
    SMOKE_TIMEOUT_S as _SMOKE_TIMEOUT_S,
)
lazy from rebrew.toolchain_cli.smoke import (
    build_failure as _build_failure,
)
lazy from rebrew.toolchain_cli.smoke import (
    declared_target as _declared_target,
)
lazy from rebrew.toolchain_cli.smoke import (
    docker_build,
    run_smoke_container,
)
lazy from rebrew.toolchain_cli.smoke import (
    masked_obj_sha256 as _masked_obj_sha256,
)
lazy from rebrew.toolchain_cli.smoke import (
    object_target as _object_target,
)
lazy from rebrew.toolchain_cli.updates import (
    MOVING_RELEASE as _MOVING_RELEASE,
)
lazy from rebrew.toolchain_cli.updates import (
    STATUS_CURRENT as STATUS_CURRENT,
)
lazy from rebrew.toolchain_cli.updates import (
    STATUS_STATIC_ASSET as STATUS_STATIC_ASSET,
)
lazy from rebrew.toolchain_cli.updates import (
    STATUS_STATIC_TARBALL as STATUS_STATIC_TARBALL,
)
lazy from rebrew.toolchain_cli.updates import (
    codeload_pattern as _codeload_pattern,
)
lazy from rebrew.toolchain_cli.updates import (
    codeload_ref as _codeload_ref,
)
lazy from rebrew.toolchain_cli.updates import (
    live_commit_sha as _live_commit_sha,
)
lazy from rebrew.toolchain_cli.vendor import (
    EXTRACT_TIMEOUT_S as _EXTRACT_TIMEOUT_S,
)
lazy from rebrew.toolchain_cli.vendor import (
    TRACKED_META_PATTERNS as _TRACKED_META_PATTERNS,
)
lazy from rebrew.toolchain_cli.vendor import (
    abort_incomplete_vendor as _abort_incomplete_vendor,
)
lazy from rebrew.toolchain_cli.vendor import (
    download_pinned_url as _download_pinned_url,
)
lazy from rebrew.toolchain_cli.vendor import (
    flatten_wrapper_dir as _flatten_wrapper_dir,
)
lazy from rebrew.toolchain_cli.vendor import (
    probe_vendored as _probe_vendored,
)
lazy from rebrew.toolchain_cli.vendor import (
    safe_extract_tar as _safe_extract_tar,
)
lazy from rebrew.toolchain_cli.vendor import (
    vendor_tree_complete as _vendor_tree_complete,
)
lazy from rebrew.utils import (
    TerminalTable,
    container_runtime,
    run_process_group,
    sha256_file,
)


def _docker_build(tag: str, context: Path, *, stream: bool) -> tuple[int, str]:
    """Run ``docker build`` via the module-bound runtime and process runner."""
    return docker_build(
        tag,
        context,
        stream=stream,
        run_fn=run_process_group,
        runtime_fn=container_runtime,
    )


def _run_smoke_container(
    image: str, name_prefix: str, workdir: Path, flags: list[str], *, kvm: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run the smoke container via the module-bound runtime and process runner."""
    return run_smoke_container(
        image,
        name_prefix,
        workdir,
        flags,
        kvm=kvm,
        run_fn=run_process_group,
        runtime_fn=container_runtime,
    )


app = typer.Typer(
    help="Manage compiler profiles and Docker images for shipped toolchains.",
    rich_markup_mode="rich",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew toolchain list\n\n"
        "  rebrew toolchain status msvc-6.0\n\n"
        "  rebrew toolchain detect original/game.exe\n\n"
        "  rebrew toolchain pull msvc-6.0\n\n"
        "  rebrew toolchain build msvc-6.0\n\n"
        "[dim]Shipped profiles compile in Docker. pull downloads an image; build uses the sibling recompile-toolchains checkout (or REBREW_TOOLCHAINS_DIR). vendor assembles compiler files for image builds. A missing image is an error; host Wine/wibo/DOSBox are not fallbacks.[/dim]\n\n"
    ),
)


@app.command(
    "list",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew toolchain list --json\n\n"),
)
def list_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """List known toolchains and how each is invoked."""
    rows = list_toolchains()
    if json_output:
        json_print({"toolchains": rows, "docker_available": docker_available()})
        return
    table = TerminalTable(title="Toolchains", header_style="bold")
    show_origin = any(r.get("origin", "packaged") != "packaged" for r in rows)
    columns = ["Name", "Image", "Binary", "Runtime", "Flags", "Obj"]
    if show_origin:
        columns.append("Origin")
    columns.append("Withdrawn")
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
        row.append(r["withdrawn"] or "")
        table.add_row(*row)
    console.print(table)
    console.print(f"[dim]docker: {'available' if docker_available() else 'NOT available'}[/dim]")


@app.command(
    "status",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew toolchain status msvc-6.0 --json\n\n"),
)
def status_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. msvc-6.0, delphi-1.0)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Show how one toolchain resolves (image built? vendored tree present?).

    Execution is Docker-only for every shipped toolchain, so the image state is the primary signal; the vendored tree is informational (it is the byte-identical source the image builds from).
    """
    from rebrew.compiler.toolchain import get_toolchain, vendored_binary

    try:
        spec = get_toolchain(name)
    except ToolchainError as exc:
        error_exit(str(exc), json_mode=json_output)
    host_ok: bool | None = None
    resolved_cmd: str | None = None
    host_probe_error: str | None = None
    if spec.host_path is not None:
        # Informational: the vendored tree (source for image builds) —
        # nothing executes from it anymore.
        try:
            hit = vendored_binary(spec)
            host_ok = hit is not None
            if hit is not None:
                resolved_cmd = str(hit)
        except Exception as exc:
            # "absent" would tell the operator to rebuild a toolchain that is
            # installed; the failure to probe is the fact worth reporting.
            host_ok = None
            host_probe_error = str(exc)
    elif spec.image is None:
        # An image-less spec (a plugin toolchain) execs its binary directly —
        # that IS the execution path.
        host_ok = shutil.which(spec.binary) is not None
    image_ok: bool | None = None
    if spec.image is not None and docker_available():
        try:
            r = run_process_group(
                [container_runtime(), "image", "inspect", spec.image],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            # A hung daemon / missing docker must not crash a status probe
            # (and must not be reported as "image not pulled").
            logging.getLogger(__name__).warning(
                "docker image inspect for %s failed: %s", spec.image, exc
            )
            image_ok = None
        else:
            image_ok = r.returncode == 0
    data: dict[str, Any] = {
        "name": spec.name,
        "image": spec.image,
        "image_pulled": image_ok,
        "host_binary_present": host_ok,
        "host_probe_error": host_probe_error,
        "resolved_host": resolved_cmd,
        "binary": spec.binary,
        "description": spec.description,
    }
    if json_output:
        json_print(data)
        return
    console.print(f"[bold]{spec.name}[/bold]: {spec.description}")
    image_state = "pulled" if image_ok else ("not pulled" if image_ok is False else "")
    console.print(f"  image:  {spec.image or 'host-only'}  {image_state}")
    if resolved_cmd:
        console.print(f"  host:   {resolved_cmd}  present (resolved mirror)")
    elif host_probe_error is not None:
        console.print(
            f"  host:   {spec.host_path or spec.binary}  probe failed: {host_probe_error}"
        )
    else:
        host_state = "present" if host_ok else "absent"
        console.print(f"  host:   {spec.host_path or spec.binary}  {host_state}")


def external_ranges(cfg: Any) -> list[tuple[int, int]]:
    """The project's library bands as ``[(lo, hi)]`` (empty without a project)."""
    out: list[tuple[int, int]] = []
    for entry in getattr(cfg, "external_ranges", None) or ():
        if isinstance(entry, (tuple, list)) and len(entry) == 2:
            out.append((int(entry[0]), int(entry[1])))
            continue
        text = str(entry).strip()
        if "-" in text:
            lo, _, hi = text.partition("-")
            try:
                out.append((int(lo, 16), int(hi.strip(), 16)))
            except ValueError:
                continue
    return out


@app.command(
    "detect",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew toolchain detect original/game.exe --json\n\n"),
)
def detect_cmd(
    binary: str = typer.Argument(
        ...,
        help="Path to the target binary (PE/NE/ELF/Mach-O)",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Detect which compiler/toolchain built a binary; check profile alignment."""
    from rebrew.toolchain_detect import (
        detect_toolchain,
        detection_tables,
        profile_matches_detection,
    )

    binary_path = Path(binary)
    if not binary_path.is_file():
        error_exit(f"Binary not found: {binary}", json_mode=json_output, code=EXIT_ERROR)
    # Load the project first (best effort): its external_ranges pad the
    # library bands, and library objects were compiled with Microsoft's own
    # settings — the code-generator family must be read from GAME code only.
    cfg = None
    try:
        from rebrew.config import load_config

        cfg = load_config(target=target)
    except (FileNotFoundError, KeyError, ValueError) as exc:
        # Without cfg the library bands are never excluded, so the family and
        # era signals get measured over the project's own static libraries.
        logging.getLogger(__name__).warning(
            "project config not loaded (%s), library bands not excluded from the "
            "code-generator signals",
            exc,
        )
        cfg = None
    exclude = external_ranges(cfg)
    try:
        info = detect_toolchain(binary_path, exclude_ranges=exclude)
    except Exception as exc:  # detection is best-effort
        error_exit(f"Detection failed: {exc}", json_mode=json_output, code=EXIT_ERROR)

    # The plugin-merged table, the same one profile_matches_detection
    # reads: the packaged-only table would report a plugin family as
    # unmatchable while the alignment check right below calls it aligned.
    compat: set[str] | None = detection_tables().profile_compat.get(info.family)
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
        "packed": info.packed,
        "packer": info.packer,
        "codegen": info.codegen,
        "msvc_version": info.msvc_version or None,
        "suggested_profiles": info.suggested_profiles or None,
        "compatible_profiles": sorted(compat) if compat else None,
    }

    # Alignment against a configured project profile (optional — detect works
    # standalone; the check is what init/intake/doctor surface per-project).
    if cfg is not None:
        profile = getattr(cfg, "compiler_profile", "") or "msvc-6.0"
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
    if info.codegen:
        console.print(f"  codegen:   {info.codegen}")
    if info.suggested_profiles:
        console.print(f"  suggest:   {', '.join(info.suggested_profiles)}")
    if info.packed:
        console.print(f"  packed:    [yellow]{info.packer}[/yellow] (unpack before analysis)")
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


@app.command(
    "pull",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew toolchain pull msvc-6.0 --json\n\n"),
)
def pull_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. delphi-1.0)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Pull a toolchain image with REBREW_CONTAINER_RUNTIME (default docker)."""
    from rebrew.compiler.toolchain import get_toolchain

    try:
        withdrawn = get_toolchain(name).withdrawn
    except ToolchainError as exc:
        error_exit(str(exc), json_mode=json_output)
    if withdrawn:
        error_exit(f"toolchain {name!r} is withdrawn: {withdrawn}", json_mode=json_output)
    try:
        tag, was_present = pull_toolchain(name)
    except ToolchainError as exc:
        error_exit(str(exc), json_mode=json_output)
    if json_output:
        json_print({"pulled": tag, "already_present": was_present})
    elif was_present:
        console.print(f"[green]Already present[/green] {tag} (locally built)")
    else:
        console.print(f"[green]Pulled[/green] {tag}")


@app.command(
    "vendor",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew toolchain vendor msvc-6.0 --json\n\n"),
)
def vendor_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. msvc-1.52, borland-5.5)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Assemble the host toolchain tree from the pinned source.

    Downloads (sha256-verified) or extracts the pinned tarball into <family>/<version>-<arch>/source under the recompile-toolchains checkout.  The pin is the image's own, from the vendored recompile-toolchains release manifest, so host trees and containers are byte-identical.  A complete tree is an idempotent success (already_present), matching pull.  An incomplete source/ from a failed prior run is removed so retry converges; unexpected non-meta content still refuses to clobber.
    """
    import tempfile

    from rebrew.compiler.toolchain import get_toolchain, require_toolchains_repo
    from rebrew.compiler.toolchain_data import pinned_sources

    withdrawn = get_toolchain(name).withdrawn
    if withdrawn:
        error_exit(f"toolchain {name!r} is withdrawn: {withdrawn}", json_mode=json_output)
    repo = require_toolchains_repo()
    sources = pinned_sources()
    src = sources.get(name)
    if src is None:
        msg = f"no pinned source for toolchain {name!r} (known: {sorted(sources)})"
        error_exit(msg, json_mode=json_output)

    host = repo / src.host_dir
    extract_dir = host / "source"
    # Canonical layout: every vendored tree nests the actual toolchain one
    # level under ``source/`` (<family>/<ver>-<arch>/source/...), so all
    # toolchain folders share the same shape.  Tracked metadata (Dockerfile,
    # wrapper scripts, the pinned tarball, pak_extract.py) lives beside it
    # and is not vendored content, so a dir holding only those is empty for
    # clobber purposes.
    # Complete tree: re-run is a no-op success (same posture as ``pull``).
    if host.exists() and _vendor_tree_complete(host, name):
        spec = get_toolchain(name)
        probe = _probe_vendored(spec, host)
        if probe is None:
            error_exit(
                f"vendor {name}: tree reported complete but {spec.binary} missing under {host}",
                json_mode=json_output,
            )
        if json_output:
            json_print({"vendored": src.host_dir, "binary": str(probe), "already_present": True})
        else:
            console.print(f"[green]Already present[/green] {src.host_dir} ({probe})")
        return
    # Crash / timeout mid-extract leaves source/ (often empty or partial).
    # Wipe incomplete trees so a re-run succeeds instead of "already has files".
    if host.exists() and extract_dir.exists() and not _vendor_tree_complete(host, name):
        shutil.rmtree(extract_dir)
    content = (
        [p for p in host.iterdir() if not any(p.match(m) for m in _TRACKED_META_PATTERNS)]
        if host.exists()
        else []
    )
    if content:
        msg = f"{host} already has files — refusing to clobber"
        error_exit(msg, json_mode=json_output)
    host.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir()

    try:
        if src.in_repo:
            tarball = repo / src.in_repo
            # No explicit compression mode: tarfile auto-detects gzip/xz, so
            # in-repo .tar.xz and remote codeload .tar.gz both extract.  PEP 706
            # filter='data' blocks zip-slip even if the sha256 pin is wrong.
            _safe_extract_tar(tarball, extract_dir)
            console.print(f"[green]Extracted[/green] {src.in_repo} -> {src.host_dir}")
        else:
            with tempfile.TemporaryDirectory(prefix="rebrew_vendor_") as td:
                td_path = Path(td)
                archive = td_path / "src.bin"
                try:
                    _download_pinned_url(src.url, archive, timeout=1800)
                except ToolchainError as exc:
                    _abort_incomplete_vendor(extract_dir, str(exc), json_mode=json_output)
                actual = sha256_file(archive)
                if actual != src.sha256:
                    msg = f"sha256 mismatch for {name}: expected {src.sha256}, got {actual}"
                    error_exit(msg, json_mode=json_output)
                if src.layout == "7z-strip1":
                    # A .7z with the same single top-level wrapper dir
                    # (mingw-builds archives carry mingw32/).
                    extract_tmp = td_path / "7z"
                    # run_process_group kills the whole group on timeout; plain
                    # subprocess.run would orphan 7z children. check=True is
                    # re-implemented below via CalledProcessError semantics:
                    # run_process_group returns a CompletedProcess, so inspect
                    # the return code and raise the same error the caller
                    # already handles.
                    _7z = run_process_group(
                        ["7z", "x", "-y", str(archive), f"-o{extract_tmp}"],
                        capture_output=True,
                        stdin=subprocess.DEVNULL,
                        timeout=_EXTRACT_TIMEOUT_S,
                    )
                    if _7z.returncode != 0:
                        raise subprocess.CalledProcessError(
                            _7z.returncode, _7z.args, output=_7z.stdout, stderr=_7z.stderr
                        )
                    _flatten_wrapper_dir(extract_tmp, extract_dir)
                elif src.layout == "tar-strip1":
                    # Auto-detect compression: gzip codeload (msvc-4.0/420/5)
                    # and xz snapshots (watcom-2.0-win32) alike.
                    _safe_extract_tar(archive, extract_dir, strip_components=1)
                else:
                    _safe_extract_tar(archive, extract_dir)
                console.print(f"[green]Downloaded + verified[/green] {src.url} -> {src.host_dir}")
    except ToolchainError as exc:
        _abort_incomplete_vendor(extract_dir, str(exc), json_mode=json_output)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        _abort_incomplete_vendor(extract_dir, f"vendor {name} failed: {exc}", json_mode=json_output)
    except Exception as exc:
        # tarfile.ReadError / FilterError — keep the vendor tree retryable
        # instead of leaving a partial extract.
        import tarfile

        if not isinstance(exc, tarfile.TarError):
            raise
        _abort_incomplete_vendor(extract_dir, f"vendor {name} failed: {exc}", json_mode=json_output)

    # The restructures below move children one at a time, so an OSError part
    # way through leaves the tree split between two layouts.  The completeness
    # probe only looks for the compiler, so the next run would report
    # "Already present" over a tree the image cannot build.  Abort instead.
    try:
        # The delphi10 tarball keeps the RTL/VCL units in ``delphi-lib/`` while the
        # image's recipe renames them to DELPHI/LIB — the path DCC.CFG's /u option
        # and the Docker wrapper both use.  Do the same rename, so a vendored
        # host tree and the image it was built from hold the same files.
        if name == "delphi-1.0":
            loose_lib = extract_dir / "delphi-lib"
            units_lib = extract_dir / "DELPHI" / "LIB"
            if loose_lib.is_dir() and not units_lib.exists():
                units_lib.parent.mkdir(parents=True, exist_ok=True)
                loose_lib.rename(units_lib)

        # The archaic MSVC 6.0 SP5 repo stashes mspdb60.dll in the IDE dir
        # (Common/MSDev98/Bin) while CL.EXE 12.00.8804 statically imports it and
        # only searches its own directory — relocate the official file so host
        # compiles work (the sp5 Dockerfile does the same relocation).
        ide_dll = extract_dir / "Common" / "MSDev98" / "Bin" / "MSPDB60.DLL"
        bin_dll = extract_dir / "VC98" / "Bin" / "MSPDB60.DLL"
        if ide_dll.exists() and not bin_dll.exists():
            bin_dll.write_bytes(ide_dll.read_bytes())
            console.print("[dim]relocated MSPDB60.DLL -> VC98/Bin (CL requires it in-dir)[/dim]")
    except OSError as exc:
        _abort_incomplete_vendor(
            extract_dir,
            f"vendor {name} restructure failed: {exc}",
            json_mode=json_output,
        )

    # Guard: a bad extraction must fail loudly (the images do the same).
    # Probe the ACTUAL extracted dir (src.host_dir) — the spec's host_path
    # is captured at import time and may predate the extraction.
    spec = get_toolchain(name)
    probe = _probe_vendored(spec, host)
    if probe is None:
        _abort_incomplete_vendor(
            extract_dir,
            f"vendor {name} produced no {spec.binary} under {host}",
            json_mode=json_output,
        )

    if json_output:
        json_print({"vendored": src.host_dir, "binary": str(probe), "already_present": False})
    else:
        console.print(f"[green]Vendored[/green] {src.host_dir} -> {probe}")


@app.command(
    "smoke",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew toolchain smoke --json\n\n"
        "Compiles a fixed probe in each selected image and compares masked object hashes with recorded expectations."
    ),
)
def smoke_cmd(
    name: str | None = typer.Argument(None, help="Toolchain name; all image-backed by default"),
    print_goldens: bool = typer.Option(
        False,
        "--print-goldens",
        help="Print computed masked SHA-256 hashes instead of comparing recorded expectations",
    ),
    fixture: str | None = typer.Option(
        None,
        "--fixture",
        help="Reuse a built-in smoke source, flags and timestamp mask; requires a named "
        "toolchain and --print-goldens",
    ),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Compile the fixed smoke source in each image and verify the object hash matches the golden bytes (reproducibility gate).

    Deterministic inputs: a FIXED work directory and a FIXED source mtime (the object metadata embeds both the source path and its modification time; fresh writes would break the golden hashes).

    --print-goldens recomputes the masked hashes WITHOUT comparing, so a maintainer who bumps a pinned toolchain source (new tarball/snapshot) can refresh the recorded expectations: run it, verify the new hashes are stable across a second run, then paste them in. --fixture selects another profile's smoke inputs for a named new or overlay profile; it is only accepted with --print-goldens and never supplies an expected hash for that profile.
    """
    import os

    from rebrew.compiler.toolchain import get_toolchain

    if fixture is not None and (not print_goldens or name is None):
        error_exit(
            "--fixture requires a named toolchain and --print-goldens", json_mode=json_output
        )
    targets = [name] if name else sorted(_SMOKE_GOLDEN)
    results: dict[str, str] = {}
    # Two failure kinds, two exit codes: a toolchain that cannot run at all
    # is infrastructure (2), an image that compiles different bytes than its
    # recorded golden is an actionable finding (1), exactly like a byte
    # mismatch in `rebrew test`.
    infra_ok = True
    reproducible = True
    # A real-disk, docker-visible workdir (the system temp dir may be
    # tmpfs or docker-invisible in sandboxed environments).
    from rebrew.compiler.temp_dirs import remove_temp_dir, writable_temp_dir

    workdir = writable_temp_dir("rebrew_smoke_")
    try:
        for tool in targets:
            spec = get_toolchain(tool)
            if spec.withdrawn:
                results[tool] = f"skip (withdrawn: {spec.withdrawn})"
                continue
            if spec.image is None and spec.host_path is None:
                results[tool] = "skip (no image, no vendored host tree)"
                continue
            recipe = _SMOKE_GOLDEN.get(fixture or tool)
            if recipe is None:
                results[tool] = (
                    f"FAIL (no smoke fixture for {fixture or tool!r}; "
                    "use --fixture with --print-goldens)"
                )
                infra_ok = False
                continue
            flags, out_name, golden, src_name, mask = recipe
            obj = workdir / out_name
            obj.unlink(missing_ok=True)
            src = _SMOKE_SOURCE if src_name == "t.c" else _SMOKE_DPR
            src_path = workdir / src_name
            src_path.write_text(src, encoding="utf-8")
            os.utime(src_path, (_SDE, _SDE))
            if spec.image is not None:
                try:
                    r = _run_smoke_container(
                        spec.image,
                        f"rebrew-smoke-{spec.name}",
                        workdir,
                        flags,
                        kvm=spec.runtime == "dosemu2",
                    )
                except subprocess.TimeoutExpired:
                    results[tool] = f"FAIL (docker run timed out after {_SMOKE_TIMEOUT_S}s)"
                    infra_ok = False
                    continue
                except OSError as exc:
                    results[tool] = f"FAIL (could not run {spec.image}: {exc})"
                    infra_ok = False
                    continue
                detail = (r.stdout + r.stderr)[-120:].strip()
                if r.returncode:
                    results[tool] = f"FAIL (compile exited {r.returncode}: {detail})"
                    infra_ok = False
                    continue
            else:
                # Host-only vendored toolchain (a plugin spec under wine, or an
                # image-less native compiler): gate its reproducibility through
                # the uniform host runner (resolves the vendored binary, sets
                # the wine env).  The same fixed-workdir + fixed-mtime
                # determinism contract applies.
                from rebrew.compiler.toolchain import ToolchainError, run_toolchain

                try:
                    rr = run_toolchain(spec, flags, workdir=workdir, timeout=_SMOKE_TIMEOUT_S)
                    detail = (rr.stdout + rr.stderr)[-120:].strip()
                except ToolchainError as exc:
                    results[tool] = "FAIL (" + str(exc)[-120:] + ")"
                    infra_ok = False
                    continue
            if not obj.exists():
                results[tool] = "FAIL (no object: " + detail + ")"
                infra_ok = False
                continue
            # An object for another machine than the profile declares can never
            # match a target of it, whatever its golden says (msvc-9.0-sp1's
            # image wrote IA-64 objects under an x86 name).
            declared = _declared_target(spec)
            wrote = _object_target(obj) if declared is not None else None
            if declared is not None and wrote is not None and wrote != declared:
                results[tool] = (
                    f"MISMATCH (writes {wrote[0]}/{wrote[1]}, declared {declared[0]}/{declared[1]})"
                )
                reproducible = False
                obj.unlink(missing_ok=True)
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
            reproducible = reproducible and actual == golden
            obj.unlink(missing_ok=True)
        # An infrastructure failure outranks a reproducibility finding: the
        # toolchain that could not run tells nothing about the others.
        code = EXIT_ERROR if not infra_ok else (EXIT_OK if reproducible else EXIT_MISMATCH)
        if json_output:
            json_print(
                {"goldens": results}
                if print_goldens
                else {"results": results, "passed": infra_ok and reproducible}
            )
        elif print_goldens:
            for tool, h in results.items():
                console.print(f"  {tool:12s} {h}")
        else:
            for tool, status in results.items():
                console.print(f"  [{'green' if status == 'OK' else 'red'}]{tool:12s}[/] {status}")
            if code == EXIT_OK:
                console.print(
                    f"[green]Smoke: {sum(1 for s in results.values() if s == 'OK')} toolchains byte-reproducible[/green]"
                )
        if code != EXIT_OK:
            raise typer.Exit(code=code)
    finally:
        remove_temp_dir(workdir)


@app.command(
    "build",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew toolchain build msvc-6.0 --json\n\n"),
)
def build_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. watcom-2.0-win32, msvc-6.0)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Build a toolchain's docker image from the recompile-toolchains checkout."""

    from rebrew.compiler.toolchain import (
        ToolchainError,
        get_toolchain,
        require_toolchains_repo,
        swap_toolchain_image,
    )

    spec = get_toolchain(name)
    if spec.withdrawn:
        error_exit(f"toolchain {name!r} is withdrawn: {spec.withdrawn}", json_mode=json_output)
    if spec.image is None:
        msg = f"toolchain {name!r} is host-only (no image to build)"
        error_exit(msg, json_mode=json_output)
    if ":" not in spec.image:
        msg = f"toolchain {name!r} image tag {spec.image!r} has no version-arch tag"
        error_exit(msg, json_mode=json_output)
    repo = require_toolchains_repo()
    verarch = spec.image.rsplit(":", 1)[1]
    image = spec.image  # narrowed local — mypy does not narrow into the closure
    # ``family`` and the image tag come from the toolchain registry, which a
    # plugin or an overlay dir can define.  Both become directories in the
    # toolchains repo, and the directory that holds a Dockerfile becomes the
    # docker build context, so a separator or a dot segment would build from
    # outside the repo.
    for component, label in ((spec.family, "family"), (verarch, "image tag")):
        if not component or "/" in component or "\\" in component or component.startswith("."):
            msg = f"toolchain {name!r} {label} {component!r} is not a plain directory name"
            error_exit(msg, json_mode=json_output)
    build_dir = repo / spec.family / verarch
    if not (build_dir / "Dockerfile").exists():
        msg = f"no Dockerfile at {build_dir}"
        error_exit(msg, json_mode=json_output)

    # Build the selected image's complete local base chain, oldest parent first.
    dependency = build_dir
    bases: list[tuple[str, Path]] = []
    seen: set[str] = {spec.image}
    while True:
        base_from = None
        build_args: dict[str, str] = {}
        for line in (dependency / "Dockerfile").read_text(encoding="utf-8").splitlines():
            words = line.split()
            if len(words) < 2:
                continue
            if words[0].upper() == "ARG":
                key, separator, value = words[1].partition("=")
                if separator:
                    build_args[key] = value
            if words[0].upper() == "FROM":
                base_from = Template(words[1]).safe_substitute(build_args)
                break
        if not base_from or not base_from.startswith("rebrew/"):
            break
        base_name = base_from.rsplit(":", 1)[0].removeprefix("rebrew/")
        if not base_name or "/" in base_name or "\\" in base_name or base_name.startswith("."):
            error_exit(f"invalid local base image {base_from!r}", json_mode=json_output)
        if base_from in seen:
            error_exit(f"local base dependency cycle at {base_from!r}", json_mode=json_output)
        seen.add(base_from)
        dependency = repo / base_name
        if not (dependency / "Dockerfile").exists():
            break
        bases.append((base_from, dependency))
    for base_tag, base_dir in reversed(bases):
        rc, log = _docker_build(base_tag, base_dir, stream=not json_output)
        if rc != 0:
            msg = f"docker build {base_tag} failed: {_build_failure(rc, log)}"
            error_exit(msg, json_mode=json_output)

    # Build through swap_toolchain_image (backup→swap→rollback): docker tags
    # on success, and a failed build leaves the previous image under the tag —
    # the swap verifies that and restores it if the tag was ever left dangling.
    def _build_image() -> None:
        rc, log = _docker_build(image, build_dir, stream=not json_output)
        if rc != 0:
            raise ToolchainError(f"docker build {image} failed: {_build_failure(rc, log)}")

    try:
        swap_toolchain_image(image, _build_image)
    except ToolchainError as exc:
        msg = str(exc)
        error_exit(msg, json_mode=json_output)
    if json_output:
        json_print({"built": spec.image})
    else:
        console.print(f"[green]Built[/green] {spec.image}")


@app.command(
    "check-updates",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew toolchain check-updates --json\n\n"
        "Reports upstream drift in pinned sources without changing pins or compiler trees."
    ),
)
def check_updates_cmd(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Detect upstream drift in pinned toolchain sources.

    GitHub-codeload sources (archaic-msvc, archaic-toolchains): compares the live head (the pinned branch's, or the default branch's for a pin that names a commit; GitHub API, no download) against the commit the pin was taken from.  The Open Watcom snapshot (a moving 'Last-CI-build' release tag) is re-downloaded and re-hashed.  Immutable release assets (decomp.me, archive.org) and pinned tarballs (16-bit media in the recompile-toolchains checkout) are reported as static.
    """
    import tempfile

    from rebrew.compiler.toolchain_data import pinned_sources

    rows: dict[str, str] = {}
    drifted: list[str] = []
    for name, src in sorted(pinned_sources().items()):
        if src.in_repo:
            rows[name] = STATUS_STATIC_TARBALL
            continue
        url = src.url or ""
        m = _codeload_pattern().match(url)
        if m:
            owner, repo, branch = m.group(1), m.group(2), _codeload_ref(m)
            try:
                live = _live_commit_sha(owner, repo, branch)
            except Exception as exc:
                logging.getLogger(__name__).warning(
                    "cannot check %s (%s/%s@%s): %s", name, owner, repo, branch, exc
                )
                rows[name] = f"check failed ({exc.__class__.__name__})"
                continue
            if not src.commit:
                rows[name] = f"unpinned (live {live[:12]})"
                continue
            if live == src.commit:
                rows[name] = STATUS_CURRENT
            else:
                rows[name] = f"DRIFTED {src.commit[:12]} -> {live[:12]}"
                drifted.append(name)
            continue
        if _MOVING_RELEASE in url:
            try:
                with tempfile.TemporaryDirectory() as td:
                    path = Path(td) / "src.bin"
                    _download_pinned_url(url, path, timeout=60)
                    actual = sha256_file(path)
                if actual == src.sha256:
                    rows[name] = STATUS_CURRENT
                else:
                    rows[name] = f"DRIFTED sha256 {src.sha256[:12]} -> {actual[:12]}"
                    drifted.append(name)
            except Exception as exc:
                logging.getLogger(__name__).warning("cannot check %s (%s): %s", name, url, exc)
                rows[name] = f"check failed ({exc.__class__.__name__})"
            continue
        rows[name] = STATUS_STATIC_ASSET
    if json_output:
        json_print({"toolchains": rows, "drifted": drifted})
        return
    for name, status in rows.items():
        color = (
            "green"
            if status == STATUS_CURRENT
            else ("red" if status.startswith("DRIFTED") else "yellow")
        )
        console.print(f"  [{color}]{name:14s}[/] {status}")
    if drifted:
        console.print(
            "[red]drifted: "
            + ", ".join(drifted)
            + " — 'rebrew toolchain update <name>' prints the new pin for"
            " recompile-toolchains' sources.json[/red]"
        )


@app.command(
    "update",
    epilog=("[bold]Examples:[/bold]\n\n  rebrew toolchain update msvc-6.0 --json\n\n"),
)
def update_cmd(
    name: str = typer.Argument(..., help="Toolchain name (e.g. msvc-6.0, watcom-2.0-win32)"),
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
) -> None:
    """Report the pin a toolchain source would take from its current upstream.

    Downloads the current source and reports the old -> new pin (sha256 + commit).  The pins are recompile-toolchains': set the new one in its sources.json and regenerate there, then vendor the released toolchains.json into rebrew (the rebrew repo's docs/TOOLCHAIN.md); `rebrew toolchain vendor`, `build` and `smoke --print-goldens` then rebuild the tree, the image and the smoke golden.
    """
    import tempfile

    from rebrew.compiler.toolchain_data import pinned_sources

    sources = pinned_sources()
    src = sources.get(name)
    if src is None:
        msg = f"no pinned source for toolchain {name!r} (known: {sorted(sources)})"
        error_exit(msg, json_mode=json_output)
    if src.in_repo:
        msg = f"toolchain {name!r} is a pinned tarball (static) — nothing to update"
        error_exit(msg, json_mode=json_output)
    m = _codeload_pattern().match(src.url)
    url = src.url
    live_commit = ""
    if m is not None and m.group(4):
        # A pin naming a commit downloads that commit for ever: the current
        # upstream is the default branch's head, so the new pin is that commit's.
        try:
            live_commit = _live_commit_sha(m.group(1), m.group(2), "HEAD")
        except Exception as exc:
            error_exit(
                f"cannot resolve the default branch of {m.group(1)}/{m.group(2)}: {exc}",
                json_mode=json_output,
            )
        url = f"https://codeload.github.com/{m.group(1)}/{m.group(2)}/tar.gz/{live_commit}"
    with tempfile.TemporaryDirectory(prefix="rebrew_update_") as td:
        archive = Path(td) / "src.bin"
        try:
            _download_pinned_url(url, archive, timeout=1800)
        except ToolchainError as exc:
            error_exit(str(exc), json_mode=json_output)
        actual_sha = sha256_file(archive)
    if actual_sha == src.sha256:
        msg = f"toolchain {name!r} is already current (sha256 {src.sha256[:16]}…)"
        if json_output:
            json_print({"toolchain": name, "status": "current", "sha256": src.sha256})
        else:
            console.print(f"[green]{msg}[/green]")
        return
    if m is not None and not live_commit:
        try:
            live_commit = _live_commit_sha(m.group(1), m.group(2), _codeload_ref(m))
        except Exception as exc:
            # The sha256 still names the new pin; an empty commit string must not
            # look like "upstream has no commit" when the lookup just failed.
            logging.getLogger(__name__).warning(
                "Could not resolve live commit for %s — reporting sha256 only: %s",
                name,
                exc,
            )
    if json_output:
        json_print(
            {
                "toolchain": name,
                "status": "drifted",
                "old": {"sha256": src.sha256, "commit": src.commit},
                "new": {"sha256": actual_sha, "commit": live_commit},
            }
        )
        return
    old_pin = f"sha256={src.sha256[:12]}…" + (f" commit={src.commit[:12]}" if src.commit else "")
    new_pin = f"sha256={actual_sha} " + (f"commit={live_commit}" if live_commit else "")
    console.print(f"[yellow]{name}:[/yellow] {old_pin} -> {new_pin.strip()}")
    console.print(
        "[dim]set it in recompile-toolchains' sources.json, regenerate there, and vendor "
        "the released toolchains.json into rebrew (the rebrew repo's docs/TOOLCHAIN.md)[/dim]"
    )


@app.command(
    "install-wibo",
    epilog=(
        "[bold]Examples:[/bold]\n\n"
        "  rebrew toolchain install-wibo\n\n"
        "  rebrew toolchain install-wibo --json\n\n"
        "Downloads the optional host runner. Docker-backed profiles retain their runner configuration."
    ),
)
def install_wibo(
    json_output: bool = typer.Option(False, "--json", help="Output results as JSON"),
    target: str | None = TargetOption,
) -> None:
    """Download wibo into tools/wibo if missing; keep existing installations."""
    from rebrew.wibo import download_wibo

    cfg = require_config(target=target, json_mode=json_output)
    wibo_path = cfg.root / "tools" / "wibo"
    if wibo_path.exists():
        console.print(f"wibo already installed at {wibo_path}")
        if json_output:
            json_print({"path": str(wibo_path), "downloaded": False, "runner_updated": False})
        return
    tag_name = download_wibo(wibo_path)
    console.print(f"Downloaded wibo {tag_name} to {wibo_path}")

    # Docker-backed profiles execute through their image, which runs
    # WINE by default (REBREW_RUNNER defaults to wine; wibo is opt-in and
    # fails on some tools).  The config runner is obsolete for them, so
    # install-wibo must NOT rewrite runner = "tools/wibo" — that would
    # silently steer a docker-only project toward the less-compatible
    # runtime the user just reported failing.  Only legacy host-runner
    # profiles (native/wine/wibo without an image) get the rewrite.
    from rebrew.compiler.toolchain import TOOLCHAINS

    profile = str(getattr(cfg, "compiler_profile", ""))
    spec = TOOLCHAINS.get(profile) if profile else None
    if spec is not None and spec.image is not None:
        console.print(
            f"[yellow]note:[/yellow] {profile} is docker-backed — execution "
            f"runs through image {spec.image}, which uses wine by default; "
            "the runner config is obsolete and was left untouched (wibo "
            "is available in tools/ for legacy profiles)"
        )
        if json_output:
            json_print(
                {
                    "path": str(wibo_path),
                    "downloaded": True,
                    "version": tag_name,
                    "runner_updated": False,
                }
            )
        return

    runner_updated = False
    if (cfg.root / "rebrew-project.toml").exists():
        from rebrew.config import project_toml_lock
        from rebrew.utils import atomic_write_text

        # One locked read-modify-write: the rewrite is a regex over the
        # whole file, so a concurrent writer of any other key in it would
        # have its edit dropped by the replace.
        with project_toml_lock(cfg.root) as toml_path:
            content = toml_path.read_text(encoding="utf-8-sig")
            if re.search(r"(?m)^\s*runner\s*=", content):
                new_content = re.sub(
                    r'(?m)^(\s*runner\s*=\s*)"[^"]*"',
                    r'\1"tools/wibo"',
                    content,
                )
            else:
                new_content = re.sub(
                    r"(?m)^(\[compiler\]\s*\n)",
                    r'\1runner = "tools/wibo"\n',
                    content,
                )
            if new_content != content:
                atomic_write_text(toml_path, new_content, encoding="utf-8")
                runner_updated = True
                console.print("Auto-enabled wibo in rebrew-project.toml")

    if json_output:
        json_print(
            {
                "path": str(wibo_path),
                "downloaded": True,
                "version": tag_name,
                "runner_updated": runner_updated,
            }
        )


def main_entry() -> None:
    """Run the Typer CLI application."""
    from rebrew.cli import run_cli

    run_cli(app)


if __name__ == "__main__":
    main_entry()
