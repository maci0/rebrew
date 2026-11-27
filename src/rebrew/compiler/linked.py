"""Linked single-function comparison using MSVC ``LINK.EXE`` inside a shell."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
lazy import subprocess
lazy import sys
lazy import uuid

lazy from rebrew.compiler import toolchain as toolchain_registry
lazy from rebrew.compiler.result import CompareResult, classify_compare_result
lazy from rebrew.compiler.toolchain import (
    ToolchainError,
    ToolchainSpec,
    bind_mount,
    docker_hardening_args,
)
lazy from rebrew.config import DEFAULT_COMPILE_TIMEOUT, ProjectConfig
lazy from rebrew.errors import RebrewError
lazy from rebrew.formats.binary_loader import load_binary
lazy from rebrew.formats.binary_model import BinaryInfo, SectionInfo
lazy from rebrew.utils import container_runtime, run_process_group, safe_shlex_split


def linked_shell_source(function_source: str, pad: int) -> str:
    """Wrap *function_source* in a padded link shell."""
    parts: list[str] = []
    if pad > 0:
        parts.append(
            '#pragma data_seg(".text$A")\n'
            f"static unsigned char __rebrew_linked_pad[{pad}] = {{ 0 }};\n"
            "#pragma data_seg()\n"
        )
    parts.append('#pragma code_seg(".text$B")\n')
    parts.append(function_source.rstrip("\n"))
    parts.append("\n#pragma code_seg()\n")
    return "\n".join(parts)


def linked_pad_size(fn_rva: int, section_rva: int) -> int:
    """Padding that places a function at *fn_rva* inside its section, or -1 if before."""
    pad = fn_rva - section_rva
    return pad if pad >= 0 else -1


def extract_linked_slice(dll_bytes: bytes, text_raw_offset: int, pad: int, size: int) -> bytes:
    """Slice *size* bytes of the linked DLL at the padded function offset."""
    start = text_raw_offset + pad
    return dll_bytes[start : start + size]


def build_linked_link_cmd(
    spec: ToolchainSpec,
    *,
    base: int,
    obj_name: str,
    out_name: str,
    workdir: str | Path,
) -> tuple[list[str], str]:
    """Docker command and script that run the image's ``LINK.EXE`` on *obj_name*."""
    if spec.image is None or spec.tool_root is None:
        raise ToolchainError(
            f"linked compare needs a docker image with LINK.EXE (toolchain "
            f"{spec.name!r} has image={spec.image!r}, tool_root={spec.tool_root!r})",
            kind="missing",
            name=spec.name,
        )
    win_root = PurePosixPath(spec.tool_root).parent.as_posix().replace("/", "\\")
    script = '. /usr/local/lib/rebrew/wrapper-common.sh && rebrew_run "$REBREW_LINK_EXE" "$@"'
    link_args = [
        "/nologo",
        "/DLL",
        "/NOENTRY",
        f"/BASE:0x{base:x}",
        "/MACHINE:IX86",
        "/ALIGN:4096",
        "/FILEALIGN:4096",
        "/OPT:NOREF",
        "/OPT:NOICF",
        "/INCREMENTAL:NO",
        "/NODEFAULTLIB",
        f"/OUT:{out_name}",
        obj_name,
    ]
    cmd = [
        container_runtime(),
        "run",
        "--rm",
        *docker_hardening_args(pull=False),
        "--name",
        f"rebrew-link-{uuid.uuid4().hex[:12]}",
        "--env",
        f"INCLUDE=Z:{win_root}\\Include",
        "--env",
        f"LIB=Z:{win_root}\\Lib",
        "--env",
        f"REBREW_LINK_EXE={spec.tool_root}/LINK.EXE",
        "-v",
        bind_mount(workdir, "/work"),
        "-w",
        "/work",
        "--entrypoint",
        "sh",
        spec.image,
        "-c",
        script,
        "sh",
        *link_args,
    ]
    return cmd, script


def linked_spec(cfg: ProjectConfig, toolchain: str | None) -> tuple[ToolchainSpec | None, str]:
    profile = getattr(cfg, "compiler_profile", "")
    compile_mod = sys.modules.get("rebrew.compiler.compile")
    registry = (
        getattr(compile_mod, "toolchain_registry", toolchain_registry)
        if compile_mod is not None
        else toolchain_registry
    )
    spec = (
        registry.TOOLCHAINS.get(toolchain)
        if toolchain
        else (registry.TOOLCHAINS.get(profile) if profile else None)
    )
    if spec is None:
        return None, f"no toolchain spec for profile {profile!r}"
    if spec.image is None:
        return None, (
            f"toolchain {spec.name!r} is host-native (no docker image) - linked "
            "compare runs LINK.EXE inside the toolchain image"
        )
    if spec.binary != "cl":
        return None, f"linked compare supports MSVC toolchains only (got {spec.name!r})"
    return spec, ""


def section_for_va(info: BinaryInfo, va: int) -> SectionInfo | None:
    for sec in info.sections.values():
        if sec.va <= va < sec.va + sec.raw_size:
            return sec
    return None


def _link_obj_docker(
    cfg: ProjectConfig,
    spec: ToolchainSpec,
    obj_path: str,
    dll_path: str,
    *,
    base: int,
    workdir: Path,
) -> tuple[bool, str]:
    backend = getattr(cfg, "execution_backend", "")
    if backend == "unshare":
        return False, "execution_backend = unshare does not support linked comparison yet"
    cmd, _script = build_linked_link_cmd(
        spec,
        base=base,
        obj_name=Path(obj_path).name,
        out_name=Path(dll_path).name,
        workdir=workdir,
    )
    if backend:
        cmd[0] = container_runtime(backend)
    timeout = getattr(cfg, "compile_timeout", DEFAULT_COMPILE_TIMEOUT) or DEFAULT_COMPILE_TIMEOUT
    try:
        r = run_process_group(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return False, f"LINK.EXE timed out after {timeout}s"
    except OSError as exc:
        return False, str(exc)
    if r.returncode != 0 or not Path(dll_path).exists():
        err = (r.stdout + "\n" + r.stderr).strip()
        return False, err[-400:] if err else f"LINK.EXE exited {r.returncode} with no output"
    return True, ""


def compile_and_compare_linked(
    cfg: ProjectConfig,
    source_path: str | Path,
    target_bytes: bytes,
    cflags: str | list[str],
    *,
    va: int,
    toolchain: str | None = None,
    use_cache: bool = True,
) -> CompareResult:
    """Compile *source_path* in a padded link shell and compare linker-resolved bytes."""
    from rebrew.compiler import compile as _compile_mod
    from rebrew.compiler.temp_dirs import writable_temp_dir

    spec, spec_err = linked_spec(cfg, toolchain)
    if spec is None:
        return classify_compare_result(
            False, f"COMPILE_ERROR: {spec_err}", target_bytes, None, None
        )

    try:
        info = load_binary(Path(cfg.target_binary))
    except (ValueError, OSError) as exc:
        return classify_compare_result(False, f"EXTRACT_ERROR: {exc}", target_bytes, None, None)
    sec = section_for_va(info, va)
    if sec is None:
        return classify_compare_result(
            False,
            f"EXTRACT_ERROR: VA 0x{va:08x} is not inside any target section",
            target_bytes,
            None,
            None,
        )
    pad = linked_pad_size(va - info.image_base, sec.va - info.image_base)
    if pad < 0:
        return classify_compare_result(
            False,
            f"EXTRACT_ERROR: function 0x{va:08x} precedes its section start - "
            "the linked shell cannot reproduce the offset",
            target_bytes,
            None,
            None,
        )

    try:
        source = Path(source_path).read_text(encoding="utf-8", errors="surrogateescape")
    except OSError as exc:
        return classify_compare_result(
            False, f"COMPILE_ERROR: cannot read source: {exc}", target_bytes, None, None
        )
    shell = linked_shell_source(source, pad)
    cflags_list = safe_shlex_split(cflags) if isinstance(cflags, str) else list(cflags)

    workdir: Path | None = None
    try:
        workdir = writable_temp_dir("rebrew_linked_")
        shell_path = workdir / ("linked_" + Path(source_path).name)
        shell_path.write_text(shell, encoding="utf-8", errors="surrogateescape")
        backend_errors: list[RebrewError] = []
        obj_path, err = _compile_mod.compile_to_obj(
            cfg,
            shell_path,
            cflags_list,
            workdir,
            use_cache=use_cache,
            toolchain=toolchain,
            extra_include_dirs=[str(Path(source_path).resolve().parent)],
            backend_errors=backend_errors,
        )
        if obj_path is None:
            return classify_compare_result(
                False,
                f"COMPILE_ERROR: {_compile_mod._compiler_error_excerpt(err)}",
                target_bytes,
                None,
                None,
                error=backend_errors[0] if backend_errors else None,
            )

        dll_path = workdir / "linked_out.dll"
        ok, link_err = _link_obj_docker(
            cfg, spec, obj_path, str(dll_path), base=info.image_base, workdir=workdir
        )
        if not ok:
            return classify_compare_result(
                False,
                (
                    "COMPILE_ERROR: link failed - the source references externals "
                    "the shell cannot resolve, or LINK.EXE failed: "
                    f"{_compile_mod._compiler_error_excerpt(link_err)}"
                ),
                target_bytes,
                None,
                None,
            )

        linked_info = load_binary(dll_path)
        linked_bytes = extract_linked_slice(
            linked_info.data, linked_info.text_raw_offset, pad, len(target_bytes)
        )
        if len(linked_bytes) != len(target_bytes):
            common = min(len(linked_bytes), len(target_bytes))
            mismatches = (
                sum(
                    a != b
                    for a, b in zip(target_bytes[:common], linked_bytes[:common], strict=True)
                )
                if common
                else 0
            )
            return CompareResult(
                matched=False,
                status="SIZE_MISMATCH",
                match_percent=((common - mismatches) / len(target_bytes) * 100)
                if target_bytes
                else 0.0,
                delta=abs(len(linked_bytes) - len(target_bytes)) + mismatches,
                obj_bytes=linked_bytes,
                reloc_offsets=None,
                match_count=common - mismatches,
                message=(
                    f"SIZE_MISMATCH: linked slice {len(linked_bytes)}B vs target "
                    f"{len(target_bytes)}B (linked .text too short at pad 0x{pad:x})"
                ),
            )
        matched = linked_bytes == target_bytes
        msg = (
            "LINKED EXACT MATCH (linker-resolved bytes)"
            if matched
            else f"LINKED COMPARE: {sum(a != b for a, b in zip(target_bytes, linked_bytes, strict=True))} byte diffs"
        )
        return classify_compare_result(matched, msg, target_bytes, linked_bytes, None)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError) as exc:
        return classify_compare_result(False, f"COMPILE_ERROR: {exc}", target_bytes, None, None)
    finally:
        if workdir is not None:
            _compile_mod._discard_temp_dir(workdir)
