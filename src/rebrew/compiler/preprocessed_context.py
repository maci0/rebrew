"""Capture a pinned MSVC translation unit's actual preprocessor output."""

from __future__ import annotations

lazy import hashlib
lazy import json
lazy import os
lazy import re
lazy import shlex
lazy import tempfile
lazy from pathlib import Path
lazy from typing import Any

lazy from rebrew.compiler.image_headers import ImageHeaders
lazy from rebrew.compiler.toolchain import get_toolchain, run_toolchain

_SKIP = frozenset({".git", ".scratch", ".venv", ".rebrew", "build"})
_MARKER = re.compile(rb'^\s*#line\s+\d+\s+"((?:\\.|[^"\\])*)"', re.MULTILINE)
_SIMPLE = re.compile(r"(?i)^(?:[/\-](?:nologo|W[0-4]|O[0-2x]|G[drys]|M[DLT]d?|Z[7iI]|EH[a-z]+))$")


def _snapshot(root: Path) -> dict[str, str]:
    """Pin every non-generated project file that an admitted source can include."""
    result: dict[str, str] = {}
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        names[:] = sorted(
            name for name in names if not (base == root and (name in _SKIP or name.startswith(".")))
        )
        for name in [*names, *sorted(files)]:
            path = base / name
            if path.is_symlink():
                raise ValueError(f"symlink in preprocessing input tree: {path}")
            if not path.is_file():
                continue
            before = path.stat()
            raw = path.read_bytes()
            after = path.stat()
            if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise ValueError(f"preprocessing input changed while reading: {path}")
            result[str(path)] = hashlib.sha256(raw).hexdigest()
    return result


def _command(entry: dict[str, Any], root: Path, source: Path) -> tuple[str, list[str]]:
    """Admit the bounded CMake driver command without changing flag order."""
    cwd = Path(entry["directory"]).resolve()
    if not cwd.is_relative_to(root):
        raise ValueError("compile directory is outside the project")
    words = list(entry["arguments"]) if "arguments" in entry else shlex.split(entry["command"])
    try:
        index = words.index("--")
    except ValueError as exc:
        raise ValueError("compile command is not a Rebrew build driver invocation") from exc
    if index < 4 or words[index - 3 : index] != ["build", "driver", "cl"]:
        raise ValueError("compile command is not a Rebrew build driver invocation")
    args = words[index + 1 :]
    profile = ""
    flags: list[str] = []
    sources = 0
    i = 0
    while i < len(args):
        token = args[i]
        lower = token.lower()
        if lower.startswith("/rebrew_toolchain:"):
            value = token.split(":", 1)[1]
            if profile and profile != value:
                raise ValueError("compile command has conflicting toolchain profiles")
            profile = value
        elif lower in {"/c", "-c"}:
            pass
        elif token.startswith(("/Fo", "/Fd", "-Fo", "-Fd")):
            if len(token) == 3:
                i += 1
                if i >= len(args):
                    raise ValueError("compile output option has no argument")
        elif token in {"/I", "-I", "/D", "-D", "/U", "-U"}:
            i += 1
            if i >= len(args):
                raise ValueError("compiler option has no argument")
            value = args[i]
            if token[1] == "I":
                include = (cwd / value).resolve()
                if not include.is_relative_to(root) or not include.is_dir():
                    raise ValueError("include directory must exist inside the project")
                value = str(include)
            flags.extend([token, value])
        elif token.startswith(("/I", "-I")):
            include = (cwd / token[2:]).resolve()
            if not include.is_relative_to(root) or not include.is_dir():
                raise ValueError("include directory must exist inside the project")
            flags.append(token[:2] + str(include))
        elif (token.startswith(("/D", "-D", "/U", "-U")) and len(token) > 2) or _SIMPLE.fullmatch(
            token
        ):
            flags.append(token)
        elif (cwd / token).resolve() == source:
            sources += 1
        else:
            raise ValueError(f"unsupported or ambiguous compiler argument: {token}")
        i += 1
    if not profile or sources != 1:
        raise ValueError("compile command must name one source and one explicit toolchain")
    return profile, flags


def capture_msvc_context(
    project_root: Path,
    compilation_database: Path,
    source: Path,
    *,
    output: str,
    execution_backend: str = "docker",
    timeout: int = 120,
) -> dict[str, Any]:
    """Run the selected CMake TU through its pinned compiler's ``/P`` mode.

    The caller must serialize compiler work. The result captures expanded source
    and compiler line markers, not a complete macro table or a proof of linked
    providers. Unreviewed switches, host includes and incomplete inputs fail.
    """
    root = project_root.resolve()
    database = compilation_database.resolve()
    source = source.resolve()
    if not source.is_relative_to(root) or not database.is_relative_to(root):
        raise ValueError("source and compilation database must belong to the project")
    if execution_backend not in {"docker", "podman", "unshare"}:
        raise ValueError("preprocessing requires an image-backed execution backend")
    raw_database = database.read_bytes()
    entries = json.loads(raw_database)
    selected = [
        e for e in entries if Path(e["file"]).resolve() == source and e.get("output") == output
    ]
    if len(selected) != 1:
        raise ValueError("select exactly one source and build output in the compilation database")
    profile, flags = _command(selected[0], root, source)
    spec = get_toolchain(profile)
    if spec.family != "msvc" or spec.runtime != "wine" or not spec.image or not spec.tool_root:
        raise ValueError("preprocessing requires an image-backed MSVC/Wine toolchain")
    before = _snapshot(root)
    if str(source) not in before:
        raise ValueError("source is outside the admitted preprocessing input tree")
    environment = {"SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH")}
    with ImageHeaders() as images:
        images.get(profile)
        image_id = images.trees[profile]["id"]
        with tempfile.TemporaryDirectory(prefix="rebrew-preprocess-") as temporary:
            workdir = Path(temporary)
            driver_flags = []
            for flag in flags:
                if flag.startswith("/I/"):
                    driver_flags.append("/IZ:" + flag[2:].replace("/", "\\"))
                elif flag.startswith("/") and Path(flag).is_dir():
                    driver_flags.append("Z:" + flag.replace("/", "\\"))
                else:
                    driver_flags.append(flag)
            wine_source = "Z:" + str(source).replace("/", "\\")
            result = run_toolchain(
                spec,
                [*driver_flags, "/P", wine_source],
                workdir=workdir,
                mounts=[(str(root), str(root))],
                image_id=image_id,
                execution_backend=execution_backend,
                timeout=timeout,
            )
            artifact = workdir / (source.stem + ".i")
            if result.returncode != 0 or not artifact.is_file():
                raise ValueError(f"MSVC preprocessing failed: {result.stdout}\n{result.stderr}")
            expanded = artifact.read_bytes()
        images.verify()
    if _snapshot(root) != before or database.read_bytes() != raw_database:
        raise ValueError("preprocessing inputs changed during compiler execution")
    if environment != {"SOURCE_DATE_EPOCH": os.environ.get("SOURCE_DATE_EPOCH")}:
        raise ValueError("preprocessing environment changed during compiler execution")
    markers = []
    sdk_root = str(Path(spec.tool_root).parent).replace("/", "\\").lower()
    for match in _MARKER.finditer(expanded):
        marker = match.group(1).replace(b"\\\\", b"\\").decode("utf-8", "surrogateescape")
        if not marker.lower().startswith("z:\\"):
            raise ValueError(f"unverified preprocessor line marker: {marker}")
        path = marker[2:]
        if path.lower().startswith(sdk_root + "\\"):
            markers.append(marker)
            continue
        project_path = Path(path.replace("\\", "/")).resolve()
        if str(project_path) not in before:
            raise ValueError(f"preprocessor read an unpinned file: {marker}")
        markers.append(marker)
    if not markers:
        raise ValueError("compiler produced no verifiable line markers")
    digest_inputs = {
        "database": hashlib.sha256(raw_database).hexdigest(),
        "source": str(source),
        "output": output,
        "profile": profile,
        "image_id": image_id,
        "flags": flags,
        "environment": environment,
        "files": before,
        "expanded_sha256": hashlib.sha256(expanded).hexdigest(),
    }
    return {
        **digest_inputs,
        "line_markers": markers,
        "expanded": expanded,
        "input_digest": hashlib.sha256(
            json.dumps(digest_inputs, sort_keys=True).encode()
        ).hexdigest(),
        "macro_table_complete": False,
        "provider_evidence": False,
    }


__all__ = ["capture_msvc_context"]
