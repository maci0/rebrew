"""Conservative content-guarded object cache for ordinary CMake CL commands.

This domain retains the driver's real cwd/argv and never shares staged test
objects. Unsupported flags, preprocessing, unresolved dependencies and mutable
shared Wine prefixes continue through the original uncached runner.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import io
import json
import re
import sys
import tempfile
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from rebrew.c_parser import mask_msvc_syntax, parse_c_source
from rebrew.compiler import toolchain
from rebrew.compiler.cache import (
    CacheBackend,
    compile_cache_key,
    get_project_cache,
    include_specs,
    scan_include_closure,
)
from rebrew.compiler.compile import extract_include_dirs
from rebrew.compiler.toolchain import ToolchainSpec
from rebrew.compiler.unshare import backend_identity
from rebrew.config import ConfigError, load_compile_cache_config, source_date_epoch
from rebrew.utils import atomic_write_bytes

# Deliberately an eligibility whitelist, not another CL command-line parser.
# Other switches still work, through the original uncached driver.
_SAFE_FLAG = re.compile(
    r"(?:c|nologo|w|W[0-4X]|O[012adgistwxy]|Ob[012]|G[dfry]|G[F]|G[es]|Gs[0-9]+|"
    r"M[DLT]|J|Za|Ze|Zp[124816]+|TC|TP|X)\Z"
)
_DEFINE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:=(?:[A-Za-z_][A-Za-z0-9_]*|"
    r"[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*))?\Z"
)
_UNSAFE_TEXT = (
    b"__DATE__",
    b"__TIME__",
    b"__TIMESTAMP__",
    b"__has_include",
    b"__pragma",
    b"_Pragma",
    b"include_next",
    b"include_alias",
    b"_asm",  # Both MSVC spellings, before mask_msvc_syntax blanks them.
    b"##",
    b"??",
    b"%:",
    b"\\\n",
    b"\\\r\n",
)


def _object_command(root: Path, args: list[str]) -> tuple[Path, Path, list[str]] | None:
    source: list[Path] = []
    outputs: list[Path] = []
    flags = iter(args)
    for arg in flags:
        option = arg[1:] if arg.startswith(("/", "-")) else ""
        if option.startswith(("Fo", "Fd", "I", "D", "U")):
            prefix = option[:2] if option.startswith(("Fo", "Fd")) else option[:1]
            value = option[len(prefix) :] or next(flags, "")
            if not value:
                return None
            if prefix in {"D", "U"}:
                # Macro bodies can inject __pragma/include_alias or synthesize
                # time builtins before a literal include. Only simple defines
                # are admitted; complex payloads remain valid uncached commands.
                raw = value.encode("utf-8", errors="surrogateescape")
                if not _DEFINE.fullmatch(value) or any(token in raw for token in _UNSAFE_TEXT):
                    return None
                if prefix == "U" and "=" in value:
                    return None
            if prefix == "Fo":
                outputs.append(Path(value))
            continue
        if option and _SAFE_FLAG.fullmatch(option):
            continue
        if Path(arg).suffix.lower() not in {".c", ".cpp", ".cc", ".cxx"} or not Path(arg).is_file():
            return None
        source.append(Path(arg))
    if not any(arg in {"/c", "-c"} for arg in args) or len(source) != 1 or len(outputs) != 1:
        return None
    output = outputs[0]
    if output.suffix.lower() != ".obj" or not output.parent.is_dir() or output.is_symlink():
        return None
    if output.exists() and (not output.is_file() or output.stat().st_nlink != 1):
        return None
    if not all(p.resolve().is_relative_to(root.resolve()) for p in (output, source[0])):
        return None
    includes = [str(Path(p).resolve()) for p in extract_include_dirs(args)]
    if any(not Path(p).is_dir() or not Path(p).is_relative_to(root.resolve()) for p in includes):
        return None
    return source[0], output, includes


def _ordinary_text(raw: bytes) -> bool:
    """Reject syntax the shared literal include scanner cannot certify."""
    if any(token in raw for token in _UNSAFE_TEXT):
        return False
    tree, _ = parse_c_source(mask_msvc_syntax(raw.decode("utf-8", errors="surrogateescape")))
    if tree.root_node.has_error:
        return False
    specs = []
    nodes = [tree.root_node]
    while nodes:
        node = nodes.pop()
        if node.type == "preproc_call":  # pragmas/imports and unknown directives
            return False
        if node.type == "preproc_include":
            path = node.child_by_field_name("path")
            if path is None or path.type not in {"string_literal", "system_lib_string"}:
                return False
            spelling = raw[path.start_byte : path.end_byte].decode(
                "utf-8", errors="surrogateescape"
            )
            name = spelling[1:-1]
            # Keep driver admission narrower than the shared include resolver;
            # directory spellings and nested include stacks stay uncached.
            if any(char in name for char in "/\\:") or name in {".", ".."}:
                return False
            specs.append(("quote" if path.type == "string_literal" else "angle", name))
        nodes.extend(reversed(node.named_children))
    # AST/scanner disagreement (e.g. a comment between # and include) bypasses.
    return specs == list(include_specs(raw.decode("utf-8", errors="surrogateescape")))


def _snapshot(
    root: Path, spec: ToolchainSpec, args: list[str], source: Path, includes: list[str], image: str
) -> str | None:
    raw = source.read_bytes()
    text = raw.decode("utf-8", errors="surrogateescape")
    contents: dict[str, bytes] = {}
    unresolved: list[tuple[str, tuple[str, ...]]] = []
    paths, fallback, _, consistent = scan_include_closure(
        text,
        str(source.resolve().parent),
        tuple(includes),
        unresolved=unresolved,
        contents=contents,
    )
    if fallback or unresolved or not consistent or set(paths) != set(contents):
        return None
    # MSVC also searches ancestors of nested quoted includes. The generic
    # resolver does not model that stack, so only leaf headers are admitted.
    if any(
        list(include_specs(value.decode("utf-8", errors="surrogateescape")))
        for value in contents.values()
    ):
        return None
    contents[str(source.resolve())] = raw
    if any(
        not Path(path).is_relative_to(root.resolve()) or not _ordinary_text(value)
        for path, value in contents.items()
    ):
        return None
    base = compile_cache_key(
        text,
        str(source),
        args,
        includes,
        image + backend_identity(),
        source.suffix,
        str(source.resolve().parent),
    )
    payload = {
        "base": base,
        "cwd": str(Path.cwd()),
        "root": str(root.resolve()),
        "argv": args,
        "spec": asdict(spec),
        "contents": {
            path: hashlib.sha256(value).hexdigest() for path, value in sorted(contents.items())
        },
    }
    return (
        "cmake-cl-v1:"
        + hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
    )


def _restore(output: Path, data: bytes) -> None:
    # Always replace a certified output, even when bytes agree: a Make-triggered
    # compile must produce a new object mtime, without touching generated inputs.
    with tempfile.TemporaryDirectory(prefix=".rebrew-cl-", dir=output.parent) as directory:
        temporary = Path(directory) / output.name
        atomic_write_bytes(temporary, data)
        temporary.replace(output)


def run_cached_cl(
    root: Path, spec: ToolchainSpec, args: list[str], run: Callable[[str | None], int]
) -> int:
    """Cache only admitted single-object unshare invocations; otherwise run(None)."""
    command = None
    key = None
    cache: CacheBackend | None = None
    record = None
    image = ""
    try:
        command = _object_command(root, args)
        if (
            command is not None
            and source_date_epoch() is not None
            and spec.image
            and spec.image.endswith("-win32")
            and spec.family == "msvc"
            and spec.runtime == "wine"
            and spec.bits in (None, 32)
        ):
            source, output, includes = command
            image = toolchain.image_content_id(toolchain.cached_image_digest(spec.image or ""))
            environment = toolchain.image_environment(image) if image else None
            if environment is not None and not any(
                value for name, value in environment.items() if name.upper() in {"CL", "_CL_"}
            ):
                key = _snapshot(root, spec, args, source, includes, image)
                if key is not None:
                    cache = get_project_cache(load_compile_cache_config(root))
                    record = cache.get(key)
    except (OSError, ValueError, ConfigError):
        key = None
    if key is None or cache is None or command is None:
        return run(None)
    source, output, includes = command
    replay: tuple[str, str] | None = None
    if record is not None:
        try:
            saved = json.loads(record)
            data = base64.b64decode(saved["object"], validate=True)
            if not data or hashlib.sha256(data).hexdigest() != saved["sha256"]:
                raise ValueError("invalid cached object")
            if not isinstance(saved["stdout"], str) or not isinstance(saved["stderr"], str):
                raise ValueError("invalid cached diagnostics")
            if _snapshot(root, spec, args, source, includes, image) == key:
                # A rejected restore must not change what a failed compile leaves.
                with tempfile.TemporaryDirectory(
                    prefix=".rebrew-cl-", dir=output.parent
                ) as directory:
                    previous = Path(directory) / output.name
                    had_output = output.exists()
                    if had_output:
                        output.replace(previous)
                    try:
                        _restore(output, data)
                        if _snapshot(root, spec, args, source, includes, image) == key:
                            replay = (saved["stdout"], saved["stderr"])
                    finally:
                        if replay is None:
                            if had_output:
                                previous.replace(output)
                            else:
                                output.unlink(missing_ok=True)
        except (OSError, ValueError, KeyError, TypeError, binascii.Error):
            pass
    if replay is not None:
        sys.stdout.write(replay[0])
        sys.stderr.write(replay[1])
        return 0
    stdout, stderr = io.StringIO(), io.StringIO()
    try:
        before = output.stat() if output.exists() else None
    except OSError:
        return run(image)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = run(image)
    finally:
        sys.stdout.write(stdout.getvalue())
        sys.stderr.write(stderr.getvalue())
    if rc == 0:
        try:
            after = output.stat()
            data = output.read_bytes()
            if (
                data
                and (
                    before is None
                    or (after.st_mtime_ns, after.st_ctime_ns, after.st_ino, after.st_size)
                    != (before.st_mtime_ns, before.st_ctime_ns, before.st_ino, before.st_size)
                )
                and _snapshot(root, spec, args, source, includes, image) == key
            ):
                saved = {
                    "object": base64.b64encode(data).decode(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "stdout": stdout.getvalue(),
                    "stderr": stderr.getvalue(),
                }
                cache.put(key, json.dumps(saved).encode())
        except (OSError, ValueError):
            pass
    return rc
